# app/__init__.py
import os
import threading
import asyncio
import atexit
from flask import Flask, render_template, request 
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_babel import Babel
from flask_apscheduler import APScheduler 
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, CSRFError
import logging
import sys 
from werkzeug.middleware.proxy_fix import ProxyFix
from config import Config 
from app.template_filters import time_ago_filter

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
babel = Babel()
scheduler = APScheduler() 
server_session = Session()
csrf = CSRFProtect()

bot_instance = None 
discord_bot_thread = None
_discord_bot_should_run = threading.Event() 
_discord_bot_lock = threading.Lock() 
_app_services_initialized_lock = threading.Lock()
_app_services_initialized_for_pid = {}

def _apply_scheduler_config_to_app(app_instance):
    logger = app_instance.logger
    pid = os.getpid()
    logger.debug(f"_apply_scheduler_config_to_app: Applying config for app in PID {pid} on instance {id(app_instance)}")
    with app_instance.app_context():
        sa_state = app_instance.extensions.get('sqlalchemy')
        if sa_state and hasattr(sa_state, 'engine') and sa_state.engine is not None:
            app_instance.config['SCHEDULER_JOBSTORES'] = {'default': SQLAlchemyJobStore(engine=sa_state.engine, tablename='apscheduler_jobs')}
            logger.debug(f"_apply_scheduler_config_to_app: Configured SCHEDULER_JOBSTORES using instance's engine (PID {pid}).")
        else:
            logger.error(f"_apply_scheduler_config_to_app: DB engine not found for instance {id(app_instance)} (PID {pid}). Using URI fallback for JOBSTORES.")
            app_instance.config['SCHEDULER_JOBSTORES'] = {'default': SQLAlchemyJobStore(url=app_instance.config['SQLALCHEMY_DATABASE_URI'], tablename='apscheduler_jobs')}
    app_instance.config.setdefault('SCHEDULER_EXECUTORS', {'default': {'type': 'threadpool', 'max_workers': 5}})
    app_instance.config.setdefault('SCHEDULER_JOB_DEFAULTS', {'coalesce': False, 'max_instances': 1, 'misfire_grace_time': 300})
    app_instance.config.setdefault('SCHEDULER_API_ENABLED', False)
    app_instance.config['SCHEDULER_AUTOSTART'] = False # Explicitly False, Gunicorn worker will start it
    app_instance.config.setdefault('SCHEDULER_CREATE_TABLES', False)
    logger.debug(f"_apply_scheduler_config_to_app: Final SCHEDULER_EXECUTORS for PID {pid}: {app_instance.config.get('SCHEDULER_EXECUTORS')}")
    logger.debug(f"_apply_scheduler_config_to_app: SCHEDULER_AUTOSTART set to {app_instance.config.get('SCHEDULER_AUTOSTART')}")

def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)
    pid = os.getpid()
    if not app.debug and not app.testing: app.logger.setLevel(logging.INFO)
    else: app.logger.setLevel(logging.DEBUG)
    app.logger.info(f"Flask app ({app.name}) creating in PID {pid}. Debug mode: {app.debug}. Instance ID: {id(app)}")
    db.init_app(app) 
    migrate.init_app(app, db) 
    _apply_scheduler_config_to_app(app) 
    scheduler.init_app(app) 
    app.logger.info(f"Flask-APScheduler initialized for app in PID {pid}. Effective AUTOSTART from config: {app.config.get('SCHEDULER_AUTOSTART')}.")
    
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    app.jinja_env.add_extension('jinja2.ext.do'); app.jinja_env.filters['time_ago'] = time_ago_filter
    try: os.makedirs(app.instance_path, exist_ok=True); os.makedirs(os.path.join(app.instance_path, 'flask_session'), exist_ok=True)
    except OSError as e: app.logger.critical(f"CRITICAL: Error creating instance path: {e}", exc_info=True)
    login_manager.init_app(app); babel.init_app(app); server_session.init_app(app); csrf.init_app(app) 
    aps_logger = logging.getLogger('apscheduler')
    if not aps_logger.handlers:
        aps_stream_handler = logging.StreamHandler(sys.stdout); aps_formatter = logging.Formatter('%(asctime)s - apscheduler - %(levelname)s - [PID:%(process)d] - %(message)s'); aps_stream_handler.setFormatter(aps_formatter); aps_logger.addHandler(aps_stream_handler)
    if app.debug: aps_logger.setLevel(logging.DEBUG); 
    else: aps_logger.setLevel(logging.WARNING)
    aps_logger.propagate = False

    # Explicit Scheduler Start Logic for Gunicorn/Werkzeug Workers
    # SCHEDULER_AUTOSTART in app.config is now False. We control start here.
    if not scheduler.running:
        is_gunicorn_worker = "gunicorn" in os.environ.get("SERVER_SOFTWARE", "").lower()
        is_werkzeug_reloader_worker = "run" in sys.argv and os.environ.get("WERKZEUG_RUN_MAIN") != "true"
        
        # These utility CLIs should not start the scheduler in create_app
        utility_cli_commands = ["db", "shell", "routes", "register_jobs_cli", "start_services_dev"]
        is_utility_or_dev_start_cli = any(cmd_arg in sys.argv for cmd_arg in utility_cli_commands)

        if (is_gunicorn_worker or is_werkzeug_reloader_worker) and not is_utility_or_dev_start_cli:
            app.logger.info(f"APScheduler (PID {pid}) in worker context. Attempting explicit start.")
            try:
                scheduler.start(paused=False)
                if scheduler.running: app.logger.info(f"APScheduler (PID {pid}) EXPLICITLY STARTED and is RUNNING in worker.")
                else: app.logger.error(f"APScheduler (PID {pid}) explicit start() called in worker, but still NOT RUNNING.")
            except Exception as e_explicit_start:
                app.logger.error(f"APScheduler (PID {pid}) error on explicit start() in worker: {e_explicit_start}", exc_info=True)
        else:
             app.logger.info(f"APScheduler (PID {pid}): Not a Gunicorn/Werkzeug worker OR is a utility/dev_start CLI. Scheduler not started by create_app here.")
    elif scheduler.running:
        app.logger.info(f"APScheduler (PID {pid}) IS ALREADY RUNNING (unexpected if AUTOSTART is False and not a worker).")

    from app import scheduler_tasks 
    app.logger.debug(f"scheduler_tasks.py imported in PID {pid}. Jobs defined by decorator.")
    
    login_manager.login_view = 'auth.login'; login_manager.login_message_category = 'info' 
    from app.routes_main import main_bp; app.register_blueprint(main_bp)
    from app.auth import bp as auth_bp; app.register_blueprint(auth_bp, url_prefix='/auth')
    from app.cli import bp as cli_bp; app.register_blueprint(cli_bp)
    from app.sso_plex import sso_plex_bp; app.register_blueprint(sso_plex_bp, url_prefix='/sso/plex')
    from app.sso_discord import sso_discord_bp; app.register_blueprint(sso_discord_bp, url_prefix='/sso/discord')
    from app.routes_setup import setup_bp; app.register_blueprint(setup_bp, url_prefix='/setup') 
    from app.routes_admin_invites import invites_bp; app.register_blueprint(invites_bp, url_prefix='/admin/invites') 
    from app.routes_admin_users import users_bp; app.register_blueprint(users_bp, url_prefix='/admin/users') 
    from app.routes_admin_settings import settings_bp; app.register_blueprint(settings_bp, url_prefix='/admin/settings')
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e): app.logger.warning(f"CSRF Error: {e.description}. Path: {request.path if request else 'Unknown'}"); return render_template('errors/csrf_error.html', error_description=e.description), 400
    @app.errorhandler(404)
    def not_found_error(error): return render_template('errors/404.html', error=error), 404
    @app.errorhandler(500)
    def internal_error(error):
        try: db.session.rollback()
        except: pass 
        app.logger.error(f"Internal Server Error occurred", exc_info=True); return render_template('errors/500.html', error=error), 500
    @app.context_processor
    def inject_app_settings_for_template():
        try: from app.models import get_all_app_settings, get_app_setting; return dict(app_settings=get_all_app_settings(), setup_completed=(get_app_setting('SETUP_COMPLETED') == 'true'))
        except Exception as e_ctx: app.logger.error(f"Context processor: DB access for settings failed: {e_ctx}", exc_info=True); return dict(app_settings={'APP_NAME':'PUM (DB Err)'}, setup_completed=False)
    atexit.register(shutdown_app_services); app.logger.info(f"Flask app instance fully created for PID {pid}.")
    return app

def initialize_app_services(current_app_instance):
    global _app_services_initialized_for_pid, scheduler
    logger = current_app_instance.logger; pid = os.getpid()
    logger.info(f"--- initialize_app_services called for PID {pid} (App ID: {id(current_app_instance)}) ---")
    with _app_services_initialized_lock:
        if _app_services_initialized_for_pid.get(pid) and "register_jobs_cli" not in sys.argv:
            logger.info(f"Services for PID {pid} already marked initialized. Skipping full re-init unless 'register_jobs_cli'.")
            return
        logger.info(f"Performing service initialization in PID {pid} (for {sys.argv[1] if len(sys.argv) > 1 else 'app'})...")
        try:
            with current_app_instance.app_context(): 
                _apply_scheduler_config_to_app(current_app_instance)
                # Ensure the global scheduler is configured with THIS app instance for job registration
                # This init_app will use the config now present on current_app_instance.config
                # SCHEDULER_AUTOSTART is False from _apply_scheduler_config_to_app, so no start here.
                scheduler.init_app(current_app_instance) 
                logger.info(f"Global scheduler (re)init'd with CLI app instance (PID {pid}) for job registration.")
                from app.scheduler_tasks import register_all_defined_jobs 
                register_all_defined_jobs(current_app_instance, scheduler) # Register jobs into DB
                
                is_start_services_dev_command = "start_services_dev" in sys.argv
                if is_start_services_dev_command: # Only for the 'flask start_services_dev' command
                    if not scheduler.running and not current_app_instance.config.get('TESTING', False):
                        logger.info(f"CLI 'start_services_dev': Attempting to start APScheduler in PID {pid}...")
                        try:
                            scheduler.start(paused=False) 
                            if scheduler.running: logger.info(f"CLI 'start_services_dev': APScheduler IS RUNNING in PID {pid}!")
                            else: logger.error(f"CLI 'start_services_dev': APScheduler start() called, but scheduler.running is FALSE.")
                        except Exception as e_sched_start_cli: 
                            logger.error(f"CLI 'start_services_dev': Error starting scheduler: {e_sched_start_cli}", exc_info=True)
                    elif scheduler.running: 
                        logger.info(f"CLI 'start_services_dev': APScheduler already running in PID {pid}.")
                    set_bot_run_flag_and_start_thread(current_app_instance)
        except Exception as e_init_svc: 
            logger.error(f"Error during initialize_app_services for PID {pid}: {e_init_svc}", exc_info=True)
        _app_services_initialized_for_pid[pid] = True
        logger.info(f"--- EXITING initialize_app_services for PID {pid} ---")

# --- Bot and Shutdown Functions ---
# (These remain the same as your last fully provided correct version)
def set_bot_run_flag_and_start_thread(flask_app_instance): # ...
    global _discord_bot_should_run, discord_bot_thread, bot_instance, _discord_bot_lock; from app.models import get_app_setting ; logger = flask_app_instance.logger 
    if get_app_setting('DISCORD_BOT_ENABLED') == 'true' and get_app_setting('DISCORD_BOT_TOKEN'): _discord_bot_should_run.set() 
    else:
        _discord_bot_should_run.clear();
        if get_app_setting('DISCORD_BOT_ENABLED') == 'true' and not get_app_setting('DISCORD_BOT_TOKEN'): logger.warning("Discord Bot enabled but TOKEN missing.")
        else: logger.info("Discord bot features disabled.")
        if bot_instance and not bot_instance.is_closed() and hasattr(bot_instance, 'thread_loop') and bot_instance.thread_loop.is_running(): asyncio.run_coroutine_threadsafe(bot_instance.close(), bot_instance.thread_loop)
        return 
    if _discord_bot_should_run.is_set(): 
        with _discord_bot_lock: 
            if discord_bot_thread is None or not discord_bot_thread.is_alive(): logger.info("Attempting to start Discord bot thread..."); discord_bot_thread = threading.Thread(target=run_discord_bot_async_loop, args=(flask_app_instance,), daemon=True, name="DiscordBotThread"); discord_bot_thread.start()
            elif flask_app_instance.debug: logger.debug("Discord bot thread already running or initiation in progress.")
    else: logger.info("Discord bot run flag is not set. Thread will not be started.")
def run_discord_bot_async_loop(flask_app_instance): # ...
    global bot_instance, _discord_bot_should_run ; from app.models import get_app_setting; from app.discord_bot_logic import setup_bot_events_and_commands, discord ; logger = flask_app_instance.logger 
    if not _discord_bot_should_run.is_set(): logger.info("Discord bot async: Run flag false. Exiting."); return
    bot_token = get_app_setting('DISCORD_BOT_TOKEN')
    if not bot_token: _discord_bot_should_run.clear(); logger.error("Discord bot async: Token missing. Exiting."); return
    bot_app_id_str = get_app_setting('DISCORD_BOT_APP_ID'); bot_app_id = int(bot_app_id_str) if bot_app_id_str and bot_app_id_str.isdigit() else None
    intents = discord.Intents.default(); intents.members = True; intents.message_content = True 
    current_bot_obj = discord.ext.commands.Bot(command_prefix=get_app_setting('DISCORD_BOT_PREFIX', '!'), intents=intents, application_id=bot_app_id)
    current_bot_obj.flask_app = flask_app_instance; setup_bot_events_and_commands(current_bot_obj); bot_instance = current_bot_obj
    new_loop = asyncio.new_event_loop(); asyncio.set_event_loop(new_loop); setattr(bot_instance, 'thread_loop', new_loop)
    try: logger.info(f"Discord bot starting event loop in thread {threading.get_ident()}..."); new_loop.run_until_complete(bot_instance.start(bot_token)) 
    except discord.LoginFailure: logger.error("Discord bot login failed."); _discord_bot_should_run.clear()
    except Exception as e: logger.error(f"Discord bot loop error: {e}", exc_info=True); _discord_bot_should_run.clear()
    finally:
        if hasattr(bot_instance, 'thread_loop') and bot_instance.thread_loop.is_running(): bot_instance.thread_loop.run_until_complete(bot_instance.thread_loop.shutdown_asyncgens())
        if hasattr(bot_instance, 'thread_loop'): bot_instance.thread_loop.close()
        bot_instance = None; logger.info("Discord bot event loop finished and resources cleaned.")
def shutdown_app_services(): # ...
    global bot_instance, _discord_bot_should_run, discord_bot_thread, scheduler, _app_services_initialized_for_pid; shutdown_logger = logging.getLogger("app.shutdown")
    if not shutdown_logger.handlers: handler = logging.StreamHandler(sys.stdout); formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - SHUTDOWN PID:%(process)d: %(message)s'); handler.setFormatter(formatter); shutdown_logger.addHandler(handler); shutdown_logger.setLevel(logging.INFO); shutdown_logger.propagate = False
    pid = os.getpid(); shutdown_logger.info(f"Application shutdown sequence initiated for PID {pid}.")
    _discord_bot_should_run.clear() 
    if bot_instance and hasattr(bot_instance, 'thread_loop') and bot_instance.thread_loop and not bot_instance.is_closed(): 
        shutdown_logger.info(f"Issuing close to Discord bot from PID {pid}...");
        if bot_instance.thread_loop.is_running(): 
            future = asyncio.run_coroutine_threadsafe(bot_instance.close(), bot_instance.thread_loop) 
            try: future.result(timeout=10); shutdown_logger.info(f"Discord bot close() ack from PID {pid}.")
            except asyncio.TimeoutError: shutdown_logger.warning(f"Discord bot close() timed out (10s) from PID {pid}.")
            except Exception as e_bot_close: shutdown_logger.warning(f"Discord bot close() failed from PID {pid}: {e_bot_close}")
        else: shutdown_logger.warning(f"Discord bot event loop not running in PID {pid}; cannot schedule close.")
    if discord_bot_thread and discord_bot_thread.is_alive():
        shutdown_logger.info(f"Waiting for Discord bot thread to join (10s) from PID {pid}...")
        discord_bot_thread.join(timeout=10) 
        if discord_bot_thread.is_alive(): shutdown_logger.warning(f"Discord bot thread did not join in time from PID {pid}.")
        else: shutdown_logger.info(f"Discord bot thread joined successfully from PID {pid}.")
    is_this_process_scheduler_running = False
    if scheduler and hasattr(scheduler, 'running') and scheduler.running: is_this_process_scheduler_running = True
    if is_this_process_scheduler_running:
        shutdown_logger.info(f"Attempting to shut down APScheduler in PID {pid}...")
        try: scheduler.shutdown(wait=True); shutdown_logger.info(f"APScheduler shutdown successful in PID {pid}.")
        except Exception as e_shutdown: shutdown_logger.error(f"Error during APScheduler shutdown in PID {pid}: {e_shutdown}", exc_info=True)
    else: shutdown_logger.info(f"APScheduler not considered running by this process (PID {pid}). No shutdown by this process.")
    if pid in _app_services_initialized_for_pid: del _app_services_initialized_for_pid[pid]
    shutdown_logger.info(f"Application service cleanup process for PID {pid} complete.")

from app import models