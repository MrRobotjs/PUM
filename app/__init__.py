# File: app/__init__.py
import os
import logging
from logging.handlers import RotatingFileHandler
import secrets
from datetime import datetime 
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, g, request, redirect, url_for, current_app, render_template
from flask_login import current_user

from .config import config
from .extensions import (
    db,
    migrate,
    login_manager,
    csrf,
    scheduler,
    babel, 
    htmx
)
from .models import AdminAccount, Setting
from .utils import helpers 

def get_locale_for_babel():
    return 'en'

def initialize_settings_from_db(app_instance):
    engine_conn = None
    try:
        engine_conn = db.engine.connect() 
        if not db.engine.dialect.has_table(engine_conn, Setting.__tablename__):
            app_instance.logger.warning("Settings table not found during init. Skipping DB config load.")
            if not app_instance.config.get('SECRET_KEY'): app_instance.config['SECRET_KEY'] = secrets.token_hex(32)
            return
    except Exception as e: 
        app_instance.logger.error(f"Cannot connect to DB or check settings table in init: {e}")
        if not app_instance.config.get('SECRET_KEY'): app_instance.config['SECRET_KEY'] = secrets.token_hex(32)
        return
    finally:
        if engine_conn: engine_conn.close()
    try:
        all_settings = Setting.query.all()
        settings_dict = {s.key: s.get_value() for s in all_settings}
        for k, v in settings_dict.items():
            if k.isupper(): app_instance.config[k] = v
        db_sk = settings_dict.get('SECRET_KEY')
        if db_sk: app_instance.config['SECRET_KEY'] = db_sk
        elif not app_instance.config.get('SECRET_KEY'): 
            app_instance.config['SECRET_KEY'] = secrets.token_hex(32)
            app_instance.logger.warning("SECRET_KEY created temporarily. Complete setup.")
        app_instance.logger.info("Application settings loaded/refreshed from database.")
    except Exception as e:
        app_instance.logger.error(f"Error querying settings from database: {e}. Using defaults.")
        if not app_instance.config.get('SECRET_KEY'): app_instance.config['SECRET_KEY'] = secrets.token_hex(32)

def register_error_handlers(app):
    @app.errorhandler(403)
    def forbidden_page(error): return render_template("errors/403.html"), 403
    @app.errorhandler(404)
    def page_not_found(error): return render_template("errors/404.html"), 404
    @app.errorhandler(500)
    def server_error_page(error): return render_template("errors/500.html"), 500
    
def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')
    
    app = Flask(__name__, instance_relative_config=True)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    app.jinja_env.add_extension('jinja2.ext.do')
    
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    try:
        if not os.path.exists(app.instance_path):
            os.makedirs(app.instance_path)
    except OSError as e:
        print(f"Init.py - create_app(): Could not create instance path at {app.instance_path}: {e}")

    log_level_name = os.environ.get('FLASK_LOG_LEVEL', 'INFO').upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    app.logger.setLevel(log_level)

    if not app.debug and not app.testing:
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            try: os.mkdir(log_dir)
            except OSError: app.logger.error(f"Init.py - create_app(): Could not create '{log_dir}' directory for file logging.")
        
        if os.path.exists(log_dir): 
            try:
                file_handler = RotatingFileHandler(os.path.join(log_dir, 'pum.log'), maxBytes=10240, backupCount=10)
                file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
                file_handler.setLevel(log_level) 
                app.logger.handlers.clear()
                app.logger.addHandler(file_handler)
                app.logger.propagate = False
                app.logger.info(f"Init.py - create_app(): File logging configured. Level: {log_level_name}")
            except Exception as e_fh:
                app.logger.error(f"Init.py - create_app(): Failed to configure file logging: {e_fh}")
    
    app.logger.info(f'Init.py - create_app(): Plex User Manager starting with log level: {log_level_name}')

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    htmx.init_app(app)
    babel.init_app(app, locale_selector=get_locale_for_babel)

    with app.app_context():
        initialize_settings_from_db(app)

    if app.config.get('SCHEDULER_API_ENABLED', True):
        if not scheduler.running:
            try:
                scheduler.init_app(app)
                scheduler.start(paused=app.config.get('SCHEDULER_PAUSED_ON_START', False))
                app.logger.info("Init.py - create_app(): APScheduler successfully started.")
                
                is_werkzeug_main_process = os.environ.get("WERKZEUG_RUN_MAIN") == "true"
                should_schedule_tasks = False

                if is_werkzeug_main_process:
                    should_schedule_tasks = True
                    app.logger.debug("Init.py - Task Scheduling Check: Running with Flask reloader (WERKZEUG_RUN_MAIN=true). Will attempt to schedule.")
                elif not app.testing: # Not Flask's reloader, and not testing (e.g., Gunicorn worker or direct python run.py)
                    should_schedule_tasks = True
                    app.logger.debug("Init.py - Task Scheduling Check: Not Werkzeug main process and not testing. Will attempt to schedule.")
                else: 
                    app.logger.debug("Init.py - Task Scheduling Check: In testing mode or other non-scheduling context. Skipping task scheduling.")

                app.logger.debug(f"Init.py - Task Scheduling Check - Values: WERKZEUG_RUN_MAIN='{os.environ.get('WERKZEUG_RUN_MAIN')}', app.debug={app.debug}, app.testing={app.testing}")
                app.logger.debug(f"Init.py - Task Scheduling Check - Decision: should_schedule_tasks = {should_schedule_tasks}")

                if should_schedule_tasks:
                    app.logger.info("Init.py - Task Scheduling Check: Condition MET. Attempting to schedule tasks.")
                    with app.app_context():
                        engine_conn_scheduler = None
                        try:
                            engine_conn_scheduler = db.engine.connect()
                            if db.engine.dialect.has_table(engine_conn_scheduler, Setting.__tablename__):
                                from .services import task_service 
                                task_service.schedule_all_tasks()
                                app.logger.info("Init.py - Successfully called task_service.schedule_all_tasks().")
                            else:
                                app.logger.warning("Init.py - Settings table not found when trying to schedule tasks; task scheduling that depends on DB settings is skipped.")
                        except Exception as e_task_sched:
                             app.logger.error(f"Init.py - Error during task scheduling DB interaction or call: {e_task_sched}", exc_info=True)
                        finally:
                            if engine_conn_scheduler:
                                engine_conn_scheduler.close()
                else:
                    app.logger.info("Init.py - Task Scheduling Check: Condition NOT MET. Skipping call to task_service.schedule_plex_session_monitoring().")

            except Exception as e_scheduler_init:
                app.logger.error(f"Init.py - Failed to initialize/start APScheduler or prepare for task scheduling: {e_scheduler_init}", exc_info=True)
        else:
            app.logger.info("Init.py - create_app(): APScheduler already running (or SCHEDULER_API_ENABLED is false).")

    app.jinja_env.filters['format_datetime_human'] = helpers.format_datetime_human
    app.jinja_env.filters['time_ago'] = helpers.time_ago

    @app.context_processor
    def inject_current_year():
        return {'current_year': datetime.utcnow().year}

    @login_manager.user_loader
    def load_user(user_id):
        # Ensure table exists before querying, critical during first `flask db upgrade`
        try:
            with app.app_context(): # Ensure context for db operations if called early
                engine_conn_lu = db.engine.connect()
                table_exists = db.engine.dialect.has_table(engine_conn_lu, AdminAccount.__tablename__)
                engine_conn_lu.close()
                if table_exists:
                    return AdminAccount.query.get(int(user_id))
                return None
        except Exception as e_load_user:
            app.logger.error(f"Init.py - load_user(): Error checking/loading user: {e_load_user}")
            return None


    @app.before_request
    def before_request_tasks():
        g.app_name = current_app.config.get('APP_NAME', 'Plex User Manager')
        g.plex_url = None; g.app_base_url = None
        g.discord_oauth_enabled_for_invite = False; g.setup_complete = False 

        current_app.logger.debug(f"Init.py - before_request_tasks(): Endpoint: {request.endpoint}, Path: {request.path if request else 'No request object'}")

        try:
            engine_conn_br = None; settings_table_exists = False; admin_table_exists = False
            try:
                engine_conn_br = db.engine.connect()
                settings_table_exists = db.engine.dialect.has_table(engine_conn_br, Setting.__tablename__)
                admin_table_exists = db.engine.dialect.has_table(engine_conn_br, AdminAccount.__tablename__)
            except Exception as e_db_check:
                current_app.logger.warning(f"Init.py - before_request_tasks(): DB connection/table check error: {e_db_check}")
            finally:
                if engine_conn_br: engine_conn_br.close()

            if settings_table_exists:
                g.app_name = Setting.get('APP_NAME', current_app.config.get('APP_NAME', 'Plex User Manager'))
                g.plex_url = Setting.get('PLEX_URL')
                g.app_base_url = Setting.get('APP_BASE_URL')
                discord_setting_val = Setting.get('DISCORD_OAUTH_ENABLED', False)
                g.discord_oauth_enabled_for_invite = discord_setting_val if isinstance(discord_setting_val, bool) else str(discord_setting_val).lower() == 'true'

                admin_account_present = AdminAccount.query.first() is not None if admin_table_exists else False
                plex_config_done = bool(g.plex_url and Setting.get('PLEX_TOKEN')) 
                pum_config_done = bool(g.app_base_url)
                g.setup_complete = admin_account_present and plex_config_done and pum_config_done
                current_app.logger.debug(f"Init.py - before_request_tasks(): Setup status: admin={admin_account_present}, plex={plex_config_done}, pum={pum_config_done} -> Overall setup_complete={g.setup_complete}")
            else: 
                g.setup_complete = False
                current_app.logger.debug("Init.py - before_request_tasks(): Settings table not found. g.setup_complete forced to False.")
        except Exception as e_g_hydrate:
            current_app.logger.error(f"Init.py - before_request_tasks(): Error hydrating g values: {e_g_hydrate}", exc_info=True)
        
        current_app.config['SETUP_COMPLETE'] = g.setup_complete

        if not g.setup_complete and \
           request.endpoint and \
           not request.endpoint.startswith('setup.') and \
           not request.endpoint == 'auth.logout_setup' and \
           not request.endpoint.startswith('static') and \
           not request.endpoint == 'api.test_plex_connection': # Allow API test during setup
            
            current_app.logger.debug(f"Init.py - before_request_tasks(): Setup not complete, current endpoint '{request.endpoint}' requires redirect to setup.")
            try:
                # Re-check table existence for redirection logic, as it's critical
                engine_conn_sr, admin_table_exists_sr_redir, settings_table_exists_sr_redir = None, False, False
                try:
                    engine_conn_sr = db.engine.connect()
                    admin_table_exists_sr_redir = db.engine.dialect.has_table(engine_conn_sr, AdminAccount.__tablename__)
                    settings_table_exists_sr_redir = db.engine.dialect.has_table(engine_conn_sr, Setting.__tablename__)
                finally:
                    if engine_conn_sr: engine_conn_sr.close()

                if not (admin_table_exists_sr_redir and AdminAccount.query.first()):
                    if request.endpoint != 'setup.account_setup' and request.endpoint != 'setup.plex_sso_callback_setup_admin':
                        current_app.logger.info(f"Init.py - before_request_tasks(): Redirecting to account_setup (no admin).")
                        return redirect(url_for('setup.account_setup'))
                elif not (settings_table_exists_sr_redir and Setting.get('PLEX_URL') and Setting.get('PLEX_TOKEN')):
                    if request.endpoint != 'setup.plex_config':
                        current_app.logger.info(f"Init.py - before_request_tasks(): Redirecting to plex_config.")
                        return redirect(url_for('setup.plex_config'))
                elif not (settings_table_exists_sr_redir and Setting.get('APP_BASE_URL')):
                    if request.endpoint != 'setup.pum_config':
                        current_app.logger.info(f"Init.py - before_request_tasks(): Redirecting to pum_config.")
                        return redirect(url_for('setup.pum_config'))
                # If all core setup DB settings seem present but g.setup_complete is still false,
                # This indicates a potential logic mismatch in g.setup_complete calculation or a new required step.
                # Defaulting to account_setup if unsure.
                elif request.endpoint != 'setup.account_setup' and \
                     request.endpoint != 'setup.plex_config' and \
                     request.endpoint != 'setup.pum_config' and \
                     request.endpoint != 'setup.discord_config' and \
                     request.endpoint != 'setup.finish_setup':
                     current_app.logger.warning(f"Init.py - before_request_tasks(): g.setup_complete is False but basic settings seem present. Endpoint: {request.endpoint}. Redirecting to account_setup as a fallback.")
                     # return redirect(url_for('setup.account_setup'))
                     pass # Or consider what the safest action is here to avoid redirect loops
            except Exception as e_setup_redirect:
                current_app.logger.error(f"Init.py - before_request_tasks(): DB error during setup redirection logic: {e_setup_redirect}", exc_info=True)
                if request.endpoint != 'setup.account_setup':
                     pass # Avoid redirect loop if account_setup itself errors


    # Register blueprints
    from .routes.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    from .routes.setup import bp as setup_bp
    app.register_blueprint(setup_bp, url_prefix='/setup')
    from .routes.dashboard import bp as dashboard_bp
    app.register_blueprint(dashboard_bp) # Root blueprint
    from .routes.users import bp as users_bp
    app.register_blueprint(users_bp, url_prefix='/users')
    from .routes.invites import bp as invites_bp
    app.register_blueprint(invites_bp) # url_prefix='/invites' is handled in invites.py itself for public link
    from .routes.api import bp as api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    register_error_handlers(app)

    return app