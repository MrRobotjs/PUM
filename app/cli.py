# app/cli.py
from flask import Blueprint, current_app
import click
from app import db, scheduler # Import global scheduler instance
from app.models import User, AppSetting, HistoryLog, InviteLink 
from app.scheduler_tasks import register_all_defined_jobs 
from datetime import datetime
# No need to import SQLAlchemyJobStore here if _apply_scheduler_config_to_app handles it
import time 
import os

# Import the specific variables/functions needed from __init__
from app.__init__ import (_discord_bot_should_run, 
                          set_bot_run_flag_and_start_thread, 
                          shutdown_app_services,
                          _apply_scheduler_config_to_app) # Import the helper

bp = Blueprint('cli', __name__, cli_group=None)

@bp.cli.command('create_admin')
@click.option('--username', prompt="Enter admin username", help='The username for the admin account.')
@click.option('--password', prompt="Enter admin password", hide_input=True, confirmation_prompt=True, help='The password for the admin account.')
@click.option('--email', prompt="Enter admin email (optional)", default="", help='Optional email for the admin account.', required=False)
def create_admin_command(username, password, email):
    """Creates an admin user. Useful for initial setup or recovery if no admin exists."""
    if not username or not password:
        click.echo(click.style("Username and password are required.", fg='red')); return
    try:
        admin = User(username=username.strip(), is_admin=True)
        admin.set_password(password)
        if email and email.strip(): admin.email = email.strip().lower()
        db.session.add(admin); db.session.commit()
        click.echo(click.style(f"Admin user '{username}' created successfully.", fg='green'))
        try: HistoryLog.create(event_type="CLI_ADMIN_CREATED", plex_username=username, details="Admin created via CLI.")
        except Exception as log_e: click.echo(click.style(f"Note: Could not log admin creation: {log_e}", fg='yellow'))
    except Exception as e:
        db.session.rollback(); click.echo(click.style(f"Error creating admin user: {e}", fg='red'))
        if current_app: current_app.logger.error(f"CLI: Error creating admin: {e}", exc_info=True)

@bp.cli.command('reset_setup_flag')
@click.confirmation_option(prompt='Are you sure you want to reset the setup completed flag? This will re-enable the setup wizard.')
def reset_setup_flag_command():
    """Resets the SETUP_COMPLETED flag in AppSettings."""
    try:
        setting = AppSetting.query.filter_by(key='SETUP_COMPLETED').first()
        if setting:
            db.session.delete(setting); db.session.commit()
            click.echo(click.style('SETUP_COMPLETED flag removed. Setup wizard can be run again.', fg='green'))
            HistoryLog.create(event_type="CLI_SETUP_FLAG_RESET", details="Setup flag reset via CLI.")
        else: click.echo(click.style('SETUP_COMPLETED flag not found.', fg='yellow'))
    except Exception as e:
        db.session.rollback(); click.echo(click.style(f"Error resetting setup flag: {e}", fg='red'))
        if current_app: current_app.logger.error(f"CLI: Error resetting setup flag: {e}", exc_info=True)

@bp.cli.command('list_settings')
def list_settings_command():
    """Lists all current application settings from the database."""
    try:
        settings = AppSetting.query.all()
        if not settings: click.echo("No application settings found."); return
        click.echo(click.style("Current Application Settings:", fg='cyan', bold=True))
        for setting in settings:
            value_display = setting.value
            if 'TOKEN' in setting.key.upper() or 'SECRET' in setting.key.upper():
                value_display = "[SENSITIVE]" if setting.value else "[Not Set]"
            click.echo(f"  {setting.key}: {value_display}")
    except Exception as e:
        click.echo(click.style(f"Error listing settings (DB may not be initialized?): {e}", fg='red'))

@bp.cli.command('set_setting')
@click.argument('key')
@click.argument('value')
def set_setting_command(key, value):
    """Sets or updates an application setting. Usage: flask set_setting KEY VALUE"""
    try:
        from app.models import update_app_setting
        standardized_key = str(key).strip().upper()
        update_app_setting(standardized_key, str(value).strip())
        click.echo(click.style(f"Setting '{standardized_key}' updated to '{value}'.", fg='green'))
        HistoryLog.create(event_type="CLI_SETTING_UPDATED", details=f"Key: {standardized_key}, New Value: {value}")
    except Exception as e:
        click.echo(click.style(f"Error updating setting '{key}': {e}", fg='red'))
        if current_app: current_app.logger.error(f"CLI: Error setting '{key}': {e}", exc_info=True)

@bp.cli.command('register_jobs_cli')
def register_jobs_command():
    """Ensures all defined APScheduler jobs are registered in the database job store.
    This command does NOT start the scheduler. Relies on create_app for scheduler init.
    """
    click.echo("Registering APScheduler jobs into the database...")
    if not current_app:
        click.echo(click.style("Error: Flask application context not found.", fg='red')); return
    
    logger = current_app.logger
    try:
        with current_app.app_context():
            logger.info(f"CLI register_jobs_cli: Using app instance {id(current_app)} (PID {os.getpid()})")
            
            # The global 'scheduler' instance should have been initialized by create_app
            # when current_app was created. Its config (jobstore, executors) should be set.
            if not scheduler.app:
                logger.warning("CLI register_jobs_cli: Global scheduler has no app. Attempting init_app with current_app.")
                # This implies create_app didn't set it, or it was cleared.
                # Ensure current_app.config is complete before this.
                from app.__init__ import _apply_scheduler_config_to_app # Import if using
                _apply_scheduler_config_to_app(current_app) # Ensure config is on this instance
                scheduler.init_app(current_app)
                if not scheduler.app.config.get('SCHEDULER_EXECUTORS'):
                    logger.error("CLI register_jobs_cli: FATAL - SCHEDULER_EXECUTORS still not set after apply and init.")
                    click.echo(click.style("Critical error: Scheduler executor config missing.", fg='red'))
                    return


            logger.debug(f"CLI register_jobs_cli: Scheduler app: {scheduler.app}, Expected: {current_app}")
            logger.debug(f"CLI register_jobs_cli: Scheduler config 'SCHEDULER_EXECUTORS': {scheduler.app.config.get('SCHEDULER_EXECUTORS')}")
            logger.debug(f"CLI register_jobs_cli: Scheduler config 'SCHEDULER_JOBSTORES': {scheduler.app.config.get('SCHEDULER_JOBSTORES')}")

            # Now, call register_all_defined_jobs. It uses the global scheduler.
            processed_info = register_all_defined_jobs(current_app, scheduler) 
            click.echo(click.style(f"APScheduler jobs registration attempt complete. Processed: {processed_info}", fg='green'))
            
            # ... (DB verification logic as before) ...

    except ValueError as ve: # Catch the specific "Cannot create executor" error
        click.echo(click.style(f"Error during job registration (ValueError): {ve}", fg='red'))
        logger.error(f"CLI register_jobs_cli (ValueError): {ve}", exc_info=True)
        logger.debug(f"Offending config during ValueError: EXECUTORS: {current_app.config.get('SCHEDULER_EXECUTORS')}, JOBSTORES: {current_app.config.get('SCHEDULER_JOBSTORES')}")
    except Exception as e:
        click.echo(click.style(f"Error during job registration: {e}", fg='red'))
        logger.error(f"CLI register_jobs_cli: Error: {e}", exc_info=True)

@bp.cli.command('start_services_dev')
def start_services_dev_command():
    """
    (FOR LOCAL DEVELOPMENT/DEBUGGING ONLY)
    Starts background services (Scheduler, Discord Bot) in the current process.
    """
    click.echo(click.style("DEV MODE: Attempting to start services (Scheduler, Bot) in this process...", fg='yellow'))
    if not current_app:
        click.echo(click.style("Error: Flask application context not found.", fg='red')); return
        
    try:
        with current_app.app_context():
            _apply_scheduler_config_to_app(current_app) # Ensure current app has full scheduler config

            scheduler.init_app(current_app) # Init global scheduler with this app
            register_all_defined_jobs(current_app, scheduler) # Ensure jobs are defined for this scheduler instance

            if not scheduler.running:
                click.echo("Attempting to start APScheduler for dev...")
                scheduler.start(paused=False)
                if scheduler.running:
                    click.echo(click.style("APScheduler IS RUNNING in this dev process.", fg='green'))
                    click.echo(f"Jobs: {[job.id for job in scheduler.get_jobs()]}")
                else:
                    click.echo(click.style("APScheduler dev start() called, but scheduler.running is FALSE.", fg='red'))
            else:
                click.echo(click.style("APScheduler already running in this dev process.", fg='yellow'))

            set_bot_run_flag_and_start_thread(current_app)
            
            click.echo(click.style("DEV services startup attempt complete. Monitor logs. Press Ctrl+C to stop.", fg='cyan'))
            if _discord_bot_should_run.is_set() or scheduler.running:
                click.echo("Services running. Keeping CLI alive (Ctrl+C to exit)...")
                while True: time.sleep(1) 
            else: click.echo("No services were set to run persistently by this dev command.")
    except KeyboardInterrupt:
        click.echo(click.style("\nDEV Services interrupted by user. Attempting shutdown...", fg='yellow'))
    except Exception as e:
        click.echo(click.style(f"Error during DEV service initialization: {e}", fg='red'))
        if current_app: current_app.logger.error(f"CLI start_services_dev: Error: {e}", exc_info=True)
    finally:
        click.echo("Calling shutdown_app_services from DEV command...")
        shutdown_app_services()

@bp.cli.command('clear_invites')
@click.option('--expired-only', is_flag=True, default=False, help='Only clear invites that have expired or reached max uses.')
@click.confirmation_option(prompt='Are you sure you want to clear these invite links? This action cannot be undone.')
def clear_invites_command(expired_only):
    """Clears invite links from the database."""
    try:
        query = InviteLink.query; action_desc = "all"
        if expired_only:
            action_desc = "expired/used"; now = datetime.utcnow()
            query = query.filter(db.or_((InviteLink.expires_at.isnot(None)) & (InviteLink.expires_at < now), 
                                        (InviteLink.max_uses.isnot(None)) & (InviteLink.max_uses > 0) & (InviteLink.current_uses >= InviteLink.max_uses)))
        invites_to_delete = query.all(); count = len(invites_to_delete)
        if count == 0: click.echo(click.style(f"No {action_desc} invite links found to clear.", fg='yellow')); return
        for invite in invites_to_delete: db.session.delete(invite)
        db.session.commit(); click.echo(click.style(f"Successfully cleared {count} {action_desc} invite link(s).", fg='green'))
        HistoryLog.create(event_type="CLI_INVITES_CLEARED", details=f"Cleared {count} {action_desc} invites.")
    except Exception as e:
        db.session.rollback(); click.echo(click.style(f"Error clearing invites: {e}", fg='red'))
        if current_app: current_app.logger.error(f"CLI: Error clearing invites: {e}", exc_info=True)