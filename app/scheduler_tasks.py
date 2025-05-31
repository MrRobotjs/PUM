# app/scheduler_tasks.py
from flask import current_app
from app import scheduler, db 
from app.models import User, HistoryLog, get_app_setting 
from app.plex_utils import remove_plex_friend # get_plex_server might not be needed if no tasks use it
from app.discord_utils import is_discord_user_on_server
from datetime import datetime, timedelta, timezone
import logging 
# import requests # Not needed if update_active_streams_task is removed and others don't use it
# import traceback # Not needed if update_active_streams_task is removed

# REMOVED: @scheduler.task('interval', id='update_active_streams_job', ...)
# REMOVED: def update_active_streams_task(): ... (the entire function)

@scheduler.task('interval', id='check_discord_members_periodic_job', hours=1, misfire_grace_time=900)
def check_discord_members_periodic_task():
    app = scheduler.app 
    if not app: 
        logging.getLogger('app.scheduler.discord_members').error("CRITICAL: No Flask app for check_discord_members_periodic_task.")
        return
    with app.app_context():
        logger = current_app.logger
        task_name = "Scheduler(DiscordMembers)"
        if not (get_app_setting('SETUP_COMPLETED') == 'true' and get_app_setting('DISCORD_BOT_ENABLED') == 'true' and \
                get_app_setting('DISCORD_BOT_TOKEN') and get_app_setting('DISCORD_SERVER_ID')):
            if logger.isEnabledFor(logging.DEBUG): logger.debug(f"{task_name}: Skipped (config missing/disabled).")
            return
        
        logger.info(f"{task_name}: Task STARTED.")
        users_to_check = User.query.filter(User.is_admin == False, User.discord_id.isnot(None), User.discord_id != "").all()
        if not users_to_check: 
            logger.info(f"{task_name}: No users with Discord IDs to check. Task FINISHED.")
            return
        
        checked_count = 0; removed_count = 0
        for user_obj in users_to_check:
            checked_count += 1
            is_on_server, check_message = is_discord_user_on_server(user_obj.discord_id) 
            if not is_on_server:
                plex_ident = user_obj.plex_username or user_obj.plex_email
                logger.info(f"{task_name}: User {plex_ident} (Discord: {user_obj.discord_id}) no longer on server ({check_message}). Removing.")
                success, plex_remove_message = remove_plex_friend(plex_ident) # Assumes remove_plex_friend handles None plex_ident
                if success:
                    HistoryLog.create(event_type="USER_REMOVED_DISCORD_POLL", plex_username=plex_ident, discord_id=user_obj.discord_id, details=f"Left Discord ({check_message}). Plex: {plex_remove_message}")
                    db.session.delete(user_obj); removed_count += 1
                else:
                    HistoryLog.create(event_type="ERROR_REMOVING_USER_DISCORD_POLL", plex_username=plex_ident, discord_id=user_obj.discord_id, details=f"Left Discord ({check_message}). Plex removal failed: {plex_remove_message}")
        if removed_count > 0:
            try: db.session.commit()
            except Exception as e: 
                db.session.rollback()
                logger.error(f"{task_name}: DB error committing removals: {e}", exc_info=True)
        logger.info(f"{task_name}: Finished. Checked: {checked_count}, Removed: {removed_count}.")


@scheduler.task('cron', id='cleanup_old_history_logs_job', day='1', hour='3', minute='0', misfire_grace_time=3600) 
def cleanup_old_history_logs_task():
    app = scheduler.app
    if not app: 
        logging.getLogger('app.scheduler.log_cleanup').error("CRITICAL: No Flask app for cleanup_old_history_logs_task.")
        return
    with app.app_context():
        logger = current_app.logger
        task_name = "Scheduler(LogCleanup)"
        days_to_keep_str = get_app_setting('HISTORY_LOG_RETENTION_DAYS', '90')
        try: days_to_keep = int(days_to_keep_str)
        except ValueError: days_to_keep = 90
        
        if days_to_keep <= 0: 
            if logger.isEnabledFor(logging.DEBUG): logger.debug(f"{task_name}: Retention disabled (<=0 days).")
            return
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
        logger.info(f"{task_name}: Task STARTED. Cleaning history logs older than {cutoff_date.strftime('%Y-%m-%d %Z')}.")
        try:
            deleted_count = HistoryLog.query.filter(HistoryLog.timestamp < cutoff_date).delete(synchronize_session=False)
            db.session.commit()
            logger.info(f"{task_name}: Deleted {deleted_count} old history log entries.")
            if deleted_count > 0: 
                try: # Best effort to log the cleanup action itself
                    HistoryLog.create(event_type="SYSTEM_LOGS_CLEANUP", details=f"Deleted {deleted_count} logs older than {days_to_keep} days.")
                except Exception as e_log_cleanup_log:
                    logger.error(f"{task_name}: Could not log the cleanup action itself: {e_log_cleanup_log}")
        except Exception as e: 
            db.session.rollback()
            logger.error(f"{task_name}: Error cleaning history logs: {e}", exc_info=True)
        logger.info(f"{task_name}: Task FINISHED.")


def register_all_defined_jobs(app_instance, scheduler_instance):
    logger = app_instance.logger 
    logger.info(f"Explicitly registering/updating jobs for scheduler: {repr(scheduler_instance)} on app: {repr(app_instance)}")
    
    # REMOVED: activity_interval_minutes logic as the job is removed
    
    # Define all jobs that should be registered
    job_definitions_config = [
        # REMOVED: {'id': 'update_active_streams_job', ... }
        {'id': 'check_discord_members_periodic_job', 'func': 'app.scheduler_tasks:check_discord_members_periodic_task', 'trigger': 'interval', 'hours': 1, 'replace_existing': True, 'misfire_grace_time':900},
        {'id': 'cleanup_old_history_logs_job', 'func': 'app.scheduler_tasks:cleanup_old_history_logs_task', 'trigger': 'cron', 'day': '1', 'hour': '3', 'minute': '0', 'replace_existing': True, 'misfire_grace_time':3600}
    ]
    jobs_processed_info = []
    # Use scheduler_instance.scheduler to get the actual APScheduler BackgroundScheduler object
    actual_apscheduler = getattr(scheduler_instance, 'scheduler', scheduler_instance) 
    
    active_job_ids_in_scheduler = {job.id for job in actual_apscheduler.get_jobs()}
    defined_job_ids = {job_def['id'] for job_def in job_definitions_config}

    # Remove jobs from scheduler that are no longer in our definitions
    for job_id_to_remove in active_job_ids_in_scheduler - defined_job_ids:
        try:
            actual_apscheduler.remove_job(job_id_to_remove)
            jobs_processed_info.append(f"{job_id_to_remove} (removed as no longer defined)")
            logger.info(f"Removed undefined job '{job_id_to_remove}' from scheduler.")
        except Exception as e_remove:
            logger.error(f"Error removing undefined job '{job_id_to_remove}': {e_remove}", exc_info=True)
            jobs_processed_info.append(f"{job_id_to_remove} (error removing: {e_remove})")

    # Add/Update defined jobs
    for job_config in job_definitions_config:
        job_id = job_config['id']
        try:
            actual_apscheduler.add_job(**job_config) 
            jobs_processed_info.append(f"{job_id} (added/updated)")
            logger.info(f"Successfully added/updated job '{job_id}'.")
        except Exception as e_add:
            logger.error(f"Error explicitly adding/updating job '{job_id}': {e_add}", exc_info=True)
            jobs_processed_info.append(f"{job_id} (error adding/updating: {e_add})")
    
    logger.info(f"Explicit job registration/update process complete. Processed actions: {jobs_processed_info}")
    return jobs_processed_info