# File: app/services/task_service.py
from flask import current_app
from app.extensions import scheduler 
from app.models import Setting, EventType, User # User model is now needed
from app.utils.helpers import log_event
from . import plex_service, user_service # user_service is needed for deleting users
from datetime import datetime, timezone, timedelta 

# --- Scheduled Tasks ---

def monitor_plex_sessions_task():
    """Monitors Plex active sessions and updates user's last_streamed_at."""
    with scheduler.app.app_context(): 
        current_app.logger.debug("Task_Service: Running monitor_plex_sessions_task...")
        if not Setting.get('PLEX_URL') or not Setting.get('PLEX_TOKEN'):
            current_app.logger.warning("Task_Service: Plex not configured, skipping session monitoring.")
            return

        try:
            active_sessions = plex_service.get_active_sessions()
            if not active_sessions:
                current_app.logger.debug("Task_Service: No active Plex sessions found by monitor_plex_sessions_task.")
                return

            updated_users_count = 0
            for session_data in active_sessions:
                plex_user_obj = getattr(session_data, 'user', None)
                if plex_user_obj and hasattr(plex_user_obj, 'id') and plex_user_obj.id:
                    plex_user_identifier = plex_user_obj.id 
                    now_utc = datetime.now(timezone.utc)
                    if user_service.update_user_last_streamed(plex_user_identifier, now_utc):
                        updated_users_count +=1
            
            if updated_users_count > 0:
                current_app.logger.info(f"Task_Service: monitor_plex_sessions_task updated last_streamed_at for {updated_users_count} users.")
        except Exception as e:
            current_app.logger.error(f"Task_Service: Error during monitor_plex_sessions_task: {e}", exc_info=True)
            try:
                log_event(EventType.ERROR_PLEX_API, f"Error in Plex session monitoring task: {e}")
            except Exception as e_log:
                current_app.logger.error(f"Task_Service: Failed to log monitor_plex_sessions_task error to DB: {e_log}")


def check_user_access_expirations_task():
    """
    Checks for users whose access (granted by invites with duration) has expired
    and removes them from PUM and Plex.
    """
    with scheduler.app.app_context():
        current_app.logger.info("Task_Service: Running check_user_access_expirations_task...")
        
        now_utc = datetime.now(timezone.utc)
        # Query for users who have an expiration date set and that date is in the past or now
        expired_users = User.query.filter(
            User.access_expires_at.isnot(None), 
            User.access_expires_at <= now_utc
        ).all()

        if not expired_users:
            current_app.logger.info("Task_Service: No users found with expired access.")
            return

        current_app.logger.info(f"Task_Service: Found {len(expired_users)} user(s) with expired access. Processing removals...")
        
        removed_count = 0
        error_count = 0
        system_admin_id = None # Or determine a system admin ID if you have one for logging

        # Attempt to get admin ID for logging purposes, if an admin account exists
        try:
            from app.models import AdminAccount # Local import
            admin = AdminAccount.query.first() # Get first admin, or a specific system admin
            if admin:
                system_admin_id = admin.id
        except Exception as e_admin:
            current_app.logger.warning(f"Task_Service: Could not fetch admin_id for logging expiration task: {e_admin}")


        for user in expired_users:
            username_for_log = user.plex_username
            pum_user_id_for_log = user.id
            original_expiry_for_log = user.access_expires_at
            
            try:
                current_app.logger.info(f"Task_Service: Expired access for user '{username_for_log}' (PUM ID: {pum_user_id_for_log}). Original expiry: {original_expiry_for_log}. Removing...")
                # The user_service.delete_user_from_pum_and_plex logs the PUM_USER_DELETED_FROM_PUM event.
                # We can add a more specific event here for automated removal due to expiration.
                user_service.delete_user_from_pum_and_plex(user_id=pum_user_id_for_log, admin_id=system_admin_id) # Pass admin_id for log
                removed_count += 1
                log_event(
                    EventType.PUM_USER_DELETED_FROM_PUM, # Consider a new EventType.USER_ACCESS_EXPIRED_REMOVED
                    f"User '{username_for_log}' automatically removed due to expired invite-based access (expired: {original_expiry_for_log}).",
                    user_id=pum_user_id_for_log,
                    admin_id=system_admin_id, 
                    details={"reason": "Automated removal: invite access duration expired."}
                )
            except Exception as e:
                error_count += 1
                current_app.logger.error(f"Task_Service: Error removing expired user '{username_for_log}' (PUM ID: {pum_user_id_for_log}): {e}", exc_info=True)
                log_event(
                    EventType.ERROR_GENERAL, # Or ERROR_TASK_PROCESSING
                    f"Task failed to remove expired user '{username_for_log}': {e}",
                    user_id=pum_user_id_for_log,
                    admin_id=system_admin_id
                )
        
        current_app.logger.info(f"Task_Service: User access expiration check complete. Removed: {removed_count}, Errors: {error_count}.")


def _schedule_job_if_not_exists_or_reschedule(job_id, func, trigger_type, **trigger_args):
    """Helper to add or reschedule a job."""
    if not scheduler.running:
        current_app.logger.warning(f"Task_Service: APScheduler not running. Cannot schedule job '{job_id}'.")
        return False
    
    try:
        existing_job = scheduler.get_job(job_id)
        if existing_job:
            # Simple reschedule, more complex trigger comparison might be needed if triggers vary widely
            scheduler.reschedule_job(job_id, trigger=trigger_type, **trigger_args)
            current_app.logger.info(f"Task_Service: Rescheduled job '{job_id}' with trigger {trigger_type} and args {trigger_args}.")
        else:
            scheduler.add_job(id=job_id, func=func, trigger=trigger_type, **trigger_args)
            current_app.logger.info(f"Task_Service: ADDED new job '{job_id}' with trigger {trigger_type} and args {trigger_args}.")
        return True
    except Exception as e:
        current_app.logger.error(f"Task_Service: Error adding/rescheduling job '{job_id}': {e}", exc_info=True)
        try:
            log_event(EventType.ERROR_GENERAL, f"Failed to schedule/reschedule task '{job_id}': {e}")
        except Exception as e_log:
            current_app.logger.error(f"Task_Service: Failed to log scheduling error for '{job_id}' to DB: {e_log}")
        return False


def schedule_all_tasks():
    """Schedules all recurring tasks defined in the application."""
    current_app.logger.info("Task_Service: Attempting to schedule all defined tasks...")

    # 1. Plex Session Monitoring
    try:
        interval_str = Setting.get('SESSION_MONITORING_INTERVAL_SECONDS', '60')
        session_interval_seconds = int(interval_str)
        if session_interval_seconds < 10: # Enforce minimum
             current_app.logger.warning(f"Session monitoring interval '{session_interval_seconds}' too low, using 10s.")
             session_interval_seconds = 10
    except (ValueError, TypeError):
        session_interval_seconds = 60
        current_app.logger.warning(f"Invalid SESSION_MONITORING_INTERVAL_SECONDS. Defaulting to {session_interval_seconds}s.")
    
    if _schedule_job_if_not_exists_or_reschedule(
        job_id='monitor_plex_sessions',
        func=monitor_plex_sessions_task,
        trigger_type='interval',
        seconds=session_interval_seconds,
        next_run_time=datetime.now(timezone.utc) + timedelta(seconds=10) # Start shortly after app start
    ):
        log_event(EventType.APP_STARTUP, f"Plex session monitoring task (re)scheduled (Interval: {session_interval_seconds}s).")

    # 2. User Access Expiration Check
    try:
        expiration_check_interval_hours_str = Setting.get('USER_EXPIRATION_CHECK_INTERVAL_HOURS', '24')
        expiration_check_interval_hours = int(expiration_check_interval_hours_str)
        if expiration_check_interval_hours <= 0: expiration_check_interval_hours = 24
    except (ValueError, TypeError):
        expiration_check_interval_hours = 24
        current_app.logger.warning(f"Invalid USER_EXPIRATION_CHECK_INTERVAL_HOURS. Defaulting to {expiration_check_interval_hours}h.")

    if _schedule_job_if_not_exists_or_reschedule(
        job_id='check_user_expirations',
        func=check_user_access_expirations_task,
        trigger_type='interval',
        hours=expiration_check_interval_hours,
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=5) # Start 5 mins from now
    ):
        log_event(EventType.APP_STARTUP, f"User access expiration check task (re)scheduled (Interval: {expiration_check_interval_hours}h).")

    current_app.logger.info("Task_Service: Finished attempting to schedule all tasks.")