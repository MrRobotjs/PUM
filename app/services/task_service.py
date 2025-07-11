# File: app/services/task_service.py
from flask import current_app
from app.extensions import scheduler 
from app.models import Setting, EventType, User, StreamHistory  # User model is now needed
from app.utils.helpers import log_event
from . import plex_service, user_service # user_service is needed for deleting users
from datetime import datetime, timezone, timedelta 
from app.extensions import db

_active_stream_sessions = {}

# --- Scheduled Tasks ---

def monitor_plex_sessions_task():
    """
    Statefully monitors Plex sessions, now with progress tracking.
    - Creates a StreamHistory record on start, including total media duration.
    - Continuously updates the view offset (progress) on each check.
    - Updates the record with a final timestamp when the session stops.
    - Enforces "No 4K Transcoding" user setting.
    """
    global _active_stream_sessions
    with scheduler.app.app_context():
        current_app.logger.debug("Task_Service: Running stateful monitor_plex_sessions_task...")
        if not Setting.get('PLEX_URL') or not Setting.get('PLEX_TOKEN'):
            return

        try:
            active_plex_sessions = plex_service.get_active_sessions()
            now_utc = datetime.now(timezone.utc)
            
            current_plex_session_keys = {session.sessionKey for session in active_plex_sessions if hasattr(session, 'sessionKey')}

            # Step 1: Check for stopped streams
            stopped_session_keys = set(_active_stream_sessions.keys()) - current_plex_session_keys
            for session_key in stopped_session_keys:
                stream_history_id = _active_stream_sessions.pop(session_key, None)
                if stream_history_id:
                    history_record = db.session.get(StreamHistory, stream_history_id)
                    if history_record and not history_record.stopped_at:
                        history_record.stopped_at = now_utc
                        started_at_aware = history_record.started_at.replace(tzinfo=timezone.utc)
                        duration_delta = history_record.stopped_at - started_at_aware
                        history_record.duration_seconds = int(duration_delta.total_seconds())
                        current_app.logger.info(f"Stream STOPPED: Session {session_key}. Duration: {history_record.duration_seconds}s.")
            
            # Step 2: Check for new and ongoing streams
            for session in active_plex_sessions:
                session_key = getattr(session, 'sessionKey', None)
                if not session_key:
                    continue

                pum_user = None
                if hasattr(session, 'user') and session.user and hasattr(session.user, 'id'):
                    pum_user = User.query.filter_by(plex_user_id=session.user.id).first()
                
                if not pum_user:
                    continue 

                # --- 4K Transcode Enforcement Logic (no changes needed here) ---
                transcode_session = getattr(session, 'transcodeSession', None)
                if transcode_session and not pum_user.allow_4k_transcode:
                    video_decision = getattr(transcode_session, 'videoDecision', 'copy').lower()
                    if video_decision == 'transcode':
                        media_item = session.media[0] if hasattr(session, 'media') and session.media else None
                        video_stream = next((s for s in media_item.parts[0].streams if s.streamType == 1), None) if media_item and media_item.parts else None
                        if video_stream and hasattr(video_stream, 'height') and video_stream.height >= 2000:
                            current_app.logger.warning(f"RULE ENFORCED: Terminating 4K transcode for user '{pum_user.plex_username}' (Session: {session_key}).")
                            termination_message = "4K to non-4K transcoding is not permitted on this server."
                            try:
                                plex_service.terminate_plex_session(session_key, termination_message)
                                log_event(EventType.PLEX_SESSION_DETECTED,
                                          f"Terminated 4K transcode session for user '{pum_user.plex_username}'.",
                                          user_id=pum_user.id,
                                          details={'reason': termination_message})
                                _active_stream_sessions.pop(session_key, None)
                                continue 
                            except Exception as e_term:
                                current_app.logger.error(f"Failed to terminate 4K transcode for session {session_key}: {e_term}")

                # --- START OF MODIFIED LOGIC ---
                
                # If the session is new, create the history record
                if session_key not in _active_stream_sessions:
                    # Get media duration, converting from milliseconds to seconds
                    media_duration_ms = getattr(session, 'duration', 0)
                    media_duration_s = int(media_duration_ms / 1000) if media_duration_ms else 0

                    new_history_record = StreamHistory(
                        user_id=pum_user.id,
                        session_key=str(session_key),
                        rating_key=str(getattr(session, 'ratingKey', None)),
                        started_at=now_utc,
                        platform=getattr(session.player, 'platform', None) if hasattr(session, 'player') else None,
                        product=getattr(session.player, 'product', None) if hasattr(session, 'player') else None,
                        player=getattr(session.player, 'title', None) if hasattr(session, 'player') else None,
                        ip_address=getattr(session.player, 'address', None) if hasattr(session, 'player') else None,
                        is_lan=getattr(session.player, 'local', False) if hasattr(session, 'player') else False,
                        media_title=getattr(session, 'title', "Unknown Title"),
                        media_type=getattr(session, 'type', None),
                        grandparent_title=getattr(session, 'grandparentTitle', None),
                        parent_title=getattr(session, 'parentTitle', None),
                        # Populate our new fields
                        media_duration_seconds=media_duration_s,
                        view_offset_at_end_seconds=int(getattr(session, 'viewOffset', 0) / 1000)
                    )
                    db.session.add(new_history_record)
                    db.session.flush()
                    _active_stream_sessions[session_key] = new_history_record.id
                    current_app.logger.info(f"Stream STARTED: Session {session_key} for user {pum_user.id}. Media Duration: {media_duration_s}s.")
                
                # If the session is ongoing, just update its progress
                else:
                    history_record_id = _active_stream_sessions.get(session_key)
                    if history_record_id:
                        history_record = db.session.get(StreamHistory, history_record_id)
                        if history_record:
                            current_offset_s = int(getattr(session, 'viewOffset', 0) / 1000)
                            history_record.view_offset_at_end_seconds = current_offset_s
                            current_app.logger.debug(f"Stream ONGOING: Session {session_key}. Updated progress to {current_offset_s}s.")

                # --- END OF MODIFIED LOGIC ---

                # Always update the user's main 'last_streamed_at' field
                user_service.update_user_last_streamed(pum_user.plex_user_id, now_utc)

            # Commit all changes for this cycle
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Task_Service: Error during monitor_plex_sessions_task: {e}", exc_info=True)

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