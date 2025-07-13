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
    Statefully monitors Plex sessions, with corrected session tracking and duration calculation.
    - Creates a new StreamHistory record when a new session starts.
    - Continuously updates the view offset (progress) on the SAME record for an ongoing session.
    - Correctly calculates final playback duration from the last known viewOffset when the session stops.
    - Enforces "No 4K Transcoding" user setting with improved detection.
    """
    global _active_stream_sessions
    with scheduler.app.app_context():
        current_app.logger.debug("Task_Service: Running stateful monitor_plex_sessions_task...")
        if not Setting.get('PLEX_URL') or not Setting.get('PLEX_TOKEN'):
            return

        try:
            active_plex_sessions = plex_service.get_active_sessions()
            now_utc = datetime.now(timezone.utc)
            
            # Create a dictionary of current sessions for easy lookup and to get the full session object
            current_sessions_dict = {session.sessionKey: session for session in active_plex_sessions if hasattr(session, 'sessionKey')}
            current_plex_session_keys = set(current_sessions_dict.keys())
            
            # DEBUG: Log session tracking info
            current_app.logger.debug(f"MONITOR_DEBUG: Current Plex sessions: {list(current_plex_session_keys)}")
            current_app.logger.debug(f"MONITOR_DEBUG: Tracked active sessions: {list(_active_stream_sessions.keys())}")
            current_app.logger.debug(f"MONITOR_DEBUG: Session key types - Plex: {[type(k) for k in current_plex_session_keys]}, Tracked: {[type(k) for k in _active_stream_sessions.keys()]}")

            # Step 1: Check for stopped streams
            stopped_session_keys = set(_active_stream_sessions.keys()) - current_plex_session_keys
            for session_key in stopped_session_keys:
                stream_history_id = _active_stream_sessions.pop(session_key, None)
                if stream_history_id:
                    history_record = db.session.get(StreamHistory, stream_history_id)
                    if history_record and not history_record.stopped_at:
                        # The final known progress IS the actual playback duration.
                        final_duration = history_record.view_offset_at_end_seconds
                        history_record.duration_seconds = final_duration if final_duration and final_duration > 0 else 0
                        
                        history_record.stopped_at = now_utc
                        current_app.logger.info(f"Stream STOPPED: Session {session_key}. Final playback duration: {history_record.duration_seconds}s.")
            
            # Step 2: Check for new and ongoing streams
            for session_key, session in current_sessions_dict.items():
                pum_user = None
                if hasattr(session, 'user') and session.user and hasattr(session.user, 'id'):
                    pum_user = User.query.filter_by(plex_user_id=session.user.id).first()
                
                if not pum_user: 
                    continue 

                # Enhanced 4K Transcode Enforcement Logic
                transcode_session = getattr(session, 'transcodeSession', None)
                if transcode_session and not pum_user.allow_4k_transcode:
                    video_decision = getattr(transcode_session, 'videoDecision', 'copy').lower()
                    if video_decision == 'transcode':
                        
                        # Enhanced 4K detection using the same logic as streaming_sessions_partial
                        is_4k_source = False
                        
                        # Get media elements to find original source
                        original_media = None
                        if hasattr(session, 'media') and isinstance(session.media, list):
                            for media in session.media:
                                if hasattr(media, '_data') and media._data is not None:
                                    if media._data.get('selected') != '1':
                                        original_media = media
                                        break
                            
                            # If no non-selected media found, use first media as fallback
                            if original_media is None and session.media:
                                original_media = session.media[0]
                        
                        # Check for 4K in original media
                        if original_media:
                            # Method 1: Check videoResolution attribute
                            if hasattr(original_media, 'videoResolution') and original_media.videoResolution:
                                vid_res = original_media.videoResolution.lower()
                                if vid_res == "4k":
                                    is_4k_source = True
                                    current_app.logger.debug(f"4K detected via videoResolution: {original_media.videoResolution}")
                            
                            # Method 2: Check height
                            elif hasattr(original_media, 'height') and original_media.height:
                                height = int(original_media.height)
                                if height >= 2160:
                                    is_4k_source = True
                                    current_app.logger.debug(f"4K detected via height: {height}p")
                            
                            # Method 3: Check video streams in parts
                            elif hasattr(original_media, 'parts') and original_media.parts:
                                part = original_media.parts[0]
                                for stream in getattr(part, 'streams', []):
                                    if getattr(stream, 'streamType', 0) == 1:  # Video stream
                                        # Check displayTitle for 4K
                                        if hasattr(stream, 'displayTitle') and stream.displayTitle:
                                            display_title = stream.displayTitle.upper()
                                            if "4K" in display_title:
                                                is_4k_source = True
                                                current_app.logger.debug(f"4K detected via displayTitle: {stream.displayTitle}")
                                                break
                                        
                                        # Check height
                                        elif hasattr(stream, 'height') and stream.height:
                                            height = int(stream.height)
                                            if height >= 2160:
                                                is_4k_source = True
                                                current_app.logger.debug(f"4K detected via stream height: {height}p")
                                                break
                        
                        # Legacy fallback method (for compatibility)
                        if not is_4k_source:
                            media_item = session.media[0] if hasattr(session, 'media') and session.media else None
                            if media_item and hasattr(media_item, 'parts') and media_item.parts:
                                video_stream = next((s for s in media_item.parts[0].streams if getattr(s, 'streamType', 0) == 1), None)
                                if video_stream and hasattr(video_stream, 'height') and video_stream.height >= 2000:
                                    is_4k_source = True
                                    current_app.logger.debug(f"4K detected via legacy method: {video_stream.height}p")
                        
                        if is_4k_source:
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

                # If the session is new, create the history record AND add it to our tracker.
                if session_key not in _active_stream_sessions:
                    current_app.logger.debug(f"MONITOR_DEBUG: Creating NEW session record for session_key: {session_key} (type: {type(session_key)})")
                    
                    media_duration_ms = getattr(session, 'duration', 0)
                    media_duration_s = int(media_duration_ms / 1000) if media_duration_ms else 0

                    new_history_record = StreamHistory(
                        user_id=pum_user.id,
                        session_key=str(session_key),
                        rating_key=str(getattr(session, 'ratingKey', None)),
                        started_at=now_utc,
                        platform=getattr(session.player, 'platform', 'N/A'),
                        product=getattr(session.player, 'product', 'N/A'),
                        player=getattr(session.player, 'title', 'N/A'),
                        ip_address=getattr(session.player, 'address', 'N/A'),
                        is_lan=getattr(session.player, 'local', False),
                        media_title=getattr(session, 'title', "Unknown"),
                        media_type=getattr(session, 'type', "Unknown"),
                        grandparent_title=getattr(session, 'grandparentTitle', None),
                        parent_title=getattr(session, 'parentTitle', None),
                        media_duration_seconds=media_duration_s,
                        view_offset_at_end_seconds=int(getattr(session, 'viewOffset', 0) / 1000)
                    )
                    db.session.add(new_history_record)
                    db.session.flush()
                    _active_stream_sessions[session_key] = new_history_record.id
                    current_app.logger.info(f"Stream STARTED: Session {session_key} for user {pum_user.id}. Recorded with DB ID {new_history_record.id}.")
                
                # If the session is ongoing, find its record and just update the progress
                else:
                    current_app.logger.debug(f"MONITOR_DEBUG: Updating EXISTING session {session_key}")
                    history_record_id = _active_stream_sessions.get(session_key)
                    if history_record_id:
                        history_record = db.session.get(StreamHistory, history_record_id)
                        if history_record:
                            current_offset_s = int(getattr(session, 'viewOffset', 0) / 1000)
                            history_record.view_offset_at_end_seconds = current_offset_s
                            current_app.logger.debug(f"Stream ONGOING: Session {session_key}. Updated progress to {current_offset_s}s.")
                        else:
                            current_app.logger.warning(f"MONITOR_DEBUG: Could not find StreamHistory record with ID {history_record_id} for session {session_key}")
                    else:
                        current_app.logger.warning(f"MONITOR_DEBUG: Session {session_key} in _active_stream_sessions but no record ID found")

                # Always update the user's main 'last_streamed_at' field
                user_service.update_user_last_streamed(pum_user.plex_user_id, now_utc)

            # Commit all changes for this cycle
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Task_Service: Error during monitor_plex_sessions_task: {e}", exc_info=True)

def check_user_access_expirations_task():
    """
    Checks for users whose access has expired and removes them from PUM and Plex.
    This version correctly compares naive datetimes to ensure accuracy.
    """
    with scheduler.app.app_context():
        current_app.logger.info("Task_Service: Running check_user_access_expirations_task...")
        
        # Enhanced debugging
        now_naive = datetime.utcnow()
        current_app.logger.info(f"Task_Service: Current UTC time (naive): {now_naive}")
        
        # First, let's see all users with expiration dates
        all_users_with_expiry = User.query.filter(User.access_expires_at.isnot(None)).all()
        current_app.logger.info(f"Task_Service: Found {len(all_users_with_expiry)} users with expiration dates:")
        
        for user in all_users_with_expiry:
            expiry_date = user.access_expires_at
            is_expired = expiry_date <= now_naive
            time_diff = (expiry_date - now_naive).total_seconds() if expiry_date else None
            current_app.logger.info(f"  - User '{user.plex_username}' (ID: {user.id}): expires {expiry_date} | Expired: {is_expired} | Time diff: {time_diff}s")
        
        # Now get actually expired users
        expired_users = User.query.filter(
            User.access_expires_at.isnot(None), 
            User.access_expires_at <= now_naive
        ).all()
        
        current_app.logger.info(f"Task_Service: Query returned {len(expired_users)} expired users")

        if not expired_users:
            current_app.logger.info("Task_Service: No users found with expired access.")
            return

        current_app.logger.info(f"Task_Service: Found {len(expired_users)} user(s) with expired access. Processing removals...")
        
        system_admin_id = None
        try:
            from app.models import AdminAccount
            admin = AdminAccount.query.first()
            if admin:
                system_admin_id = admin.id
            current_app.logger.debug(f"Task_Service: Using system_admin_id: {system_admin_id}")
        except Exception as e_admin:
            current_app.logger.warning(f"Task_Service: Could not fetch admin_id for logging expiration task: {e_admin}")

        removal_count = 0
        for user in expired_users:
            username_for_log = user.plex_username
            pum_user_id_for_log = user.id
            original_expiry_for_log = user.access_expires_at
            
            try:
                current_app.logger.info(f"Task_Service: Processing expired user '{username_for_log}' (PUM ID: {pum_user_id_for_log}). Expiry: {original_expiry_for_log}. Removing...")
                
                # Check if user_service.delete_user_from_pum_and_plex exists
                if not hasattr(user_service, 'delete_user_from_pum_and_plex'):
                    current_app.logger.error(f"Task_Service: user_service.delete_user_from_pum_and_plex method not found!")
                    continue
                
                user_service.delete_user_from_pum_and_plex(user_id=pum_user_id_for_log, admin_id=system_admin_id)
                removal_count += 1
                
                log_event(
                    EventType.PUM_USER_DELETED_FROM_PUM,
                    f"User '{username_for_log}' automatically removed due to expired invite-based access (expired: {original_expiry_for_log}).",
                    user_id=pum_user_id_for_log,
                    admin_id=system_admin_id, 
                    details={"reason": "Automated removal: invite access duration expired."}
                )
                current_app.logger.info(f"Task_Service: Successfully removed expired user '{username_for_log}'")
                
            except Exception as e:
                current_app.logger.error(f"Task_Service: Error removing expired user '{username_for_log}' (PUM ID: {pum_user_id_for_log}): {e}", exc_info=True)
                log_event(
                    EventType.ERROR_GENERAL,
                    f"Task failed to remove expired user '{username_for_log}': {e}",
                    user_id=pum_user_id_for_log,
                    admin_id=system_admin_id
                )
        
        current_app.logger.info(f"Task_Service: User access expiration check complete. Removed: {removal_count}/{len(expired_users)} users.")

# Add this helper function to check scheduler status
def debug_scheduler_status():
    """Debug function to check scheduler status"""
    with scheduler.app.app_context():
        current_app.logger.info("=== SCHEDULER DEBUG INFO ===")
        current_app.logger.info(f"Scheduler running: {scheduler.running}")
        current_app.logger.info(f"Scheduler state: {scheduler.state}")
        
        jobs = scheduler.get_jobs()
        current_app.logger.info(f"Total jobs: {len(jobs)}")
        
        for job in jobs:
            current_app.logger.info(f"Job ID: {job.id}")
            current_app.logger.info(f"  Function: {job.func}")
            current_app.logger.info(f"  Next run: {job.next_run_time}")
            current_app.logger.info(f"  Trigger: {job.trigger}")
            
        # Check specific expiration job
        expiration_job = scheduler.get_job('check_user_expirations')
        if expiration_job:
            current_app.logger.info(f"Expiration job found:")
            current_app.logger.info(f"  Next run: {expiration_job.next_run_time}")
            current_app.logger.info(f"  Trigger: {expiration_job.trigger}")
        else:
            current_app.logger.warning("Expiration job NOT found in scheduler!")
        
        current_app.logger.info("=== END SCHEDULER DEBUG ===")

# Add this manual trigger function
def manually_trigger_expiration_check():
    """Manually trigger the expiration check for testing"""
    current_app.logger.info("MANUAL TRIGGER: Running expiration check manually...")
    check_user_access_expirations_task()
    current_app.logger.info("MANUAL TRIGGER: Expiration check completed.")

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

    # Get the session monitoring interval from settings
    try:
        interval_str = Setting.get('SESSION_MONITORING_INTERVAL_SECONDS', '60')
        session_interval_seconds = int(interval_str)
        if session_interval_seconds < 10: # Enforce minimum
             current_app.logger.warning(f"Session monitoring interval '{session_interval_seconds}' too low, using 10s.")
             session_interval_seconds = 10
    except (ValueError, TypeError):
        session_interval_seconds = 60
        current_app.logger.warning(f"Invalid SESSION_MONITORING_INTERVAL_SECONDS. Defaulting to {session_interval_seconds}s.")

    # 1. Plex Session Monitoring
    if _schedule_job_if_not_exists_or_reschedule(
        job_id='monitor_plex_sessions',
        func=monitor_plex_sessions_task,
        trigger_type='interval',
        seconds=session_interval_seconds,
        next_run_time=datetime.now(timezone.utc) + timedelta(seconds=10) # Start shortly after app start
    ):
        log_event(EventType.APP_STARTUP, f"Plex session monitoring task (re)scheduled (Interval: {session_interval_seconds}s).")

    # 2. User Access Expiration Check - NOW USES SAME INTERVAL AS SESSION MONITORING
    if _schedule_job_if_not_exists_or_reschedule(
        job_id='check_user_expirations',
        func=check_user_access_expirations_task,
        trigger_type='interval',
        seconds=session_interval_seconds,  # CHANGED: Now uses same interval as session monitoring
        next_run_time=datetime.now(timezone.utc) + timedelta(seconds=30) # Start 30 seconds after app start (offset from session monitoring)
    ):
        log_event(EventType.APP_STARTUP, f"User access expiration check task (re)scheduled (Interval: {session_interval_seconds}s - same as session monitoring).")

    current_app.logger.info("Task_Service: Finished attempting to schedule all tasks.")