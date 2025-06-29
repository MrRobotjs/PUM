# File: app/utils/helpers.py
import re
from datetime import datetime, timezone, timedelta
from flask import current_app, flash, url_for, g as flask_g # Use flask_g to avoid conflict with local g
from functools import wraps
# app.models import HistoryLog, EventType # This creates circular import if models also import helpers
# from app.extensions import db # Same here

# It's better to import db and models within the function or pass them if needed,
# or ensure helpers don't directly cause DB interaction at module level.

def is_setup_complete():
    return getattr(flask_g, 'setup_complete', False)


def setup_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_setup_complete():
            from app.models import AdminAccount, Setting # Local import
            # ... rest of the logic
        return f(*args, **kwargs)
    return decorated_function


def log_event(event_type, message: str, details: dict = None, # Removed type hint for EventType to avoid import here
              admin_id: int = None, user_id: int = None, invite_id: int = None):
    """Logs an event to the HistoryLog. Gracefully handles DB not ready."""
    from app.models import HistoryLog, EventType as EventTypeEnum # Local import for models and Enum
    from app.extensions import db # Local import for db
    from flask_login import current_user # Local import for current_user

    if not isinstance(event_type, EventTypeEnum): # Use the imported Enum
        current_app.logger.error(f"Invalid event_type provided to log_event: {event_type}")
        return

    try:
        # Check if HistoryLog table exists before trying to write to it
        # This is especially for early startup/CLI commands like `flask db upgrade`
        engine_conn = None
        history_table_exists = False
        try:
            engine_conn = db.engine.connect()
            history_table_exists = db.engine.dialect.has_table(engine_conn, HistoryLog.__tablename__)
        finally:
            if engine_conn:
                engine_conn.close()

        if not history_table_exists:
            current_app.logger.info(f"History_logs table not found. Skipping log: {event_type.name} - {message}")
            return

        log_entry = HistoryLog(
            event_type=event_type,
            message=message,
            details=details or {}
        )

        if admin_id is None and current_user and current_user.is_authenticated and hasattr(current_user, 'id'):
            from app.models import AdminAccount # Local import
            if isinstance(current_user, AdminAccount):
                log_entry.admin_id = current_user.id
        elif admin_id: # Ensure explicitly passed admin_id is used
             log_entry.admin_id = admin_id


        if user_id: log_entry.user_id = user_id
        if invite_id: log_entry.invite_id = invite_id

        db.session.add(log_entry)
        db.session.commit()
        current_app.logger.info(f"Event logged: {event_type.name} - {message}")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error logging event (original: {event_type.name} - {message}): {e}")

def calculate_expiry_date(days: int) -> datetime | None:
    if days is None or days <= 0: return None
    return datetime.now(timezone.utc) + timedelta(days=days)

def format_datetime_human(dt: datetime | None, include_time=True, naive_as_utc=True) -> str:
    if dt is None: return "N/A"
    if dt.tzinfo is None and naive_as_utc: dt = dt.replace(tzinfo=timezone.utc)
    if include_time: return dt.strftime("%Y-%m-%d %I:%M %p %Z").replace(" UTC", " (UTC)").replace(" Coordinated Universal Time", " (UTC)")
    else: return dt.strftime("%Y-%m-%d")

def time_ago(dt: datetime | None, naive_as_utc=True) -> str:
    if dt is None: return "Never"
    dt_aware = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None and naive_as_utc else dt
    now = datetime.now(timezone.utc)
    diff = now - dt_aware
    if diff.total_seconds() < 0: return "In the future"
    seconds = int(diff.total_seconds()); days = diff.days; months = days // 30; years = days // 365
    if seconds < 60: return "just now"
    elif seconds < 3600: minutes = seconds // 60; return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    elif seconds < 86400: hours = seconds // 3600; return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif days < 7: return f"{days} day{'s' if days > 1 else ''} ago"
    elif days < 30: weeks = days // 7; return f"{weeks} week{'s' if weeks > 1 else ''} ago"
    elif months < 12: return f"{months} month{'s' if months > 1 else ''} ago"
    else: return f"{years} year{'s' if years > 1 else ''} ago"

def generate_plex_auth_url(plex_client_id, forward_url, app_name="Plex User Manager"):
    from plexapi.myplex import MyPlexAccount # Local import
    try:
        pin_data = MyPlexAccount.get_plex_pin(plex_client_id,product_name=app_name,forwardUrl=forward_url)
        pin_id = pin_data['id']; pin_code = pin_data['code']
        auth_url_with_pin = f"https://app.plex.tv/auth#?clientID={plex_client_id}&code={pin_code}&context[device][product]={app_name.replace(' ', '%20')}"
        return pin_id, auth_url_with_pin
    except Exception as e: current_app.logger.error(f"Error generating Plex PIN: {e}"); return None, None

def check_plex_pin_auth(plex_client_id, pin_id):
    from plexapi.myplex import MyPlexAccount # Local import
    try:
        auth_token = MyPlexAccount.check_plex_pin(plex_client_id, pin_id)
        if auth_token: return auth_token
        return None
    except Exception as e: current_app.logger.error(f"Error checking Plex PIN: {e}"); return None

def sanitize_filename(filename: str) -> str:
    if not filename: return "untitled"
    filename = filename.split('/')[-1].split('\\')[-1]
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    filename = re.sub(r'__+', '_', filename)
    filename = filename.strip('_.-')
    if not filename: return "sanitized_file"
    return filename