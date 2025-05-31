# app/template_filters.py (New File)
from datetime import datetime, timezone

def time_ago_filter(dt, default="Never"):
    """
    Converts a datetime object or an ISO 8601 string to a human-readable "time ago" string.
    """
    if not dt:
        return default

    # If dt is already a datetime object, ensure it's offset-aware (UTC)
    if isinstance(dt, datetime):
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            # Assuming naive datetimes from DB are UTC, make them aware
            dt_aware = dt.replace(tzinfo=timezone.utc)
        else:
            dt_aware = dt # It's already aware
    else:
        # Try to parse if it's a string (though your model uses DateTime)
        try:
            dt_aware = datetime.fromisoformat(str(dt)).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return default # Could not parse

    now_aware = datetime.now(timezone.utc)
    diff = now_aware - dt_aware

    seconds = diff.total_seconds()
    days = diff.days

    if seconds < 0: # Future date
        return "In the future" # Or format as actual date

    if days == 0:
        if seconds < 60:
            return "Just now" if seconds < 10 else f"{int(seconds)} seconds ago"
        elif seconds < 3600: # Less than an hour
            minutes = int(seconds / 60)
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else: # Less than a day
            hours = int(seconds / 3600)
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif days == 1:
        return "Yesterday"
    elif days < 7:
        return f"{days} days ago"
    elif days < 30:
        weeks = days // 7
        return f"{weeks} week{'s' if weeks > 1 else ''} ago"
    elif days < 365:
        months = days // 30
        return f"{months} month{'s' if months > 1 else ''} ago"
    else:
        years = days // 365
        return f"{years} year{'s' if years > 1 else ''} ago"