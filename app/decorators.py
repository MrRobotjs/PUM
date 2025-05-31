# app/decorators.py
from functools import wraps
from flask import flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from app.models import get_app_setting # Assuming get_app_setting is in app.models

def setup_complete_required(f):
    """
    Decorator to ensure that the application setup has been completed.
    If not, flashes a message and redirects to the setup wizard.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # It's generally safer to access app context items like this inside the request
        # or use try-except if current_app might not be fully available (e.g., very early startup).
        # However, for a decorator on a route, an app context should exist.
        is_setup_complete = False
        try:
            # Ensure we are in an app context if get_app_setting needs it
            with current_app.app_context():
                 is_setup_complete = get_app_setting('SETUP_COMPLETED') == 'true'
        except RuntimeError: # Handles case where current_app might not be fully available or no app context
            current_app.logger.warning("setup_complete_required decorator: Could not determine setup status due to missing app context. Allowing access with caution.")
            # Decide on fallback behavior: either allow access or deny. Forcing setup might be safer.
            # For now, let's assume if this fails, something is very wrong, and redirecting to setup is a safe bet.
            # However, if get_app_setting handles DB errors gracefully, this might not be hit often.
            # Let's rely on get_app_setting's own default/error handling for now.
            is_setup_complete = get_app_setting('SETUP_COMPLETED') == 'true'


        if not is_setup_complete:
            flash('Application setup is not yet complete. Please finish the setup wizard.', 'warning')
            # Ensure the setup blueprint is named 'setup' and the route is 'setup_wizard'
            return redirect(url_for('setup.setup_wizard'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """
    Decorator that combines login_required, setup_complete_required,
    and checks if the current user is an admin.
    """
    @wraps(f)
    @login_required  # Ensures user is logged in
    @setup_complete_required  # Ensures setup is complete
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Admin access is required to view this page.', 'danger')
            # Ensure the main blueprint is 'main' and has an 'index_or_setup' route
            return redirect(url_for('main.index_or_setup'))
        return f(*args, **kwargs)
    return decorated_function