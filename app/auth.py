# app/auth.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session # Added session
from flask_login import login_user, logout_user, current_user
from urllib.parse import urlparse, urljoin 
from app import db
from app.models import User, get_app_setting
from app.forms import LoginForm

bp = Blueprint('auth', __name__)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if get_app_setting('SETUP_COMPLETED') != 'true':
        # If setup isn't complete, redirect to the setup wizard.
        # Determine which step to redirect to based on admin existence.
        admin_exists = User.query.filter_by(is_admin=True).first()
        if not admin_exists:
            flash('Application setup is incomplete. Please create an admin account.', 'warning')
            return redirect(url_for('setup.setup_wizard', step=1))
        else: 
            # Admin exists, but other setup steps (Plex/App URL, Discord) might be pending.
            # Defaulting to step 2 if admin exists but setup isn't fully marked complete.
            flash('Application setup may be incomplete. Please review setup steps or contact an administrator if issues persist after setup.', 'warning')
            # Check if Plex URL is set, if not, step 2 is appropriate
            if not get_app_setting('PLEX_URL'):
                 return redirect(url_for('setup.setup_wizard', step=2))
            return redirect(url_for('setup.setup_wizard', step=3)) # Or a generic "complete setup" page if you had one

    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('main.dashboard'))

    form = LoginForm() # For traditional username/password login

    # Handle POST for traditional login
    if form.validate_on_submit(): # This checks if the LoginForm's submit button was pressed
        admin_user = User.query.filter_by(username=form.username.data.strip(), is_admin=True).first()
        
        if admin_user and admin_user.password_hash and admin_user.check_password(form.password.data):
            login_user(admin_user, remember=form.remember_me.data)
            flash('Logged in successfully as admin!', 'success')
            
            next_page_url = request.args.get('next')
            if not next_page_url or not is_safe_url(next_page_url) or urlparse(next_page_url).path == url_for('auth.login', _external=False):
                current_app.logger.debug(f"Login: next_page_url '{next_page_url}' invalid or login page. Redirecting to dashboard.")
                return redirect(url_for('main.dashboard'))
            
            current_app.logger.debug(f"Login: Redirecting to safe next_page_url: {next_page_url}")
            return redirect(next_page_url)
        else:
            flash('Invalid admin username or password. Please try again.', 'danger')
            current_app.logger.warning(f"Failed admin login attempt for username: {form.username.data}")
            
    # For GET request or if form validation failed
    # We need to pass a flag or check if Plex login is enabled to show the button
    plex_login_enabled = bool(get_app_setting('PLEX_URL') and get_app_setting('PLEX_TOKEN'))

    return render_template('auth/login.html', 
                           title='Admin Sign In', 
                           form=form, 
                           plex_login_enabled=plex_login_enabled)

@bp.route('/initiate_plex_admin_login', methods=['GET']) # New route for Plex login button
def initiate_plex_admin_login():
    if get_app_setting('SETUP_COMPLETED') != 'true':
        flash("Setup is not complete. Cannot use Plex admin login yet.", "warning")
        return redirect(url_for('setup.setup_wizard'))
        
    if not (get_app_setting('PLEX_URL') and get_app_setting('PLEX_TOKEN')):
        flash("Plex server details are not configured. Plex login for admin is unavailable.", "danger")
        return redirect(url_for('auth.login'))

    session['sso_plex_purpose'] = 'admin_login'
    # Store the 'next' parameter if it exists, so we can redirect after successful Plex login
    next_url = request.args.get('next')
    if next_url and is_safe_url(next_url):
        session['sso_plex_next_url'] = next_url 
        current_app.logger.debug(f"Plex Admin Login: Storing next_url in session: {next_url}")
    else:
        session.pop('sso_plex_next_url', None) # Clear if not present or unsafe

    current_app.logger.info("Auth: Initiating Plex admin login via SSO.")
    return redirect(url_for('sso_plex.start_plex_sso_auth_redirect', purpose='admin_login'))


@bp.route('/logout')
def logout():
    if current_user.is_authenticated: 
        logout_user()
        flash('You have been successfully logged out.', 'info')
    else:
        flash('You were not logged in.', 'info') 
    return redirect(url_for('auth.login'))