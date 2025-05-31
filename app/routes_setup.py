# app/routes_setup.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session # Added session
from app import db 
from app.models import User, AppSetting, HistoryLog, get_app_setting, update_app_setting
from app.forms import SetupAdminForm, SetupPlexAndAppForm, DiscordSettingsForm, CSRFOnlyForm 
from app.plex_utils import test_plex_connection
from functools import wraps

setup_bp = Blueprint('setup', __name__, url_prefix='/setup')

def setup_in_progress_or_forced(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        force_setup = request.args.get('force', 'false').lower() == 'true'
        # Check if setup is complete AND no force flag is present
        if get_app_setting('SETUP_COMPLETED') == 'true' and not force_setup:
            # Also check if current user is authenticated admin if setup is complete
            # This prevents redirect loop if admin is already logged in and tries /setup
            from flask_login import current_user # Local import
            if current_user.is_authenticated and current_user.is_admin:
                flash('Application setup is already complete. You are logged in as admin.', 'info')
                return redirect(url_for('main.dashboard')) # Redirect to dashboard if admin
            else:
                flash('Application setup is already complete. Please login.', 'info')
                return redirect(url_for('auth.login')) # Redirect to login if not admin
        return f(*args, **kwargs)
    return decorated_function

@setup_bp.route('/wizard', methods=['GET', 'POST'])
@setup_bp.route('/wizard/<int:step>', methods=['GET', 'POST'])
@setup_in_progress_or_forced
def setup_wizard(step=1):
    force_setup = request.args.get('force', 'false').lower() == 'true'

    # --- Step 1: Create Admin User (Username/Password OR Plex SSO) ---
    if step == 1:
        # If an admin user already exists and we are not forcing setup, skip to step 2
        admin_exists = User.query.filter_by(is_admin=True).first()
        if admin_exists and not force_setup:
            current_app.logger.info("Setup Step 1: Admin already exists, redirecting to step 2.")
            return redirect(url_for('setup.setup_wizard', step=2))
        
        form = SetupAdminForm() # For traditional username/password setup

        # Handle POST for traditional admin creation
        if request.method == 'POST' and form.validate_on_submit(): # form.validate_on_submit checks if its own submit was clicked
            try:
                # Ensure this username or email (if provided) isn't already an admin if force_setup is true
                if force_setup and admin_exists and admin_exists.username.lower() == form.username.data.strip().lower():
                    flash("An admin with this username already exists. Choose a different username or login.", "warning")
                    return render_template('setup/wizard_step_1_admin.html', title='Setup: Create Admin Account', form=form, show_plex_setup_button=True)

                admin_user = User(username=form.username.data.strip(), is_admin=True)
                admin_user.set_password(form.password.data)
                # Add email if provided by form, not currently in SetupAdminForm
                # if form.email.data: admin_user.email = form.email.data.strip().lower()
                
                db.session.add(admin_user)
                db.session.commit()
                flash('Admin user created successfully with username/password. Next, configure Plex & App settings.', 'success')
                HistoryLog.create(event_type="SETUP_ADMIN_CREATED", plex_username=admin_user.username, details="Admin via username/password")
                current_app.logger.info(f"Setup Step 1: Admin '{admin_user.username}' created (username/password).")
                # Log the new admin in (optional, but good UX)
                from flask_login import login_user
                login_user(admin_user, remember=True)
                return redirect(url_for('setup.setup_wizard', step=2))
            except Exception as e:
                db.session.rollback()
                flash(f'Error creating admin user: {str(e)[:200]}', 'danger')
                current_app.logger.error(f"Setup Wizard (Step 1 - U/P): Error creating admin: {e}", exc_info=True)
        
        # For GET request or if form validation failed for traditional setup
        return render_template('setup/wizard_step_1_admin.html', title='Setup: Create Admin Account', form=form, show_plex_setup_button=True)

    # --- Step 2: Plex & App Configuration ---
    elif step == 2:
        if not User.query.filter_by(is_admin=True).first() and not force_setup:
            flash("Admin account not found. Please complete Step 1 first.", "warning")
            return redirect(url_for('setup.setup_wizard', step=1))
        
        form = SetupPlexAndAppForm(request.form if request.method == 'POST' else None)
        if request.method == 'GET':
            form.plex_url.data = get_app_setting('PLEX_URL')
            form.plex_token.data = get_app_setting('PLEX_TOKEN')
            form.app_base_url.data = get_app_setting('APP_BASE_URL', request.url_root.rstrip('/'))
        
        if form.validate_on_submit():
            plex_url = form.plex_url.data.strip()
            plex_token = form.plex_token.data.strip()
            app_base_url = form.app_base_url.data.strip().rstrip('/')
            
            is_valid, message = test_plex_connection(plex_url, plex_token)
            if is_valid:
                try:
                    update_app_setting('PLEX_URL', plex_url)
                    update_app_setting('PLEX_TOKEN', plex_token)
                    update_app_setting('APP_BASE_URL', app_base_url)
                    if get_app_setting('SYNC_REMOVE_STALE_USERS') is None: update_app_setting('SYNC_REMOVE_STALE_USERS', 'true')
                    if get_app_setting('ACTIVITY_POLL_INTERVAL_MINUTES') is None: update_app_setting('ACTIVITY_POLL_INTERVAL_MINUTES', '5')

                    flash(f'Plex and App settings saved. Connection: {message}. Next, configure Discord integration (optional).', 'success')
                    HistoryLog.create(event_type="SETUP_PLEX_APP_CONFIGURED", details=f"Plex URL: {plex_url[:30]}..., App URL: {app_base_url}")
                    return redirect(url_for('setup.setup_wizard', step=3))
                except Exception as e:
                    flash(f'Error saving settings: {str(e)[:200]}', 'danger')
                    current_app.logger.error(f"Setup Wizard (Step 2): Error saving settings: {e}", exc_info=True)
            else:
                flash(f'Plex connection failed: {message}. Check URL/Token.', 'danger')
        return render_template('setup/wizard_step_2_plex.html', title='Setup: Plex & App Configuration', form=form)

    # --- Step 3: Discord Configuration (Optional) ---
    elif step == 3:
        # (Validation checks for admin and plex_url remain the same)
        if not User.query.filter_by(is_admin=True).first() and not force_setup : return redirect(url_for('setup.setup_wizard', step=1))
        if not get_app_setting('PLEX_URL') and not force_setup: return redirect(url_for('setup.setup_wizard', step=2))

        csrf_skip_form = CSRFOnlyForm(prefix="skip_discord_")
        form = DiscordSettingsForm(request.form if request.method == 'POST' and 'submit_discord_settings' in request.form else None)
        
        # (Populating form on GET remains similar, though OAuth fields aren't in this specific setup form)
        if request.method == 'GET':
            form.discord_bot_enabled.data = (get_app_setting('DISCORD_BOT_ENABLED') == 'true')
            # ... (populate other discord bot fields from get_app_setting) ...
            form.discord_bot_token.data = get_app_setting('DISCORD_BOT_TOKEN')
            form.discord_server_id.data = get_app_setting('DISCORD_SERVER_ID')
            form.discord_bot_app_id.data = get_app_setting('DISCORD_BOT_APP_ID')
            form.admin_discord_id.data = get_app_setting('ADMIN_DISCORD_ID')
            form.discord_command_channel_id.data = get_app_setting('DISCORD_COMMAND_CHANNEL_ID')
            form.discord_mention_role_id.data = get_app_setting('DISCORD_MENTION_ROLE_ID')
            form.discord_plex_access_role_id.data = get_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID')
            form.discord_bot_user_whitelist.data = get_app_setting('DISCORD_BOT_USER_WHITELIST')
        
        if 'submit_discord_settings' in request.form and form.validate_on_submit():
            try:
                # (Saving Discord bot settings logic remains similar)
                is_bot_being_enabled = form.discord_bot_enabled.data
                update_app_setting('DISCORD_BOT_ENABLED', 'true' if is_bot_being_enabled else 'false')
                if is_bot_being_enabled:
                    update_app_setting('DISCORD_BOT_TOKEN', form.discord_bot_token.data.strip() or "") 
                    # ... (save other discord bot settings)
                    update_app_setting('DISCORD_SERVER_ID', form.discord_server_id.data.strip() or "")
                    update_app_setting('DISCORD_BOT_APP_ID', form.discord_bot_app_id.data.strip() or "")
                    update_app_setting('ADMIN_DISCORD_ID', form.admin_discord_id.data.strip() or "")
                    update_app_setting('DISCORD_COMMAND_CHANNEL_ID', form.discord_command_channel_id.data.strip() or "")
                    update_app_setting('DISCORD_MENTION_ROLE_ID', form.discord_mention_role_id.data.strip() or "")
                    update_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID', form.discord_plex_access_role_id.data.strip() or "")
                    raw_bot_wl = form.discord_bot_user_whitelist.data or ""
                    processed_bot_wl = [item.strip() for item in raw_bot_wl.replace('\n',',').split(',') if item.strip()]
                    update_app_setting('DISCORD_BOT_USER_WHITELIST', ",".join(set(processed_bot_wl)))
                else: 
                    keys_to_clear_if_bot_disabled = ['DISCORD_BOT_TOKEN', 'DISCORD_SERVER_ID', 'DISCORD_BOT_APP_ID', 'ADMIN_DISCORD_ID', 'DISCORD_COMMAND_CHANNEL_ID', 'DISCORD_MENTION_ROLE_ID', 'DISCORD_PLEX_ACCESS_ROLE_ID','DISCORD_BOT_USER_WHITELIST']
                    for key_to_clear in keys_to_clear_if_bot_disabled: update_app_setting(key_to_clear, "")
                
                update_app_setting('SETUP_COMPLETED', 'true')
                flash_msg = 'Discord settings processed. Setup is complete! Please login.'
                token_validation_message = getattr(form.discord_bot_token, 'description', None) # From form validation
                if is_bot_being_enabled and token_validation_message: flash_msg = f"Discord Bot Token: {token_validation_message}. " + flash_msg
                flash(flash_msg, 'success')
                HistoryLog.create(event_type="SETUP_DISCORD_CONFIGURED", details=f"Bot Enabled: {is_bot_being_enabled}")
                HistoryLog.create(event_type="SETUP_COMPLETED")
                from app.__init__ import initialize_app_services # Local import
                initialize_app_services(current_app._get_current_object())
                current_app.logger.info(f"Setup Step 3: Discord saved. Bot: {is_bot_being_enabled}. Setup completed.")
                return redirect(url_for('auth.login'))
            except Exception as e:
                flash(f'Error saving Discord settings: {str(e)[:200]}', 'danger')
                current_app.logger.error(f"Setup Wizard (Step 3): Error Discord settings: {e}", exc_info=True)
        
        return render_template('setup/wizard_step_3_discord.html', title='Setup: Discord Configuration', form=form, csrf_skip_form=csrf_skip_form)
    
    else: # Invalid step
        return redirect(url_for('setup.setup_wizard', step=1))


@setup_bp.route('/wizard/initiate_plex_admin_setup', methods=['GET']) # New route
@setup_in_progress_or_forced # Ensure setup isn't already complete (unless forced)
def initiate_plex_admin_setup():
    # This route just sets the purpose and redirects to the main Plex SSO start
    if User.query.filter_by(is_admin=True).first() and not request.args.get('force', 'false').lower() == 'true':
        flash("Admin account already exists. Cannot setup another via Plex.", "warning")
        return redirect(url_for('setup.setup_wizard', step=1)) # Or redirect to login
    
    session['sso_plex_purpose'] = 'admin_setup' # Set purpose for callback
    current_app.logger.info("Setup: Initiating Plex admin setup via SSO.")
    # No need to pass invite_path for admin setup
    return redirect(url_for('sso_plex.start_plex_sso_auth_redirect', purpose='admin_setup'))


@setup_bp.route('/wizard/skip_discord_and_complete', methods=['POST'])
@setup_in_progress_or_forced
def skip_discord_and_complete_setup():
    # (This route remains the same as your last correct version)
    csrf_form = CSRFOnlyForm(prefix="skip_discord_") 
    if not csrf_form.validate_on_submit():
        flash("Invalid request. Please try again.", "danger")
        return redirect(url_for('setup.setup_wizard', step=3))
    if not User.query.filter_by(is_admin=True).first(): return redirect(url_for('setup.setup_wizard', step=1))
    if not get_app_setting('PLEX_URL'): return redirect(url_for('setup.setup_wizard', step=2))

    try:
        update_app_setting('DISCORD_BOT_ENABLED', 'false')
        # Clear all Discord related bot settings
        keys_to_clear = ['DISCORD_BOT_TOKEN', 'DISCORD_SERVER_ID', 'DISCORD_BOT_APP_ID', 
                         'ADMIN_DISCORD_ID', 'DISCORD_COMMAND_CHANNEL_ID', 
                         'DISCORD_MENTION_ROLE_ID', 'DISCORD_PLEX_ACCESS_ROLE_ID',
                         'DISCORD_BOT_USER_WHITELIST', 
                         'DISCORD_OAUTH_CLIENT_ID', 'DISCORD_OAUTH_CLIENT_SECRET'] # Also clear OAuth if skipping
        for key in keys_to_clear: update_app_setting(key, "")
        
        update_app_setting('SETUP_COMPLETED', 'true')
        flash('Discord configuration skipped. Setup is complete! Please login.', 'success')
        HistoryLog.create(event_type="SETUP_DISCORD_SKIPPED")
        HistoryLog.create(event_type="SETUP_COMPLETED")
        from app.__init__ import initialize_app_services
        initialize_app_services(current_app._get_current_object())
        current_app.logger.info("Setup: Discord skipped. Setup completed.")
        return redirect(url_for('auth.login'))
    except Exception as e:
        flash(f'Error finalizing setup after skipping Discord: {str(e)[:200]}', 'danger')
        current_app.logger.error(f"Setup Wizard (Skip Discord): Error: {e}", exc_info=True)
        return redirect(url_for('setup.setup_wizard', step=3))