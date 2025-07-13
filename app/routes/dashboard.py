# File: app/routes/dashboard.py
from flask import (
    Blueprint, render_template, redirect, url_for, 
    flash, request, current_app, g, make_response, session
)
from flask_login import login_required, current_user, logout_user 
import secrets
from app.models import User, Invite, HistoryLog, Setting, EventType, SettingValueType, AdminAccount, Role 
from app.forms import (
    GeneralSettingsForm, PlexSettingsForm, DiscordConfigForm, SetPasswordForm, ChangePasswordForm, AdminCreateForm, AdminEditForm, RoleEditForm, RoleCreateForm, RoleMemberForm, AdminResetPasswordForm 
    # If you create an AdvancedSettingsForm, import it here too.
)
from app.extensions import db, scheduler # For db.func.now() if used, or db specific types
from app.utils.helpers import log_event, setup_required, permission_required, any_permission_required
# No direct plexapi imports here, plex_service should handle that.
from app.services import plex_service, history_service
import json
from urllib.parse import urlparse
from datetime import datetime 
from functools import wraps

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.id == 1:
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated_function

bp = Blueprint('dashboard', __name__)

@bp.route('/')
@bp.route('/dashboard')
@login_required
@setup_required 
def index():
    total_users = User.query.count()
    active_invites_count = Invite.query.filter(
        Invite.is_active == True,
        (Invite.expires_at == None) | (Invite.expires_at > db.func.now()), # Use db.func.now() for DB comparison
        (Invite.max_uses == None) | (Invite.current_uses < Invite.max_uses)
    ).count()

    # --- NEW: Get active streams count ---
    active_streams_count = 0
    try:
        active_sessions_list = plex_service.get_active_sessions() # This returns a list
        if active_sessions_list:
            active_streams_count = len(active_sessions_list)
    except Exception as e:
        current_app.logger.error(f"Dashboard: Failed to get active streams count: {e}")
    # --- END NEW ---

    # Get Plex server status directly from the plex_service
    # This will either return cached status or perform a check if never done/config missing
    plex_server_status_data = plex_service.get_last_plex_connection_status()
    current_app.logger.debug(f"Dashboard.py - index(): Plex status from service: {plex_server_status_data}")

    recent_activities = HistoryLog.query.order_by(HistoryLog.timestamp.desc()).limit(10).all()
    recent_activities_count = HistoryLog.query.count()

    return render_template('dashboard/index.html',
                           title="Dashboard",
                           total_users=total_users,
                           active_invites_count=active_invites_count,
                           active_streams_count=active_streams_count,
                           plex_server_status=plex_server_status_data, # Pass the retrieved status
                           recent_activities=recent_activities,
                           recent_activities_count=recent_activities_count)

# Helper function to build the history query based on request args
def _get_history_logs_query():
    query = HistoryLog.query
    search_message = request.args.get('search_message')
    event_type_filter = request.args.get('event_type')
    related_user_filter = request.args.get('related_user')

    if search_message: query = query.filter(HistoryLog.message.ilike(f"%{search_message}%"))
    if event_type_filter:
        try: query = query.filter(HistoryLog.event_type == EventType[event_type_filter])
        except KeyError: flash(f"Invalid event type filter: {event_type_filter}", "warning") # Flash won't show on partial
    if related_user_filter:
        from sqlalchemy import or_ 
        query = query.join(AdminAccount, AdminAccount.id == HistoryLog.admin_id, isouter=True) \
                     .join(User, User.id == HistoryLog.user_id, isouter=True) \
                     .filter(or_(
                         AdminAccount.username.ilike(f"%{related_user_filter}%"), 
                         AdminAccount.plex_username.ilike(f"%{related_user_filter}%"), 
                         User.plex_username.ilike(f"%{related_user_filter}%"), 
                         HistoryLog.admin_id.cast(db.String).ilike(f"%{related_user_filter}%"), 
                         HistoryLog.user_id.cast(db.String).ilike(f"%{related_user_filter}%")
                     ))
    return query

@bp.route('/settings')
@login_required
@setup_required
def settings_index():
    # Defines the order of tabs to check for permissions.
    # The first one the user has access to will be their destination.
    permission_map = [
        ('manage_general_settings', 'dashboard.settings_general'),
        ('view_admins_tab', 'dashboard.settings_admins'),
        ('view_admins_tab', 'dashboard.settings_roles'), # Use same perm for both admin tabs
        ('manage_plex_settings', 'dashboard.settings_plex'),
        ('manage_discord_settings', 'dashboard.settings_discord'),
        ('manage_advanced_settings', 'dashboard.settings_advanced'), # A placeholder for a more general 'advanced' perm
    ]

    # Super Admin (ID 1) can see everything, default to general.
    if current_user.id == 1:
        return redirect(url_for('dashboard.settings_general'))

    # Find the first settings page the user has permission to view.
    for permission, endpoint in permission_map:
        if current_user.has_permission(permission):
            return redirect(url_for(endpoint))

    # If the user has a login but no settings permissions at all, deny access.
    flash("You do not have permission to view any settings pages.", "danger")
    return redirect(url_for('dashboard.index'))

@bp.route('/settings/general', methods=['GET', 'POST'])
@login_required
@setup_required
@permission_required('manage_general_settings')
def settings_general():
    form = GeneralSettingsForm()
    if form.validate_on_submit():
        # This route now ONLY handles general app settings.
        Setting.set('APP_NAME', form.app_name.data, SettingValueType.STRING, "Application Name")
        Setting.set('APP_BASE_URL', form.app_base_url.data.rstrip('/'), SettingValueType.STRING, "Application Base URL")
        
        log_event(EventType.SETTING_CHANGE, "General application settings updated.", admin_id=current_user.id)
        flash('General settings saved successfully.', 'success')
        return redirect(url_for('dashboard.settings_general'))
    elif request.method == 'GET':
        form.app_name.data = Setting.get('APP_NAME')
        form.app_base_url.data = Setting.get('APP_BASE_URL')
    return render_template(
        'settings/index.html',
        title="General Settings", 
        form=form, 
        active_tab='general'
    )

@bp.route('/settings/account', methods=['GET', 'POST'])
@login_required
@setup_required
def settings_account():
    set_password_form = SetPasswordForm()
    change_password_form = ChangePasswordForm()
    
    # --- Handle "Change Password" Form Submission ---
    if 'submit_change_password' in request.form and change_password_form.validate_on_submit():
        admin = AdminAccount.query.get(current_user.id)
        # Verify the current password first
        if admin.check_password(change_password_form.current_password.data):
            admin.set_password(change_password_form.new_password.data)
            admin.force_password_change = False
            db.session.commit()
            log_event(EventType.ADMIN_PASSWORD_CHANGE, "Admin changed their password.", admin_id=current_user.id)
            flash('Your password has been changed successfully.', 'success')
            return redirect(url_for('dashboard.settings_account'))
        else:
            flash('Incorrect current password.', 'danger')

    # --- Handle "Set Initial Password" Form Submission (moved from general) ---
    elif 'submit_set_password' in request.form and set_password_form.validate_on_submit():
        admin = AdminAccount.query.get(current_user.id)
        admin.username = set_password_form.username.data
        admin.set_password(set_password_form.password.data)
        admin.is_plex_sso_only = False
        db.session.commit()
        log_event(EventType.ADMIN_PASSWORD_CHANGE, "Admin added username/password to their SSO-only account.", admin_id=current_user.id)
        flash('Username and password have been set successfully!', 'success')
        return redirect(url_for('dashboard.settings_account'))

    return render_template(
        'account/index.html', #<-- Render the new standalone template
        title="My Account",
        set_password_form=set_password_form,
        change_password_form=change_password_form,
    )

@bp.route('/settings/plex', methods=['GET', 'POST'])
@login_required
@setup_required
@permission_required('manage_plex_settings')
def settings_plex():
    form = PlexSettingsForm()
    if form.validate_on_submit():
        # Only save Plex URL/Token if connection was tested successfully in this submission
        # The form.connection_tested_successfully.data is set by JS after a successful test via API
        if form.plex_url.data and form.plex_token.data: # If user provided values for these
            if form.connection_tested_successfully.data == 'true':
                Setting.set('PLEX_URL', form.plex_url.data, SettingValueType.STRING, "Plex Server URL")
                Setting.set('PLEX_TOKEN', form.plex_token.data, SettingValueType.SECRET, "Plex Auth Token")
                current_app.config['PLEX_URL'] = form.plex_url.data
                current_app.config['PLEX_TOKEN'] = form.plex_token.data # Be careful with storing tokens in app.config
                log_event(EventType.PLEX_CONFIG_SAVE, "Plex server URL/Token updated.", admin_id=current_user.id)
                flash('Plex server URL/Token saved successfully.', 'success')
        
        # Always save other settings like interval
        old_interval = int(Setting.get('SESSION_MONITORING_INTERVAL_SECONDS', 60))
        new_interval = form.session_monitoring_interval.data
        Setting.set('SESSION_MONITORING_INTERVAL_SECONDS', str(new_interval), SettingValueType.INTEGER, "Session Monitoring Interval")
        current_app.config['SESSION_MONITORING_INTERVAL_SECONDS'] = new_interval
        
        if old_interval != new_interval and scheduler.running:
            job = scheduler.get_job('monitor_plex_sessions')
            if job:
                try: 
                    job.reschedule(trigger='interval', seconds=new_interval)
                    log_event(EventType.SETTING_CHANGE, f"Plex session monitoring interval rescheduled to {new_interval}s.", admin_id=current_user.id)
                    flash(f"Session monitoring interval updated to {new_interval}s.", "info")
                except Exception as e_scheduler:
                    current_app.logger.error(f"Failed to reschedule session_monitoring_interval: {e_scheduler}")
                    flash("Failed to update scheduler interval. Check logs.", "warning")
            else: # Job might not exist if scheduler was just started or if it failed to add previously
                from app.services import task_service # Ensure it's imported
                task_service.schedule_plex_session_monitoring() # Try to schedule it now
                flash("Session monitoring task was not running, attempted to schedule it.", "info")


        return redirect(url_for('dashboard.settings_plex'))

    elif request.method == 'GET':
        form.plex_url.data = Setting.get('PLEX_URL')
        # Token is secret, do not pre-fill for display in form field
        form.session_monitoring_interval.data = int(Setting.get('SESSION_MONITORING_INTERVAL_SECONDS', 60))
        # Important: connection_tested_successfully should be false on GET to force re-test if URL/token are changed
        form.connection_tested_successfully.data = 'false' 
        
    return render_template('settings/index.html', title="Plex Settings", form=form, active_tab='plex')


@bp.route('/settings/discord', methods=['GET', 'POST'])
@login_required
@setup_required
@permission_required('manage_discord_settings')
def settings_discord():
    form = DiscordConfigForm(request.form if request.method == 'POST' else None)
    
    app_base_url_from_settings = Setting.get('APP_BASE_URL')
    invite_callback_path = "/invites/discord_callback" 
    admin_link_callback_path = "/auth/discord_callback_admin"
    try:
        invite_callback_path = url_for('invites.discord_oauth_callback', _external=False)
        admin_link_callback_path = url_for('auth.discord_callback_admin', _external=False)
    except Exception as e_url_gen:
        current_app.logger.error(f"Error generating relative callback paths for Discord settings display: {e_url_gen}")

    if app_base_url_from_settings:
        clean_app_base = app_base_url_from_settings.rstrip('/')
        if not invite_callback_path.startswith('/'): invite_callback_path = '/' + invite_callback_path
        if not admin_link_callback_path.startswith('/'): admin_link_callback_path = '/' + admin_link_callback_path
        discord_invite_redirect_uri_generated = f"{clean_app_base}{invite_callback_path}"
        discord_admin_link_redirect_uri_generated = f"{clean_app_base}{admin_link_callback_path}"
    else:
        discord_invite_redirect_uri_generated = "APP_BASE_URL not set - Cannot generate Invite Redirect URI"
        discord_admin_link_redirect_uri_generated = "APP_BASE_URL not set - Cannot generate Admin Link Redirect URI"
    
    discord_admin_linked = bool(current_user.discord_user_id)
    discord_admin_user_info = {
        'username': current_user.discord_username, 
        'id': current_user.discord_user_id, 
        'avatar': current_user.discord_avatar_hash 
    } if discord_admin_linked else None
    
    initial_oauth_enabled_for_admin_link_section = Setting.get_bool('DISCORD_OAUTH_ENABLED', False)

    if request.method == 'POST':
        if form.validate_on_submit():
            # Store original global setting state BEFORE changes
            original_require_guild = Setting.get_bool('DISCORD_REQUIRE_GUILD_MEMBERSHIP', False)

            enable_oauth_from_form = form.enable_discord_oauth.data
            enable_bot_from_form = form.enable_discord_bot.data
            require_guild_membership_from_form = form.discord_require_guild_membership.data
            require_sso_on_invite_from_form = form.discord_bot_require_sso_on_invite.data

            final_enable_oauth = enable_oauth_from_form
            if (enable_bot_from_form or require_guild_membership_from_form) and not final_enable_oauth:
                final_enable_oauth = True
                flash_msg = "Discord OAuth (Section 1) was automatically enabled because "
                if enable_bot_from_form: flash_msg += "Bot Features require it."
                elif require_guild_membership_from_form: flash_msg += "'Require Server Membership' needs it."
                flash(flash_msg, "info")
            
            Setting.set('DISCORD_OAUTH_ENABLED', final_enable_oauth, SettingValueType.BOOLEAN)
            current_app.config['DISCORD_OAUTH_ENABLED'] = final_enable_oauth
            if hasattr(g, 'discord_oauth_enabled_for_invite'):
                g.discord_oauth_enabled_for_invite = final_enable_oauth

            if final_enable_oauth:
                Setting.set('DISCORD_CLIENT_ID', form.discord_client_id.data or Setting.get('DISCORD_CLIENT_ID', ""), SettingValueType.STRING)
                if form.discord_client_secret.data: 
                    Setting.set('DISCORD_CLIENT_SECRET', form.discord_client_secret.data, SettingValueType.SECRET)
                Setting.set('DISCORD_OAUTH_AUTH_URL', form.discord_oauth_auth_url.data or Setting.get('DISCORD_OAUTH_AUTH_URL', ""), SettingValueType.STRING)
                Setting.set('DISCORD_REDIRECT_URI_INVITE', discord_invite_redirect_uri_generated, SettingValueType.STRING)
                Setting.set('DISCORD_REDIRECT_URI_ADMIN_LINK', discord_admin_link_redirect_uri_generated, SettingValueType.STRING)

                if enable_bot_from_form: 
                    Setting.set('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', True, SettingValueType.BOOLEAN)
                else: 
                    Setting.set('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', require_sso_on_invite_from_form, SettingValueType.BOOLEAN)
                
                # --- NEW LOGIC: Grandfathering invites when guild requirement is disabled ---
                if original_require_guild is True and require_guild_membership_from_form is False:
                    now = datetime.utcnow()
                    affected_invites_query = Invite.query.filter(
                        Invite.is_active == True,
                        (Invite.expires_at == None) | (Invite.expires_at > now),
                        (Invite.max_uses == None) | (Invite.current_uses < Invite.max_uses),
                        Invite.force_guild_membership.is_(None)
                    )
                    affected_invites = affected_invites_query.all()
                    
                    if affected_invites:
                        updated_invite_ids = []
                        for invite in affected_invites:
                            invite.force_guild_membership = True
                            updated_invite_ids.append(invite.id)
                        
                        try:
                            # The commit for this is handled below with other settings
                            log_event(
                                EventType.SETTING_CHANGE,
                                f"Admin disabled 'Require Guild Membership'. Grandfathered {len(affected_invites)} existing invite(s) by forcing their requirement to ON.",
                                admin_id=current_user.id,
                                details={'updated_invite_ids': updated_invite_ids}
                            )
                        except Exception as e_log:
                            current_app.logger.error(f"Error logging grandfathering of invites: {e_log}")
                # --- END NEW LOGIC ---

                # Now save the new global setting
                Setting.set('DISCORD_REQUIRE_GUILD_MEMBERSHIP', require_guild_membership_from_form, SettingValueType.BOOLEAN)
                
                if enable_bot_from_form or require_guild_membership_from_form:
                    Setting.set('DISCORD_GUILD_ID', form.discord_guild_id.data or Setting.get('DISCORD_GUILD_ID', ""), SettingValueType.STRING)
                    if require_guild_membership_from_form:
                        Setting.set('DISCORD_SERVER_INVITE_URL', form.discord_server_invite_url.data or Setting.get('DISCORD_SERVER_INVITE_URL', ""), SettingValueType.STRING)
                    elif not enable_bot_from_form: 
                        Setting.set('DISCORD_SERVER_INVITE_URL', "", SettingValueType.STRING) 
                else:
                    Setting.set('DISCORD_GUILD_ID', "", SettingValueType.STRING)
                    Setting.set('DISCORD_SERVER_INVITE_URL', "", SettingValueType.STRING)
            else: 
                # If OAuth is disabled, clear all related settings
                Setting.set('DISCORD_CLIENT_ID', "", SettingValueType.STRING)
                Setting.set('DISCORD_CLIENT_SECRET', "", SettingValueType.SECRET)
                Setting.set('DISCORD_OAUTH_AUTH_URL', "", SettingValueType.STRING)
                Setting.set('DISCORD_REDIRECT_URI_INVITE', "", SettingValueType.STRING)
                Setting.set('DISCORD_REDIRECT_URI_ADMIN_LINK', "", SettingValueType.STRING)
                Setting.set('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', False, SettingValueType.BOOLEAN)
                Setting.set('DISCORD_REQUIRE_GUILD_MEMBERSHIP', False, SettingValueType.BOOLEAN)
                Setting.set('DISCORD_GUILD_ID', "", SettingValueType.STRING)
                Setting.set('DISCORD_SERVER_INVITE_URL', "", SettingValueType.STRING)

            # Bot settings save logic (unchanged)
            Setting.set('DISCORD_BOT_ENABLED', enable_bot_from_form, SettingValueType.BOOLEAN)
            if enable_bot_from_form:
                if form.discord_bot_token.data: Setting.set('DISCORD_BOT_TOKEN', form.discord_bot_token.data, SettingValueType.SECRET)
                Setting.set('DISCORD_MONITORED_ROLE_ID', form.discord_monitored_role_id.data or Setting.get('DISCORD_MONITORED_ROLE_ID', ""), SettingValueType.STRING)
                Setting.set('DISCORD_THREAD_CHANNEL_ID', form.discord_thread_channel_id.data or Setting.get('DISCORD_THREAD_CHANNEL_ID', ""), SettingValueType.STRING)
                Setting.set('DISCORD_BOT_LOG_CHANNEL_ID', form.discord_bot_log_channel_id.data or Setting.get('DISCORD_BOT_LOG_CHANNEL_ID', ""), SettingValueType.STRING)
                if not require_guild_membership_from_form:
                    Setting.set('DISCORD_SERVER_INVITE_URL', form.discord_server_invite_url.data or Setting.get('DISCORD_SERVER_INVITE_URL', ""), SettingValueType.STRING)
                Setting.set('DISCORD_BOT_WHITELIST_SHARERS', form.discord_bot_whitelist_sharers.data, SettingValueType.BOOLEAN)
                log_event(EventType.DISCORD_CONFIG_SAVE, "Discord settings updated (Bot Enabled).", admin_id=current_user.id)
            else: 
                if form.discord_bot_token.data:
                    Setting.set('DISCORD_BOT_TOKEN', "", SettingValueType.SECRET)
                Setting.set('DISCORD_BOT_WHITELIST_SHARERS', form.discord_bot_whitelist_sharers.data, SettingValueType.BOOLEAN)
                log_event(EventType.DISCORD_CONFIG_SAVE, "Discord settings updated (Bot Disabled).", admin_id=current_user.id)

            db.session.commit() # A single commit at the end to save grandfathered invites and settings
            flash('Discord settings saved successfully.', 'success')
            return redirect(url_for('dashboard.settings_discord'))

    if request.method == 'GET':
        is_oauth_enabled_db = Setting.get_bool('DISCORD_OAUTH_ENABLED', False)
        form.enable_discord_oauth.data = is_oauth_enabled_db
        if is_oauth_enabled_db:
            form.discord_client_id.data = Setting.get('DISCORD_CLIENT_ID')
            form.discord_oauth_auth_url.data = Setting.get('DISCORD_OAUTH_AUTH_URL')
        
        is_bot_enabled_db = Setting.get_bool('DISCORD_BOT_ENABLED', False)
        form.enable_discord_bot.data = is_bot_enabled_db

        if is_oauth_enabled_db:
            if is_bot_enabled_db:
                form.discord_bot_require_sso_on_invite.data = True
            else:
                form.discord_bot_require_sso_on_invite.data = Setting.get_bool('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', False)
            form.discord_require_guild_membership.data = Setting.get_bool('DISCORD_REQUIRE_GUILD_MEMBERSHIP', False)
        else:
            form.discord_bot_require_sso_on_invite.data = False
            form.discord_require_guild_membership.data = False
            
        form.discord_guild_id.data = Setting.get('DISCORD_GUILD_ID')
        form.discord_server_invite_url.data = Setting.get('DISCORD_SERVER_INVITE_URL')
        
        if is_bot_enabled_db:
            form.discord_monitored_role_id.data = Setting.get('DISCORD_MONITORED_ROLE_ID')
            form.discord_thread_channel_id.data = Setting.get('DISCORD_THREAD_CHANNEL_ID')
            form.discord_bot_log_channel_id.data = Setting.get('DISCORD_BOT_LOG_CHANNEL_ID')
        form.discord_bot_whitelist_sharers.data = Setting.get_bool('DISCORD_BOT_WHITELIST_SHARERS', False)
            
    return render_template('settings/index.html', 
                           title="Discord Settings", 
                           form=form,
                           active_tab='discord',
                           discord_invite_redirect_uri=discord_invite_redirect_uri_generated,
                           discord_admin_link_redirect_uri=discord_admin_link_redirect_uri_generated,
                           discord_admin_linked=discord_admin_linked,
                           discord_admin_user_info=discord_admin_user_info,
                           initial_discord_enabled_state=initial_oauth_enabled_for_admin_link_section)

@bp.route('/settings/advanced', methods=['GET'])
@login_required
@setup_required
@permission_required('manage_advanced_settings')
def settings_advanced():
    all_db_settings = Setting.query.order_by(Setting.key).all()
    return render_template('settings/index.html', title="Advanced Settings", active_tab='advanced', all_db_settings=all_db_settings)

@bp.route('/settings/regenerate_secret_key', methods=['POST'])
@login_required
@setup_required
@permission_required('manage_advanced_settings')
def regenerate_secret_key():
    try:
        new_secret_key = secrets.token_hex(32)
        Setting.set('SECRET_KEY', new_secret_key, SettingValueType.SECRET, "Application Secret Key"); current_app.config['SECRET_KEY'] = new_secret_key
        admin_id_for_log = current_user.id if current_user and current_user.is_authenticated else None 
        logout_user() # User's session is now invalid due to new secret key
        log_event(EventType.SETTING_CHANGE, "Application SECRET_KEY re-generated by admin.", admin_id=admin_id_for_log)
        # Flash message might not be seen if user is immediately logged out and redirected by Flask-Login
        # flash('SECRET_KEY re-generated. All users (including you) have been logged out.', 'success') 
        
        # For HTMX, explicitly tell client to redirect to login
        if request.headers.get('HX-Request'):
            response = make_response('<div class="alert alert-success p-2">SECRET_KEY re-generated. You will be logged out. Refreshing...</div>')
            response.headers['HX-Refresh'] = 'true' # Or HX-Redirect to login page
            return response
        return redirect(url_for('auth.app_login')) # Redirect to login for standard request
    except Exception as e:
        current_app.logger.error(f"Error regenerating SECRET_KEY: {e}")
        log_event(EventType.ERROR_GENERAL, f"Failed to re-generate SECRET_KEY: {str(e)}", admin_id=current_user.id if current_user and current_user.is_authenticated else None)
        flash(f'Error re-generating SECRET_KEY: {e}', 'danger')
        if request.headers.get('HX-Request'): return f'<div class="alert alert-error p-2">Error: {e}</div>', 500
        return redirect(url_for('dashboard.settings_advanced'))
    
@bp.route('/settings/logs/clear', methods=['POST'])
@login_required
@setup_required
@permission_required('clear_logs')
def clear_logs_route():
    event_types_selected = request.form.getlist('event_types_to_clear[]')
    clear_all = request.form.get('clear_all_types') == 'true'
    
    current_app.logger.info(f"Dashboard.py - clear_logs_route(): Received request to clear logs. Selected types: {event_types_selected}, Clear All: {clear_all}")

    types_to_delete_in_service = None
    if not clear_all and event_types_selected:
        types_to_delete_in_service = event_types_selected
    elif clear_all:
        types_to_delete_in_service = None
    else: 
        toast_message = "No event types selected to clear. No logs were deleted."
        toast_category = "info"
        # flash(toast_message, toast_category) # <<< REMOVE/COMMENT OUT if you don't want session flash
        
        response = make_response("") 
        trigger_payload = json.dumps({"showToastEvent": {"message": toast_message, "category": toast_category}})
        response.headers['HX-Trigger-After-Swap'] = trigger_payload 
        # Also trigger list refresh, though nothing changed
        refresh_trigger_payload = json.dumps({"refreshHistoryList": True})
        existing_trigger = response.headers.get('HX-Trigger-After-Swap')
        if existing_trigger:
            try:
                data = json.loads(existing_trigger)
                data.update(json.loads(refresh_trigger_payload))
                response.headers['HX-Trigger-After-Swap'] = json.dumps(data)
            except json.JSONDecodeError:
                 response.headers['HX-Trigger-After-Swap'] = refresh_trigger_payload # fallback
        else:
            response.headers['HX-Trigger-After-Swap'] = refresh_trigger_payload
        
        return response, 200 # Send 200 OK as an action was processed (even if no-op)

    toast_message = ""
    toast_category = "info"
    try:
        cleared_count = history_service.clear_history_logs(
            event_types_to_clear=types_to_delete_in_service,
            admin_id=current_user.id
        )
        toast_message = f"Successfully cleared {cleared_count} history log entries."
        toast_category = "success"
        # flash(toast_message, toast_category) # <<< REMOVE/COMMENT OUT if you don't want session flash
        # The log_event in history_service already records this action.
        current_app.logger.info(f"Dashboard.py - clear_logs_route(): {toast_message}")

    except Exception as e:
        current_app.logger.error(f"Dashboard.py - clear_logs_route(): Failed to clear history: {e}", exc_info=True)
        toast_message = f"Error clearing history logs: {str(e)}"
        toast_category = "danger"
        # flash(toast_message, toast_category) # <<< REMOVE/COMMENT OUT if you don't want session flash
        # The log_event in history_service (if it has an error case) or a new one here could record.

    response_content_for_form = "" 
    response = make_response(response_content_for_form)
    
    triggers = {}
    if toast_message:
        triggers["showToastEvent"] = {"message": toast_message, "category": toast_category}
    
    triggers["refreshHistoryList"] = True # Always refresh the list after attempting a clear
    
    response.headers['HX-Trigger-After-Swap'] = json.dumps(triggers)
    current_app.logger.debug(f"Dashboard.py - clear_logs_route(): Sending HX-Trigger-After-Swap: {response.headers['HX-Trigger-After-Swap']}")

    return response

@bp.route('/streaming')
@login_required
@setup_required
@permission_required('view_streaming')
def streaming_sessions():
    # Fetch the session monitoring interval from settings
    default_interval = current_app.config.get('SESSION_MONITORING_INTERVAL_SECONDS', 30) # Default fallback
    try:
        interval_seconds_str = Setting.get('SESSION_MONITORING_INTERVAL_SECONDS', str(default_interval))
        # Ensure it's a valid integer, otherwise use a sensible default for the template
        streaming_refresh_interval_seconds = int(interval_seconds_str)
        if streaming_refresh_interval_seconds < 5: # Enforce a minimum reasonable refresh interval for UI
            current_app.logger.warning(f"Streaming page refresh interval ({streaming_refresh_interval_seconds}s) is too low, defaulting to 5s for UI.")
            streaming_refresh_interval_seconds = 5 
    except ValueError:
        current_app.logger.warning(f"Invalid SESSION_MONITORING_INTERVAL_SECONDS ('{interval_seconds_str}') in settings. Using default {default_interval}s for streaming page refresh.")
        streaming_refresh_interval_seconds = default_interval
    except Exception as e_setting:
        current_app.logger.error(f"Error fetching SESSION_MONITORING_INTERVAL_SECONDS: {e_setting}. Using default {default_interval}s.")
        streaming_refresh_interval_seconds = default_interval


    current_app.logger.debug(f"Streaming page will use refresh interval: {streaming_refresh_interval_seconds} seconds.")
    
    return render_template('dashboard/streaming.html', 
                           title="Active Streams", 
                           streaming_refresh_interval=streaming_refresh_interval_seconds)

@bp.route('/streaming/partial')
@login_required
@setup_required
@permission_required('view_streaming')
def streaming_sessions_partial():
    active_sessions_data = []
    summary_stats = {
        "total_streams": 0,
        "direct_play_count": 0,
        "transcode_count": 0,
        "total_bandwidth_mbps": 0.0,
        "lan_bandwidth_mbps": 0.0,
        "wan_bandwidth_mbps": 0.0
    }

    try:
        raw_sessions_from_plex = plex_service.get_active_sessions()

        if raw_sessions_from_plex:
            summary_stats["total_streams"] = len(raw_sessions_from_plex)
            
            plex_user_ids_in_session_for_query = set()
            for rs in raw_sessions_from_plex:
                if hasattr(rs, 'user') and rs.user and hasattr(rs.user, 'id'):
                    try: 
                        plex_user_ids_in_session_for_query.add(int(rs.user.id))
                    except (ValueError, TypeError) as e:
                        current_app.logger.warning(f"Could not parse user ID '{getattr(rs.user, 'id', 'N/A')}' for session user '{getattr(rs.user, 'title', 'Unknown User')}': {e}")
            
            pum_users_map_by_plex_id = {} 
            if plex_user_ids_in_session_for_query:
                pum_db_users = User.query.filter(User.plex_user_id.in_(list(plex_user_ids_in_session_for_query))).all()
                for u in pum_db_users:
                    if u.plex_user_id is not None:
                        pum_users_map_by_plex_id[u.plex_user_id] = u 
            current_app.logger.debug(f"STREAMING_DEBUG: PUM Users Map for sessions: { {k:v.plex_username for k,v in pum_users_map_by_plex_id.items()} }")

            current_app.logger.debug(f"--- Found {summary_stats['total_streams']} raw sessions from Plex ---")
            for i, raw_plex_session in enumerate(raw_sessions_from_plex):
                session_title_for_log = getattr(raw_plex_session, 'title', 'N/A_SessionTitle')
                current_app.logger.debug(f"--- Processing Raw Session {i+1} ({session_title_for_log}) ---")
                current_app.logger.debug(f"STREAMING_DEBUG: Raw Session Object Type: {type(raw_plex_session)}")

                # --- START DEBUG BLOCK ---
                try:
                    # Log all top-level attributes of the session object
                    session_attribs = {key: getattr(raw_plex_session, key, 'N/A') for key in [
                        'title', 'type', 'duration', 'viewOffset', 'sessionKey', 'ratingKey',
                        'state', 'grandparentTitle', 'parentTitle', 'librarySectionTitle', 'videoResolution'
                    ]}
                    current_app.logger.debug(f"[Session Details]: {session_attribs}")

                    if hasattr(raw_plex_session, 'player'):
                        player_attribs = {key: getattr(raw_plex_session.player, key, 'N/A') for key in [
                            'title', 'platform', 'product', 'version', 'address', 'local', 'state'
                        ]}
                        current_app.logger.debug(f"[Player Details]: {player_attribs}")

                    if hasattr(raw_plex_session, 'media') and raw_plex_session.media:
                        media = raw_plex_session.media[0]
                        media_attribs = {key: getattr(media, key, 'N/A') for key in [
                            'id', 'duration', 'bitrate', 'videoCodec', 'videoResolution', 'audioCodec', 'audioChannels', 'container'
                        ]}
                        current_app.logger.debug(f"[Media Details (media[0])]: {media_attribs}")
                        if hasattr(media, 'parts') and media.parts:
                            part = media.parts[0]
                            for s_idx, stream in enumerate(getattr(part, 'streams', [])):
                                stream_attribs = {key: getattr(stream, key, 'N/A') for key in [
                                    'id', 'streamType', 'codec', 'height', 'width', 'displayTitle', 'language', 'format', 'channels'
                                ]}
                                current_app.logger.debug(f"  [Stream #{s_idx}]: {stream_attribs}")
                    
                    if hasattr(raw_plex_session, 'transcodeSession'):
                        transcode_session = raw_plex_session.transcodeSession
                        transcode_attribs = {key: getattr(transcode_session, key, 'N/A') for key in [
                            'key', 'throttled', 'speed', 'videoDecision', 'audioDecision', 'subtitleDecision', 
                            'container', 'videoCodec', 'audioCodec', 'sourceVideoCodec', 'sourceAudioCodec', 'videoHeight', 'videoWidth'
                        ]}
                        current_app.logger.debug(f"[Transcode Details]: {transcode_attribs}")
                    
                    # Also log the full XML attributes for deep diving if needed
                    if hasattr(raw_plex_session, '_data') and raw_plex_session._data is not None:
                        current_app.logger.debug(f"[Full XML Attribs]: {json.dumps(raw_plex_session._data.attrib if hasattr(raw_plex_session._data, 'attrib') else raw_plex_session._data, indent=2, default=str)}")

                except Exception as e_log:
                    current_app.logger.error(f"Error during debug logging for session: {e_log}")
                # --- END DEBUG BLOCK ---
                
                if hasattr(raw_plex_session, '_data') and raw_plex_session._data is not None: # Log raw XML attributes
                   current_app.logger.debug(f"STREAMING_DEBUG:   raw_plex_session._data.attrib: {json.dumps(raw_plex_session._data.attrib if hasattr(raw_plex_session._data, 'attrib') else raw_plex_session._data, indent=2, default=str)}")
                
                progress_value = 0.0
                raw_duration = getattr(raw_plex_session, 'duration', None)
                raw_view_offset = getattr(raw_plex_session, 'viewOffset', None)
                # current_app.logger.debug(f"STREAMING_DEBUG (Progress): raw_duration='{raw_duration}', raw_view_offset='{raw_view_offset}'")
                if raw_duration and raw_view_offset:
                    try:
                        duration = float(raw_duration); view_offset = float(raw_view_offset)
                        if duration > 0: progress_value = (view_offset / duration) * 100
                    except (ValueError, TypeError): pass # Handled by default progress_value = 0.0
                
                user_name_from_session = getattr(raw_plex_session.user, 'title', 'Unknown User') if hasattr(raw_plex_session, 'user') and raw_plex_session.user else 'Unknown User'
                player_title = getattr(raw_plex_session.player, 'title', 'Unknown Player') if hasattr(raw_plex_session, 'player') and raw_plex_session.player else 'Unknown Player'
                player_platform = getattr(raw_plex_session.player, 'platform', '') if hasattr(raw_plex_session, 'player') and raw_plex_session.player else ''
                media_title = getattr(raw_plex_session, 'title', "Unknown Title")
                media_type = getattr(raw_plex_session, 'type', 'unknown').capitalize()
                year = getattr(raw_plex_session, 'year', None)
                library_name = getattr(raw_plex_session, 'librarySectionTitle', "N/A")
                grandparent_title = None; parent_title = None;
                if media_type == 'Episode':
                    grandparent_title = getattr(raw_plex_session, 'grandparentTitle', None)
                    parent_title = getattr(raw_plex_session, 'parentTitle', None)
                elif media_type == 'Track':
                    grandparent_title = getattr(raw_plex_session, 'grandparentTitle', None)
                    parent_title = getattr(raw_plex_session, 'parentTitle', None)
                
                session_state = getattr(raw_plex_session, 'state', "N/A")
                if session_state == "N/A" and hasattr(raw_plex_session, 'player') and raw_plex_session.player:
                    player_state = getattr(raw_plex_session.player, 'state', None)
                    if player_state: session_state = player_state.capitalize()
                
                thumb_url_for_template_final = None 
                plex_image_path_relative = None
                if media_type == 'Episode' and hasattr(raw_plex_session, 'grandparentThumb') and raw_plex_session.grandparentThumb:
                    plex_image_path_relative = raw_plex_session.grandparentThumb
                elif hasattr(raw_plex_session, 'thumbUrl') and raw_plex_session.thumbUrl:
                    plex_image_path_relative = raw_plex_session.thumbUrl
                elif hasattr(raw_plex_session, 'thumb') and raw_plex_session.thumb:
                    plex_image_path_relative = raw_plex_session.thumb
                if plex_image_path_relative:
                    path_to_proxy = None
                    if plex_image_path_relative.startswith('http://') or plex_image_path_relative.startswith('https://'):
                        try:
                            parsed_url = urlparse(plex_image_path_relative); path_to_proxy = parsed_url.path
                        except Exception: pass
                    else: path_to_proxy = plex_image_path_relative
                    if path_to_proxy:
                        try: thumb_url_for_template_final = url_for('api.plex_image_proxy', path=path_to_proxy.lstrip('/'))
                        except Exception: pass
                # current_app.logger.debug(f"STREAMING_DEBUG (Thumb): Final thumb_url_for_template_final: {thumb_url_for_template_final}")


                # --- Detailed Stream Information Extraction ---
                stream_details_text = "Direct Play"
                container_text_val = "N/A"
                video_text = "N/A"
                audio_text = "N/A"
                subtitle_text = "None"
                current_bitrate_kbps = None
                
                media_item = None
                video_stream_info = None
                audio_stream_info = None
                subtitle_stream_info = None
                source_container_from_media_item = "N/A" # Default for clarity

                if hasattr(raw_plex_session, 'media') and isinstance(raw_plex_session.media, list) and len(raw_plex_session.media) > 0:
                    media_item = raw_plex_session.media[0]
                    current_bitrate_kbps = getattr(media_item, 'bitrate', None)
                    source_container_from_media_item = getattr(media_item, 'container', "N/A") # Get source from media_item
                    current_app.logger.debug(f"STREAMING_DEBUG (Container): Source container from media_item (media[0]): '{source_container_from_media_item}'")
                    container_text_val = source_container_from_media_item.upper() if source_container_from_media_item else "N/A"
                    
                    if hasattr(media_item, 'parts') and isinstance(media_item.parts, list) and len(media_item.parts) > 0:
                        part_item = media_item.parts[0]
                        for stream in getattr(part_item, 'streams', []):
                            if getattr(stream, 'streamType', 0) == 1: video_stream_info = stream
                            elif getattr(stream, 'streamType', 0) == 2: audio_stream_info = stream
                            elif getattr(stream, 'streamType', 0) == 3: subtitle_stream_info = stream
                
                # --- FIXED VIDEO RESOLUTION LOGIC ---
                # Get source resolution from video stream displayTitle (e.g., "1080p (HEVC Main 10)")
                source_resolution = "N/A"
                if video_stream_info and hasattr(video_stream_info, 'displayTitle') and video_stream_info.displayTitle:
                    # Extract resolution from displayTitle like "1080p (HEVC Main 10)"
                    display_title = video_stream_info.displayTitle
                    # Look for pattern like "1080p", "720p", "480p", etc.
                    import re
                    resolution_match = re.search(r'(\d+p)', display_title)
                    if resolution_match:
                        source_resolution = resolution_match.group(1)
                    else:
                        # Fallback to height-based resolution if no 'p' format found
                        if hasattr(video_stream_info, 'height') and video_stream_info.height:
                            source_resolution = f"{video_stream_info.height}p"
                elif video_stream_info and hasattr(video_stream_info, 'height') and video_stream_info.height:
                    # Fallback to height if no displayTitle
                    source_resolution = f"{video_stream_info.height}p"
                
                # Get target resolution - use media_item.videoResolution for transcoded content
                target_resolution = "N/A"
                transcode_session_obj = getattr(raw_plex_session, 'transcodeSession', None)
                if transcode_session_obj:
                    # For transcoded content, use media_item.videoResolution as the target
                    if media_item and hasattr(media_item, 'videoResolution') and media_item.videoResolution:
                        target_resolution = media_item.videoResolution
                    elif hasattr(transcode_session_obj, 'videoHeight') and transcode_session_obj.videoHeight:
                        target_resolution = f"{transcode_session_obj.videoHeight}p"
                    else:
                        target_resolution = source_resolution  # Fallback
                else:
                    # For direct play, target = source
                    target_resolution = source_resolution
                
                # For quality description, use the final resolution (target for transcoded, source for direct play)
                video_resolution_final = target_resolution if transcode_session_obj else source_resolution
                
                current_app.logger.debug(f"STREAMING_DEBUG (Quality): Source resolution: '{source_resolution}', Target resolution: '{target_resolution}', Final: '{video_resolution_final}'")
                
                if transcode_session_obj:
                    stream_details_text = "Transcode"
                    if getattr(transcode_session_obj, 'throttled', False): stream_details_text += " (Throttled)"
                    if getattr(transcode_session_obj, 'speed', None) is not None: stream_details_text += f" (Speed: {transcode_session_obj.speed:.1f})"
                    
                    target_container_from_transcode = getattr(transcode_session_obj, 'container', "N/A_transcode")
                    current_app.logger.debug(f"STREAMING_DEBUG (Container): Target container from transcode_session_obj: '{target_container_from_transcode}'")
                    if source_container_from_media_item != "N/A" and target_container_from_transcode != "N/A_transcode":
                        container_text_val = f"Converting ({source_container_from_media_item.upper()} -> {target_container_from_transcode.upper()})"
                    elif target_container_from_transcode != "N/A_transcode": container_text_val = f"To {target_container_from_transcode.upper()}"
                    # else: container_text_val remains what was set from source_container_from_media_item
                    
                    # Safely get all potentially None attributes from the transcode object first.
                    video_decision_str = getattr(transcode_session_obj, 'videoDecision', 'Unknown')
                    src_v_codec_str = getattr(transcode_session_obj, 'sourceVideoCodec', 'N/A')
                    tgt_v_codec_str = getattr(transcode_session_obj, 'videoCodec', 'N/A')
                    
                    audio_decision_str = getattr(transcode_session_obj, 'audioDecision', 'Unknown')
                    src_a_codec_str = getattr(transcode_session_obj, 'sourceAudioCodec', 'N/A')
                    tgt_a_codec_str = getattr(transcode_session_obj, 'audioCodec', 'N/A')

                    # Now, call methods only if the strings are not None.
                    v_decision = video_decision_str.capitalize() if video_decision_str else 'Unknown'
                    src_v_codec = src_v_codec_str.upper() if src_v_codec_str else 'N/A'
                    tgt_v_codec = tgt_v_codec_str.upper() if tgt_v_codec_str else 'N/A'

                    a_decision = audio_decision_str.capitalize() if audio_decision_str else 'Unknown'
                    src_a_codec = src_a_codec_str.upper() if src_a_codec_str else 'N/A'
                    tgt_a_codec = tgt_a_codec_str.upper() if tgt_a_codec_str else 'N/A'

                    # Use the FIXED resolution values
                    video_text = f"{v_decision} ({src_v_codec} {source_resolution} -> {tgt_v_codec} {target_resolution})"
                    
                    src_a_ch = audio_stream_info.channels if audio_stream_info and hasattr(audio_stream_info, 'channels') else 'N/A'
                    tgt_a_ch = transcode_session_obj.audioChannels if hasattr(transcode_session_obj, 'audioChannels') else 'N/A'
                    audio_lang = (audio_stream_info.displayTitle or audio_stream_info.language) if audio_stream_info else ''
                    audio_text = f"{a_decision} ({audio_lang} - {src_a_codec} {src_a_ch}ch -> {tgt_a_codec} {tgt_a_ch}ch)".replace("  - ", " - ").replace("( - ", "(").strip()
                else: 
                    if video_stream_info: video_text = f"Direct Play ({getattr(video_stream_info, 'codec', 'N/A').upper()} {source_resolution})"
                    if audio_stream_info:
                        audio_lang = (audio_stream_info.displayTitle or audio_stream_info.language) if audio_stream_info and (audio_stream_info.displayTitle or audio_stream_info.language) else ''
                        audio_text = f"Direct Play ({audio_lang} - {getattr(audio_stream_info, 'codec', 'N/A').upper()} {getattr(audio_stream_info, 'channels', 'N/A')}ch)".replace("  - ", " - ").replace("( - ", "(").strip()
                
                if subtitle_stream_info:
                    sub_lang_parts = []
                    if hasattr(subtitle_stream_info, 'displayTitle') and subtitle_stream_info.displayTitle: sub_lang_parts.append(subtitle_stream_info.displayTitle)
                    elif hasattr(subtitle_stream_info, 'language') and subtitle_stream_info.language: sub_lang_parts.append(subtitle_stream_info.language.capitalize())
                    sub_lang = " - ".join(sub_lang_parts) if sub_lang_parts else "Und"
                    raw_sub_format = getattr(subtitle_stream_info, 'format', None) or getattr(subtitle_stream_info, 'codec', None)
                    sub_format = (raw_sub_format or '').upper()
                    subtitle_text = f"{sub_lang}"
                    if sub_format: subtitle_text += f" ({sub_format})"
                    if transcode_session_obj and getattr(transcode_session_obj, 'subtitleDecision', 'copy') == 'burn':
                        subtitle_text = f"Burn - {subtitle_text}"
                
                quality_desc = f"{video_resolution_final if video_resolution_final != 'N/A' else 'Unknown Res'}"
                current_bitrate_kbps_for_calc = 0 
                if current_bitrate_kbps:
                    try:
                        current_bitrate_kbps_for_calc = int(current_bitrate_kbps)
                        if current_bitrate_kbps_for_calc > 0: quality_desc += f" ({ (current_bitrate_kbps_for_calc / 1000.0):.1f} Mbps)"
                    except (ValueError, TypeError): pass # quality_desc will not have bitrate part
                
                product = getattr(raw_plex_session.player, 'product', 'N/A') if hasattr(raw_plex_session, 'player') else 'N/A'
                location_ip = getattr(raw_plex_session.player, 'address', 'N/A') if hasattr(raw_plex_session, 'player') else 'N/A'
                is_lan = hasattr(raw_plex_session.player, 'local') and raw_plex_session.player.local
                is_public_ip = not is_lan and location_ip not in ['127.0.0.1', 'localhost']
                location_lan_wan = "LAN" if is_lan else "WAN" if is_public_ip else "Local"

                pum_user_id_for_link = None
                plex_user_id_from_session_int = None
                if hasattr(raw_plex_session, 'user') and raw_plex_session.user and hasattr(raw_plex_session.user, 'id'):
                    try:
                        plex_user_id_from_session_int = int(raw_plex_session.user.id)
                        if plex_user_id_from_session_int in pum_users_map_by_plex_id:
                            pum_user_id_for_link = pum_users_map_by_plex_id[plex_user_id_from_session_int].id
                    except (ValueError, TypeError): pass

                session_details = {
                    'user': user_name_from_session, 'pum_user_id': pum_user_id_for_link,
                    'player_title': player_title, 'player_platform': player_platform, 'product': product,
                    'media_title': media_title, 'grandparent_title': grandparent_title, 'parent_title': parent_title,
                    'media_type': media_type, 'library_name': library_name, 'year': year,
                    'state': session_state, 'progress': round(progress_value, 1),
                    'thumb_url': thumb_url_for_template_final, 
                    'session_key': getattr(raw_plex_session, 'sessionKey', None),
                    
                    'quality_detail': quality_desc, 'stream_detail': stream_details_text,
                    'container_detail': container_text_val, 'video_detail': video_text,
                    'audio_detail': audio_text, 'subtitle_detail': subtitle_text,
                    'location_detail': f"{location_lan_wan}: {location_ip if location_ip != 'N/A' else ''}".strip(),
                    'is_public_ip': is_public_ip, # Add the new boolean flag
                    'location_ip': location_ip, # Pass the raw IP for the URL
                    'bandwidth_detail': f"{ (current_bitrate_kbps_for_calc / 1000.0):.1f} Mbps" if current_bitrate_kbps_for_calc > 0 else "N/A",

                    'bitrate_calc': current_bitrate_kbps_for_calc,
                    'location_type_calc': location_lan_wan,
                    'is_transcode_calc': bool(transcode_session_obj)
                }
                active_sessions_data.append(session_details)

                if session_details['is_transcode_calc']: summary_stats["transcode_count"] += 1
                else: summary_stats["direct_play_count"] += 1
                if session_details['bitrate_calc'] > 0:
                    bitrate_mbps = session_details['bitrate_calc'] / 1000.0
                    summary_stats["total_bandwidth_mbps"] += bitrate_mbps
                    if session_details['location_type_calc'] == 'LAN': summary_stats["lan_bandwidth_mbps"] += bitrate_mbps
                    elif session_details['location_type_calc'] == 'WAN': summary_stats["wan_bandwidth_mbps"] += bitrate_mbps
            
            summary_stats["total_bandwidth_mbps"] = round(summary_stats["total_bandwidth_mbps"], 1)
            summary_stats["lan_bandwidth_mbps"] = round(summary_stats["lan_bandwidth_mbps"], 1)
            summary_stats["wan_bandwidth_mbps"] = round(summary_stats["wan_bandwidth_mbps"], 1)
            # current_app.logger.debug(f"STREAMING_DEBUG: Final Summary Stats: {json.dumps(summary_stats)}") # Already present
        else: 
            current_app.logger.debug("STREAMING_DEBUG: No active Plex sessions found by service.")

    except Exception as e:
        current_app.logger.error(f"STREAMING_DEBUG: Error during streaming_sessions_partial: {e}", exc_info=True)
            
    return render_template('dashboard/_streaming_sessions_content.html', 
                           sessions=active_sessions_data, 
                           summary_stats=summary_stats)

@bp.route('/settings/admins')
@login_required
@any_permission_required(['create_admin', 'edit_admin', 'delete_admin'])
def settings_admins():
    admins = AdminAccount.query.order_by(AdminAccount.id).all()
    return render_template(
        'settings/index.html',
        title="Manage Admins",
        admins=admins,
        active_tab='admins'
    )

@bp.route('/settings/admins/create', methods=['POST'])
@login_required
@permission_required('create_admin')
def create_admin():
    form = AdminCreateForm()
    if form.validate_on_submit():
        new_admin = AdminAccount(
            username=form.username.data,
            force_password_change=True,
            roles=[] # New admins start with no explicit permissions/roles
        )
        new_admin.set_password(form.password.data)
        db.session.add(new_admin)
        db.session.commit()
        
        toast = {"showToastEvent": {"message": f"Admin '{new_admin.username}' created.", "category": "success"}}
        response = make_response("", 204) # No Content
        response.headers['HX-Trigger'] = json.dumps({"refreshAdminList": True, **toast})
        return response
    
    # If validation fails, re-render the form partial with errors
    return render_template('admins/_create_admin_modal_form_content.html', form=form), 422

@bp.route('/settings/admins/create_form')
@login_required
@permission_required('create_admin')
def get_admin_create_form():
    form = AdminCreateForm()
    return render_template('admins/_create_admin_modal_form_content.html', form=form)

@bp.route('/settings/roles/edit/<int:role_id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_role')
def edit_role(role_id):
    tab = request.args.get('tab', 'display')
    role = Role.query.get_or_404(role_id)
    form = RoleEditForm(original_name=role.name, obj=role)
    member_form = RoleMemberForm()

    if current_user.id != 1 and current_user in role.admins:
        flash("You cannot edit a role you are currently assigned to.", "danger")
        return redirect(url_for('dashboard.settings_roles'))

    # --- Define the hierarchical permission structure ---
    permissions_structure = {
        'Users': {
            'label': 'Users',
            'children': {
                'view_user': {'label': 'View User', 'description': 'Can view user profile.'},
                'edit_user': {'label': 'Edit User', 'description': 'Can edit user details, notes, whitelists, and library access.'},
                'delete_user': {'label': 'Delete User', 'description': 'Can permanently remove users from PUM and the Plex server.'},
                'purge_users': {'label': 'Purge Users', 'description': 'Can use the inactivity purge feature.'},
                'mass_edit_users': {'label': 'Mass Edit Users', 'description': 'Can perform bulk actions like assigning libraries or whitelisting.'},
            }
        },
        'Invites': {
            'label': 'Invites',
            'children': {
                'create_invites': {'label': 'Create Invites', 'description': 'Can create new invite links.'},
                'delete_invites': {'label': 'Delete Invites', 'description': 'Can delete existing invite links.'},
                'edit_invites': {'label': 'Edit Invites', 'description': 'Can modify settings for existing invites.'},
            }
        },
        'Admins': { 
            'label': 'Admins & Roles', 
            'children': {
                'view_admins_tab': {'label': 'View Admin Management Section', 'description': 'Allows user to see the "Admins" and "Roles" tabs in settings.'},
                'create_admin':    {'label': 'Create Admin', 'description': 'Can create new administrator accounts.'},
                'edit_admin':      {'label': 'Edit Admin', 'description': 'Can edit other administrators. (roles, reset password etc.)'},
                'delete_admin':    {'label': 'Delete Admin', 'description': 'Can delete other non-primary administrators.'},
                'create_role':     {'label': 'Create Role', 'description': 'Can create new administrator roles.'},
                'edit_role':       {'label': 'Edit Role Permissions', 'description': 'Can edit a role\'s name, color, and permissions.'},
                'delete_role':     {'label': 'Delete Roles', 'description': 'Can delete roles that are not in use.'},
            }
        },
        'Streams': {
            'label': 'Streams',
            'children': {
                'view_streaming': {'label': 'View Streams', 'description': 'Can access the "Active Streams" page.'},
                'kill_stream': {'label': 'Terminate Stream', 'description': 'Can stop a user\'s active stream.'},
            }
        },
        'EventLogs': {
            'label': 'Application Logs',
            'children': {
                 'view_logs': {'label': 'View Application Logs', 'description': 'Can access the full "Application Logs" page in settings.'},
                 'clear_logs': {'label': 'Clear Application Logs', 'description': 'Can erase the full "Application Logs".'},
            }
        },
        'AppSettings': {
            'label': 'App Settings',
            'children': {
                'manage_general_settings': {'label': 'Manage General', 'description': 'Can change the application name and base URL.'},
                'manage_plex_settings': {'label': 'Manage Plex', 'description': 'Can change the Plex server connection details.'},
                'manage_discord_settings': {'label': 'Manage Discord', 'description': 'Can change Discord OAuth, Bot, and feature settings.'},
                'manage_advanced_settings' : {'label': 'Manage Advanced', 'description': 'Can access and manage advanced settings page.'},
            }
        }
    }

    # Flatten the structure to populate the form's choices
    all_permission_choices = []
    for category_data in permissions_structure.values():
        for p_key, p_label in category_data.get('children', {}).items():
            all_permission_choices.append((p_key, p_label))
    form.permissions.choices = all_permission_choices
    
    # Populate choices for the 'Add Members' modal form
    admins_not_in_role = AdminAccount.query.filter(
        AdminAccount.id != 1, 
        ~AdminAccount.roles.any(id=role.id)
    ).order_by(AdminAccount.username).all()
    member_form.admins_to_add.choices = [(a.id, a.username or a.plex_username) for a in admins_not_in_role]

    # Handle form submissions from different tabs
    if request.method == 'POST':
        if 'submit_display' in request.form and form.validate():
            role.name = form.name.data
            role.description = form.description.data
            role.color = form.color.data
            role.icon = form.icon.data.strip()
            db.session.commit()
            flash(f"Display settings for role '{role.name}' updated.", "success")
            return redirect(url_for('dashboard.edit_role', role_id=role_id, tab='display'))
        
        elif 'submit_permissions' in request.form and form.validate():
            # The form.permissions.data will correctly contain all checked permissions
            role.permissions = form.permissions.data
            db.session.commit()
            flash(f"Permissions for role '{role.name}' updated.", "success")
            return redirect(url_for('dashboard.edit_role', role_id=role_id, tab='permissions'))
            
        elif 'submit_add_members' in request.form and member_form.validate_on_submit():
            admins_to_add = AdminAccount.query.filter(AdminAccount.id.in_(member_form.admins_to_add.data)).all()
            if admins_to_add:
                for admin in admins_to_add:
                    if admin not in role.admins:
                        role.admins.append(admin)
                db.session.commit()
                
                # On SUCCESS, send back a trigger for a toast and a list refresh
                toast = {"showToastEvent": {"message": f"Added {len(admins_to_add)} member(s) to role '{role.name}'.", "category": "success"}}
                # Create an empty 204 response because we don't need to swap any content
                response = make_response("", 204)
                # Set the header that HTMX and our JS will listen for
                response.headers['HX-Trigger'] = json.dumps({"refreshMembersList": True, **toast})
                return response

            else:
                # User submitted the form without selecting anyone
                toast = {"showToastEvent": {"message": "No members were selected to be added.", "category": "info"}}
                response = make_response("", 204)
                response.headers['HX-Trigger'] = json.dumps(toast)
                return response

    # Populate form for GET request
    if request.method == 'GET' and tab == 'permissions':
        form.permissions.data = role.permissions

    return render_template(
        'settings/index.html',
        title=f"Edit Role: {role.name}",
        role=role,
        edit_form=form,
        form=form,
        member_form=member_form,
        current_members=role.admins,
        permissions_structure=permissions_structure, # Pass the hierarchy
        active_tab='roles_edit', 
        active_role_tab=tab 
    )

@bp.route('/settings/admins/delete/<int:admin_id>', methods=['POST'])
@login_required
@permission_required('delete_admin')
def delete_admin(admin_id):
    if admin_id == 1 or admin_id == current_user.id:
        flash("The primary admin or your own account cannot be deleted.", "danger")
        return redirect(url_for('dashboard.settings_admins'))
    
    admin_to_delete = AdminAccount.query.get_or_404(admin_id)
    db.session.delete(admin_to_delete)
    db.session.commit()
    flash(f"Admin '{admin_to_delete.username}' has been deleted.", "success")
    return redirect(url_for('dashboard.settings_admins'))

@bp.route('/settings/roles') # This now ONLY lists roles
@login_required
@any_permission_required(['create_role', 'edit_role', 'delete_role'])
def settings_roles():
    roles = Role.query.order_by(Role.name).all()
    return render_template(
        'settings/index.html',
        title="Manage Roles",
        roles=roles,
        active_tab='roles'
    )

@bp.route('/settings/roles/create', methods=['GET', 'POST'])
@login_required
@permission_required('create_role')
def create_role():
    form = RoleCreateForm()
    if form.validate_on_submit():
        new_role = Role(
            name=form.name.data,
            description=form.description.data,
            color=form.color.data,
            icon=form.icon.data.strip()
        )
        db.session.add(new_role)
        db.session.commit()
        
        # --- START MODIFICATION ---
        flash(f"Role '{new_role.name}' created successfully. You can now set its permissions.", "success")
        # Redirect to the 'edit' page for the newly created role
        return redirect(url_for('dashboard.edit_role', role_id=new_role.id))
        # --- END MODIFICATION ---

    # The GET request rendering remains the same, but the template it renders will be changed.
    return render_template(
        'roles/create.html',
        title="Create New Role",
        form=form,
        active_tab='roles' # Keep 'roles' highlighted in the main settings sidebar
    )

@bp.route('/settings/roles/edit/<int:role_id>/remove_member/<int:admin_id>', methods=['POST'])
@login_required
@permission_required('edit_role')
def remove_role_member(role_id, admin_id):
    role = Role.query.get_or_404(role_id)
    admin = AdminAccount.query.get_or_404(admin_id)
    if admin in role.admins:
        role.admins.remove(admin)
        db.session.commit()
        flash(f"Removed '{admin.username}' from role '{role.name}'.", "success")
    # Redirect back to the members tab
    return redirect(url_for('dashboard.edit_role', role_id=role.id, tab='members'))

@bp.route('/settings/roles/delete/<int:role_id>', methods=['POST'])
@login_required
@permission_required('delete_role')
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)

    if current_user.id != 1 and current_user in role.admins:
        flash("You cannot delete a role you are currently assigned to.", "danger")
        return redirect(url_for('dashboard.settings_roles'))
    
    if role.admins:
        flash(f"Cannot delete role '{role.name}' as it is currently assigned to one or more admins.", "danger")
        return redirect(url_for('dashboard.settings_roles'))
    
    db.session.delete(role)
    db.session.commit()
    flash(f"Role '{role.name}' deleted.", "success")
    return redirect(url_for('dashboard.settings_roles'))

@bp.route('/settings/admins/edit/<int:admin_id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_admin')
def edit_admin(admin_id):
    admin = AdminAccount.query.get_or_404(admin_id)

    if admin.id == 1:
        flash("The primary admin's roles and permissions cannot be edited.", "warning")
        return redirect(url_for('dashboard.settings_admins'))
    
    if admin_id == current_user.id:
        flash("To manage your own account, please use the 'My Account' page.", "info")
        return redirect(url_for('dashboard.settings_account'))
        
    form = AdminEditForm(obj=admin)
    form.roles.choices = [(r.id, r.name) for r in Role.query.order_by('name')]

    if form.validate_on_submit():
        admin.roles = Role.query.filter(Role.id.in_(form.roles.data)).all()
        db.session.commit()
        flash(f"Roles for '{admin.username or admin.plex_username}' updated.", "success")
        return redirect(url_for('dashboard.settings_admins'))
        
    if request.method == 'GET':
        form.roles.data = [r.id for r in admin.roles]

    return render_template(
        'admins/edit.html',
        title="Edit Admin",
        admin=admin,
        form=form,
        active_tab='admins'
    )

@bp.route('/settings/admins/reset_password/<int:admin_id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_admin')
def reset_admin_password(admin_id):
    admin = AdminAccount.query.get_or_404(admin_id)
    if admin.id == 1 or admin.id == current_user.id:
        flash("You cannot reset the password for the primary admin or yourself.", "danger")
        return redirect(url_for('dashboard.edit_admin', admin_id=admin_id))
    
    form = AdminResetPasswordForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            admin.set_password(form.new_password.data)
            admin.force_password_change = True # Force change on next login
            db.session.commit()
            
            log_event(EventType.ADMIN_PASSWORD_CHANGE, f"Password was reset for admin '{admin.username}'.", admin_id=current_user.id)
            toast = {"showToastEvent": {"message": "Password has been reset.", "category": "success"}}
            response = make_response("", 204)
            response.headers['HX-Trigger'] = json.dumps(toast)
            return response
        else:
            # Re-render form with validation errors for HTMX
            return render_template('admins/_reset_password_modal.html', form=form, admin=admin), 422
    
    # For GET request, just render the form
    return render_template('admins/_reset_password_modal.html', form=form, admin=admin)

@bp.route('/libraries')
@login_required
@setup_required
# Optional: Add a new permission check here if desired
# @permission_required('view_libraries')
def libraries():
    library_data = plex_service.get_library_details()
    return render_template(
        'libraries/index.html',
        title="Libraries",
        libraries=library_data
    )

@bp.route('/settings/logs')
@login_required
@setup_required
@permission_required('view_logs') # Renamed permission
def settings_logs():
    # This route now just renders the main settings layout.
    # The content will be loaded via the partial included in settings/index.html
    return render_template('settings/index.html', 
                           title="Application Logs", 
                           active_tab='logs')

@bp.route('/settings/logs/partial')
@login_required
@setup_required
@permission_required('view_logs') # Renamed permission
def settings_logs_partial():
    page = request.args.get('page', 1, type=int)
    session_per_page_key = 'logs_list_per_page' # New session key
    default_per_page = int(current_app.config.get('DEFAULT_HISTORY_PER_PAGE', 20)) # Can keep old config name
    
    per_page_from_request = request.args.get('per_page', type=int)
    if per_page_from_request and per_page_from_request in [20, 50, 100, 200]:
        items_per_page = per_page_from_request
        session[session_per_page_key] = items_per_page
    else:
        items_per_page = session.get(session_per_page_key, default_per_page)
        if items_per_page not in [20, 50, 100, 200]:
            items_per_page = default_per_page
            session[session_per_page_key] = items_per_page

    query = _get_history_logs_query() # This helper function can be reused as is
    logs = query.order_by(HistoryLog.timestamp.desc()).paginate(page=page, per_page=items_per_page, error_out=False)
    event_types = list(EventType) 
    
    # This now renders the new partial for the log list content
    return render_template('settings/_logs_list_content.html', 
                           logs=logs, 
                           event_types=event_types,
                           current_per_page=items_per_page)