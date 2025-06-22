# File: app/routes/dashboard.py
from flask import (
    Blueprint, render_template, redirect, url_for, 
    flash, request, current_app, jsonify, g, make_response, session
)
from flask_login import login_required, current_user, logout_user 
import secrets
from app.models import User, Invite, HistoryLog, Setting, EventType, SettingValueType, AdminAccount
from app.forms import (
    GeneralSettingsForm, PlexSettingsForm, DiscordConfigForm
    # If you create an AdvancedSettingsForm, import it here too.
)
from app.extensions import db, scheduler # For db.func.now() if used, or db specific types
from app.utils.helpers import log_event, setup_required 
# No direct plexapi imports here, plex_service should handle that.
from app.services import plex_service, history_service
import json
from urllib.parse import urlparse

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

@bp.route('/history') # Main route for full page load
@login_required
@setup_required
def history():
    page = request.args.get('page', 1, type=int)
    session_per_page_key = 'history_list_per_page'
    default_per_page = int(current_app.config.get('DEFAULT_HISTORY_PER_PAGE', 20))
    per_page_from_request = request.args.get('per_page', type=int)

    if per_page_from_request and per_page_from_request in [20, 50, 100, 200]:
        items_per_page = per_page_from_request
        session[session_per_page_key] = items_per_page
    else:
        items_per_page = session.get(session_per_page_key, default_per_page)
        if items_per_page not in [20, 50, 100, 200]:
            items_per_page = default_per_page
            session[session_per_page_key] = items_per_page
            
    # Query logic is now part of _get_history_logs_query
    query = _get_history_logs_query()
    logs = query.order_by(HistoryLog.timestamp.desc()).paginate(page=page, per_page=items_per_page, error_out=False)
    event_types = list(EventType) 

    return render_template('history/index.html', 
                           title="Event History", 
                           logs=logs, 
                           event_types=event_types,
                           current_per_page=items_per_page)

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

@bp.route('/history/partial') # Route for HTMX partial updates
@login_required
@setup_required
def history_partial():
    page = request.args.get('page', 1, type=int)
    session_per_page_key = 'history_list_per_page'
    default_per_page = int(current_app.config.get('DEFAULT_HISTORY_PER_PAGE', 20))
    
    items_per_page_from_arg = request.args.get('per_page', type=int)
    if items_per_page_from_arg and items_per_page_from_arg in [20, 50, 100, 200]:
        items_per_page = items_per_page_from_arg
        # session[session_per_page_key] = items_per_page # Already set by main route if changed via dropdown
    else:
        items_per_page = session.get(session_per_page_key, default_per_page)

    query = _get_history_logs_query() # Use helper to build query based on current request.args
    logs = query.order_by(HistoryLog.timestamp.desc()).paginate(page=page, per_page=items_per_page, error_out=False)
    
    # event_types are not strictly needed by the partial if filters are outside the swapped area,
    # but good to pass if the partial template might use it.
    # event_types = list(EventType) 

    return render_template('history/_history_list_content.html', 
                           logs=logs,
                           # event_types=event_types, # Only if _history_list_content.html needs it
                           current_per_page=items_per_page)


@bp.route('/settings', methods=['GET']) 
@bp.route('/settings/general', methods=['GET', 'POST'])
@login_required
@setup_required
def settings_general():
    form = GeneralSettingsForm()
    if form.validate_on_submit():
        Setting.set('APP_NAME', form.app_name.data, SettingValueType.STRING, "Application Name")
        current_app.config['APP_NAME'] = form.app_name.data
        if hasattr(g, 'app_name'): g.app_name = form.app_name.data 
        log_event(EventType.SETTING_CHANGE, "General settings updated.", admin_id=current_user.id)
        flash('General settings saved successfully.', 'success'); return redirect(url_for('dashboard.settings_general'))
    elif request.method == 'GET':
        form.app_name.data = Setting.get('APP_NAME', current_app.config.get('APP_NAME'))
    return render_template('settings/index.html', title="General Settings", form=form, active_tab='general')

@bp.route('/settings/plex', methods=['GET', 'POST'])
@login_required
@setup_required
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
@setup_required # Assuming this decorator is correctly defined and used
def settings_discord():
    form = DiscordConfigForm(request.form if request.method == 'POST' else None)
    
    app_base_url = Setting.get('APP_BASE_URL')
    # Generate redirect URIs safely, providing placeholder text if app_base_url is not set
    discord_invite_redirect_uri = url_for('invites.discord_oauth_callback', _external=True) if app_base_url else "App Base URL not set (needed for URI)"
    discord_admin_link_redirect_uri = url_for('auth.discord_callback_admin', _external=True) if app_base_url else "App Base URL not set (needed for URI)"
    
    discord_admin_linked = bool(current_user.discord_user_id)
    discord_admin_user_info = {
        'username': current_user.discord_username, 
        'id': current_user.discord_user_id, 
        'avatar': current_user.discord_avatar_hash 
    } if discord_admin_linked else None
    
    # This is for the visibility of the "Admin Account Link" section based on *saved* DISCORD_OAUTH_ENABLED
    initial_oauth_enabled_for_admin_link_section = Setting.get_bool('DISCORD_OAUTH_ENABLED', False)

    if request.method == 'POST':
        if form.validate_on_submit():
            # Get values from form
            enable_oauth_from_form = form.enable_discord_oauth.data
            enable_bot_from_form = form.enable_discord_bot.data

            # --- Determine final state of DISCORD_OAUTH_ENABLED ---
            final_enable_oauth = enable_oauth_from_form
            if enable_bot_from_form and not enable_oauth_from_form:
                final_enable_oauth = True # Force OAuth ON if bot is ON
                flash("Discord OAuth (Section 1) was automatically enabled because Bot Features are active.", "info")
            
            Setting.set('DISCORD_OAUTH_ENABLED', final_enable_oauth, SettingValueType.BOOLEAN)
            current_app.config['DISCORD_OAUTH_ENABLED'] = final_enable_oauth
            if hasattr(g, 'discord_oauth_enabled_for_invite'):
                g.discord_oauth_enabled_for_invite = final_enable_oauth

            # --- Save OAuth Credentials and "Require SSO" toggle ---
            if final_enable_oauth:
                Setting.set('DISCORD_CLIENT_ID', form.discord_client_id.data or Setting.get('DISCORD_CLIENT_ID', ""), SettingValueType.STRING)
                if form.discord_client_secret.data: 
                    Setting.set('DISCORD_CLIENT_SECRET', form.discord_client_secret.data, SettingValueType.SECRET)
                Setting.set('DISCORD_OAUTH_AUTH_URL', form.discord_oauth_auth_url.data or Setting.get('DISCORD_OAUTH_AUTH_URL', ""), SettingValueType.STRING)
                Setting.set('DISCORD_REDIRECT_URI_INVITE', discord_invite_redirect_uri, SettingValueType.STRING)
                Setting.set('DISCORD_REDIRECT_URI_ADMIN_LINK', discord_admin_link_redirect_uri, SettingValueType.STRING)

                # Save "Require SSO on Invite" setting
                if enable_bot_from_form: # If bot is ON, force require_sso to True
                    Setting.set('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', True, SettingValueType.BOOLEAN)
                else: # Bot is OFF, respect form input for require_sso (since OAuth is ON)
                    Setting.set('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', form.discord_bot_require_sso_on_invite.data, SettingValueType.BOOLEAN)
            else: 
                # OAuth is OFF (so bot must also be off, or was just turned off)
                Setting.set('DISCORD_CLIENT_ID', "", SettingValueType.STRING)
                Setting.set('DISCORD_CLIENT_SECRET', "", SettingValueType.SECRET)
                Setting.set('DISCORD_OAUTH_AUTH_URL', "", SettingValueType.STRING)
                Setting.set('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', False, SettingValueType.BOOLEAN) # If OAuth is off, can't require SSO

            # --- Save Bot Settings ---
            Setting.set('DISCORD_BOT_ENABLED', enable_bot_from_form, SettingValueType.BOOLEAN)
            if enable_bot_from_form:
                if form.discord_bot_token.data: Setting.set('DISCORD_BOT_TOKEN', form.discord_bot_token.data, SettingValueType.SECRET)
                Setting.set('DISCORD_GUILD_ID', form.discord_guild_id.data or Setting.get('DISCORD_GUILD_ID', ""), SettingValueType.STRING)
                Setting.set('DISCORD_MONITORED_ROLE_ID', form.discord_monitored_role_id.data or Setting.get('DISCORD_MONITORED_ROLE_ID', ""), SettingValueType.STRING)
                Setting.set('DISCORD_THREAD_CHANNEL_ID', form.discord_thread_channel_id.data or Setting.get('DISCORD_THREAD_CHANNEL_ID', ""), SettingValueType.STRING)
                Setting.set('DISCORD_BOT_LOG_CHANNEL_ID', form.discord_bot_log_channel_id.data or Setting.get('DISCORD_BOT_LOG_CHANNEL_ID', ""), SettingValueType.STRING)
                Setting.set('DISCORD_SERVER_INVITE_URL', form.discord_server_invite_url.data or Setting.get('DISCORD_SERVER_INVITE_URL', ""), SettingValueType.STRING)
                Setting.set('DISCORD_BOT_WHITELIST_SHARERS', form.discord_bot_whitelist_sharers.data, SettingValueType.BOOLEAN)
                log_event(EventType.DISCORD_CONFIG_SAVE, "Discord settings updated (Bot Enabled).", admin_id=current_user.id)
                # TODO: Signal bot to restart/reload config
            else: 
                if form.discord_bot_token.data: # Clear token if provided while disabling
                    Setting.set('DISCORD_BOT_TOKEN', "", SettingValueType.SECRET)
                # Still save whitelist_sharers even if bot is off
                Setting.set('DISCORD_BOT_WHITELIST_SHARERS', form.discord_bot_whitelist_sharers.data, SettingValueType.BOOLEAN)
                log_event(EventType.DISCORD_CONFIG_SAVE, "Discord settings updated (Bot Disabled).", admin_id=current_user.id)
                # TODO: Signal bot to stop

            flash('Discord settings saved successfully.', 'success')
            return redirect(url_for('dashboard.settings_discord'))

    # For GET request or if POST validation failed:
    if request.method == 'GET':
        # Populate OAuth toggle and its dependent fields
        form.enable_discord_oauth.data = initial_oauth_enabled_for_admin_link_section
        if initial_oauth_enabled_for_admin_link_section:
            form.discord_client_id.data = Setting.get('DISCORD_CLIENT_ID')
            form.discord_oauth_auth_url.data = Setting.get('DISCORD_OAUTH_AUTH_URL')
            # Secrets (Client Secret, Bot Token) are not pre-filled

        # Populate Bot toggle and its dependent fields
        is_bot_currently_enabled_in_db = Setting.get_bool('DISCORD_BOT_ENABLED', False)
        form.enable_discord_bot.data = is_bot_currently_enabled_in_db

        if is_bot_currently_enabled_in_db: # Bot is ON
            form.discord_guild_id.data = Setting.get('DISCORD_GUILD_ID')
            form.discord_monitored_role_id.data = Setting.get('DISCORD_MONITORED_ROLE_ID')
            form.discord_thread_channel_id.data = Setting.get('DISCORD_THREAD_CHANNEL_ID')
            form.discord_bot_log_channel_id.data = Setting.get('DISCORD_BOT_LOG_CHANNEL_ID')
            form.discord_server_invite_url.data = Setting.get('DISCORD_SERVER_INVITE_URL')
            form.discord_bot_whitelist_sharers.data = Setting.get_bool('DISCORD_BOT_WHITELIST_SHARERS', False)
            form.discord_bot_require_sso_on_invite.data = True # Forced if bot is ON
        else: # Bot is OFF
            form.discord_bot_whitelist_sharers.data = Setting.get_bool('DISCORD_BOT_WHITELIST_SHARERS', False)
            # If bot is OFF, 'require_sso' depends on its own setting, but only if OAuth is ON
            if initial_oauth_enabled_for_admin_link_section:
                form.discord_bot_require_sso_on_invite.data = Setting.get_bool('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', False)
            else: # OAuth is OFF, so require_sso must be False
                form.discord_bot_require_sso_on_invite.data = False
            
    return render_template('settings/index.html', title="Discord Settings", form=form,
                           active_tab='discord',
                           discord_invite_redirect_uri=discord_invite_redirect_uri,
                           discord_admin_link_redirect_uri=discord_admin_link_redirect_uri,
                           discord_admin_linked=discord_admin_linked,
                           discord_admin_user_info=discord_admin_user_info,
                           initial_discord_enabled_state=initial_oauth_enabled_for_admin_link_section) # For admin link section visibility

@bp.route('/settings/advanced', methods=['GET'])
@login_required
@setup_required
def settings_advanced():
    all_db_settings = Setting.query.order_by(Setting.key).all()
    return render_template('settings/index.html', title="Advanced Settings", active_tab='advanced', all_db_settings=all_db_settings)

@bp.route('/settings/regenerate_secret_key', methods=['POST'])
@login_required
@setup_required
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
    
@bp.route('/history/clear', methods=['POST'])
@login_required
@setup_required
def clear_history_logs_route():
    event_types_selected = request.form.getlist('event_types_to_clear[]')
    clear_all = request.form.get('clear_all_types') == 'true'
    
    current_app.logger.info(f"Dashboard.py - clear_history_logs_route(): Received request to clear logs. Selected types: {event_types_selected}, Clear All: {clear_all}")

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
        current_app.logger.info(f"Dashboard.py - clear_history_logs_route(): {toast_message}")

    except Exception as e:
        current_app.logger.error(f"Dashboard.py - clear_history_logs_route(): Failed to clear history: {e}", exc_info=True)
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
    current_app.logger.debug(f"Dashboard.py - clear_history_logs_route(): Sending HX-Trigger-After-Swap: {response.headers['HX-Trigger-After-Swap']}")

    return response

@bp.route('/streaming')
@login_required
@setup_required
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
                if hasattr(raw_plex_session, '_data') and raw_plex_session._data is not None: # Log raw XML attributes
                   current_app.logger.debug(f"STREAMING_DEBUG:   raw_plex_session._data.attrib: {json.dumps(raw_plex_session._data.attrib if hasattr(raw_plex_session._data, 'attrib') else raw_plex_session._data, indent=2, default=str)}")
                
                progress_value = 0.0
                # ... (Progress calculation with its debug logs as before) ...
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
                # ... (Thumb logic as before) ...
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
                
                video_resolution_final = "N/A"
                if hasattr(raw_plex_session, 'transcodeSession') and raw_plex_session.transcodeSession and getattr(raw_plex_session.transcodeSession, 'videoResolution', None):
                    video_resolution_final = raw_plex_session.transcodeSession.videoResolution
                elif getattr(raw_plex_session, 'videoResolution', None) and getattr(raw_plex_session, 'videoResolution') != "N/A": # Check if it's not already "N/A"
                    video_resolution_final = raw_plex_session.videoResolution
                elif video_stream_info and hasattr(video_stream_info, 'height') and video_stream_info.height:
                    video_resolution_final = f"{video_stream_info.height}p"
                elif video_stream_info and hasattr(video_stream_info, 'width') and video_stream_info.width:
                    video_resolution_final = f"{video_stream_info.width}w"
                # current_app.logger.debug(f"STREAMING_DEBUG (Quality): Final video_resolution_final for quality_desc: '{video_resolution_final}'")
                
                transcode_session_obj = getattr(raw_plex_session, 'transcodeSession', None)
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
                    
                    v_decision = getattr(transcode_session_obj, 'videoDecision', 'unknown').capitalize()
                    src_v_codec = getattr(transcode_session_obj, 'sourceVideoCodec', 'N/A').upper()
                    tgt_v_codec = getattr(transcode_session_obj, 'videoCodec', 'N/A').upper()
                    src_v_res_display = (f"{video_stream_info.height}p" if video_stream_info and hasattr(video_stream_info, 'height') and video_stream_info.height else "N/A")
                    tgt_v_res_display = (f"{transcode_session_obj.videoHeight}p" if hasattr(transcode_session_obj, 'videoHeight') and transcode_session_obj.videoHeight else video_resolution_final)
                    video_text = f"{v_decision} ({src_v_codec} {src_v_res_display} -> {tgt_v_codec} {tgt_v_res_display})"
                    
                    a_decision = getattr(transcode_session_obj, 'audioDecision', 'unknown').capitalize()
                    src_a_codec = getattr(transcode_session_obj, 'sourceAudioCodec', 'N/A').upper()
                    tgt_a_codec = getattr(transcode_session_obj, 'audioCodec', 'N/A').upper()
                    src_a_ch = audio_stream_info.channels if audio_stream_info and hasattr(audio_stream_info, 'channels') else 'N/A'
                    tgt_a_ch = transcode_session_obj.audioChannels if hasattr(transcode_session_obj, 'audioChannels') else 'N/A'
                    audio_lang = (audio_stream_info.displayTitle or audio_stream_info.language) if audio_stream_info and (audio_stream_info.displayTitle or audio_stream_info.language) else ''
                    audio_text = f"{a_decision} ({audio_lang} - {src_a_codec} {src_a_ch}ch -> {tgt_a_codec} {tgt_a_ch}ch)".replace("  - ", " - ").replace("( - ", "(").strip()
                else: 
                    if video_stream_info: video_text = f"Direct Play ({getattr(video_stream_info, 'codec', 'N/A').upper()} {video_resolution_final})"
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
                location_lan_wan = "LAN" if is_lan else "WAN" if location_ip != 'N/A' else "Unknown"

                pum_user_id_for_link = None
                # ... (PUM User ID lookup logic from previous correct version) ...
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