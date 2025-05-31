# app/routes_admin_settings.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from app import db, scheduler # Import scheduler
from app.models import AppSetting, HistoryLog, get_app_setting, update_app_setting, get_all_app_settings
from app.forms import PlexSettingsForm, GeneralAppSettingsForm, DiscordSettingsForm # Removed GlobalWhitelistSettingsForm if unused
from app.plex_utils import test_plex_connection
# from datetime import datetime # Not needed if activity poll interval is removed
import os 

from app.decorators import admin_required

settings_bp = Blueprint('admin_settings', __name__, url_prefix='/settings')

def _get_plex_server_settings_as_dict():
    return {
        'plex_url': get_app_setting('PLEX_URL'),
        'plex_token': get_app_setting('PLEX_TOKEN'),
    }

def _get_general_app_settings_as_dict():
    return {
        'app_base_url': get_app_setting('APP_BASE_URL', request.url_root.rstrip('/')),
        'sync_remove_stale_users': (get_app_setting('SYNC_REMOVE_STALE_USERS', 'false') == 'true'), # Default to 'false' string
        # REMOVED: 'activity_poll_interval_minutes': get_app_setting('ACTIVITY_POLL_INTERVAL_MINUTES', '5')
    }

def _get_discord_settings_as_dict():
    # This function remains the same as your last correct version
    return {
        'discord_oauth_client_id': get_app_setting('DISCORD_OAUTH_CLIENT_ID'),
        'discord_oauth_client_secret': get_app_setting('DISCORD_OAUTH_CLIENT_SECRET'),
        'discord_bot_enabled': (get_app_setting('DISCORD_BOT_ENABLED', 'false') == 'true'),
        'discord_bot_token': get_app_setting('DISCORD_BOT_TOKEN'),
        'discord_server_id': get_app_setting('DISCORD_SERVER_ID'),
        'discord_bot_app_id': get_app_setting('DISCORD_BOT_APP_ID'),
        'admin_discord_id': get_app_setting('ADMIN_DISCORD_ID'),
        'discord_command_channel_id': get_app_setting('DISCORD_COMMAND_CHANNEL_ID'),
        'discord_mention_role_id': get_app_setting('DISCORD_MENTION_ROLE_ID'),
        'discord_plex_access_role_id': get_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID'),
        'discord_bot_user_whitelist': get_app_setting('DISCORD_BOT_USER_WHITELIST')
    }

@settings_bp.route('/', methods=['GET', 'POST'])
@admin_required
def app_settings_page():
    # Determine which form was submitted based on its submit button's name attribute
    plex_server_form_submitted = request.method == 'POST' and plex_form_prefix + '-submit_plex_server_settings' in request.form
    general_app_form_submitted = request.method == 'POST' and general_form_prefix + '-submit_general_app_settings' in request.form
    discord_form_submitted = request.method == 'POST' and discord_form_prefix + '-submit_discord_settings' in request.form

    # Define prefixes for forms
    plex_form_prefix = "plex_server"
    general_form_prefix = "general_app"
    discord_form_prefix = "discord"

    # Instantiate forms
    # If GET, populate with current settings.
    # If POST, populate with request.form if it's the one submitted, otherwise current settings.
    plex_form = PlexSettingsForm(
        request.form if plex_server_form_submitted else None, 
        prefix=plex_form_prefix, 
        data=None if plex_server_form_submitted else _get_plex_server_settings_as_dict()
    )
    general_form = GeneralAppSettingsForm(
        request.form if general_app_form_submitted else None, 
        prefix=general_form_prefix,
        data=None if general_app_form_submitted else _get_general_app_settings_as_dict()
    )
    discord_form = DiscordSettingsForm(
        request.form if discord_form_submitted else None, 
        prefix=discord_form_prefix,
        data=None if discord_form_submitted else _get_discord_settings_as_dict()
    )
    
    form_processed_successfully = False

    if request.method == 'POST':
        if plex_server_form_submitted:
            if plex_form.validate():
                is_valid_conn, message_conn = test_plex_connection(plex_form.plex_url.data.strip(), plex_form.plex_token.data.strip())
                if is_valid_conn:
                    try:
                        update_app_setting('PLEX_URL', plex_form.plex_url.data.strip())
                        update_app_setting('PLEX_TOKEN', plex_form.plex_token.data.strip())
                        flash(f'Plex Server settings updated. Connection: {message_conn}', 'success')
                        HistoryLog.create(event_type="SETTINGS_PLEX_SERVER_UPDATED")
                        # Invalidate Plex server instance cache if you have one
                        from app.plex_utils import _plex_instance # type: ignore 
                        if _plex_instance is not None: _plex_instance = None # type: ignore
                        form_processed_successfully = True
                    except Exception as e: 
                        flash(f'Error saving Plex Server settings: {str(e)[:200]}', 'danger')
                        current_app.logger.error(f"Error saving Plex Server settings: {e}", exc_info=True)
                else: 
                    flash(f'Plex connection failed: {message_conn}. Settings NOT saved.', 'danger')
            # else: Errors will be displayed by the form rendering

        elif general_app_form_submitted:
            if general_form.validate():
                try:
                    update_app_setting('APP_BASE_URL', general_form.app_base_url.data.strip().rstrip('/'))
                    update_app_setting('SYNC_REMOVE_STALE_USERS', 'true' if general_form.sync_remove_stale_users.data else 'false')
                    
                    # REMOVED: Logic for activity_poll_interval_minutes and scheduler job modification
                    # old_interval_setting = get_app_setting('ACTIVITY_POLL_INTERVAL_MINUTES')
                    # new_interval_str = str(general_form.activity_poll_interval_minutes.data).strip()
                    # update_app_setting('ACTIVITY_POLL_INTERVAL_MINUTES', new_interval_str)
                    # if old_interval_setting != new_interval_str:
                    #    # ... (scheduler job update logic was here) ...
                    #    flash(f"Plex activity check interval updated to {new_interval_str} minutes. Changes will take effect based on scheduler's next reload or new job addition.", "info")
                    
                    flash('General Application settings updated successfully.', 'success')
                    HistoryLog.create(event_type="SETTINGS_GENERAL_APP_UPDATED")
                    form_processed_successfully = True
                except Exception as e: 
                    flash(f'Error saving General App settings: {str(e)[:200]}', 'danger')
                    current_app.logger.error(f"Error saving General App settings: {e}", exc_info=True)
            # else: Errors will be displayed by the form rendering

        elif discord_form_submitted:
            if discord_form.validate():
                try:
                    update_app_setting('DISCORD_OAUTH_CLIENT_ID', discord_form.discord_oauth_client_id.data.strip() or "")
                    update_app_setting('DISCORD_OAUTH_CLIENT_SECRET', discord_form.discord_oauth_client_secret.data.strip() or "") # Stored as string
                    
                    bot_enabled_changed = (get_app_setting('DISCORD_BOT_ENABLED', 'false') == 'true') != discord_form.discord_bot_enabled.data
                    update_app_setting('DISCORD_BOT_ENABLED', 'true' if discord_form.discord_bot_enabled.data else 'false')
                    
                    # Save or clear other bot settings based on discord_bot_enabled
                    bot_settings_fields = ['discord_bot_token', 'discord_server_id', 'discord_bot_app_id', 
                                           'admin_discord_id', 'discord_command_channel_id', 
                                           'discord_mention_role_id', 'discord_plex_access_role_id',
                                           'discord_bot_user_whitelist']
                    
                    if discord_form.discord_bot_enabled.data:
                        for field_name in bot_settings_fields:
                            form_field = getattr(discord_form, field_name)
                            db_key = field_name.upper() # Assuming AppSetting keys are uppercase
                            update_app_setting(db_key, form_field.data.strip() if form_field.data else "")
                    else: # If bot disabled, clear related settings
                        for field_name in bot_settings_fields:
                            update_app_setting(field_name.upper(), "")

                    flash_msg = 'Discord settings updated successfully.'
                    token_validation_msg = getattr(discord_form.discord_bot_token, 'description', None)
                    if discord_form.discord_bot_enabled.data and token_validation_msg:
                        flash_msg += f" Bot Token: {token_validation_msg}"
                    if bot_enabled_changed:
                        flash_msg += " Application restart might be needed for Discord Bot changes to fully take effect."
                    flash(flash_msg, 'success')
                    HistoryLog.create(event_type="SETTINGS_DISCORD_UPDATED", details=f"Bot Enabled: {discord_form.discord_bot_enabled.data}")
                    form_processed_successfully = True
                except Exception as e: 
                    flash(f'Error saving Discord settings: {str(e)[:200]}', 'danger')
                    current_app.logger.error(f"Error saving Discord settings: {e}", exc_info=True)
            # else: Errors will be displayed by the form rendering

        if form_processed_successfully:
            return redirect(url_for('admin_settings.app_settings_page'))
        # If any form submission failed validation, we fall through to render the template
        # The forms will retain their submitted data and errors.
        # We need to ensure non-submitted forms are re-populated with DB values if one form fails.
        if plex_server_form_submitted and plex_form.errors:
            if not general_app_form_submitted: general_form.process(data=_get_general_app_settings_as_dict())
            if not discord_form_submitted: discord_form.process(data=_get_discord_settings_as_dict())
        elif general_app_form_submitted and general_form.errors:
            if not plex_server_form_submitted: plex_form.process(data=_get_plex_server_settings_as_dict())
            if not discord_form_submitted: discord_form.process(data=_get_discord_settings_as_dict())
        elif discord_form_submitted and discord_form.errors:
            if not plex_server_form_submitted: plex_form.process(data=_get_plex_server_settings_as_dict())
            if not general_app_form_submitted: general_form.process(data=_get_general_app_settings_as_dict())


    # For GET request, forms are already populated using 'data=' argument during instantiation
    
    # REMOVED: scheduler_status_in_worker and activity_job_status_active logic
    all_db_settings = get_all_app_settings()
    # Define known settings and their typical defaults for display completeness
    known_settings_with_defaults = {
        'PLEX_URL': None, 'PLEX_TOKEN': None, 
        'APP_BASE_URL': request.url_root.rstrip('/'), 
        'SYNC_REMOVE_STALE_USERS': 'false', 
        # 'ACTIVITY_POLL_INTERVAL_MINUTES': '5', # Removed
        'PLEX_API_TIMEOUT': '15', 
        'DISCORD_OAUTH_CLIENT_ID': None, 'DISCORD_OAUTH_CLIENT_SECRET': None, 
        'DISCORD_BOT_ENABLED': 'false', 'DISCORD_BOT_TOKEN': None, 'DISCORD_SERVER_ID': None, 
        'DISCORD_BOT_APP_ID': None, 'ADMIN_DISCORD_ID': None, 'DISCORD_COMMAND_CHANNEL_ID': None, 
        'DISCORD_MENTION_ROLE_ID': None, 'DISCORD_PLEX_ACCESS_ROLE_ID': None, 
        'DISCORD_BOT_USER_WHITELIST': None, 'BOT_INVITE_EXPIRY_HOURS': '24', 
        'APP_NAME': 'Plex User Manager', 'SECRET_KEY': None, 'ITEMS_PER_PAGE': '25', 
        'HISTORY_LOG_RETENTION_DAYS': '90', 'SETUP_COMPLETED': 'false',
        'PLEX_CLIENT_IDENTIFIER': None, 'APP_VERSION': '1.0.0'
    }
    # Merge DB settings with known keys to ensure all are present for display
    final_display_settings = {k: all_db_settings.get(k, v) for k, v in known_settings_with_defaults.items()}
    for db_key, db_value in all_db_settings.items(): # Add any extra settings from DB not in known_settings
        if db_key not in final_display_settings: final_display_settings[db_key] = db_value


    return render_template('admin/settings.html', title='Application Settings',
                           plex_form=plex_form, 
                           general_form=general_form,
                           discord_form=discord_form,
                           current_settings=final_display_settings) # Removed scheduler status vars


@settings_bp.route('/history')
@admin_required
def view_history():
    page = request.args.get('page', 1, type=int)
    try:
        per_page_setting = get_app_setting('ITEMS_PER_PAGE', '25')
        per_page = int(per_page_setting)
        if per_page <= 0: per_page = 25
    except ValueError:
        per_page = 25
    logs_pagination = HistoryLog.query.order_by(HistoryLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('admin/history.html', title='Activity History', logs_pagination=logs_pagination)