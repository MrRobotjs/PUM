# File: app/routes/invites.py
import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session, g, make_response
from markupsafe import Markup # Import Markup from markupsafefrom flask_login import login_required, current_user 
from datetime import datetime 
from urllib.parse import urlencode, quote as url_quote, urlparse, parse_qs, urlunparse 
import requests 
import xml.etree.ElementTree as ET 
from plexapi.myplex import MyPlexAccount 
from app.models import Invite, Setting, EventType, User, InviteUsage, AdminAccount, SettingValueType 
from app.forms import InviteCreateForm 
from app.extensions import db
from app.utils.helpers import log_event, setup_required, calculate_expiry_date
from app.services import plex_service, user_service, invite_service 
import json
from flask_login import login_required, current_user # <<< MAKE SURE login_required IS HERE

bp = Blueprint('invites', __name__)

PLEX_API_V2_PINS_URL = "https://plex.tv/api/v2/pins"
PLEX_CHECK_PIN_URL_TEMPLATE = "https://plex.tv/api/v2/pins/{pin_id}"
PLEX_AUTH_APP_URL_BASE = "https://app.plex.tv/auth/"
DISCORD_API_BASE_URL = 'https://discord.com/api/v10' 

def _get_plex_sso_headers(client_identifier_suffix="Invite", product_name_override=None, client_id_override=None):
    base_client_id = client_id_override or Setting.get('PLEX_APP_CLIENT_IDENTIFIER') or current_app.config.get('PLEX_APP_CLIENT_IDENTIFIER_FALLBACK', "PUM-Default-" + str(uuid.uuid4())[:8])
    final_client_id = f"{base_client_id}-{client_identifier_suffix}"
    app_name = product_name_override or Setting.get('APP_NAME', current_app.config.get('APP_NAME', "Plex User Manager"))
    app_version = current_app.config.get('APP_VERSION', '1.0.0')
    headers = {
        'X-Plex-Product': app_name, 'X-Plex-Version': app_version,
        'X-Plex-Client-Identifier': final_client_id, 'X-Plex-Device': "Application",
        'X-Plex-Device-Name': f"{app_name} ({client_identifier_suffix})", 'X-Plex-Platform': "Web", 'Accept': 'application/xml'}
    return headers

@bp.route('/manage') 
@login_required
@setup_required
def list_invites():
    page = request.args.get('page', 1, type=int)
    items_per_page_setting = Setting.get('DEFAULT_INVITES_PER_PAGE', current_app.config.get('DEFAULT_INVITES_PER_PAGE', 10))
    items_per_page = int(items_per_page_setting) if items_per_page_setting else 10
    
    query = Invite.query
    filter_status = request.args.get('filter', 'all'); search_path = request.args.get('search_path', '').strip()
    if search_path: query = query.filter(Invite.custom_path.ilike(f"%{search_path}%"))
    now = datetime.utcnow() 
    if filter_status == 'active': query = query.filter(Invite.is_active == True, (Invite.expires_at == None) | (Invite.expires_at > now), (Invite.max_uses == None) | (Invite.current_uses < Invite.max_uses))
    elif filter_status == 'expired': query = query.filter(Invite.expires_at != None, Invite.expires_at <= now)
    elif filter_status == 'maxed': query = query.filter(Invite.max_uses != None, Invite.current_uses >= Invite.max_uses)
    elif filter_status == 'inactive': query = query.filter(Invite.is_active == False)
    
    invites_pagination = query.order_by(Invite.created_at.desc()).paginate(page=page, per_page=items_per_page, error_out=False)
    invites_count = query.count() # Get count after filtering
    
    form = InviteCreateForm()
    available_libraries = plex_service.get_plex_libraries_dict()
    form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]
    if form.libraries.data is None: form.libraries.data = [] 
    
    return render_template('invites/list.html', title="Manage Invites", invites=invites_pagination, invites_count=invites_count, form=form, available_libraries=available_libraries, current_per_page=items_per_page)

@bp.route('/manage/create', methods=['POST'])
@login_required
@setup_required
def create_invite():
    form = InviteCreateForm()
    available_libraries = plex_service.get_plex_libraries_dict()
    form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]
    
    if request.method == 'POST' and not form.libraries.data and 'libraries' in request.form:
         form.libraries.data = request.form.getlist('libraries')

    toast_message_text = ""
    toast_category = "info"

    if form.validate_on_submit():
        custom_path = form.custom_path.data.strip() if form.custom_path.data else None
        if custom_path:
            existing_invite = Invite.query.filter(Invite.custom_path == custom_path, Invite.is_active == True).first()
            if existing_invite and existing_invite.is_usable:
                error_msg = f"An active and usable invite with the custom path '{custom_path}' already exists."
                form.custom_path.errors.append(error_msg)
                if request.headers.get('HX-Request'):
                    return render_template('invites/_create_invite_modal_form_content.html', form=form, available_libraries=available_libraries), 422
                flash(error_msg, "danger")
                return redirect(url_for('invites.list_invites'))

        expires_at = calculate_expiry_date(form.expires_in_days.data)
        max_uses = form.number_of_uses.data if form.number_of_uses.data and form.number_of_uses.data > 0 else None

        membership_duration = form.membership_duration_days.data
        if membership_duration is not None and membership_duration <= 0: # Ensure positive if set
            membership_duration = None 
        
        new_invite = Invite(
            custom_path=custom_path, expires_at=expires_at, max_uses=max_uses,
            grant_library_ids=form.libraries.data or [], allow_downloads=form.allow_downloads.data,
            membership_duration_days=membership_duration, created_by_admin_id=current_user.id
        )
        try:
            db.session.add(new_invite); db.session.commit()
            invite_url = new_invite.get_full_url(g.app_base_url or request.url_root.rstrip('/'))
            log_msg_details = f"Downloads: {'Enabled' if new_invite.allow_downloads else 'Disabled'}."
            if new_invite.membership_duration_days:
                log_msg_details += f" Membership: {new_invite.membership_duration_days} days."
            else:
                log_msg_details += " Membership: Permanent."
                
            log_event(EventType.INVITE_CREATED, 
                      f"Invite created: Path='{custom_path or new_invite.token}'. {log_msg_details} URL: {invite_url}", 
                      invite_id=new_invite.id, 
                      admin_id=current_user.id)
            toast_message_text = f"Invite link created successfully!"; toast_category = "success"
            if request.headers.get('HX-Request'):
                response = make_response(""); response.status_code = 204 
                trigger_payload = {"refreshInvitesList": True, "showToastEvent": {"message": toast_message_text, "category": toast_category}}
                response.headers['HX-Trigger-After-Swap'] = json.dumps(trigger_payload)
                return response
            flash(f"Invite link created: {invite_url}", toast_category) 
            return redirect(url_for('invites.list_invites'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating invite in DB: {e}", exc_info=True)
            toast_message_text = f"Error creating invite: {str(e)[:100]}"; toast_category = "danger"
            if request.headers.get('HX-Request'):
                response = make_response("Error saving invite to database.", 500) 
                trigger_payload = {"showToastEvent": {"message": toast_message_text, "category": toast_category}}
                response.headers['HX-Trigger-After-Swap'] = json.dumps(trigger_payload)
                return response
            flash(toast_message_text, toast_category)
            return redirect(url_for('invites.list_invites'))
    else: 
        if request.headers.get('HX-Request'):
            return render_template('invites/_create_invite_modal_form_content.html', form=form, available_libraries=available_libraries), 422
        for field, errors_list in form.errors.items():
            for error in errors_list: flash(f"Error in {getattr(form, field).label.text}: {error}", "danger")
        return redirect(url_for('invites.list_invites'))

@bp.route('/manage/list_partial') 
@login_required
@setup_required
def list_invites_partial():
    page = request.args.get('page', 1, type=int)
    session_per_page_key = 'invites_list_per_page'
    default_per_page_setting = Setting.get('DEFAULT_INVITES_PER_PAGE', current_app.config.get('DEFAULT_INVITES_PER_PAGE', 10))
    default_per_page = int(default_per_page_setting) if default_per_page_setting else 10
    
    items_per_page_from_arg = request.args.get('per_page', type=int)
    if items_per_page_from_arg and items_per_page_from_arg in [10, 25, 50, 100]:
        items_per_page = items_per_page_from_arg
        session[session_per_page_key] = items_per_page # Update session if user explicitly changes it
    else:
        items_per_page = session.get(session_per_page_key, default_per_page)
        if items_per_page not in [10, 25, 50, 100]: items_per_page = default_per_page # Fallback

    query = Invite.query
    filter_status = request.args.get('filter', 'all'); search_path = request.args.get('search_path', '').strip()
    if search_path: query = query.filter(Invite.custom_path.ilike(f"%{search_path}%"))
    now = datetime.utcnow() 
    if filter_status == 'active': query = query.filter(Invite.is_active == True, (Invite.expires_at == None) | (Invite.expires_at > now), (Invite.max_uses == None) | (Invite.current_uses < Invite.max_uses))
    # ... (other filters)
    invites_pagination = query.order_by(Invite.created_at.desc()).paginate(page=page, per_page=items_per_page, error_out=False)
    available_libraries = plex_service.get_plex_libraries_dict()
    return render_template('invites/_invites_table_and_pagination.html', invites=invites_pagination, available_libraries=available_libraries, current_per_page=items_per_page)

@bp.route('/manage/delete/<int:invite_id>', methods=['DELETE'])
@login_required
@setup_required
def delete_invite(invite_id):
    invite = Invite.query.get_or_404(invite_id)
    path_or_token = invite.custom_path or invite.token # For logging and toast message
    pum_invite_id_for_log = invite.id # Store before deletion

    try:
        db.session.delete(invite)
        db.session.commit()
        
        log_event(EventType.INVITE_DELETED, 
                  f"Invite '{path_or_token}' deleted.", 
                  invite_id=pum_invite_id_for_log, # Use the stored ID for log
                  admin_id=current_user.id)
        
        toast_message = f"Invite '{path_or_token}' deleted successfully."
        toast_category = "success"
        
        # Prepare headers for HTMX response
        headers = {}
        trigger_payload = {
            "showToastEvent": {"message": toast_message, "category": toast_category},
            # "refreshInvitesList": True # This will be triggered by the swap on the row itself if list needs full refresh
                                         # Or, if removing the row isn't enough and you want the whole list to re-fetch pagination etc.
                                         # For now, let's assume row removal is sufficient immediate feedback.
                                         # If pagination needs update, the list container should also listen for a specific event
                                         # or be triggered by the successful deletion.
                                         # Let's keep it simple: the row is removed, toast is shown.
                                         # If the count on the page title needs updating, that requires refreshing more.
                                         # For full refresh including count:
            "refreshInvitesList": True 
        }
        headers['HX-Trigger'] = json.dumps(trigger_payload)
        
        # HTMX will remove the row based on hx-target and hx-swap="outerHTML".
        # We return an empty response with a 200 OK, and the headers do the work.
        current_app.logger.info(f"Invite '{path_or_token}' deleted. Sending HX-Trigger: {headers['HX-Trigger']}")
        return make_response("", 200, headers)

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting invite '{path_or_token}': {e}", exc_info=True)
        log_event(EventType.ERROR_GENERAL, 
                  f"Error deleting invite '{path_or_token}': {str(e)}", 
                  invite_id=pum_invite_id_for_log, 
                  admin_id=current_user.id)
        
        toast_message = f"Error deleting invite '{path_or_token}'. Please try again."
        toast_category = "error"
        headers = {}
        trigger_payload = {
            "showToastEvent": {"message": toast_message, "category": toast_category}
            # Optionally, still trigger a list refresh to ensure UI consistency on error
            # "refreshInvitesList": True 
        }
        headers['HX-Trigger'] = json.dumps(trigger_payload)
        
        # Return an error status that HTMX can interpret as a failure for the swap,
        # but still send the toast.
        # A 200 with an error toast is also fine, as the swap won't happen on error if hx-swap handles errors.
        # For simplicity, let's still return 200 but the toast indicates error.
        # The hx-target on the button for row removal will still try to happen unless swap specifies otherwise for errors.
        # Since the row might not be deleted on error, let's not rely on outerHTML swap for error feedback.
        # It's better to just show the toast.
        return make_response("", 200, headers) # Still 200, toast will show error

@bp.route('/manage/usages/<int:invite_id>', methods=['GET'])
@login_required
@setup_required
def view_invite_usages(invite_id):
    invite = Invite.query.get_or_404(invite_id)
    usages = InviteUsage.query.filter_by(invite_id=invite.id).order_by(InviteUsage.used_at.desc()).all()
    return render_template('invites/_invite_usages_modal_content.html', invite=invite, usages=usages)

@bp.route('/invite/<invite_path_or_token>', methods=['GET', 'POST'])
@setup_required 
def process_invite_form(invite_path_or_token):
    from flask_wtf import FlaskForm # Local import for this simple form
    
    invite, error = invite_service.validate_invite_usability(invite_path_or_token)
    
    if request.method == 'GET' and not error and invite:
        log_event(EventType.INVITE_VIEWED, f"Invite '{invite.custom_path or invite.token}' (ID: {invite.id}) viewed/accessed.", invite_id=invite.id)

    if error: 
        return render_template('invites/public_invite.html', error=error, invite=None, form=FlaskForm())

    form = FlaskForm() 
    already_authenticated_plex_user_info = session.get(f'invite_{invite.id}_plex_user')
    already_authenticated_discord_user_info = session.get(f'invite_{invite.id}_discord_user')
    
    # --- Determine if Discord SSO is available and/or mandatory ---
    oauth_is_generally_enabled_setting = Setting.get('DISCORD_OAUTH_ENABLED', False)
    oauth_is_generally_enabled = oauth_is_generally_enabled_setting if isinstance(oauth_is_generally_enabled_setting, bool) else str(oauth_is_generally_enabled_setting).lower() == 'true'

    bot_is_enabled_setting = Setting.get('DISCORD_BOT_ENABLED', False)
    bot_is_enabled = bot_is_enabled_setting if isinstance(bot_is_enabled_setting, bool) else str(bot_is_enabled_setting).lower() == 'true'

    discord_sso_is_mandatory = False
    if oauth_is_generally_enabled: # Only consider mandatory if OAuth itself is enabled
        if bot_is_enabled: 
            discord_sso_is_mandatory = True # Bot ON (and OAuth ON) forces SSO to be mandatory
        else: 
            # Bot is OFF, so respect the DISCORD_BOT_REQUIRE_SSO_ON_INVITE setting
            require_sso_when_bot_off_setting = Setting.get('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', False) 
            discord_sso_is_mandatory = require_sso_when_bot_off_setting if isinstance(require_sso_when_bot_off_setting, bool) else str(require_sso_when_bot_off_setting).lower() == 'true'
    
    show_discord_button = oauth_is_generally_enabled # Show Discord button if OAuth is generally available
    # --- End Discord SSO determination ---
    current_app.logger.info(f"Public Invite '{invite_path_or_token}': OAuthGenEnable={oauth_is_generally_enabled}, BotEnable={bot_is_enabled}, MandatorySSO={discord_sso_is_mandatory}, ShowDiscordBtn={show_discord_button}")


    if request.method == 'POST':
        auth_method = request.form.get('auth_method')
        action_taken = request.form.get('action') 

        if auth_method == 'plex':
            session['plex_oauth_invite_id'] = invite.id 
            headers = _get_plex_sso_headers(client_identifier_suffix="InvitePlexLink-" + str(invite.id)[:8])
            plex_client_id_used = headers['X-Plex-Client-Identifier']
            try:
                pin_request_url = f"{PLEX_API_V2_PINS_URL}?strong=true"; response = requests.post(pin_request_url, headers=headers, timeout=10); response.raise_for_status(); pin_data_xml_root = ET.fromstring(response.content); pin_code = pin_data_xml_root.get('code'); pin_id = pin_data_xml_root.get('id')
                if not pin_code or not pin_id: raise Exception("Could not get PIN details from Plex.")
                session['plex_pin_id_invite_flow'] = pin_id; session['plex_pin_code_invite_flow'] = pin_code; session['plex_client_id_for_pin_check_invite_flow'] = plex_client_id_used
                app_base_url = Setting.get('APP_BASE_URL', request.url_root.rstrip('/')); callback_path_segment = url_for('invites.plex_oauth_callback', _external=False); forward_url_to_our_app = f"{app_base_url.rstrip('/')}{callback_path_segment}"
                auth_app_params = {'clientID': plex_client_id_used, 'code': pin_code, 'forwardUrl': forward_url_to_our_app, 'context[device][product]': headers.get('X-Plex-Product'), 'context[device][deviceName]': headers.get('X-Plex-Device-Name'), 'context[device][platform]': headers.get('X-Plex-Platform')}
                auth_url_for_user_to_visit = f"{PLEX_AUTH_APP_URL_BASE}#?{urlencode(auth_app_params, quote_via=url_quote)}"
                return redirect(auth_url_for_user_to_visit)
            except Exception as e: flash(f"Could not initiate Plex login: {str(e)[:150]}", "danger"); log_event(EventType.ERROR_PLEX_API, f"Invite {invite.id}: Plex PIN init failed: {e}", invite_id=invite.id)
        
        elif auth_method == 'discord':
            if not show_discord_button: flash("Discord login is not currently available.", "warning") # Should not happen if button isn't shown
            else:
                admin_provided_oauth_url = Setting.get('DISCORD_OAUTH_AUTH_URL')
                client_id_from_settings = Setting.get('DISCORD_CLIENT_ID')
                if admin_provided_oauth_url and client_id_from_settings: # If admin provided full URL
                    session['discord_oauth_invite_id'] = invite.id; session['discord_oauth_state_invite'] = str(uuid.uuid4())
                    parsed_url = urlparse(admin_provided_oauth_url); query_params = parse_qs(parsed_url.query)
                    query_params['state'] = [session['discord_oauth_state_invite']] 
                    expected_redirect_uri = Setting.get('DISCORD_REDIRECT_URI_INVITE') or url_for('invites.discord_oauth_callback', _external=True)
                    if 'redirect_uri' not in query_params or query_params.get('redirect_uri', [''])[0] != expected_redirect_uri:
                         query_params['redirect_uri'] = [expected_redirect_uri]
                    final_query_string = urlencode(query_params, doseq=True)
                    final_discord_auth_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, final_query_string, parsed_url.fragment))
                    return redirect(final_discord_auth_url)
                elif client_id_from_settings: # Construct URL if only client ID is set (fallback)
                    session['discord_oauth_invite_id'] = invite.id; session['discord_oauth_state_invite'] = str(uuid.uuid4())
                    redirect_uri = Setting.get('DISCORD_REDIRECT_URI_INVITE') or url_for('invites.discord_oauth_callback', _external=True)
                    required_scopes = "identify email guilds"; params = {'client_id': client_id_from_settings, 'redirect_uri': redirect_uri, 'response_type': 'code', 'scope': required_scopes, 'state': session['discord_oauth_state_invite']}
                    discord_auth_url = f"{DISCORD_API_BASE_URL}/oauth2/authorize?{urlencode(params)}"; return redirect(discord_auth_url)
                else: flash("Discord integration is not properly configured by admin.", "danger")

        elif action_taken == 'accept_invite':
            if not already_authenticated_plex_user_info: flash("Sign in with Plex first.", "warning")
            elif discord_sso_is_mandatory and not already_authenticated_discord_user_info: flash("Discord login is required for this invite.", "warning")
            else:
                # Guild membership check (if bot enabled)
                if bot_is_enabled and already_authenticated_discord_user_info: # Assumes oauth_is_generally_enabled is true too
                    # Placeholder for discord_service.is_user_in_guild (requires bot to be running and configured)
                    is_member = True # TODO: Replace with actual check: discord_service.is_user_in_guild(already_authenticated_discord_user_info['id'])
                    if not is_member:
                        server_invite_url = Setting.get('DISCORD_SERVER_INVITE_URL'); msg = "You must be a member of our Discord server to accept this Plex invite."
                        if server_invite_url: msg += f" Please join here: <a href='{server_invite_url}' target='_blank' class='link link-accent'>{server_invite_url}</a>, then try again."
                        else: msg += " Please contact an admin for an invite to the Discord server."
                        flash(Markup(msg), "warning")
                        # Re-render the page without processing the invite acceptance
                        return render_template('invites/public_invite.html', form=form, invite=invite, error=None, invite_path_or_token=invite_path_or_token, discord_oauth_enabled=oauth_is_generally_enabled, discord_sso_is_mandatory=discord_sso_is_mandatory, show_discord_button=show_discord_button, already_authenticated_plex_user=already_authenticated_plex_user_info, already_authenticated_discord_user=already_authenticated_discord_user_info)
                
                # Proceed with invite acceptance
                success, result_message = invite_service.accept_invite_and_grant_access(
                    invite=invite, plex_user_uuid=already_authenticated_plex_user_info['uuid'], 
                    plex_username=already_authenticated_plex_user_info['username'], 
                    plex_email=already_authenticated_plex_user_info['email'], 
                    plex_thumb=already_authenticated_plex_user_info['thumb'], 
                    discord_user_id=already_authenticated_discord_user_info.get('id') if already_authenticated_discord_user_info else None, 
                    discord_username=already_authenticated_discord_user_info.get('username') if already_authenticated_discord_user_info else None, 
                    discord_avatar_hash=already_authenticated_discord_user_info.get('avatar') if already_authenticated_discord_user_info else None, 
                    ip_address=request.remote_addr
                )
                if success: 
                    session.pop(f'invite_{invite.id}_plex_user', None); session.pop(f'invite_{invite.id}_discord_user', None)
                    flash(f"Welcome, {already_authenticated_plex_user_info['username']}! Access granted.", "success")
                    return redirect(url_for('invites.invite_success', username=already_authenticated_plex_user_info['username']))
                else: 
                    flash(f"Failed to accept invite: {result_message}", "danger")
        
        return redirect(url_for('invites.process_invite_form', invite_path_or_token=invite_path_or_token))

    return render_template('invites/public_invite.html', form=form, invite=invite, error=error, 
                           invite_path_or_token=invite_path_or_token, 
                           discord_oauth_enabled=oauth_is_generally_enabled, # For general UI elements
                           discord_sso_is_mandatory=discord_sso_is_mandatory, # For specific mandatory checks/text
                           show_discord_button=show_discord_button, # To control Discord button visibility
                           already_authenticated_plex_user=already_authenticated_plex_user_info, 
                           already_authenticated_discord_user=already_authenticated_discord_user_info)

@bp.route('/plex_callback') # Path is /invites/plex_callback
@setup_required
def plex_oauth_callback():
    # ... (Plex OAuth callback logic as before - no changes needed here for this feature)
    invite_id = session.get('plex_oauth_invite_id'); pin_id_from_session = session.get('plex_pin_id_invite_flow'); client_id_used_for_pin = session.get('plex_client_id_for_pin_check_invite_flow')
    invite_path_or_token_for_redirect = "error_path" 
    if invite_id: temp_invite_for_redirect = Invite.query.get(invite_id); 
    if temp_invite_for_redirect: invite_path_or_token_for_redirect = temp_invite_for_redirect.custom_path or temp_invite_for_redirect.token
    fallback_redirect = url_for('invites.process_invite_form', invite_path_or_token=invite_path_or_token_for_redirect)
    if not invite_id or not pin_id_from_session or not client_id_used_for_pin:
        flash('Plex login callback invalid. Try invite again.', 'danger'); 
        session.pop('plex_pin_id_invite_flow', None); session.pop('plex_pin_code_invite_flow', None); session.pop('plex_client_id_for_pin_check_invite_flow', None); session.pop('plex_oauth_invite_id', None)
        return redirect(fallback_redirect) 
    invite = Invite.query.get(invite_id)
    if not invite: flash('Invite not found. Try again.', 'danger'); return redirect(url_for('invites.invite_landing_page')) # Use generic landing
    try:
        headers_for_check = {'X-Plex-Client-Identifier': client_id_used_for_pin, 'Accept': 'application/xml'}
        check_pin_url = PLEX_CHECK_PIN_URL_TEMPLATE.format(pin_id=pin_id_from_session)
        response = requests.get(check_pin_url, headers=headers_for_check, timeout=10); response.raise_for_status()
        pin_data_xml_root = ET.fromstring(response.content); plex_auth_token = pin_data_xml_root.get('authToken')
        if not plex_auth_token: flash('Plex PIN not linked or expired.', 'warning'); return redirect(url_for('invites.process_invite_form', invite_path_or_token=invite.custom_path or invite.token))
        plex_account = MyPlexAccount(token=plex_auth_token)
        plex_user_id_int = getattr(plex_account, 'id', None)
        user_uuid_str = str(plex_user_id_int) if plex_user_id_int is not None else None # Or plex_account.uuid if that's preferred for consistency
        
        session[f'invite_{invite.id}_plex_user'] = {
            'id': plex_user_id_int, 
            'uuid': user_uuid_str, 
            'username': getattr(plex_account, 'username', None), 
            'email': getattr(plex_account, 'email', None), 
            'thumb': getattr(plex_account, 'thumb', None)
        }
        log_event(EventType.INVITE_USED_SUCCESS_PLEX, f"Plex auth success for {plex_account.username} on invite {invite.id}.", invite_id=invite.id)
    except requests.exceptions.HTTPError as e_http:
        if e_http.response.status_code == 404: flash('Plex PIN invalid/expired.', 'danger')
        else: flash(f'Plex API error checking PIN: {e_http.response.status_code}.', 'danger')
        log_event(EventType.ERROR_PLEX_API, f"Invite {invite.id}: Plex PIN check HTTPError {e_http.response.status_code}", invite_id=invite.id)
    except ET.ParseError as e_xml: flash("Error parsing PIN check response from Plex.tv.", "danger"); log_event(EventType.ERROR_PLEX_API, f"Invite {invite.id}: Plex PIN check XML ParseError: {e_xml}", invite_id=invite.id)
    except Exception as e: flash(f"Error during Plex login for invite: {str(e)[:150]}", "danger"); log_event(EventType.ERROR_PLEX_API, f"Invite {invite.id}: Plex callback error: {e}", invite_id=invite.id)
    finally: 
        session.pop('plex_pin_id_invite_flow', None); session.pop('plex_pin_code_invite_flow', None); session.pop('plex_client_id_for_pin_check_invite_flow', None); session.pop('plex_oauth_invite_id', None)
    return redirect(url_for('invites.process_invite_form', invite_path_or_token=invite.custom_path or invite.token))

@bp.route('/discord_callback') # Path is /invites/discord_callback
@setup_required
def discord_oauth_callback():
    # ... (Discord OAuth callback logic as before - no changes needed here for this feature)
    invite_id = session.get('discord_oauth_invite_id'); returned_state = request.args.get('state')
    if not invite_id or not returned_state or returned_state != session.pop('discord_oauth_state_invite', None):
        flash('Discord login failed: Invalid session/state.', 'danger'); return redirect(url_for('invites.invite_landing_page'))
    invite = Invite.query.get(invite_id)
    if not invite: flash('Discord login failed: Invite not found.', 'danger'); return redirect(url_for('invites.invite_landing_page'))
    code = request.args.get('code')
    if not code: flash(f'Discord login failed: {request.args.get("error_description", "Auth failed.")}', 'danger'); return redirect(url_for('invites.process_invite_form', invite_path_or_token=invite.custom_path or invite.token))
    client_id = Setting.get('DISCORD_CLIENT_ID'); client_secret = Setting.get('DISCORD_CLIENT_SECRET'); redirect_uri = Setting.get('DISCORD_REDIRECT_URI_INVITE')
    if not client_id or not client_secret or not redirect_uri: flash('Discord not configured by admin.', 'danger'); return redirect(url_for('invites.process_invite_form', invite_path_or_token=invite.custom_path or invite.token))
    token_url = f"{DISCORD_API_BASE_URL}/oauth2/token"; payload = {'client_id': client_id, 'client_secret': client_secret, 'grant_type': 'authorization_code', 'code': code, 'redirect_uri': redirect_uri}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        token_response = requests.post(token_url, data=payload, headers=headers); token_response.raise_for_status()
        access_token = token_response.json()['access_token']
        user_info_url = f"{DISCORD_API_BASE_URL}/users/@me"; auth_headers = {'Authorization': f'Bearer {access_token}'}
        user_response = requests.get(user_info_url, headers=auth_headers); user_response.raise_for_status()
        discord_user = user_response.json()
        username_field = f"{discord_user['username']}#{discord_user['discriminator']}" if discord_user.get('discriminator') and discord_user.get('discriminator') != '0' else discord_user['username']
        session[f'invite_{invite.id}_discord_user'] = {'id': discord_user['id'], 'username': username_field, 'avatar': discord_user.get('avatar')}
        log_event(EventType.INVITE_USED_SUCCESS_DISCORD, f"Discord auth success for {username_field} on invite {invite.id}.", invite_id=invite.id)
    except requests.exceptions.RequestException as e: 
        error_detail = str(e); flash(f'Failed to link Discord: {error_detail}', 'danger'); log_event(EventType.ERROR_DISCORD_API, f"Invite {invite.id}: Discord callback error: {error_detail}", invite_id=invite.id)
    session.pop('discord_oauth_invite_id', None) 
    return redirect(url_for('invites.process_invite_form', invite_path_or_token=invite.custom_path or invite.token))

@bp.route('/success') # Path is /invites/success
@setup_required 
def invite_success():
    username = request.args.get('username', 'there'); plex_app_url = "https://app.plex.tv"
    return render_template('invites/invite_success.html', username=username, plex_app_url=plex_app_url)

@bp.route('/') # Defines the base /invites/ path
@setup_required 
def invite_landing_page(): # Renamed from placeholder
    flash("Please use a specific invite link.", "info")
    if current_user.is_authenticated: 
        return redirect(url_for('dashboard.index'))
    # If not authenticated and no specific invite, perhaps redirect to admin login or a generic info page
    return redirect(url_for('auth.app_login')) 