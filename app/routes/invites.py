# File: app/routes/invites.py
import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session, g, make_response
from markupsafe import Markup # Import Markup from markupsafefrom flask_login import login_required, current_user 
from datetime import datetime, timezone
from urllib.parse import urlencode, quote as url_quote, urlparse, parse_qs, urlunparse 
import requests 
import xml.etree.ElementTree as ET 
from plexapi.myplex import MyPlexAccount 
from app.models import Invite, Setting, EventType, User, InviteUsage, AdminAccount, SettingValueType 
from app.forms import InviteCreateForm, InviteEditForm
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
    # Get view mode, defaulting to 'cards'
    view_mode = request.args.get('view', Setting.get('DEFAULT_INVITE_VIEW', 'cards'))

    items_per_page_setting = Setting.get('DEFAULT_INVITES_PER_PAGE', current_app.config.get('DEFAULT_INVITES_PER_PAGE', 10))
    items_per_page = int(items_per_page_setting) if items_per_page_setting else 10
    
    # Query logic is unchanged
    query = Invite.query
    filter_status = request.args.get('filter', 'all'); search_path = request.args.get('search_path', '').strip()
    if search_path: query = query.filter(Invite.custom_path.ilike(f"%{search_path}%"))
    now = datetime.utcnow() 
    if filter_status == 'active': query = query.filter(Invite.is_active == True, (Invite.expires_at == None) | (Invite.expires_at > now), (Invite.max_uses == None) | (Invite.current_uses < Invite.max_uses))
    elif filter_status == 'expired': query = query.filter(Invite.expires_at != None, Invite.expires_at <= now)
    elif filter_status == 'maxed': query = query.filter(Invite.max_uses != None, Invite.current_uses >= Invite.max_uses)
    elif filter_status == 'inactive': query = query.filter(Invite.is_active == False)
    
    invites_pagination = query.order_by(Invite.created_at.desc()).paginate(page=page, per_page=items_per_page, error_out=False)
    invites_count = query.count()
    
    # Create modal form logic is unchanged
    form = InviteCreateForm()
    available_libraries = plex_service.get_plex_libraries_dict()
    form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]
    bot_is_enabled = Setting.get_bool('DISCORD_BOT_ENABLED', False)
    global_force_sso = Setting.get_bool('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', False) or bot_is_enabled
    global_require_guild = Setting.get_bool('DISCORD_REQUIRE_GUILD_MEMBERSHIP', False)
    form.override_force_discord_auth.data = global_force_sso
    form.override_force_guild_membership.data = global_require_guild
    
    # If the request is from HTMX, render the list content partial
    if request.headers.get('HX-Request'):
        return render_template('invites/_invites_list_content.html', 
                               invites=invites_pagination,
                               available_libraries=available_libraries,
                               current_view=view_mode,
                               current_per_page=items_per_page)

    # For a full page load, render the main list.html
    return render_template('invites/list.html', 
                           title="Manage Invites", 
                           invites_count=invites_count, 
                           form=form, 
                           available_libraries=available_libraries, 
                           current_per_page=items_per_page,
                           global_force_sso=global_force_sso,
                           global_require_guild=global_require_guild,
                           current_view=view_mode) # Pass the view mode

@bp.route('/manage/create', methods=['POST'])
@login_required
@setup_required
def create_invite():
    form = InviteCreateForm()
    available_libraries = plex_service.get_plex_libraries_dict()
    form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]
    
    bot_is_enabled = Setting.get_bool('DISCORD_BOT_ENABLED', False)
    global_force_sso = Setting.get_bool('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', False) or bot_is_enabled
    global_require_guild = Setting.get_bool('DISCORD_REQUIRE_GUILD_MEMBERSHIP', False)
    
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
                return render_template('invites/_create_invite_modal_form_content.html', form=form, available_libraries=available_libraries, global_force_sso=global_force_sso, global_require_guild=global_require_guild), 422
        
        expires_at = calculate_expiry_date(form.expires_in_days.data)
        max_uses = form.number_of_uses.data if form.number_of_uses.data and form.number_of_uses.data > 0 else None
        membership_duration = form.membership_duration_days.data
        if membership_duration is not None and membership_duration <= 0: membership_duration = None 
        
        # --- NEW: Logic for saving override values ---
        form_force_sso = form.override_force_discord_auth.data
        force_sso_db_value = None  # Default to None (use global)
        if form_force_sso != global_force_sso:
            force_sso_db_value = form_force_sso

        form_require_guild = form.override_force_guild_membership.data
        require_guild_db_value = None # Default to None (use global)
        if global_require_guild and form_require_guild != global_require_guild:
            # We only store an override if the global setting is True and the user toggled it to False
            require_guild_db_value = form_require_guild
        # --- END NEW ---

        new_invite = Invite(
            custom_path=custom_path, expires_at=expires_at, max_uses=max_uses,
            grant_library_ids=form.libraries.data or [], allow_downloads=form.allow_downloads.data,
            membership_duration_days=membership_duration, created_by_admin_id=current_user.id,
            # Set the new override fields
            force_discord_auth=force_sso_db_value,
            force_guild_membership=require_guild_db_value
        )
        try:
            db.session.add(new_invite); db.session.commit()
            invite_url = new_invite.get_full_url(g.app_base_url or request.url_root.rstrip('/'))
            log_msg_details = f"Downloads: {'Enabled' if new_invite.allow_downloads else 'Disabled'}."
            if new_invite.membership_duration_days: log_msg_details += f" Membership: {new_invite.membership_duration_days} days."
            else: log_msg_details += " Membership: Permanent."
            if new_invite.force_discord_auth is not None: log_msg_details += f" Force Discord Auth: {new_invite.force_discord_auth} (Override)."
            if new_invite.force_guild_membership is not None: log_msg_details += f" Force Guild Membership: {new_invite.force_guild_membership} (Override)."
                
            log_event(EventType.INVITE_CREATED, f"Invite created: Path='{custom_path or new_invite.token}'. {log_msg_details}", invite_id=new_invite.id, admin_id=current_user.id)
            toast_message_text = f"Invite link created successfully!"; toast_category = "success"
            if request.headers.get('HX-Request'):
                response = make_response(""); response.status_code = 204 
                trigger_payload = {"refreshInvitesList": True, "showToastEvent": {"message": toast_message_text, "category": toast_category}}
                response.headers['HX-Trigger-After-Swap'] = json.dumps(trigger_payload)
                return response
            flash(f"Invite link created: {invite_url}", toast_category) 
            return redirect(url_for('invites.list_invites'))
        except Exception as e:
            db.session.rollback(); current_app.logger.error(f"Error creating invite in DB: {e}", exc_info=True)
            toast_message_text = f"Error creating invite: {str(e)[:100]}"; toast_category = "danger"
            if request.headers.get('HX-Request'):
                response = make_response("Error saving invite to database.", 500) 
                response.headers['HX-Trigger-After-Swap'] = json.dumps({"showToastEvent": {"message": toast_message_text, "category": toast_category}})
                return response
            flash(toast_message_text, toast_category); return redirect(url_for('invites.list_invites'))
    else: 
        if request.headers.get('HX-Request'):
            return render_template('invites/_create_invite_modal_form_content.html', form=form, available_libraries=available_libraries, global_force_sso=global_force_sso, global_require_guild=global_require_guild), 422
        for field, errors_list in form.errors.items():
            for error in errors_list: flash(f"Error in {getattr(form, field).label.text}: {error}", "danger")
        return redirect(url_for('invites.list_invites'))

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
    from flask_wtf import FlaskForm
    invite, error_message_from_validation = invite_service.validate_invite_usability(invite_path_or_token)
    
    if request.method == 'GET' and not error_message_from_validation and invite:
        log_event(EventType.INVITE_VIEWED, f"Invite '{invite.custom_path or invite.token}' (ID: {invite.id}) viewed/accessed.", invite_id=invite.id)

    if error_message_from_validation: 
        return render_template('invites/public_invite.html', error=error_message_from_validation, invite=None, form=FlaskForm(), discord_sso_is_mandatory=False, show_discord_button=False)

    if not invite:
        flash("The invite link is invalid or no longer available.", "danger")
        return redirect(url_for('invites.invite_landing_page'))

    form_instance = FlaskForm()
    already_authenticated_plex_user_info = session.get(f'invite_{invite.id}_plex_user')
    already_authenticated_discord_user_info = session.get(f'invite_{invite.id}_discord_user')
    
    # --- MODIFIED: Determine effective Discord settings using invite overrides ---
    oauth_is_generally_enabled = Setting.get_bool('DISCORD_OAUTH_ENABLED', False)
    
    # Determine effective "Require SSO" setting
    if invite.force_discord_auth is not None:
        effective_require_sso = invite.force_discord_auth
    else:
        bot_is_enabled = Setting.get_bool('DISCORD_BOT_ENABLED', False)
        effective_require_sso = Setting.get_bool('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', False) or bot_is_enabled
        
    # Determine effective "Require Guild Membership" setting
    if invite.force_guild_membership is not None:
        effective_require_guild = invite.force_guild_membership
    else:
        effective_require_guild = Setting.get_bool('DISCORD_REQUIRE_GUILD_MEMBERSHIP', False)

    # These settings are fetched for display purposes if guild membership is required
    setting_discord_guild_id = Setting.get('DISCORD_GUILD_ID')
    setting_discord_server_invite_url = Setting.get('DISCORD_SERVER_INVITE_URL')
    show_discord_button = oauth_is_generally_enabled
    # --- END MODIFIED ---

    if request.method == 'POST':
        auth_method = request.form.get('auth_method'); action_taken = request.form.get('action') 
        if auth_method == 'plex': # ... (Plex auth logic is unchanged)
            session['plex_oauth_invite_id'] = invite.id 
            headers = _get_plex_sso_headers(client_identifier_suffix="InvitePlexLink-" + str(invite.id)[:8])
            plex_client_id_used = headers['X-Plex-Client-Identifier']
            try:
                pin_request_url = f"{PLEX_API_V2_PINS_URL}?strong=true"
                response = requests.post(pin_request_url, headers=headers, timeout=10); response.raise_for_status()
                pin_data_xml_root = ET.fromstring(response.content)
                pin_code = pin_data_xml_root.get('code'); pin_id = pin_data_xml_root.get('id')
                if not pin_code or not pin_id: raise Exception("Could not get PIN details from Plex.")
                session['plex_pin_id_invite_flow'] = pin_id; session['plex_pin_code_invite_flow'] = pin_code; session['plex_client_id_for_pin_check_invite_flow'] = plex_client_id_used
                app_base_url = Setting.get('APP_BASE_URL', request.url_root.rstrip('/'))
                callback_path_segment = url_for('invites.plex_oauth_callback', _external=False)
                forward_url_to_our_app = f"{app_base_url.rstrip('/')}{callback_path_segment}"
                auth_app_params = {'clientID': plex_client_id_used, 'code': pin_code, 'forwardUrl': forward_url_to_our_app, 'context[device][product]': headers.get('X-Plex-Product'), 'context[device][deviceName]': headers.get('X-Plex-Device-Name'), 'context[device][platform]': headers.get('X-Plex-Platform')}
                auth_url_for_user_to_visit = f"{PLEX_AUTH_APP_URL_BASE}#?{urlencode(auth_app_params, quote_via=url_quote)}"
                return redirect(auth_url_for_user_to_visit)
            except Exception as e:
                flash(f"Could not initiate Plex login: {str(e)[:150]}", "danger"); log_event(EventType.ERROR_PLEX_API, f"Invite {invite.id}: Plex PIN init failed: {e}", invite_id=invite.id)
        
        elif auth_method == 'discord': # ... (Discord auth logic is unchanged)
            if not show_discord_button: flash("Discord login is not currently available.", "warning")
            else:
                admin_provided_oauth_url = Setting.get('DISCORD_OAUTH_AUTH_URL'); client_id_from_settings = Setting.get('DISCORD_CLIENT_ID')
                if admin_provided_oauth_url and client_id_from_settings:
                    session['discord_oauth_invite_id'] = invite.id; session['discord_oauth_state_invite'] = str(uuid.uuid4())
                    parsed_url = urlparse(admin_provided_oauth_url)
                    query_params = parse_qs(parsed_url.query); query_params['state'] = [session['discord_oauth_state_invite']]
                    expected_redirect_uri = Setting.get('DISCORD_REDIRECT_URI_INVITE') or url_for('invites.discord_oauth_callback', _external=True)
                    if 'redirect_uri' not in query_params or query_params.get('redirect_uri', [''])[0] != expected_redirect_uri: query_params['redirect_uri'] = [expected_redirect_uri]
                    final_query_string = urlencode(query_params, doseq=True)
                    final_discord_auth_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, final_query_string, parsed_url.fragment))
                    return redirect(final_discord_auth_url)
                elif client_id_from_settings:
                    session['discord_oauth_invite_id'] = invite.id; session['discord_oauth_state_invite'] = str(uuid.uuid4())
                    redirect_uri = Setting.get('DISCORD_REDIRECT_URI_INVITE') or url_for('invites.discord_oauth_callback', _external=True)
                    required_scopes = "identify email guilds"; params = {'client_id': client_id_from_settings, 'redirect_uri': redirect_uri, 'response_type': 'code', 'scope': required_scopes, 'state': session['discord_oauth_state_invite']}
                    discord_auth_url = f"{DISCORD_API_BASE_URL}/oauth2/authorize?{urlencode(params)}"
                    return redirect(discord_auth_url)
                else: flash("Discord integration is not properly configured by admin for login.", "danger")

        elif action_taken == 'accept_invite':
            if not already_authenticated_plex_user_info: flash("Please sign in with Plex first to accept the invite.", "warning")
            elif effective_require_sso and not already_authenticated_discord_user_info: flash("Discord account linking is required for this invite. Please link your Discord account.", "warning")
            else:
                success, result_object_or_message = invite_service.accept_invite_and_grant_access(
                    invite=invite, 
                    plex_user_uuid=already_authenticated_plex_user_info['uuid'], 
                    plex_username=already_authenticated_plex_user_info['username'], 
                    plex_email=already_authenticated_plex_user_info['email'], 
                    plex_thumb=already_authenticated_plex_user_info['thumb'], 
                    # Pass the entire dictionary as a single argument
                    discord_user_info=already_authenticated_discord_user_info, 
                    ip_address=request.remote_addr
                )
                if success: 
                    session.pop(f'invite_{invite.id}_plex_user', None); session.pop(f'invite_{invite.id}_discord_user', None)
                    flash(f"Welcome, {already_authenticated_plex_user_info['username']}! Access granted to the Plex server.", "success")
                    return redirect(url_for('invites.invite_success', username=already_authenticated_plex_user_info['username']))
                else: flash(f"Failed to accept invite: {result_object_or_message}", "danger")
        
        return redirect(url_for('invites.process_invite_form', invite_path_or_token=invite_path_or_token))

    return render_template('invites/public_invite.html', 
                           form=form_instance, 
                           invite=invite, 
                           error=None,
                           invite_path_or_token=invite_path_or_token, 
                           # Pass the effective values to the template
                           discord_sso_is_mandatory=effective_require_sso,
                           setting_require_guild_membership=effective_require_guild,
                           show_discord_button=show_discord_button,
                           already_authenticated_plex_user=already_authenticated_plex_user_info, 
                           already_authenticated_discord_user=already_authenticated_discord_user_info,
                           setting_discord_guild_id=setting_discord_guild_id,
                           setting_discord_server_invite_url=setting_discord_server_invite_url
                           )

@bp.route('/plex_callback') # Path is /invites/plex_callback
@setup_required
def plex_oauth_callback():
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

@bp.route('/discord_callback')
@setup_required
def discord_oauth_callback():
    invite_id_from_session = session.get('discord_oauth_invite_id')
    returned_state = request.args.get('state')
    
    invite_path_for_redirect_on_error = "unknown_invite_path"
    invite_object_for_redirect = None
    if invite_id_from_session:
        invite_object_for_redirect = Invite.query.get(invite_id_from_session)
        if invite_object_for_redirect:
            invite_path_for_redirect_on_error = invite_object_for_redirect.custom_path or invite_object_for_redirect.token
    
    public_invite_page_url_with_path = url_for('invites.process_invite_form', invite_path_or_token=invite_path_for_redirect_on_error)
    generic_invite_landing_url = url_for('invites.invite_landing_page')

    if not invite_id_from_session or not returned_state or returned_state != session.pop('discord_oauth_state_invite', None):
        flash('Discord login failed: Invalid session or state. Please try the invite link again.', 'danger')
        current_app.logger.warning("Discord OAuth Callback: Invalid state or missing invite_id in session.")
        return redirect(public_invite_page_url_with_path if invite_object_for_redirect else generic_invite_landing_url)

    if not invite_object_for_redirect:
        flash('Discord login failed: Invite information is no longer available. Please try a fresh invite link.', 'danger')
        current_app.logger.warning(f"Discord OAuth Callback: Invite ID {invite_id_from_session} not found in DB after state check.")
        return redirect(generic_invite_landing_url)

    code = request.args.get('code')
    if not code:
        error_description = request.args.get("error_description", "Authentication with Discord failed. No authorization code received.")
        flash(f'Discord login failed: {error_description}', 'danger')
        log_event(EventType.ERROR_DISCORD_API, f"Discord OAuth callback failed (no code): {error_description}", invite_id=invite_id_from_session)
        return redirect(public_invite_page_url_with_path)

    client_id = Setting.get('DISCORD_CLIENT_ID')
    client_secret = Setting.get('DISCORD_CLIENT_SECRET')
    redirect_uri_for_token_exchange = Setting.get('DISCORD_REDIRECT_URI_INVITE') 
    
    if not (client_id and client_secret and redirect_uri_for_token_exchange):
        flash('Discord integration is not properly configured by the admin. Cannot complete login.', 'danger')
        log_event(EventType.ERROR_DISCORD_API, "Discord OAuth callback failed: PUM settings (client_id/secret/redirect_uri_invite) missing.", invite_id=invite_id_from_session)
        return redirect(public_invite_page_url_with_path)

    token_url = f"{DISCORD_API_BASE_URL}/oauth2/token"
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri_for_token_exchange
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        token_response = requests.post(token_url, data=payload, headers=headers, timeout=15)
        token_response.raise_for_status()
        token_data = token_response.json()
        access_token = token_data['access_token']
        
        user_info_url = f"{DISCORD_API_BASE_URL}/users/@me"
        auth_headers = {'Authorization': f'Bearer {access_token}'}
        user_response = requests.get(user_info_url, headers=auth_headers, timeout=10)
        user_response.raise_for_status()
        discord_user_data = user_response.json()
        
        discord_username_from_oauth = f"{discord_user_data['username']}#{discord_user_data['discriminator']}" if discord_user_data.get('discriminator') and discord_user_data.get('discriminator') != '0' else discord_user_data['username']
        
        # Determine the effective "Require Guild Membership" setting for this specific invite
        if invite_object_for_redirect.force_guild_membership is not None:
            effective_require_guild = invite_object_for_redirect.force_guild_membership
        else:
            effective_require_guild = Setting.get_bool('DISCORD_REQUIRE_GUILD_MEMBERSHIP', False)
        
        if effective_require_guild:
            current_app.logger.info(f"Discord OAuth Callback: Guild membership is required for invite {invite_object_for_redirect.id}.")
            configured_guild_id_str = Setting.get('DISCORD_GUILD_ID')
            if not configured_guild_id_str or not configured_guild_id_str.isdigit():
                flash('Server configuration error: Target Discord Server ID for membership check is not set or invalid. Please contact admin.', 'danger')
                session.pop('discord_oauth_invite_id', None)
                return redirect(public_invite_page_url_with_path)
            
            configured_guild_id = int(configured_guild_id_str)
            user_guilds_url = f"{DISCORD_API_BASE_URL}/users/@me/guilds"
            guilds_response = requests.get(user_guilds_url, headers=auth_headers, timeout=10)
            guilds_response.raise_for_status()
            user_guilds_list = guilds_response.json()
            is_member = any(str(g.get('id')) == str(configured_guild_id) for g in user_guilds_list)

            if not is_member:
                server_invite_link = Setting.get('DISCORD_SERVER_INVITE_URL')
                error_html = "To accept this invite, you must be a member of our Discord server."
                if server_invite_link: error_html += f" Please join using the button below and then attempt to link your Discord account again on the invite page."
                else: error_html += " Please contact an administrator for an invite to the server."
                flash(Markup(error_html), 'warning')
                log_event(EventType.DISCORD_BOT_GUILD_MEMBER_CHECK_FAIL, f"User {discord_username_from_oauth} (ID: {discord_user_data['id']}) failed guild membership check for guild {configured_guild_id}.", invite_id=invite_object_for_redirect.id)
                session.pop('discord_oauth_invite_id', None)
                return redirect(public_invite_page_url_with_path)
        
        # If all checks pass, store all relevant info in the session
        discord_user_info_for_session = {
            'id': discord_user_data.get('id'), 
            'username': discord_username_from_oauth,
            'avatar': discord_user_data.get('avatar'),
            'email': discord_user_data.get('email'),
            'verified': discord_user_data.get('verified')
        }
        session[f'invite_{invite_object_for_redirect.id}_discord_user'] = discord_user_info_for_session
        log_event(EventType.INVITE_USED_SUCCESS_DISCORD, f"Discord auth success for {discord_username_from_oauth} on invite {invite_object_for_redirect.id}.", invite_id=invite_object_for_redirect.id)

    except requests.exceptions.HTTPError as e_http:
        error_message = f"Discord API Error ({e_http.response.status_code})"
        try: 
            error_json = e_http.response.json()
            error_message = error_json.get('error_description', error_json.get('message', error_message))
        except ValueError: 
            error_message = e_http.response.text[:200] if e_http.response.text else error_message
        flash(f'Failed to link Discord: {error_message}', 'danger')
        log_event(EventType.ERROR_DISCORD_API, f"Invite {invite_id_from_session}: Discord callback HTTPError: {error_message}", invite_id=invite_id_from_session, details={'status_code': e_http.response.status_code})
    except Exception as e_gen:
        flash('An unexpected error occurred during Discord login. Please try again.', 'danger')
        log_event(EventType.ERROR_DISCORD_API, f"Invite {invite_id_from_session}: Unexpected Discord callback error: {e_gen}", invite_id=invite_id_from_session, details={'error': str(e_gen)})
    finally:
        session.pop('discord_oauth_invite_id', None) 

    return redirect(public_invite_page_url_with_path)

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

@bp.route('/manage/edit/<int:invite_id>', methods=['GET'])
@login_required
@setup_required
def get_edit_invite_form(invite_id):
    invite = Invite.query.get_or_404(invite_id)
    form = InviteEditForm(obj=invite) # Pre-populate form with existing data

    # Manually populate fields that don't map directly from the object
    if invite.expires_at and invite.expires_at > datetime.now(timezone.utc):
        days_left = (invite.expires_at - datetime.now(timezone.utc)).days + 1
        form.expires_in_days.data = days_left if days_left > 0 else 0
    else:
        form.expires_in_days.data = 0
    
    form.number_of_uses.data = invite.max_uses or 0
    form.membership_duration_days.data = invite.membership_duration_days
    form.allow_downloads.data = invite.allow_downloads
    form.grant_purge_whitelist.data = invite.grant_purge_whitelist
    form.grant_bot_whitelist.data = invite.grant_bot_whitelist
    form.libraries.data = list(invite.grant_library_ids or [])
    
    available_libraries = plex_service.get_plex_libraries_dict()
    form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]

    # Handle Discord override toggles based on global settings
    bot_is_enabled = Setting.get_bool('DISCORD_BOT_ENABLED', False)
    global_force_sso = Setting.get_bool('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', False) or bot_is_enabled
    global_require_guild = Setting.get_bool('DISCORD_REQUIRE_GUILD_MEMBERSHIP', False)
    
    # If there's an override, use it. Otherwise, use the global default.
    form.override_force_discord_auth.data = invite.force_discord_auth if invite.force_discord_auth is not None else global_force_sso
    form.override_force_guild_membership.data = invite.force_guild_membership if invite.force_guild_membership is not None else global_require_guild

    return render_template(
        'invites/_edit_invite_modal_form_content.html',
        form=form,
        invite=invite,
        global_require_guild=global_require_guild # For conditional display in template
    )

# --- NEW: Edit Invite POST Route (for saving changes) ---
@bp.route('/manage/edit/<int:invite_id>', methods=['POST'])
@login_required
@setup_required
def update_invite(invite_id):
    invite = Invite.query.get_or_404(invite_id)
    form = InviteEditForm()
    
    available_libraries = plex_service.get_plex_libraries_dict()
    form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]

    bot_is_enabled = Setting.get_bool('DISCORD_BOT_ENABLED', False)
    global_force_sso = Setting.get_bool('DISCORD_BOT_REQUIRE_SSO_ON_INVITE', False) or bot_is_enabled
    global_require_guild = Setting.get_bool('DISCORD_REQUIRE_GUILD_MEMBERSHIP', False)
    
    if form.validate_on_submit():
        # Expiration
        if form.clear_expiry.data:
            invite.expires_at = None
        elif form.expires_in_days.data is not None and form.expires_in_days.data > 0:
            invite.expires_at = calculate_expiry_date(form.expires_in_days.data)

        # Max Uses
        if form.clear_max_uses.data:
            invite.max_uses = None
        elif form.number_of_uses.data is not None and form.number_of_uses.data >= 0:
            invite.max_uses = form.number_of_uses.data or None # 0 means unlimited (NULL)

        # Membership Duration
        if form.clear_membership_duration.data:
            invite.membership_duration_days = None
        elif form.membership_duration_days.data is not None and form.membership_duration_days > 0:
            invite.membership_duration_days = form.membership_duration_days.data

        # Other fields
        invite.allowed_library_ids = form.libraries.data
        invite.allow_downloads = form.allow_downloads.data
        invite.grant_purge_whitelist = form.grant_purge_whitelist.data
        invite.grant_bot_whitelist = form.grant_bot_whitelist.data

        # Discord Override Logic
        if form.override_force_discord_auth.data == global_force_sso:
            invite.force_discord_auth = None
        else:
            invite.force_discord_auth = form.override_force_discord_auth.data
        
        if global_require_guild:
            if form.override_force_guild_membership.data == global_require_guild:
                invite.force_guild_membership = None
            else:
                invite.force_guild_membership = form.override_force_guild_membership.data

        db.session.commit()
        log_event(EventType.SETTING_CHANGE, f"Invite '{invite.custom_path or invite.token}' updated.", invite_id=invite.id, admin_id=current_user.id)
        
        response = make_response("", 204)
        trigger_payload = {"refreshInvitesList": True, "showToastEvent": {"message": "Invite updated successfully!", "category": "success"}}
        response.headers['HX-Trigger-After-Swap'] = json.dumps(trigger_payload)
        return response
    
    # If validation fails, re-render the form partial with errors
    return render_template(
        'invites/_edit_invite_modal_form_content.html',
        form=form,
        invite=invite,
        global_require_guild=global_require_guild
    ), 422