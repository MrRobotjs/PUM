# app/sso_plex.py
from flask import Blueprint, current_app, session, request, redirect, url_for, flash
import requests
import uuid
from urllib.parse import urlencode, quote_plus, urlparse, urljoin # Added urlparse, urljoin
import xml.etree.ElementTree as ET

from app.models import get_app_setting, User, db, HistoryLog # Import User, db, HistoryLog
from flask_login import login_user # For logging in the admin

sso_plex_bp = Blueprint('sso_plex', __name__, url_prefix='/sso/plex')

PLEX_API_V2_PINS_URL = "https://plex.tv/api/v2/pins"
PLEX_AUTH_URL_BASE = "https://app.plex.tv/auth/"

# Helper function for redirect safety
def is_safe_url(target):
    if not target: 
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def _get_plex_headers():
    client_identifier = get_app_setting('PLEX_CLIENT_IDENTIFIER')
    if not client_identifier:
        client_identifier = str(uuid.uuid4())
        current_app.logger.warning(f"Plex SSO: PLEX_CLIENT_IDENTIFIER not found. Generated temp: {client_identifier}.")
        # from app.models import update_app_setting # Avoid circular import here if possible
        # update_app_setting('PLEX_CLIENT_IDENTIFIER', client_identifier) # Decide if you auto-save

    app_name = get_app_setting('APP_NAME', 'Plex User Manager')
    app_version = get_app_setting('APP_VERSION', '1.0.0')

    if not app_name:
        current_app.logger.error("Plex SSO: APP_NAME setting is missing or empty!")
        app_name = "Plex User Manager (Default)"

    headers = {
        'X-Plex-Product': app_name,
        'X-Plex-Version': app_version,
        'X-Plex-Client-Identifier': client_identifier,
        'X-Plex-Device': "Application",
        'X-Plex-Device-Name': f"{app_name} (PUM SSO)",
        'X-Plex-Platform': "Web",
        'Accept': 'application/xml' 
    }
    current_app.logger.debug(f"Plex SSO: Generated headers for Plex API: {headers}")
    return headers

@sso_plex_bp.route('/start_auth_redirect', methods=['GET'])
def start_plex_sso_auth_redirect():
    current_app.logger.info(f"Plex SSO Redirect Flow: /start_auth_redirect called. Query: {request.args}")
    
    sso_purpose = request.args.get('purpose', session.get('sso_plex_purpose', 'invite')) 
    invite_path_for_redirect = request.args.get('invite_path') 

    session['sso_plex_purpose'] = sso_purpose
    current_app.logger.info(f"Plex SSO: Initiated for purpose: '{sso_purpose}'")

    if sso_purpose == 'invite':
        if invite_path_for_redirect:
            session['plex_sso_origin_invite_path'] = invite_path_for_redirect
        elif not session.get('plex_sso_origin_invite_path'): # If no path in query and not already in session for invite
            current_app.logger.warning("Plex SSO: Purpose is 'invite' but no 'invite_path' provided or in session.")
            flash("Cannot initiate Plex login for invite without an invite path.", "danger")
            return redirect(url_for('main.index_or_setup'))
    elif sso_purpose in ['admin_setup', 'admin_login']:
        session.pop('plex_sso_origin_invite_path', None) # Clear invite path if not an invite flow
        # For admin login, capture the 'next' URL
        if sso_purpose == 'admin_login':
            next_url_from_query = request.args.get('next')
            if next_url_from_query and is_safe_url(next_url_from_query):
                session['sso_plex_next_url'] = next_url_from_query
                current_app.logger.debug(f"Plex Admin Login Start: Storing next_url: {next_url_from_query}")
            else:
                session.pop('sso_plex_next_url', None)
    else: # Unknown purpose
        current_app.logger.error(f"Plex SSO: Unknown purpose '{sso_purpose}' specified.")
        flash("Invalid Plex login purpose.", "danger")
        return redirect(url_for('main.index_or_setup'))

    try:
        headers = _get_plex_headers()
        pin_request_url = f"{PLEX_API_V2_PINS_URL}?strong=true"
        response = requests.post(pin_request_url, headers=headers, timeout=10)
        response.raise_for_status()

        pin_data_xml_root = ET.fromstring(response.content)
        pin_code = pin_data_xml_root.get('code')
        pin_id = pin_data_xml_root.get('id')

        if not pin_code or not pin_id:
            current_app.logger.error("Plex SSO Redirect: 'code' or 'id' missing from PIN response.")
            flash("Error initiating Plex login: Could not get PIN details from Plex.", "danger")
            # Determine fallback based on original purpose
            if sso_purpose == 'invite': return redirect(url_for('main.use_invite_link', custom_path=session.get('plex_sso_origin_invite_path', 'invalid')))
            if sso_purpose == 'admin_setup': return redirect(url_for('setup.setup_wizard', step=1))
            if sso_purpose == 'admin_login': return redirect(url_for('auth.login'))
            return redirect(url_for('main.index_or_setup'))


        session['plex_sso_pin_id_for_callback'] = pin_id
        session['plex_sso_client_id_for_callback'] = headers.get('X-Plex-Client-Identifier')

        app_base_url = get_app_setting('APP_BASE_URL', request.url_root.rstrip('/'))
        if not get_app_setting('APP_BASE_URL'): # Log if we're using fallback
            current_app.logger.warning("Plex SSO: APP_BASE_URL not set! Using request.url_root for callback. This may fail behind proxies.")
        
        callback_path_segment = url_for('sso_plex.plex_sso_callback', _external=False)
        
        # Parameters for our app's callback URL (which Plex will redirect to within forwardUrl)
        our_callback_params = {'pin_id_to_check': pin_id, 'sso_purpose': sso_purpose}
        if sso_purpose == 'invite' and session.get('plex_sso_origin_invite_path'):
            our_callback_params['invite_path'] = session.get('plex_sso_origin_invite_path')
        # If purpose is admin_login, sso_plex_next_url is in session, not passed via Plex redirect query params

        forward_url_to_our_app = f"{app_base_url.rstrip('/')}{callback_path_segment}?{urlencode(our_callback_params)}"
        
        auth_app_params = {
            'clientID': headers.get('X-Plex-Client-Identifier'),
            'code': pin_code,
            'forwardUrl': forward_url_to_our_app,
            'context[device][product]': headers.get('X-Plex-Product'),
            'context[device][deviceName]': headers.get('X-Plex-Device-Name'),
            'context[device][platform]': headers.get('X-Plex-Platform'),
        }
        plex_auth_url_for_user = f"{PLEX_AUTH_URL_BASE}#?{urlencode(auth_app_params, quote_via=quote_plus)}"
        current_app.logger.info(f"Plex SSO Redirect: PIN: {pin_code}, ID: {pin_id}. Redirecting user to Plex auth.")
        return redirect(plex_auth_url_for_user)

    except requests.exceptions.RequestException as e_req:
        current_app.logger.error(f"Plex SSO Redirect: RequestException: {e_req}", exc_info=True)
        flash(f"Could not connect to Plex.tv: {str(e_req)[:100]}.", "danger")
    except ET.ParseError as e_xml:
        current_app.logger.error(f"Plex SSO Redirect: XML ParseError from Plex: {e_xml}", exc_info=True)
        flash("Error parsing response from Plex.tv.", "danger")
    except Exception as e_general:
        current_app.logger.error(f"Plex SSO Redirect: General error: {e_general}", exc_info=True)
        flash(f"Could not initiate Plex login: {str(e_general)[:100]}.", "danger")
    
    # Fallback redirect if any error before redirecting to Plex
    if session.get('sso_plex_purpose') == 'invite': return redirect(url_for('main.use_invite_link', custom_path=session.get('plex_sso_origin_invite_path', 'error')))
    if session.get('sso_plex_purpose') == 'admin_setup': return redirect(url_for('setup.setup_wizard', step=1))
    if session.get('sso_plex_purpose') == 'admin_login': return redirect(url_for('auth.login'))
    return redirect(url_for('main.index_or_setup'))


@sso_plex_bp.route('/callback', methods=['GET'])
def plex_sso_callback():
    current_app.logger.info(f"Plex SSO Callback: Received request. Query Args: {request.args}")
    
    pin_id_from_plex = request.args.get('pin_id_to_check') 
    sso_purpose_from_plex_forward = request.args.get('sso_purpose') 
    invite_path_from_plex_forward = request.args.get('invite_path')

    expected_pin_id_from_session = session.get('plex_sso_pin_id_for_callback')
    client_id_for_pin_check = session.get('plex_sso_client_id_for_callback')
    # Use session's purpose as primary, as it was set by our app before redirect to Plex
    sso_final_purpose = session.get('sso_plex_purpose', sso_purpose_from_plex_forward) 

    # Determine fallback URL based on the final purpose
    if sso_final_purpose == 'invite':
        invite_path = invite_path_from_plex_forward or session.get('plex_sso_origin_invite_path')
        fallback_redirect_url = url_for('main.use_invite_link', custom_path=invite_path) if invite_path else url_for('main.index_or_setup')
    elif sso_final_purpose == 'admin_setup':
        fallback_redirect_url = url_for('setup.setup_wizard', step=1)
    elif sso_final_purpose == 'admin_login':
        fallback_redirect_url = url_for('auth.login')
    else:
        current_app.logger.warning(f"Plex SSO Callback: Unknown SSO purpose '{sso_final_purpose}'.")
        _clear_plex_sso_session_vars()
        flash("Plex login failed due to an unknown operation.", "danger")
        return redirect(url_for('main.index_or_setup'))

    if not pin_id_from_plex or not client_id_for_pin_check:
        flash("Plex login callback invalid: Missing PIN info.", "danger")
        _clear_plex_sso_session_vars()
        return redirect(fallback_redirect_url)
    
    if expected_pin_id_from_session != pin_id_from_plex:
        flash("Plex login callback state mismatch. Please try again.", "warning")
        current_app.logger.warning(f"Plex SSO Callback: PIN ID mismatch. Session: '{expected_pin_id_from_session}', Query: '{pin_id_from_plex}'.")
        _clear_plex_sso_session_vars()
        return redirect(fallback_redirect_url)

    try:
        headers_for_check = {'X-Plex-Client-Identifier': client_id_for_pin_check, 'Accept': 'application/xml'}
        check_pin_status_url = f"{PLEX_API_V2_PINS_URL}/{pin_id_from_plex}"
        response = requests.get(check_pin_status_url, headers=headers_for_check, timeout=10)
        response.raise_for_status()
        pin_data_xml_root = ET.fromstring(response.content)
        auth_token = pin_data_xml_root.get('authToken')

        if auth_token:
            current_app.logger.info(f"Plex SSO Callback: PIN {pin_id_from_plex} verified for purpose '{sso_final_purpose}'. Token received.")
            plex_user_details = _fetch_plex_user_details_with_sso_token(auth_token)
            
            if not plex_user_details or not plex_user_details.get('email'):
                flash("Authenticated with Plex, but could not retrieve essential account details (email).", "danger")
                _clear_plex_sso_session_vars()
                return redirect(fallback_redirect_url)

            plex_email = plex_user_details['email'].lower()
            plex_username = plex_user_details.get('username')
            plex_id = plex_user_details.get('plex_id')
            plex_thumb = plex_user_details.get('thumb_url')

            final_redirect_target = fallback_redirect_url 

            if sso_final_purpose == 'invite':
                session['sso_plex_email'] = plex_email
                session['sso_plex_username'] = plex_username
                # fallback_redirect_url is already correct for invite
                flash(f"Plex login successful as {plex_username or plex_email}! Please confirm your details.", "success")

            elif sso_final_purpose == 'admin_setup':
                existing_admin = User.query.filter_by(is_admin=True).first()
                if existing_admin:
                    flash(f"An admin account ('{existing_admin.username}') already exists. Please login or force setup if you intend to overwrite.", "warning")
                    final_redirect_target = url_for('auth.login')
                else:
                    # Ensure a unique username for the admin
                    potential_username = plex_username
                    if not potential_username: # If Plex username is blank
                        potential_username = plex_email.split('@')[0]
                    if User.query.filter_by(username=potential_username).first(): # If derived username taken
                        potential_username = f"{potential_username}_{str(plex_id)[:4]}" # Append part of Plex ID
                    
                    new_admin = User(
                        username=potential_username,
                        plex_email=plex_email, 
                        plex_username=plex_username, # Store the actual Plex username if available
                        plex_user_id=plex_id,
                        plex_thumb_url=plex_thumb,
                        is_admin=True,
                        password_hash=None # Plex-only authenticated admin
                    )
                    try:
                        db.session.add(new_admin); db.session.commit()
                        login_user(new_admin, remember=True)
                        flash(f"Admin account '{new_admin.username}' created via Plex ({plex_email}) and logged in!", "success")
                        HistoryLog.create(event_type="SETUP_ADMIN_PLEX_CREATED", plex_username=new_admin.username, details=f"Plex Email: {plex_email}")
                        final_redirect_target = url_for('setup.setup_wizard', step=2)
                    except Exception as e_db:
                        db.session.rollback()
                        flash(f"DB Error creating admin from Plex: {str(e_db)[:100]}", "danger")
                        current_app.logger.error(f"Plex SSO Admin Setup DB error: {e_db}", exc_info=True)
                        final_redirect_target = url_for('setup.setup_wizard', step=1) # Back to step 1

            elif sso_final_purpose == 'admin_login':
                admin_user = User.query.filter(User.is_admin==True, User.plex_email==plex_email).first()
                if not admin_user and plex_username:
                    admin_user = User.query.filter(User.is_admin==True, User.plex_username==plex_username).first()
                
                if admin_user:
                    # Update details if admin logs in via Plex
                    admin_user.plex_email = plex_email # Ensure email is up-to-date
                    if plex_username and not admin_user.plex_username: admin_user.plex_username = plex_username
                    if plex_id and admin_user.plex_user_id != plex_id: admin_user.plex_user_id = plex_id
                    if plex_thumb and admin_user.plex_thumb_url != plex_thumb: admin_user.plex_thumb_url = plex_thumb
                    try: db.session.commit()
                    except: db.session.rollback() # Ignore update errors silently for login
                    
                    login_user(admin_user, remember=True)
                    flash(f"Logged in as admin ({admin_user.username}) via Plex!", "success")
                    HistoryLog.create(event_type="ADMIN_LOGIN_PLEX", plex_username=admin_user.username)
                    
                    sso_next_url = session.pop('sso_plex_next_url', None) # Pop the stored next_url
                    if sso_next_url and is_safe_url(sso_next_url) and urlparse(sso_next_url).path != url_for('auth.login', _external=False):
                        final_redirect_target = sso_next_url
                    else:
                        final_redirect_target = url_for('main.dashboard')
                else:
                    flash("No admin account is linked to this Plex account.", "danger")
                    final_redirect_target = url_for('auth.login')
            
            _clear_plex_sso_session_vars()
            return redirect(final_redirect_target)
        else:
            flash("Plex login did not complete (no token). Please try again.", "warning")
    except Exception as e:
        flash(f"Error finalizing Plex login: {str(e)[:100]}.", "danger")
        current_app.logger.error(f"Plex SSO Callback general error: {e}", exc_info=True)
    
    _clear_plex_sso_session_vars()
    return redirect(fallback_redirect_url)

def _fetch_plex_user_details_with_sso_token(auth_token):
    if not auth_token: return None
    headers = {'X-Plex-Token': auth_token, 'Accept': 'application/json'}
    user_account_url = "https://plex.tv/users/account.json"
    try:
        response = requests.get(user_account_url, headers=headers, timeout=10)
        response.raise_for_status()
        user_data = response.json().get('user')
        if user_data and user_data.get('email'):
            return {
                'plex_id': user_data.get('id'),
                'username': user_data.get('username'),
                'title': user_data.get('title'), 
                'email': user_data.get('email').lower(),
                'thumb_url': user_data.get('thumb')
            }
        current_app.logger.error(f"Plex SSO: 'user' key or 'email' missing in /users/account.json. Data: {response.json()}")
    except Exception as e:
        current_app.logger.error(f"Plex SSO: Error fetching user details: {e}", exc_info=True)
    return None

def _clear_plex_sso_session_vars():
    session.pop('plex_sso_pin_id_for_callback', None)
    session.pop('plex_sso_client_id_for_callback', None)
    session.pop('sso_plex_purpose', None)
    session.pop('plex_sso_origin_invite_path', None)
    session.pop('sso_plex_next_url', None) # Clear the next URL for admin login
    session.pop('sso_plex_email', None)
    session.pop('sso_plex_username', None)
    current_app.logger.debug("Plex SSO: Cleared all Plex SSO session variables.")