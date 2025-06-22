# File: app/routes/setup.py
import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session, g
from flask_login import login_user, logout_user, current_user, login_required
from plexapi.exceptions import Unauthorized, NotFound
from plexapi.myplex import MyPlexAccount 
import secrets
import urllib.parse 
import requests 
import xml.etree.ElementTree as ET 
# import plexapi # Not strictly needed for version here unless debugging again

from app.models import AdminAccount, Setting, EventType, SettingValueType
from app.forms import AccountSetupForm, PlexConfigForm, AppBaseUrlForm, DiscordConfigForm
from app.extensions import db
from app.utils.helpers import log_event

bp = Blueprint('setup', __name__)

PLEX_API_V2_PINS_URL = "https://plex.tv/api/v2/pins" 
PLEX_CHECK_PIN_URL_TEMPLATE = "https://plex.tv/api/v2/pins/{pin_id}" 
PLEX_AUTH_APP_URL_BASE = "https://app.plex.tv/auth/"

def _get_plex_sso_headers(client_identifier_suffix="Setup"):
    base_client_id = Setting.get('PLEX_APP_CLIENT_IDENTIFIER', current_app.config.get('PLEX_APP_CLIENT_IDENTIFIER_FALLBACK', "PUM-Default-" + str(uuid.uuid4())[:8]))
    final_client_id = f"{base_client_id}-{client_identifier_suffix}"
    app_name = Setting.get('APP_NAME', current_app.config.get('APP_NAME', "Plex User Manager"))
    app_version = current_app.config.get('APP_VERSION', '1.0.0')
    headers = {
        'X-Plex-Product': app_name, 'X-Plex-Version': app_version,
        'X-Plex-Client-Identifier': final_client_id, 'X-Plex-Device': "Application", 
        'X-Plex-Device-Name': f"{app_name} ({client_identifier_suffix})", 'X-Plex-Platform': "Web", 
        'Accept': 'application/xml'
    }
    current_app.logger.debug(f"Plex SSO: Generated headers for Plex API: {headers}")
    return headers

def get_completed_steps():
    completed = set()
    engine_conn_steps, admin_table_exists_steps = None, False
    try:
        engine_conn_steps = db.engine.connect()
        if engine_conn_steps: admin_table_exists_steps = db.engine.dialect.has_table(engine_conn_steps, AdminAccount.__tablename__)
    except Exception as e: current_app.logger.error(f"DB connection error in get_completed_steps: {e}")
    finally:
        if engine_conn_steps: engine_conn_steps.close()
    if admin_table_exists_steps and AdminAccount.query.first(): completed.add('account')
    if Setting.get('PLEX_URL') and Setting.get('PLEX_TOKEN'): completed.add('plex')
    if Setting.get('APP_BASE_URL'): completed.add('pum')
    discord_enabled_setting_val = Setting.get('DISCORD_OAUTH_ENABLED') # Can be bool or string default
    if discord_enabled_setting_val is not None:
        is_discord_truly_disabled = (isinstance(discord_enabled_setting_val, bool) and not discord_enabled_setting_val) or \
                                    (isinstance(discord_enabled_setting_val, str) and discord_enabled_setting_val.lower() == 'false')
        is_discord_configured_if_enabled = Setting.get('DISCORD_CLIENT_ID') and Setting.get('DISCORD_CLIENT_SECRET')
        is_discord_truly_enabled = (isinstance(discord_enabled_setting_val, bool) and discord_enabled_setting_val) or \
                                   (isinstance(discord_enabled_setting_val, str) and discord_enabled_setting_val.lower() == 'true')

        if is_discord_truly_disabled: completed.add('discord')
        elif is_discord_truly_enabled and is_discord_configured_if_enabled : completed.add('discord')
    return completed

@bp.before_request
def check_setup_status_for_blueprint():
    setup_complete_flag = getattr(g, 'setup_complete', False)
    if setup_complete_flag and current_user.is_authenticated:
        if request.endpoint and request.endpoint != 'setup.finish_setup': return redirect(url_for('dashboard.index'))
    elif setup_complete_flag and not current_user.is_authenticated:
        if request.endpoint and not request.endpoint.startswith('auth.'): return redirect(url_for('auth.app_login'))

@bp.route('/account', methods=['GET', 'POST'])
def account_setup():
    form = AccountSetupForm()
    error_message = None # Initialize error_message

    # Check if admin account already exists and redirect if appropriate (only on initial GET load)
    # This part needs careful handling of DB connection state if tables don't exist yet.
    if request.method == 'GET' and not request.args.get('submit_type'): # Only for plain GET
        try:
            if 'account' in get_completed_steps(): # Relies on get_completed_steps working
                return redirect(url_for('setup.plex_config'))
        except Exception as e_check:
            current_app.logger.warning(f"Error checking completed steps in account_setup GET: {e_check}")
            # Proceed to render form if check fails, as setup might not be done.

    if request.method == 'GET' and request.args.get('submit_type') == 'plex_sso':
        current_app.logger.info("GET /setup/account?submit_type=plex_sso: START")
        try:
            session['admin_setup_method'] = 'plex_sso'
            current_app.logger.info("CHECKPOINT 1: Session admin_setup_method set")

            headers = _get_plex_sso_headers(client_identifier_suffix="AdminSetup")
            plex_client_id_used = headers['X-Plex-Client-Identifier']
            current_app.logger.info(f"CHECKPOINT 2: Headers created. ClientID: {plex_client_id_used}")

            pin_request_url = f"{PLEX_API_V2_PINS_URL}?strong=true"
            current_app.logger.info(f"CHECKPOINT 3: PIN Request URL: {pin_request_url}")

            current_app.logger.info(f"Plex SSO Setup (GET): Requesting PIN with ClientID {plex_client_id_used}")
            response = requests.post(pin_request_url, headers=headers, timeout=10)
            current_app.logger.info(f"CHECKPOINT 4: requests.post done. Status: {response.status_code}")

            response.raise_for_status()
            current_app.logger.info("CHECKPOINT 5: response.raise_for_status() passed.")

            pin_data_xml_root = ET.fromstring(response.content)
            current_app.logger.info("CHECKPOINT 6: XML parsed from response.")

            pin_code = pin_data_xml_root.get('code')
            pin_id = pin_data_xml_root.get('id')
            current_app.logger.info(f"CHECKPOINT 7: PIN Code: {pin_code}, PIN ID: {pin_id}")

            if not pin_code or not pin_id:
                current_app.logger.error("PIN Code or PIN ID is missing from Plex response!")
                raise Exception("Could not retrieve PIN details from Plex (code or id missing).")
            current_app.logger.info("CHECKPOINT 8: PIN Code and ID successfully retrieved.")

            session['plex_pin_id_admin_setup'] = pin_id
            session['plex_pin_code_admin_setup'] = pin_code
            session['plex_client_id_for_pin_check_admin_setup'] = plex_client_id_used
            current_app.logger.info("CHECKPOINT 9: PIN details stored in session.")

            # Attempt to get APP_BASE_URL from settings; fallback to request.url_root
            # Setting.get handles DB not ready by falling back to app.config or default None
            app_base_url_setting = Setting.get('APP_BASE_URL')
            current_app.logger.info(f"CHECKPOINT 10: Setting.get('APP_BASE_URL') returned: {app_base_url_setting}")
            
            app_base_url = app_base_url_setting if app_base_url_setting else request.url_root.rstrip('/')
            current_app.logger.info(f"CHECKPOINT 11: Effective app_base_url: {app_base_url}")

            if not app_base_url_setting and app_base_url == request.url_root.rstrip('/'): # Log only if we actually used request.url_root
                current_app.logger.warning("Plex SSO Setup (GET): APP_BASE_URL not set! Using request.url_root for callback.")

            callback_path_segment = url_for('setup.plex_sso_callback_setup_admin', _external=False)
            current_app.logger.info(f"CHECKPOINT 12: Callback path segment: {callback_path_segment}")
            
            forward_url_to_our_app = f"{app_base_url.rstrip('/')}{callback_path_segment}"
            current_app.logger.info(f"CHECKPOINT 13: Full forwardUrl: {forward_url_to_our_app}")

            auth_app_params = {
                'clientID': plex_client_id_used, 'code': pin_code, 'forwardUrl': forward_url_to_our_app,
                'context[device][product]': headers.get('X-Plex-Product'),
                'context[device][deviceName]': headers.get('X-Plex-Device-Name'),
                'context[device][platform]': headers.get('X-Plex-Platform'),
            }
            auth_url_for_user_to_visit = f"{PLEX_AUTH_APP_URL_BASE}#?{urllib.parse.urlencode(auth_app_params, quote_via=urllib.parse.quote_plus)}"
            current_app.logger.info(f"CHECKPOINT 14: Final auth URL for user: {auth_url_for_user_to_visit}")

            current_app.logger.info(f"Plex SSO Setup (GET): About to redirect. PIN: {pin_code}, ID: {pin_id}.")
            return redirect(auth_url_for_user_to_visit)

        except requests.exceptions.RequestException as e_req:
            current_app.logger.error(f"Plex SSO Setup (GET) EXCEPTION - RequestException: {e_req}", exc_info=True)
            error_message = f"Could not connect to Plex.tv: {type(e_req).__name__}."
        except ET.ParseError as e_xml:
            current_app.logger.error(f"Plex SSO Setup (GET) EXCEPTION - XML ParseError: {e_xml}", exc_info=True)
            error_message = "Error parsing response from Plex.tv."
        except Exception as e: # Generic catch-all
            current_app.logger.error(f"Plex SSO Setup (GET) EXCEPTION - Generic: {type(e).__name__} - {e}", exc_info=True)
            error_message = f"An unexpected error occurred: {type(e).__name__}."
        
        current_app.logger.info(f"GET /setup/account?submit_type=plex_sso: Reached end of GET SSO block, error_message: '{error_message}'. Will render_template.")
        # If an exception occurred, error_message is set, and it falls through to the final render_template

    elif request.method == 'POST':
        submit_type = request.form.get('submit_type')
        current_app.logger.info(f"POST /setup/account: submit_type='{submit_type}'") # Log POST attempts

        if submit_type == 'plex_sso':
            session['admin_setup_method'] = 'plex_sso'
            headers = _get_plex_sso_headers(client_identifier_suffix="AdminSetup")
            plex_client_id_used = headers['X-Plex-Client-Identifier']
            try:
                pin_request_url = f"{PLEX_API_V2_PINS_URL}?strong=true"
                current_app.logger.info(f"Plex SSO Setup (POST): Requesting PIN from {pin_request_url} with ClientID {plex_client_id_used}")
                response = requests.post(pin_request_url, headers=headers, timeout=10)
                response.raise_for_status()
                pin_data_xml_root = ET.fromstring(response.content)
                pin_code = pin_data_xml_root.get('code')
                pin_id = pin_data_xml_root.get('id')
                if not pin_code or not pin_id:
                    raise Exception("Could not retrieve PIN details from Plex (POST).")
                
                session['plex_pin_id_admin_setup'] = pin_id
                session['plex_pin_code_admin_setup'] = pin_code
                session['plex_client_id_for_pin_check_admin_setup'] = plex_client_id_used

                app_base_url_setting = Setting.get('APP_BASE_URL')
                app_base_url = app_base_url_setting if app_base_url_setting else request.url_root.rstrip('/')
                if not app_base_url_setting and app_base_url == request.url_root.rstrip('/'):
                     current_app.logger.warning("Plex SSO Setup (POST): APP_BASE_URL not set! Using request.url_root for callback.")
                
                callback_path_segment = url_for('setup.plex_sso_callback_setup_admin', _external=False)
                forward_url_to_our_app = f"{app_base_url.rstrip('/')}{callback_path_segment}"
                
                auth_app_params = {
                    'clientID': plex_client_id_used, 'code': pin_code, 'forwardUrl': forward_url_to_our_app,
                    'context[device][product]': headers.get('X-Plex-Product'),
                    'context[device][deviceName]': headers.get('X-Plex-Device-Name'),
                    'context[device][platform]': headers.get('X-Plex-Platform'),
                }
                auth_url_for_user_to_visit = f"{PLEX_AUTH_APP_URL_BASE}#?{urllib.parse.urlencode(auth_app_params, quote_via=urllib.parse.quote_plus)}"
                current_app.logger.info(f"Plex SSO Setup (POST): PIN: {pin_code}, ID: {pin_id}. Redirecting user to: {auth_url_for_user_to_visit}")
                return redirect(auth_url_for_user_to_visit)
            except requests.exceptions.RequestException as e_req:
                current_app.logger.error(f"Plex SSO Setup (POST): RequestException: {e_req}", exc_info=True)
                error_message = f"Could not connect to Plex.tv for PIN: {type(e_req).__name__}."
            except ET.ParseError as e_xml:
                current_app.logger.error(f"Plex SSO Setup (POST): XML ParseError: {e_xml}", exc_info=True)
                error_message = "Error parsing PIN response from Plex.tv."
            except Exception as e:
                current_app.logger.error(f"Error initiating Plex PIN for admin setup (POST): {e}", exc_info=True)
                error_message = f"Could not initiate Plex SSO PIN. Error: {type(e).__name__}."
            # If an exception occurred, error_message is set, and it falls through to render_template

        elif submit_type == 'username_password':
            # Make username/password fields required for this submission type
            form.username.validators[0].optional = False # Assuming DataRequired is first or similar
            form.password.validators[0].optional = False
            form.confirm_password.validators[0].optional = False
            # Ensure EqualTo validator has a message if not already set (good practice)
            if len(form.confirm_password.validators) > 1 and hasattr(form.confirm_password.validators[1], 'message') and not form.confirm_password.validators[1].message:
                 form.confirm_password.validators[1].message = 'Passwords must match.'

            if form.validate():
                try:
                    if AdminAccount.query.first(): # This will fail if table doesn't exist
                        flash('Admin account already exists. If you need to reset, consult documentation.', 'warning')
                        return redirect(url_for('setup.plex_config')) # Or login if setup complete
                except Exception: # Table admin_accounts likely doesn't exist, proceed with creation
                    pass

                admin = AdminAccount(username=form.username.data, is_plex_sso_only=False)
                admin.set_password(form.password.data)
                try:
                    db.session.add(admin)
                    db.session.commit()
                    login_user(admin, remember=True) # Log in the newly created admin
                    log_event(EventType.ADMIN_LOGIN_SUCCESS, f"Admin '{admin.username}' created and logged in (setup).", admin_id=admin.id) # Use admin.id
                    flash('Admin account created successfully.', 'success')
                    return redirect(url_for('setup.plex_config'))
                except Exception as e_db_commit:
                    db.session.rollback()
                    current_app.logger.error(f"DB error creating admin account: {e_db_commit}", exc_info=True)
                    error_message = "Database error creating admin account. Check logs." # Display generic to user
            else:
                # Form validation failed for username/password
                error_message = "Please correct the errors below for username/password setup."
                # Errors will be displayed by the form fields themselves in the template
    
    # Fallback: Render the page if it's an initial GET, or if a POST/GET for SSO had an error,
    # or if username/password POST validation failed.
    return render_template('setup/account_setup.html',
                           form=form,
                           error_message=error_message,
                           completed_steps=get_completed_steps(),
                           current_step_id='account')

@bp.route('/plex_sso_callback_setup_admin') 
def plex_sso_callback_setup_admin():
    pin_id_from_session = session.get('plex_pin_id_admin_setup'); client_id_used_for_pin = session.get('plex_client_id_for_pin_check_admin_setup')
    if not pin_id_from_session or not client_id_used_for_pin:
        flash('Plex login callback invalid or session expired.', 'danger'); current_app.logger.warning("Plex SSO Callback (Setup): Missing pin_id or client_id in session.")
        return redirect(url_for('setup.account_setup'))
    current_app.logger.info(f"Plex SSO Callback (Setup): Checking PIN ID {pin_id_from_session} with ClientID {client_id_used_for_pin}")
    try:
        headers_for_check = {'X-Plex-Client-Identifier': client_id_used_for_pin, 'Accept': 'application/xml'}
        check_pin_url = PLEX_CHECK_PIN_URL_TEMPLATE.format(pin_id=pin_id_from_session)
        response = requests.get(check_pin_url, headers=headers_for_check, timeout=10); response.raise_for_status()
        pin_data_xml_root = ET.fromstring(response.content); plex_auth_token = pin_data_xml_root.get('authToken')
        if not plex_auth_token: 
            flash('Plex PIN not yet linked or has expired.', 'warning'); current_app.logger.warning(f"Plex SSO Callback (Setup): PIN {pin_id_from_session} checked, but no authToken found.")
            return redirect(url_for('setup.account_setup', show_pin_retry_message=True, pin_code_to_display=session.get('plex_pin_code_admin_setup')))
        plex_account = MyPlexAccount(token=plex_auth_token)
        engine_conn_cb, admin_table_exists_cb = None, False
        try: engine_conn_cb = db.engine.connect(); admin_table_exists_cb = db.engine.dialect.has_table(engine_conn_cb, AdminAccount.__tablename__)
        finally:
            if engine_conn_cb: engine_conn_cb.close()
        if admin_table_exists_cb and AdminAccount.query.first():
            flash('Admin account already exists.', 'warning'); existing_admin = AdminAccount.query.filter_by(plex_uuid=plex_account.uuid).first()
            if existing_admin: login_user(existing_admin, remember=True); return redirect(url_for('setup.plex_config'))
            else: flash("Admin account exists but doesn't match this Plex account.", "danger"); return redirect(url_for('setup.account_setup'))
        admin = AdminAccount(plex_uuid=plex_account.uuid, plex_username=plex_account.username, plex_thumb=plex_account.thumb, email=plex_account.email, is_plex_sso_only=True)
        db.session.add(admin); db.session.commit(); login_user(admin, remember=True)
        log_event(EventType.ADMIN_LOGIN_SUCCESS, f"Admin '{admin.plex_username}' created (Plex SSO setup).")
        flash(f'Admin account for {admin.plex_username} created successfully using Plex.', 'success')
        session.pop('plex_pin_id_admin_setup', None); session.pop('plex_pin_code_admin_setup', None); session.pop('plex_client_id_for_pin_check_admin_setup', None)
        return redirect(url_for('setup.plex_config'))
    except requests.exceptions.HTTPError as e_http:
        if e_http.response.status_code == 404: flash('Plex PIN invalid, expired, or not found. Try again.', 'danger'); current_app.logger.warning(f"Plex SSO Callback (Setup): PIN {pin_id_from_session} check returned 404.")
        else: flash(f'Plex API error checking PIN: {e_http.response.status_code}.', 'danger'); current_app.logger.error(f"Plex SSO Callback (Setup): HTTPError checking PIN {pin_id_from_session}: {e_http}", exc_info=True)
    except ET.ParseError as e_xml: current_app.logger.error(f"Plex SSO Callback (Setup): XML ParseError: {e_xml}", exc_info=True); flash("Error parsing PIN check response from Plex.tv.", "danger")
    except Exception as e: current_app.logger.error(f"Error during Plex PIN check/account creation for admin setup: {e}", exc_info=True); flash(f'An unexpected error: {e}', 'danger')
    session.pop('plex_pin_id_admin_setup', None); session.pop('plex_pin_code_admin_setup', None); session.pop('plex_client_id_for_pin_check_admin_setup', None)
    return redirect(url_for('setup.account_setup'))

@bp.route('/plex', methods=['GET', 'POST'])
@login_required 
def plex_config():
    engine_conn_pc, admin_table_exists_pc = None, False
    try: engine_conn_pc = db.engine.connect(); admin_table_exists_pc = db.engine.dialect.has_table(engine_conn_pc, AdminAccount.__tablename__)
    finally:
        if engine_conn_pc: engine_conn_pc.close()
    if not (admin_table_exists_pc and AdminAccount.query.first()): return redirect(url_for('setup.account_setup'))
    if 'plex' in get_completed_steps() and request.method == 'GET': return redirect(url_for('setup.pum_config'))
    form = PlexConfigForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            if form.connection_tested_successfully.data != 'true': flash('Test connection before saving.', 'warning')
            else:
                Setting.set('PLEX_URL', form.plex_url.data, SettingValueType.STRING, "Plex Server URL"); Setting.set('PLEX_TOKEN', form.plex_token.data, SettingValueType.SECRET, "Plex Auth Token")
                if not Setting.get('SECRET_KEY'):
                    app_secret_key = secrets.token_hex(32)
                    Setting.set('SECRET_KEY', app_secret_key, SettingValueType.SECRET, "Application Secret Key"); current_app.config['SECRET_KEY'] = app_secret_key
                    log_event(EventType.SETTING_CHANGE, "SECRET_KEY generated.")
                log_event(EventType.PLEX_CONFIG_SAVE, f"Plex config saved. URL: {form.plex_url.data}", admin_id=current_user.id)
                flash('Plex configuration saved.', 'success'); return redirect(url_for('setup.pum_config'))
    else: 
        form.plex_url.data = Setting.get('PLEX_URL')
        if form.plex_url.data: form.connection_tested_successfully.data = 'false'
    return render_template('setup/plex_config.html', form=form, completed_steps=get_completed_steps(), current_step_id='plex')

@bp.route('/pum', methods=['GET', 'POST'])
@login_required
def pum_config():
    if not 'plex' in get_completed_steps(): return redirect(url_for('setup.plex_config'))
    if 'pum' in get_completed_steps() and request.method == 'GET': return redirect(url_for('setup.discord_config'))
    form = AppBaseUrlForm()
    if form.validate_on_submit():
        app_base_url = form.app_base_url.data.rstrip('/')
        Setting.set('APP_BASE_URL', app_base_url, SettingValueType.STRING, "Application Base URL"); current_app.config['APP_BASE_URL'] = app_base_url
        if hasattr(g, 'app_base_url'): g.app_base_url = app_base_url
        log_event(EventType.SETTING_CHANGE, f"App Base URL set: {app_base_url}", admin_id=current_user.id)
        flash('App Base URL saved.', 'success'); return redirect(url_for('setup.discord_config'))
    elif request.method == 'GET':
        form.app_base_url.data = Setting.get('APP_BASE_URL') or request.url_root.rstrip('/')
    return render_template('setup/pum_config.html', form=form, completed_steps=get_completed_steps(), current_step_id='pum')

@bp.route('/discord', methods=['GET', 'POST'])
@login_required
def discord_config():
    if not 'pum' in get_completed_steps(): return redirect(url_for('setup.pum_config'))
    form = DiscordConfigForm()
    app_base_url = Setting.get('APP_BASE_URL')
    discord_invite_redirect_uri = url_for('invites.discord_oauth_callback', _external=True) if app_base_url else "Set App Base URL first"
    discord_admin_link_redirect_uri = url_for('auth.discord_callback_admin', _external=True) if app_base_url else "Set App Base URL first"
    if form.validate_on_submit():
        enable_discord = form.enable_discord_oauth.data
        Setting.set('DISCORD_OAUTH_ENABLED', enable_discord, SettingValueType.BOOLEAN, "Enable Discord OAuth for Invites") # Store as bool
        if enable_discord:
            if not form.discord_client_id.data or not form.discord_client_secret.data:
                flash('Discord Client ID and Secret are required if enabled.', 'warning')
                return render_template('setup/discord_config.html', form=form, discord_invite_redirect_uri=discord_invite_redirect_uri, discord_admin_link_redirect_uri=discord_admin_link_redirect_uri, saved_discord_enabled=enable_discord, prev_step_url=url_for('setup.pum_config'), completed_steps=get_completed_steps(), current_step_id='discord')
            Setting.set('DISCORD_CLIENT_ID', form.discord_client_id.data, SettingValueType.STRING); Setting.set('DISCORD_CLIENT_SECRET', form.discord_client_secret.data, SettingValueType.SECRET)
            Setting.set('DISCORD_REDIRECT_URI_INVITE', discord_invite_redirect_uri, SettingValueType.STRING); Setting.set('DISCORD_REDIRECT_URI_ADMIN_LINK', discord_admin_link_redirect_uri, SettingValueType.STRING)
            log_event(EventType.DISCORD_CONFIG_SAVE, "Discord OAuth enabled/configured.", admin_id=current_user.id); flash('Discord configuration saved.', 'success')
        else:
            Setting.set('DISCORD_CLIENT_ID', "", SettingValueType.STRING); Setting.set('DISCORD_CLIENT_SECRET', "", SettingValueType.SECRET)
            log_event(EventType.DISCORD_CONFIG_SAVE, "Discord OAuth disabled.", admin_id=current_user.id); flash('Discord OAuth disabled.', 'info')
        return redirect(url_for('setup.finish_setup'))
    elif request.method == 'GET':
        retrieved_setting = Setting.get('DISCORD_OAUTH_ENABLED', False) # Default to Python bool False
        if isinstance(retrieved_setting, bool): current_discord_enabled = retrieved_setting
        else: current_discord_enabled = str(retrieved_setting).lower() == 'true' # Handle if somehow stored as string
        form.enable_discord_oauth.data = current_discord_enabled
        if current_discord_enabled: form.discord_client_id.data = Setting.get('DISCORD_CLIENT_ID')
    saved_discord_enabled_for_partial = form.enable_discord_oauth.data 
    return render_template('setup/discord_config.html', form=form, discord_invite_redirect_uri=discord_invite_redirect_uri, discord_admin_link_redirect_uri=discord_admin_link_redirect_uri, saved_discord_enabled=saved_discord_enabled_for_partial, prev_step_url=url_for('setup.pum_config'), completed_steps=get_completed_steps(), current_step_id='discord')

@bp.route('/discord/toggle_partial', methods=['POST'])
@login_required
def toggle_discord_partial():
    form = DiscordConfigForm(request.form) 
    app_base_url = Setting.get('APP_BASE_URL')
    discord_invite_redirect_uri = url_for('invites.discord_oauth_callback', _external=True) if app_base_url else "Set App Base URL first"
    discord_admin_link_redirect_uri = url_for('auth.discord_callback_admin', _external=True) if app_base_url else "Set App Base URL first"
    if form.enable_discord_oauth.data:
        form.discord_client_id.data = Setting.get('DISCORD_CLIENT_ID', form.discord_client_id.data)
    # Pass the boolean from the form directly to the partial for its state
    return render_template('settings/_discord_oauth_fields_partial.html', form=form, discord_invite_redirect_uri=discord_invite_redirect_uri, discord_admin_link_redirect_uri=discord_admin_link_redirect_uri, initial_discord_enabled_state=form.enable_discord_oauth.data)


@bp.route('/finish')
@login_required
def finish_setup():
    required_steps_complete = ( AdminAccount.query.first() and Setting.get('PLEX_URL') and Setting.get('PLEX_TOKEN') and Setting.get('APP_BASE_URL'))
    if not required_steps_complete:
        flash("Not all required setup steps are complete.", "warning")
        if not AdminAccount.query.first(): return redirect(url_for('setup.account_setup'))
        if not (Setting.get('PLEX_URL') and Setting.get('PLEX_TOKEN')): return redirect(url_for('setup.plex_config'))
        if not Setting.get('APP_BASE_URL'): return redirect(url_for('setup.pum_config'))
    if not Setting.get('SECRET_KEY'):
        app_secret_key = secrets.token_hex(32)
        Setting.set('SECRET_KEY', app_secret_key, SettingValueType.SECRET, "Application Secret Key"); current_app.config['SECRET_KEY'] = app_secret_key
        log_event(EventType.SETTING_CHANGE, "SECRET_KEY generated at finish.")
    flash('Application setup complete!', 'success'); log_event(EventType.APP_STARTUP, "Setup completed.", admin_id=current_user.id)
    if hasattr(g, 'setup_complete'): g.setup_complete = True; current_app.config['SETUP_COMPLETE'] = True
    return redirect(url_for('dashboard.index'))