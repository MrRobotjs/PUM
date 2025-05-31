# app/sso_discord.py
from flask import Blueprint, current_app, session, jsonify, request, redirect, url_for, flash
import requests
from urllib.parse import urlencode, quote_plus
import secrets

from app.models import get_app_setting

sso_discord_bp = Blueprint('sso_discord', __name__, url_prefix='/sso/discord')

DISCORD_API_BASE = "https://discord.com/api/v10" # Or current stable

def _get_discord_oauth_credentials():
    client_id = get_app_setting('DISCORD_OAUTH_CLIENT_ID')
    client_secret = get_app_setting('DISCORD_OAUTH_CLIENT_SECRET')
    
    app_base_url = get_app_setting('APP_BASE_URL')
    if not app_base_url:
        app_base_url = request.url_root.rstrip('/')
        current_app.logger.warning("Discord SSO: APP_BASE_URL not set for constructing redirect_uri, falling back to request.url_root. This might be incorrect if behind a proxy without proper configuration (e.g. ProxyFix).")

    # Construct redirect_uri using APP_BASE_URL + path from url_for
    callback_path_segment = url_for('sso_discord.discord_oauth_callback', _external=False)
    redirect_uri = f"{app_base_url.rstrip('/')}{callback_path_segment}"
    
    if not client_id or not client_secret:
        current_app.logger.error("Discord SSO: DISCORD_OAUTH_CLIENT_ID or DISCORD_OAUTH_CLIENT_SECRET is not configured in app settings.")
        return None, None, None
    
    current_app.logger.debug(f"Discord SSO: Using Client ID: {client_id[:5]}..., Redirect URI: {redirect_uri}")
    return client_id, client_secret, redirect_uri

@sso_discord_bp.route('/login')
def discord_oauth_login():
    """Redirects the user to Discord for authorization."""
    client_id, _, redirect_uri = _get_discord_oauth_credentials()
    
    original_invite_path = request.args.get('invite_path') # Passed from invite_landing.html JS

    if not client_id or not redirect_uri:
        flash("Discord login is not configured correctly by the administrator. Please contact support.", "danger")
        return redirect(url_for('main.use_invite_link', custom_path=original_invite_path) if original_invite_path else url_for('main.index_or_setup'))

    if original_invite_path:
        session['sso_discord_invite_path'] = original_invite_path # Store for callback
        current_app.logger.info(f"Discord SSO: Storing original invite_path in session: {original_invite_path} for Discord OAuth flow.")
    else:
        session.pop('sso_discord_invite_path', None) # Clear if not provided to avoid using a stale one
        current_app.logger.warning("Discord SSO: original_invite_path not provided to /login route. Callback will redirect to a default page.")

    oauth_state = secrets.token_urlsafe(16)
    session['discord_oauth_state'] = oauth_state # For CSRF protection

    scopes = ['identify'] # Basic scope to get user ID, username, avatar, discriminator
    # Add 'email' scope if you need their email from Discord (requires user consent)
    # Add 'guilds.join' if you intend to programmatically add user to your server
    
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': ' '.join(scopes),
        'state': oauth_state
        # 'prompt': 'consent' # To always show the Discord auth screen, even if previously authorized
    }
    discord_auth_url = f"{DISCORD_API_BASE}/oauth2/authorize?{urlencode(params)}"
    current_app.logger.info(f"Discord SSO: Redirecting user to Discord for authorization: {discord_auth_url}")
    return redirect(discord_auth_url)

@sso_discord_bp.route('/callback')
def discord_oauth_callback():
    """Handles the callback from Discord after user authorization."""
    current_app.logger.info(f"Discord SSO Callback: Received request. Query Args: {request.args}")
    
    # Retrieve the original invite path from session to redirect back correctly
    # Pop it here as it's single-use for this callback flow
    origin_invite_path = session.pop('sso_discord_invite_path', None)
    fallback_redirect_url = url_for('main.use_invite_link', custom_path=origin_invite_path) if origin_invite_path else url_for('main.index_or_setup')

    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'An unknown error occurred with Discord login.')
        flash(f"Discord login failed: {error_description}", "danger")
        current_app.logger.error(f"Discord SSO Callback Error from Discord: {error} - {error_description}")
        return redirect(fallback_redirect_url)

    code = request.args.get('code')
    returned_state = request.args.get('state')
    expected_state = session.pop('discord_oauth_state', None) # Get and clear state

    if not expected_state or returned_state != expected_state:
        flash("Discord login failed due to a security check (invalid state). Please try again.", "danger")
        current_app.logger.error(f"Discord SSO Callback: State mismatch. Expected: '{expected_state}', Got: '{returned_state}'. Possible CSRF.")
        return redirect(fallback_redirect_url)

    if not code:
        flash("Discord login failed: No authorization code was received from Discord.", "danger")
        current_app.logger.error("Discord SSO Callback: 'code' parameter missing in callback from Discord.")
        return redirect(fallback_redirect_url)

    client_id, client_secret, actual_redirect_uri_for_token_exchange = _get_discord_oauth_credentials()
    if not client_id or not client_secret or not actual_redirect_uri_for_token_exchange:
        flash("Discord login is not configured correctly on the server. Please contact an administrator.", "danger")
        current_app.logger.error("Discord SSO Callback: OAuth credentials (ID, Secret, or Redirect URI) missing from server config during token exchange.")
        return redirect(fallback_redirect_url)

    # --- Exchange authorization code for an access token ---
    token_request_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': actual_redirect_uri_for_token_exchange # Must exactly match the one used in /login
    }
    token_request_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    try:
        token_api_url = f"{DISCORD_API_BASE}/oauth2/token"
        # Log data carefully, mask secret
        loggable_token_data = {k: (v[:10]+'...' if k=='client_secret' and v else v) for k,v in token_request_data.items()}
        current_app.logger.info(f"Discord SSO Callback: Exchanging code for token. URL: {token_api_url}. Data: {loggable_token_data}")
        
        token_response = requests.post(token_api_url, data=token_request_data, headers=token_request_headers, timeout=10)
        current_app.logger.info(f"Discord SSO Callback: Token API Response Status: {token_response.status_code}")
        current_app.logger.debug(f"Discord SSO Callback: Token API Response Text (Preview): {token_response.text[:500]}")
        token_response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')

        if not access_token:
            flash("Discord login failed: Could not obtain a valid access token from Discord.", "danger")
            current_app.logger.error(f"Discord SSO Callback: Access token missing from Discord's response. JSON: {token_json}")
            return redirect(fallback_redirect_url)

        # --- Fetch user information using the access token ---
        user_info_headers = {'Authorization': f'Bearer {access_token}'}
        user_info_api_url = f"{DISCORD_API_BASE}/users/@me"
        current_app.logger.info(f"Discord SSO Callback: Fetching user info from {user_info_api_url}")
        
        user_info_response = requests.get(user_info_api_url, headers=user_info_headers, timeout=10)
        current_app.logger.info(f"Discord SSO Callback: User Info API Response Status: {user_info_response.status_code}")
        current_app.logger.debug(f"Discord SSO Callback: User Info API Response Text (Preview): {user_info_response.text[:500]}")
        user_info_response.raise_for_status()
        
        user_info_json = user_info_response.json()
        discord_id = user_info_json.get('id')
        discord_username = user_info_json.get('username')
        # For full username like "User#1234" or new unique usernames:
        # discord_discriminator = user_info_json.get('discriminator')
        # full_display_username = f"{discord_username}#{discord_discriminator}" if discord_discriminator and discord_discriminator != "0" else discord_username
        
        if discord_id:
            session['sso_discord_id'] = str(discord_id) # Ensure it's stored as a string
            session['sso_discord_username'] = discord_username # Store the base username; discriminator might not be needed for display
            flash(f"Successfully logged in with Discord as {discord_username}! Your ID should be pre-filled.", "success")
            current_app.logger.info(f"Discord SSO: User '{discord_username}' (ID: {discord_id}) authenticated successfully via OAuth.")
        else:
            flash("Discord login was successful, but we could not retrieve your Discord ID. Please enter it manually.", "warning")
            current_app.logger.warning(f"Discord SSO Callback: User info fetched from Discord, but 'id' field was missing. JSON: {user_info_json}")

    except requests.exceptions.HTTPError as e_http:
        error_details = e_http.response.text[:500] if e_http.response is not None else "No response details."
        flash(f"Error communicating with Discord (HTTP {e_http.response.status_code if e_http.response is not None else 'N/A'}). Details: {error_details}", "danger")
        current_app.logger.error(f"Discord SSO Callback: HTTPError during token exchange or user info fetch: {e_http}. Response: {error_details}", exc_info=True)
    except requests.exceptions.RequestException as e_req: # Handles connection errors, timeouts, etc.
        flash("A connection error occurred while trying to log in with Discord. Please try again.", "danger")
        current_app.logger.error(f"Discord SSO Callback: RequestException: {e_req}", exc_info=True)
    except Exception as e_general: # Catch-all for other issues like JSONDecodeError
        flash("An unexpected error occurred during the Discord login process. Please try again.", "danger")
        current_app.logger.error(f"Discord SSO Callback: Unexpected error: {e_general}", exc_info=True)
    
    return redirect(fallback_redirect_url)