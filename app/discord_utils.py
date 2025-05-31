import requests
from app.models import get_app_setting # For DISCORD_BOT_TOKEN, DISCORD_SERVER_ID
from flask import current_app # For logging
# import asyncio # Only needed if using asyncio.run_coroutine_threadsafe for an async helper here

DISCORD_API_BASE_URL = "https://discord.com/api/v10" # Use a recent, stable API version

def _get_bot_token():
    """Helper to retrieve the bot token from app settings."""
    return get_app_setting('DISCORD_BOT_TOKEN')

def _get_server_id():
    """Helper to retrieve the server ID from app settings."""
    return get_app_setting('DISCORD_SERVER_ID')

def test_discord_bot_token(token_to_test):
    """
    Tests if a given Discord Bot Token is valid by fetching the bot's own user info.
    Returns: (bool: is_valid, str: message)
    """
    if not token_to_test:
        return False, "Discord Bot Token cannot be empty."
    
    headers = {"Authorization": f"Bot {token_to_test.strip()}"}
    try:
        # Increased timeout for potentially slow Discord API response
        response = requests.get(f"{DISCORD_API_BASE_URL}/users/@me", headers=headers, timeout=10) 
        
        if response.status_code == 200:
            bot_user_data = response.json()
            username = bot_user_data.get('username', 'UnknownBot')
            discriminator = bot_user_data.get('discriminator', '0000')
            if discriminator == '0': # New username system
                full_username = username
            else:
                full_username = f"{username}#{discriminator}"
            return True, f"Token valid for bot: {full_username}"
        elif response.status_code == 401:
            return False, "Invalid Discord Bot Token (Unauthorized - 401)."
        else:
            # Log the actual error response for admin debugging
            if current_app and current_app.logger: 
                current_app.logger.warning(f"Discord token validation HTTP error: {response.status_code} - {response.text[:200]}")
            return False, f"Error validating token with Discord API: HTTP {response.status_code}."
    except requests.exceptions.Timeout:
        if current_app and current_app.logger: current_app.logger.warning("Discord token validation: Connection to Discord API timed out.")
        return False, "Connection to Discord API timed out."
    except requests.exceptions.RequestException as e:
        if current_app and current_app.logger: current_app.logger.error(f"Discord token validation connection error: {e}", exc_info=True)
        return False, f"Connection error to Discord API: {str(e)[:100]}"
    except Exception as e:
        if current_app and current_app.logger: current_app.logger.error(f"Unexpected error during Discord token validation: {e}", exc_info=True)
        return False, f"Unexpected error: {str(e)[:100]}"


def is_discord_user_on_server(discord_user_id_to_check):
    """
    Checks if a Discord user (by ID) is present on the configured Discord server using direct API calls.
    Returns: (bool: is_on_server, str: message)
    """
    bot_token = _get_bot_token()
    server_id = _get_server_id()

    if not discord_user_id_to_check or not discord_user_id_to_check.isdigit():
        return False, "Invalid Discord User ID format provided for check."

    if not bot_token or not server_id:
        # This function might be called even if bot features are partially configured.
        # The calling function should decide if this is a critical failure.
        return False, "Discord Bot Token or Server ID not configured in app settings. Cannot verify member."

    headers = {"Authorization": f"Bot {bot_token.strip()}"}
    try:
        # Attempt to fetch the member from the guild
        url = f"{DISCORD_API_BASE_URL}/guilds/{server_id.strip()}/members/{discord_user_id_to_check.strip()}"
        response = requests.get(url, headers=headers, timeout=10) # Increased timeout
        
        if response.status_code == 200:
            return True, "User is present on the configured Discord server."
        elif response.status_code == 404: # User not found in guild
            return False, "User not found on the Discord server."
        elif response.status_code == 401: 
            if current_app and current_app.logger: current_app.logger.error("Discord API (is_user_on_server) 401: Bot token is invalid or revoked.")
            return False, "Discord Bot Token became invalid. Admin should check settings."
        elif response.status_code == 403: 
            if current_app and current_app.logger: current_app.logger.error(f"Discord API (is_user_on_server) 403: Bot missing 'View Members' (or similar) permission for server {server_id}.")
            return False, "Discord Bot lacks permissions on the server to verify members."
        else:
            if current_app and current_app.logger: current_app.logger.warning(f"Discord API error (is_user_on_server) checking member {discord_user_id_to_check}: HTTP {response.status_code} - {response.text[:200]}")
            return False, f"Could not verify Discord status (API Error HTTP {response.status_code})."
    except requests.exceptions.Timeout:
        return False, "Connection to Discord API timed out while checking member status."
    except requests.exceptions.RequestException as e:
        if current_app and current_app.logger: current_app.logger.error(f"Discord API connection error (is_user_on_server): {e}", exc_info=True)
        return False, f"Could not connect to Discord API to check member status: {str(e)[:100]}"
    except Exception as e:
        if current_app and current_app.logger: current_app.logger.error(f"Unexpected error in is_discord_user_on_server: {e}", exc_info=True)
        return False, f"Unexpected error checking member status: {str(e)[:100]}"


def get_discord_user_details_by_id_sync(discord_user_id_str):
    """
    Synchronously fetches Discord user details (username#discriminator or new unique username) by making a direct API call.
    This is a blocking call.
    Returns: (str: full_username_or_None, str: error_message_or_None)
    """
    bot_token = _get_bot_token()
    if not bot_token:
        return None, "Discord Bot Token not configured. Cannot fetch username."
    if not discord_user_id_str or not discord_user_id_str.isdigit():
        return None, "Invalid or missing Discord User ID for fetching details."

    headers = {"Authorization": f"Bot {bot_token.strip()}"}
    url = f"{DISCORD_API_BASE_URL}/users/{discord_user_id_str.strip()}"
    try:
        response = requests.get(url, headers=headers, timeout=7) # Slightly shorter timeout for user lookup
        if response.status_code == 200:
            user_data = response.json()
            username = user_data.get('username')
            discriminator = user_data.get('discriminator')
            # global_name = user_data.get('global_name') # New display name, might be None

            if not username: # Should not happen for a valid user object
                return None, "Discord API returned user data without a username."

            if discriminator and discriminator != '0000' and discriminator != '0': # Legacy username with discriminator
                full_username = f"{username}#{discriminator}"
            else: # New unique username system (discriminator is "0" or "0000" or field might be absent for new users)
                full_username = username # global_name can also be used for display if preferred
            return full_username, None 
        elif response.status_code == 404:
            return None, "Discord user with that ID not found."
        else:
            if current_app and current_app.logger: current_app.logger.warning(f"Discord API error fetching user {discord_user_id_str}: HTTP {response.status_code} - {response.text[:200]}")
            return None, f"Discord API error (HTTP {response.status_code})."
    except requests.exceptions.Timeout:
        return None, "Connection to Discord API timed out while fetching user details."
    except requests.exceptions.RequestException as e:
        if current_app and current_app.logger: current_app.logger.error(f"Discord API connection error fetching user details: {e}", exc_info=True)
        return None, f"Connection error to Discord API: {str(e)[:100]}"
    except Exception as e: 
        if current_app and current_app.logger: current_app.logger.error(f"Unexpected error fetching Discord user details for ID {discord_user_id_str}: {e}", exc_info=True)
        return None, f"Unexpected error: {str(e)[:100]}"

# The async version (get_discord_user_details_by_id_async) might not be needed if the sync version
# is always used from Flask routes, and the discord.py bot uses its own `bot.fetch_user()`
# for its internal async operations. If you specifically need an async helper that uses `requests`
# (e.g., if `aiohttp` is not a project dependency), it would be similar to the sync version
# but would need to be run in an async context or via an async HTTP library.
# For now, the synchronous `get_discord_user_details_by_id_sync` is the primary one used by routes.