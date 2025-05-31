# app/plex_utils.py
import requests
from plexapi.server import PlexServer
from plexapi.exceptions import Unauthorized, NotFound, BadRequest 
from plexapi.myplex import MyPlexAccount
from app.models import get_app_setting
from flask import current_app
import logging 
import xml.etree.ElementTree as ET
from datetime import datetime, timezone # Keep for other potential uses, though not for lastSeenAt here

_plex_instance = None
_plex_instance_config_key = None 

# ... (get_plex_server, test_plex_connection, get_plex_libraries, invite_to_plex, 
#      get_user_shared_library_titles, remove_plex_friend, get_users_sharing_servers_with_me
#      remain the SAME as your last correct versions of these functions) ...
def get_plex_server(force_reconnect=False):
    global _plex_instance, _plex_instance_config_key
    logger = current_app.logger if current_app else logging.getLogger(__name__)

    current_plex_url = get_app_setting('PLEX_URL')
    current_plex_token = get_app_setting('PLEX_TOKEN')
    
    if not current_plex_url or not current_plex_token:
        logger.warning("Plex_utils: PLEX_URL or PLEX_TOKEN not configured.")
        _plex_instance = None 
        return None

    current_config_key = f"{current_plex_url}_{current_plex_token}"

    if _plex_instance is not None and current_config_key == _plex_instance_config_key and not force_reconnect:
        try:
            _plex_instance.clients() 
            logger.debug("Plex_utils: Using cached PlexServer instance.")
            return _plex_instance
        except (requests.exceptions.RequestException, Unauthorized, Exception) as e:
            logger.warning(f"Plex_utils: Existing Plex connection check failed ({type(e).__name__}), attempting to reconnect: {str(e)[:100]}")
            _plex_instance = None 

    logger.info(f"Plex_utils: Initializing new PlexServer instance for URL: {current_plex_url[:30]}...")
    try:
        session = requests.Session()
        timeout_str = get_app_setting('PLEX_API_TIMEOUT', '15')
        try:
            session.timeout = int(timeout_str)
        except ValueError:
            logger.warning(f"Plex_utils: Invalid PLEX_API_TIMEOUT value '{timeout_str}'. Defaulting to 15s.")
            session.timeout = 15
        
        new_instance = PlexServer(current_plex_url, current_plex_token, session=session)
        account_info = new_instance.account() 
        
        _plex_instance = new_instance
        _plex_instance_config_key = current_config_key
        logger.info(f"Plex_utils: Successfully connected to Plex server: {getattr(_plex_instance, 'friendlyName', 'Unknown Server')}, Account: {getattr(account_info, 'username', 'Unknown User')}")
        return _plex_instance
    except Unauthorized:
        logger.error("Plex_utils: Plex Unauthorized. Please check your Plex Token in settings.")
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        logger.error(f"Plex_utils: Plex connection error or timeout - {e}")
    except BadRequest as e_br: 
        logger.error(f"Plex_utils: Plex bad request - likely invalid URL or not a Plex server: {e_br}")
    except Exception as e_other: 
        logger.error(f"Plex_utils: An unexpected error occurred during Plex connection: {e_other}", exc_info=True)
    
    _plex_instance = None 
    return None

def test_plex_connection(url, token):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    if not url or not token:
        return False, "Plex URL and Token are required for testing."
    try:
        session = requests.Session()
        session.timeout = 10 
        test_server = PlexServer(url, token, session=session)
        account_info = test_server.account() 
        return True, f"Connection successful. Server: {test_server.friendlyName}, Account: {account_info.username}"
    except Unauthorized:
        return False, "Unauthorized. Check Plex Token."
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        return False, f"Connection error or timeout: {str(e)[:150]}. Check URL."
    except BadRequest: 
        return False, "Bad request. Ensure URL is correct (e.g. http://host:port) and it's a Plex server."
    except Exception as e:
        logger.error(f"Plex_utils (test_plex_connection): Unexpected error: {e}", exc_info=True)
        return False, f"An unexpected error: {str(e)[:100]}"

def get_plex_libraries():
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    plex = get_plex_server()
    if not plex:
        logger.warning("Plex_utils (get_plex_libraries): Plex server not connected.")
        return []
    try:
        libraries = plex.library.sections()
        return [{"id": section.key, "uuid": section.uuid, "title": section.title, "type": section.type}
                for section in libraries]
    except Exception as e:
        logger.error(f"Plex_utils: Error fetching Plex libraries: {e}", exc_info=True)
        return []

def invite_to_plex(email_or_username_to_invite, library_titles=None):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    
    plex_tv_token = get_app_setting('PLEX_TOKEN')
    plex_server_url_setting = get_app_setting('PLEX_URL')

    if not plex_tv_token:
        return False, "Plex Account Token not configured. Cannot manage shares."
    if not plex_server_url_setting:
        return False, "Your Plex Server URL not configured."

    my_plex_account = None
    server_to_share_from = None
    target_machine_identifier = None

    try:
        my_plex_account = MyPlexAccount(token=plex_tv_token)
        
        temp_server_connection = PlexServer(plex_server_url_setting, plex_tv_token, timeout=5)
        target_machine_identifier = temp_server_connection.machineIdentifier

        found_resource = False
        for resource in my_plex_account.resources():
            if resource.product == "Plex Media Server" and resource.clientIdentifier == target_machine_identifier:
                try:
                    server_to_share_from = resource.connect(timeout=5)
                    found_resource = True
                    break
                except Exception as e_connect_resource:
                     logger.error(f"Plex Share: Failed to connect to server resource '{resource.name}': {e_connect_resource}", exc_info=True)
        
        if not found_resource or not server_to_share_from:
            return False, "Your configured Plex server not found as an accessible resource of the authenticated Plex account."

    except Exception as e_acct_init:
        return False, f"Error with Plex account setup/server ID: {str(e_acct_init)[:100]}"

    target_user_identifier_str = str(email_or_username_to_invite).strip()
    plex_user_object = None
    is_existing_friend = False

    try:
        plex_user_object = my_plex_account.user(target_user_identifier_str)
        if plex_user_object: is_existing_friend = True
    except NotFound: pass 
    except Exception as e_fetch_user:
        return False, f"Error identifying target Plex user '{target_user_identifier_str}': {str(e_fetch_user)[:100]}"

    sections_to_share_plexapi_objs = []
    all_available_libs_on_server = server_to_share_from.library.sections()

    if library_titles is not None:
        for title in library_titles:
            found_lib = next((lib for lib in all_available_libs_on_server if lib.title == title), None)
            if found_lib: sections_to_share_plexapi_objs.append(found_lib)
            else: logger.warning(f"Plex Share: Library '{title}' for '{target_user_identifier_str}' not found on server '{server_to_share_from.friendlyName}'.")
        
        if library_titles and not sections_to_share_plexapi_objs:
            return False, f"None of the specified libraries for '{target_user_identifier_str}' matched. No shares changed."
            
    sections_param_for_api = None 
    remove_sections_param = False
    
    if library_titles is not None:
        sections_param_for_api = sections_to_share_plexapi_objs
        if not sections_to_share_plexapi_objs: remove_sections_param = True

    try:
        action_performed_log_str = ""
        if is_existing_friend and plex_user_object:
            action_performed_log_str = "shares updated"
            my_plex_account.updateFriend(user=plex_user_object, server=server_to_share_from, sections=sections_param_for_api, removeSections=remove_sections_param)
        else:
            action_performed_log_str = "invite sent"
            my_plex_account.inviteFriend(user=target_user_identifier_str, server=server_to_share_from, sections=sections_param_for_api)

        final_shared_libs_message = ", ".join([s.title for s in sections_param_for_api]) if sections_param_for_api else ("no specific libraries" if remove_sections_param else "all libraries (server default)")
        return True, f"Plex {action_performed_log_str} for '{target_user_identifier_str}' for libraries: {final_shared_libs_message}."
    except NotFound:
        return False, f"User '{target_user_identifier_str}' not found by Plex (ensure email/username is correct)."
    except BadRequest as e_br:
        return False, f"Plex API bad request: {str(e_br)[:150]}"
    except Exception as e_final:
        return False, f"Failed to update/send Plex invite: {str(e_final)[:150]}"


def get_user_shared_library_titles(plex_user_identifier_or_id):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    plex = get_plex_server() 
    if not plex: return None 
    try:
        my_plex_account = plex.myPlexAccount()
        target_friend_account = None
        try:
            target_friend_account = my_plex_account.user(plex_user_identifier_or_id)
            if not target_friend_account: return []
        except NotFound: return [] 
        except Exception as e_find_user:
            logger.error(f"Plex_utils: Error trying to find friend '{plex_user_identifier_or_id}': {e_find_user}", exc_info=True)
            return None

        shared_titles = []
        found_our_server_for_friend = False
        for server_instance_friend_sees in target_friend_account.servers:
            if server_instance_friend_sees.machineIdentifier == plex.machineIdentifier:
                found_our_server_for_friend = True
                shared_sections_for_this_user = server_instance_friend_sees.sections()
                shared_titles = [section.title for section in shared_sections_for_this_user]
                break 
        if not found_our_server_for_friend: return []
        return shared_titles
    except Exception as e:
        logger.error(f"Plex_utils: General error getting shared libraries for '{plex_user_identifier_or_id}': {e}", exc_info=True)
        return None 

def remove_plex_friend(username_or_email_of_friend):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    plex = get_plex_server()
    if not plex: return False, "Plex server not configured or unreachable."
    try:
        target_user_identifier = username_or_email_of_friend.strip()
        user_to_remove_account = plex.myPlexAccount().user(target_user_identifier) 
        if user_to_remove_account:
            plex.myPlexAccount().removeFriend(user_to_remove_account) 
            return True, f"User '{target_user_identifier}' successfully removed from Plex friends."
        return False, f"User '{target_user_identifier}' not found as a Plex friend." 
    except NotFound:
         return False, f"User '{target_user_identifier}' not found in your Plex account's friend list."
    except Exception as e:
        logger.error(f"Error removing Plex friend '{target_user_identifier}': {e}", exc_info=True)
        return False, f"Error removing Plex friend: {str(e)[:150]}"


def get_shared_plex_users_info():
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    plex_token = get_app_setting('PLEX_TOKEN')
    local_plex_server = get_plex_server()

    if not local_plex_server or not plex_token:
        logger.warning("Plex_utils (get_shared_users): Plex server or token not configured.")
        return [], "Plex server or token not configured for fetching users."

    my_server_machine_id = local_plex_server.machineIdentifier
    if not my_server_machine_id:
        logger.error("Plex_utils (get_shared_users): Could not determine this server's machineIdentifier.")
        return [], "Could not identify this server's machine ID."

    api_url = "https://plex.tv/api/users"
    headers = {
        "X-Plex-Token": plex_token,
        "X-Plex-Client-Identifier": get_app_setting('APP_NAME', 'PlexUserManager') + "-UserSync",
        "Accept": "application/xml"
    }
    users_info = []
    response = None
    try:
        logger.info(f"Plex_utils: Fetching user list from {api_url} (expecting XML).")
        response = requests.get(api_url, headers=headers, timeout=20)
        logger.debug(f"Plex_utils: /api/users response status: {response.status_code}")
        response.raise_for_status()
        
        root = ET.fromstring(response.content)
        plex_tv_account_users = root.findall("User")

        if not plex_tv_account_users:
            logger.info("Plex_utils: No <User> elements found in /api/users XML response.")
            return [], "No users returned from Plex.tv user API."

        owner_plex_id = None
        try:
            if local_plex_server.myPlexAccount():
                 owner_plex_id = int(local_plex_server.myPlexAccount().id)
        except Exception as e_owner:
            logger.warning(f"Plex_utils: Could not determine owner's Plex ID: {e_owner}")

        for user_node in plex_tv_account_users:
            user_id_str = user_node.get("id")
            if not user_id_str: continue
            user_id = int(user_id_str)

            if owner_plex_id and user_id == owner_plex_id:
                logger.debug(f"Plex_utils: Skipping owner account (ID: {user_id}) in user list.")
                continue

            username = user_node.get("title") 
            email = user_node.get("email")
            is_home = bool(int(user_node.get("home", "0")))
            thumb = user_node.get("thumb")
            api_username_attr = user_node.get("username")
            
            has_access_to_our_server = False
            # REMOVED: api_last_seen_on_our_server_dt initialization and parsing

            user_servers = user_node.findall("Server")
            for server_entry in user_servers:
                if server_entry.get("machineIdentifier") == my_server_machine_id:
                    if bool(int(server_entry.get("pending", "0"))):
                        logger.info(f"Plex_utils: Share with {username or email} (ID: {user_id}) for server {my_server_machine_id} is pending. Excluding.")
                        has_access_to_our_server = False
                        break
                    has_access_to_our_server = True
                    # REMOVED: lastSeenAt timestamp parsing for this server entry
                    break 
            
            if has_access_to_our_server:
                user_dict = {
                    'plex_id': user_id, 
                    'username': username, 
                    'email': email,
                    'is_home_user': is_home, 
                    'thumb_url': thumb,
                    'plex_api_username_attr': api_username_attr,
                    # REMOVED: 'api_last_seen_on_server': api_last_seen_on_our_server_dt 
                }
                if user_dict['email'] or user_dict['username'] or user_dict['plex_id']:
                    users_info.append(user_dict)
                else:
                    logger.warning(f"Plex user sync: Skipped user from plex.tv/api/users with no email, username/title, or Plex ID.")

        return users_info, f"Fetched {len(users_info)} users with detected access to server '{local_plex_server.friendlyName}' from plex.tv."
    except requests.exceptions.HTTPError as e:
        logger.error(f"Plex_utils: HTTP error fetching users from {api_url}: {e.response.status_code if e.response else 'N/A'}", exc_info=False)
        return [], f"HTTP error {e.response.status_code if e.response else 'N/A'} from Plex.tv API."
    except ET.ParseError as e_xml:
        status_code_for_log = response.status_code if response is not None else 'N/A'
        response_text_for_log = response.text[:500] if response is not None and response.text else '[No Response Text Available]'
        logger.error(f"Plex_utils: XML parsing error from {api_url}. Status: {status_code_for_log}. Response: {response_text_for_log}. Error: {e_xml}", exc_info=True)
        return [], "Error parsing user data XML from Plex.tv API."
    except Exception as e_other:
        logger.error(f"Plex_utils: Unexpected error in get_shared_plex_users_info: {e_other}", exc_info=True)
        return [], f"Unexpected error fetching users: {str(e_other)[:150]}"

def get_users_sharing_servers_with_me():
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    plex_token = get_app_setting('PLEX_TOKEN')
    if not plex_token:
        logger.warning("Plex_utils (get_users_sharing_with_me): PLEX_TOKEN not configured.")
        return set() 
    try:
        logger.info("Plex_utils: Fetching list of servers shared with the configured Plex account...")
        my_account = MyPlexAccount(token=plex_token) 
        users_sharing_with_me_identifiers = set()
        for resource in my_account.resources(): 
            if resource.product == "Plex Media Server" and getattr(resource, 'owned', True) is False:
                owner_id_val = resource.ownerId
                owner_id_int = None
                if owner_id_val is not None:
                    try: owner_id_int = int(owner_id_val)
                    except ValueError: logger.warning(f"Plex_utils: ownerId '{owner_id_val}' is not valid int for resource '{resource.name}'."); continue
                if owner_id_int:
                    try:
                        sharing_user_account = my_account.user(owner_id_int)
                        identifier = None
                        if sharing_user_account.username and sharing_user_account.username.strip(): identifier = sharing_user_account.username.lower()
                        elif sharing_user_account.email and sharing_user_account.email.strip(): identifier = sharing_user_account.email.lower()
                        if identifier: users_sharing_with_me_identifiers.add(identifier); logger.debug(f"Plex_utils: User '{identifier}' (ID: {owner_id_int}) shares server '{resource.name}'.")
                        else: logger.warning(f"Plex_utils: Shared server '{resource.name}' (Owner ID {owner_id_int}), but no username/email found for owner.")
                    except NotFound: logger.warning(f"Plex_utils: Could not find user for owner ID {owner_id_int} of shared server '{resource.name}'.")
                    except Exception as e_detail: logger.error(f"Plex_utils: Error fetching owner details for shared server '{resource.name}' (Owner ID: {owner_id_int}): {e_detail}", exc_info=False)
                else: logger.warning(f"Plex_utils: Shared server '{resource.name}' missing valid ownerId.")
        logger.info(f"Plex_utils: Found {len(users_sharing_with_me_identifiers)} unique users sharing their servers.")
        return users_sharing_with_me_identifiers
    except Unauthorized: logger.error("Plex_utils (get_users_sharing_with_me): Plex Unauthorized. Check PLEX_TOKEN."); return set()
    except Exception as e: logger.error(f"Plex_utils (get_users_sharing_with_me): Unexpected error: {e}", exc_info=True); return set()