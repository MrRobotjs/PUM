# File: app/services/plex_service.py
from flask import current_app
from plexapi.server import PlexServer
from plexapi.myplex import MyPlexAccount
from plexapi.exceptions import Unauthorized, NotFound, BadRequest
import requests
import xml.etree.ElementTree as ET
from app.models import Setting, EventType # Adjust path if needed
from app.utils.helpers import log_event # Adjust path if needed
from datetime import datetime, timezone # Keep for other parts if needed, but not for plex_server_status_data's time

# --- Module-level variables to store last check status ---
_last_plex_check_time = None
_last_plex_check_status_online = False
_last_plex_check_error_message = "Not yet checked."
_last_plex_server_friendly_name = None
_last_plex_server_version = None
# ---------------------------------------------------------

_plex_server_instance = None
_plex_server_instance_config_key = None 

def get_plex_instance(force_reconnect=False):
    global _plex_server_instance, _plex_server_instance_config_key
    global _last_plex_check_time, _last_plex_check_status_online
    global _last_plex_check_error_message, _last_plex_server_friendly_name, _last_plex_server_version
    
    logger = current_app.logger 
    
    # Do NOT update _last_plex_check_time here unconditionally.
    # It should only be updated when an actual check/connection attempt is made.

    try:
        current_plex_url = Setting.get('PLEX_URL')
        current_plex_token = Setting.get('PLEX_TOKEN')
        if not current_plex_url or not current_plex_token: # Check early if config is missing
            logger.warning("Plex_Service.py - get_plex_instance(): PLEX_URL or PLEX_TOKEN not configured.")
            _last_plex_check_status_online = False; _last_plex_check_error_message = "Plex not configured."
            _last_plex_check_time = datetime.now(timezone.utc) # Config check is a "check"
            _last_plex_server_friendly_name = None; _last_plex_server_version = None
            _plex_server_instance = None; _plex_server_instance_config_key = None # Clear cache
            return None
        timeout_str = Setting.get('PLEX_TIMEOUT', str(current_app.config.get('PLEX_TIMEOUT', 10)))
        try: timeout = int(timeout_str)
        except ValueError: timeout = 10
    except RuntimeError as e: 
        logger.error(f"Plex_Service.py - get_plex_instance(): Cannot get Plex settings: {e}")
        _last_plex_check_status_online = False; _last_plex_check_error_message = "App context error during settings load."
        _last_plex_check_time = datetime.now(timezone.utc) # Attempt to get settings is a "check"
        _last_plex_server_friendly_name = None; _last_plex_server_version = None
        _plex_server_instance = None; _plex_server_instance_config_key = None
        return None

    new_config_key = f"{current_plex_url}_{current_plex_token}"

    if not force_reconnect and _plex_server_instance and new_config_key == _plex_server_instance_config_key:
        try:
            _ = _plex_server_instance.friendlyName # Lightweight check
            logger.debug("Plex_Service.py - get_plex_instance(): Using cached and validated PlexServer instance.")
            # Status variables should already be set from the time this instance was cached.
            # We do NOT update _last_plex_check_time here, as we are using a cache.
            return _plex_server_instance
        except (requests.exceptions.RequestException, Unauthorized, NotFound, Exception) as e:
            logger.warning(f"Plex_Service.py - get_plex_instance(): Cached Plex connection check failed ({type(e).__name__}), attempting to reconnect.")
            _plex_server_instance = None 

    logger.info(f"Plex_Service.py - get_plex_instance(): Attempting NEW connection to Plex server: {current_plex_url}")
    _last_plex_check_time = datetime.now(timezone.utc) # <<<< UPDATE TIME ONLY FOR ACTUAL NEW CONNECTION/RECONNECT ATTEMPT

    try:
        session = requests.Session(); session.timeout = timeout 
        server = PlexServer(baseurl=current_plex_url, token=current_plex_token, session=session)
        
        _last_plex_server_friendly_name = server.friendlyName 
        _last_plex_server_version = server.version
        _plex_server_instance = server
        _plex_server_instance_config_key = new_config_key 
        _last_plex_check_status_online = True 
        _last_plex_check_error_message = None 
        logger.info(f"Plex_Service.py - get_plex_instance(): Successfully connected to Plex: {_last_plex_server_friendly_name} (v{_last_plex_server_version})")
        return server
    except Exception as e: # Catch all specific exceptions as before, then a general one
        _plex_server_instance = None; _plex_server_instance_config_key = None # Clear cache on any failure
        _last_plex_check_status_online = False
        _last_plex_server_friendly_name = None; _last_plex_server_version = None
        if isinstance(e, Unauthorized):
            _last_plex_check_error_message = "Unauthorized. Check Plex Token."
            logger.error(f"Plex_Service.py - get_plex_instance(): {_last_plex_check_error_message}")
        elif isinstance(e, NotFound):
            _last_plex_check_error_message = "Server not found. Check Plex URL."
            logger.error(f"Plex_Service.py - get_plex_instance(): {_last_plex_check_error_message}")
        elif isinstance(e, requests.exceptions.RequestException):
            _last_plex_check_error_message = f"Network error: {type(e).__name__}"
            logger.error(f"Plex_Service.py - get_plex_instance(): {_last_plex_check_error_message} - {e}")
        else:
            _last_plex_check_error_message = f"Unexpected error connecting: {type(e).__name__}"
            logger.error(f"Plex_Service.py - get_plex_instance(): {_last_plex_check_error_message} - {e}", exc_info=True)
    return None


def get_last_plex_connection_status():
    global _last_plex_check_time, _last_plex_check_status_online
    global _last_plex_check_error_message, _last_plex_server_friendly_name, _last_plex_server_version

    # If never checked (_last_plex_check_time is None) OR if Plex is not configured,
    # then trigger a check by calling get_plex_instance.
    # get_plex_instance() itself will update the _last_plex_check_time.
    if _last_plex_check_time is None or not (Setting.get('PLEX_URL') and Setting.get('PLEX_TOKEN')):
        current_app.logger.debug("Plex_Service.py - get_last_plex_connection_status(): Initial check or config missing. Triggering get_plex_instance.")
        get_plex_instance(force_reconnect=True) # This call will update all the _last_plex... vars
    
    # Now, return the current state of the module-level variables
    return {
        'online': _last_plex_check_status_online,
        'friendly_name': _last_plex_server_friendly_name,
        'version': _last_plex_server_version,
        'error_message': _last_plex_check_error_message,
        'last_check_time': _last_plex_check_time
    }

def get_plex_admin_account():
    logger = current_app.logger
    try:
        plex_token = Setting.get('PLEX_TOKEN') 
    except RuntimeError as e:
        logger.error(f"Plex Service: Cannot get PLEX_TOKEN for MyPlexAccount, possibly outside app context: {e}")
        return None
    if not plex_token:
        logger.error("Plex Service: PLEX_TOKEN not configured for admin MyPlexAccount.")
        return None
    try:
        admin_plex_account = MyPlexAccount(token=plex_token)
        _ = admin_plex_account.username 
        return admin_plex_account
    except Unauthorized:
        logger.error("Plex Service: MyPlexAccount authentication failed (Unauthorized). Check PLEX_TOKEN.")
        log_event(EventType.ERROR_PLEX_API, "Admin MyPlexAccount auth failed: Unauthorized token.")
    except Exception as e:
        logger.error(f"Plex Service: Failed to get MyPlexAccount instance: {e}", exc_info=True)
        log_event(EventType.ERROR_PLEX_API, f"Failed to get MyPlexAccount instance: {e}")
    return None

def get_plex_libraries(force_refresh=False):
    plex = get_plex_instance(force_reconnect=force_refresh) # <<< CALLING WITH reconnect, which should match force_reconnect
    if plex:
        try: return plex.library.sections()
        except Exception as e: current_app.logger.error(f"Error fetching Plex libraries: {e}", exc_info=True); log_event(EventType.ERROR_PLEX_API, f"Error fetching libraries: {e}")
    return []

def get_plex_libraries_dict(force_refresh=False):
    libraries = get_plex_libraries(force_refresh=force_refresh) # Pass argument along
    return {str(lib.key): lib.title for lib in libraries} if libraries else {}

def get_library_names_by_ids(library_ids):
    if not library_ids: return []
    all_libs_dict = get_plex_libraries_dict()
    return [all_libs_dict.get(str(lib_id), f"Unknown Library (ID: {lib_id})") for lib_id in library_ids]

def get_user_ids_sharing_servers_with_admin():
    admin_account = get_plex_admin_account()
    if not admin_account: return set()
    owner_ids_sharing_with_admin = set()
    try:
        for resource in admin_account.resources():
            if resource.product == "Plex Media Server" and getattr(resource, 'owned', True) is False:
                owner_id_str = getattr(resource, 'ownerId', None)
                if owner_id_str:
                    try: owner_ids_sharing_with_admin.add(int(owner_id_str))
                    except ValueError: current_app.logger.warning(f"Plex Service: Invalid ownerId '{owner_id_str}' for resource '{resource.name}'.")
        current_app.logger.info(f"Plex Service: Found {len(owner_ids_sharing_with_admin)} users sharing their servers with admin.")
    except Exception as e:
        current_app.logger.error(f"Plex Service: Error fetching resources shared with admin: {e}", exc_info=True)
        log_event(EventType.ERROR_PLEX_API, f"Error fetching admin's shared resources: {e}")
    return owner_ids_sharing_with_admin

def get_plex_server_users_raw(users_sharing_back_ids=None):
    if users_sharing_back_ids is None:
        users_sharing_back_ids = get_user_ids_sharing_servers_with_admin()

    admin_account = get_plex_admin_account() 
    plex_server = get_plex_instance()   

    if not admin_account:
        current_app.logger.error("Plex_Service.py - get_plex_server_users_raw(): Admin MyPlexAccount connection failed.")
        return [], users_sharing_back_ids if users_sharing_back_ids is not None else set()
    if not plex_server:
        current_app.logger.error("Plex_Service.py - get_plex_server_users_raw(): PlexServer instance connection failed.")
        return [], users_sharing_back_ids if users_sharing_back_ids is not None else set()
        
    server_machine_id = plex_server.machineIdentifier
    admin_plex_id = getattr(admin_account, 'id', None)
    
    all_my_server_library_ids_as_strings = []
    try:
        all_my_server_library_ids_as_strings = [str(lib_section.key) for lib_section in plex_server.library.sections()]
        current_app.logger.info(f"Plex_Service.py - get_plex_server_users_raw(): All available library IDs on this server: {all_my_server_library_ids_as_strings}")
    except Exception as e_all_libs:
        current_app.logger.error(f"Plex_Service.py - get_plex_server_users_raw(): Could not fetch all library IDs from server: {e_all_libs}.")

    detailed_shares_by_userid = {} 
    try:
        if hasattr(admin_account, '_session') and admin_account._session is not None and \
           hasattr(admin_account, '_token') and admin_account._token is not None:
            base_plextv_url = "https://plex.tv"
            shared_servers_url = f"{base_plextv_url}/api/servers/{server_machine_id}/shared_servers"
            
            current_app.logger.info(f"Plex_Service.py - get_plex_server_users_raw(): Fetching detailed shares from: {shared_servers_url}")
            headers = {'X-Plex-Token': admin_account._token, 'Accept': 'application/xml'} 
            
            resp = admin_account._session.get(shared_servers_url, headers=headers, timeout=10)
            resp.raise_for_status() 
            
            current_app.logger.debug(f"Plex_Service.py - get_plex_server_users_raw(): Raw XML from /shared_servers: {resp.text[:500]}...") 
            shared_servers_xml_root = ET.fromstring(resp.content)
            
            for shared_server_elem in shared_servers_xml_root.findall('SharedServer'):
                user_id_str = shared_server_elem.get('userID')
                if not user_id_str: 
                    current_app.logger.warning(f"Plex_Service.py - get_plex_server_users_raw(): Found SharedServer element with no userID.")
                    continue
                try:
                    user_id_int_key = int(user_id_str)
                except ValueError:
                    current_app.logger.warning(f"Plex_Service.py - get_plex_server_users_raw(): Found SharedServer element with non-integer userID: '{user_id_str}'.")
                    continue
                
                all_libs = (shared_server_elem.get('allLibraries', "0") == "1")
                
                shared_section_keys_for_user = []
                if not all_libs: 
                    for section_elem in shared_server_elem.findall('Section'):
                        if section_elem.get('shared') == "1" and section_elem.get('key'):
                            shared_section_keys_for_user.append(str(section_elem.get('key')))
                
                detailed_shares_by_userid[user_id_int_key] = {
                    'allLibraries': all_libs,
                    'sharedSectionKeys': shared_section_keys_for_user
                }
    except Exception as e_shared_servers:
        current_app.logger.error(f"Plex_Service.py - Error fetching or parsing detailed /shared_servers data: {type(e_shared_servers).__name__} - {e_shared_servers}", exc_info=True)

    processed_users_data = []
    try:
        all_associated_users = admin_account.users()
        for plex_user_obj in all_associated_users:
            plex_user_id_int = getattr(plex_user_obj, 'id', None)
            if plex_user_id_int is None: continue
            if admin_plex_id and plex_user_id_int == admin_plex_id: continue
            
            plex_user_uuid_str = None
            plex_thumb_url = getattr(plex_user_obj, 'thumb', None)
            
            # Extract the alphanumeric UUID from the thumbnail URL.
            if plex_thumb_url and "/users/" in plex_thumb_url and "/avatar" in plex_thumb_url:
                try:
                    plex_user_uuid_str = plex_thumb_url.split('/users/')[1].split('/avatar')[0]
                except IndexError:
                    plex_user_uuid_str = None

            # For safety, if we couldn't parse the UUID, we don't send one.
            # user_service will then know this user can only be matched by their integer ID.
            if not plex_user_uuid_str:
                current_app.logger.warning(f"Could not parse alphanumeric UUID for user '{plex_user_obj.username}' (ID: {plex_user_id_int}). They will be matched by integer ID only.")


            user_data_basic = {
                'id': plex_user_id_int,
                'uuid': plex_user_uuid_str, # Will be alphanumeric if available, otherwise None
                'username': getattr(plex_user_obj, 'username', None) or getattr(plex_user_obj, 'title', 'Unknown'),
                'email': getattr(plex_user_obj, 'email', None), 
                'thumb': plex_thumb_url,
                'is_home_user': getattr(plex_user_obj, 'home', False),
                'is_friend': not getattr(plex_user_obj, 'home', False),
                'shares_back': users_sharing_back_ids is not None and plex_user_id_int in users_sharing_back_ids,
                'allowed_library_ids_on_server': [],
            }
            current_app.logger.info(f"Plex_Service.py - Processing User: {user_data_basic['username']} (ID: {user_data_basic['id']}, UUID: {user_data_basic['uuid']})")

            user_share_details = detailed_shares_by_userid.get(plex_user_id_int)
            add_user_to_pum_list = False
            effective_library_ids = []

            if user_data_basic['username'] == 'lucifea6':
                current_app.logger.info(f"Plex_Service.py - DEBUG lucifea6: Data from detailed_shares_by_userid: {user_share_details}")

            if user_share_details:
                if user_share_details.get('allLibraries'):
                    effective_library_ids = all_my_server_library_ids_as_strings[:] 
                    add_user_to_pum_list = True
                else: 
                    specific_keys = user_share_details.get('sharedSectionKeys', [])
                    effective_library_ids = specific_keys[:] 
                    if effective_library_ids: add_user_to_pum_list = True
            
            elif user_data_basic['is_home_user']:
                effective_library_ids = all_my_server_library_ids_as_strings[:] 
                add_user_to_pum_list = True
            else: 
                server_resource_for_this_user = None
                for res in getattr(plex_user_obj, 'servers', []):
                    if getattr(res, 'machineIdentifier', None) == server_machine_id:
                        server_resource_for_this_user = res
                        break
                if server_resource_for_this_user:
                    if not getattr(server_resource_for_this_user, 'pending', False):
                        add_user_to_pum_list = True
            
            if add_user_to_pum_list:
                user_data_basic['allowed_library_ids_on_server'] = effective_library_ids
                processed_users_data.append(user_data_basic)

        return processed_users_data, users_sharing_back_ids if users_sharing_back_ids is not None else set()

    except Exception as e_main_loop:
        current_app.logger.error(f"Plex_Service.py - get_plex_server_users_raw(): General error in main user processing loop: {type(e_main_loop).__name__} - {e_main_loop}", exc_info=True)
        return [], users_sharing_back_ids if users_sharing_back_ids is not None else set()

def update_user_plex_access(plex_username_or_id, library_ids_to_share=None, allow_sync: bool = None):
    """
    Updates a user's library access and/or download permissions on the Plex server.

    :param plex_username_or_id: The username or ID of the Plex user.
    :param library_ids_to_share: A list of library section IDs to share.
                                 If an empty list `[]` is provided, it typically means share all libraries (for updateFriend).
                                 If `None`, library access is not changed by this call.
    :param allow_sync: Boolean to set the 'Allow Sync/Downloads' permission.
                       If `True`, downloads are allowed. If `False`, they are disallowed.
                       If `None`, this permission is not changed by this call.
    :return: True if the update was successfully attempted.
    :raises: Exception from plexapi or if connection fails.
    """
    admin_account = get_plex_admin_account()
    plex_server_instance = get_plex_instance()

    if not admin_account or not plex_server_instance:
        current_app.logger.error("Plex_Service: Plex admin or server connection failed for update_user_plex_access.")
        raise Exception("Plex admin or server connection failed for update_user_plex_access.")

    try:
        # Fetch the MyPlexUser object. This represents the friend/managed user.
        user_to_update = admin_account.user(plex_username_or_id) 
        if not user_to_update:
            current_app.logger.warning(f"Plex_Service: Plex user '{plex_username_or_id}' not found as friend. Cannot update shares.")
            # Depending on desired behavior, you could return False or raise a more specific error.
            # For now, raising an exception is consistent with connection failures.
            raise Exception(f"Plex user '{plex_username_or_id}' not found as friend to update shares.")

        kwargs_for_update = {
            'user': user_to_update,
            'server': plex_server_instance
        }
        
        action_summary = []

        # Prepare 'sections' argument for plexapi if library access is being changed.
        if library_ids_to_share is not None: # library_ids_to_share is explicitly passed (could be empty list or list of IDs)
            if not library_ids_to_share: # An empty list `[]` means share all libraries to updateFriend
                kwargs_for_update['sections'] = [] 
                action_summary.append("libraries set to ALL")
                current_app.logger.info(f"Updating Plex libraries for {plex_username_or_id}: Setting to ALL libraries.")
            else:
                all_server_libs_dict = {str(lib.key): lib for lib in plex_server_instance.library.sections()}
                valid_plexapi_sections = []
                for lib_id_str in library_ids_to_share: # Ensure lib_id is treated as string for dict lookup
                    lib_obj = all_server_libs_dict.get(str(lib_id_str))
                    if lib_obj:
                        valid_plexapi_sections.append(lib_obj)
                    else:
                        current_app.logger.warning(f"Plex_Service: Library ID '{lib_id_str}' not found on server during update for user {plex_username_or_id}.")
                kwargs_for_update['sections'] = valid_plexapi_sections
                action_summary.append(f"libraries updated ({len(valid_plexapi_sections)} specified)")
                current_app.logger.info(f"Updating Plex libraries for {plex_username_or_id}: Setting to {len(valid_plexapi_sections)} specific libraries.")
        else:
            action_summary.append("libraries not changed")


        # Prepare 'allowSync' argument for plexapi if download permission is being changed.
        if allow_sync is not None: # allow_sync is explicitly True or False
            kwargs_for_update['allowSync'] = allow_sync
            action_summary.append(f"downloads {'enabled' if allow_sync else 'disabled'}")
            current_app.logger.info(f"Updating Plex downloads for {plex_username_or_id}: Setting allowSync to {allow_sync}.")
        else:
             action_summary.append("downloads not changed")


        # Only call updateFriend if there's actually something to update
        # (either libraries changed OR allow_sync was specified)
        if 'sections' in kwargs_for_update or 'allowSync' in kwargs_for_update:
            current_app.logger.info(f"Calling admin_account.updateFriend for {plex_username_or_id} with kwargs: { {k: (type(v) if k != 'user' and k != 'server' else str(v)) for k,v in kwargs_for_update.items()} }") # Log types for sections/allowSync
            admin_account.updateFriend(**kwargs_for_update)
            
            log_event(
                EventType.PLEX_USER_LIBS_UPDATED, # Or a more generic PLEX_USER_SETTINGS_UPDATED
                f"Updated Plex access for user '{user_to_update.title}'. Summary: {'; '.join(action_summary)}.",
                details={'user': user_to_update.title, 'plex_user_id': user_to_update.id, 'actions': action_summary}
            )
            current_app.logger.info(f"Plex_Service: Successfully updated Plex access for '{user_to_update.title}'. Details: {'; '.join(action_summary)}")
        else:
            current_app.logger.info(f"Plex_Service: No changes specified for libraries or download settings for user '{user_to_update.title}'. No API call made to updateFriend.")

        return True

    except BadRequest as e_br:
        current_app.logger.error(f"Plex_Service: BadRequest updating Plex access for '{plex_username_or_id}': {e_br}", exc_info=True)
        log_event(EventType.ERROR_PLEX_API, f"BadRequest updating Plex access for '{plex_username_or_id}': {e_br}")
        raise # Re-raise specific error
    except Exception as e:
        current_app.logger.error(f"Plex_Service: Error updating Plex access for '{plex_username_or_id}': {e}", exc_info=True)
        log_event(EventType.ERROR_PLEX_API, f"Error updating Plex access for '{plex_username_or_id}': {e}")
        raise # Re-raise general error

def invite_user_to_plex_server(plex_username_or_email, library_ids_to_share=None, allow_sync=False):
    admin_account = get_plex_admin_account(); plex_server_instance = get_plex_instance()
    if not admin_account or not plex_server_instance: raise Exception("Plex admin or server connection failed for invite_user_to_plex_server.")
    try:
        sections_to_share_plexapi_objects = None 
        if library_ids_to_share is not None: 
            if not library_ids_to_share: sections_to_share_plexapi_objects = None
            else: 
                all_server_libs_dict = {str(lib.key): lib for lib in plex_server_instance.library.sections()}
                sections_to_share_plexapi_objects = []
                for lib_id in library_ids_to_share:
                    lib_obj = all_server_libs_dict.get(str(lib_id))
                    if lib_obj: sections_to_share_plexapi_objects.append(lib_obj)
                    else: current_app.logger.warning(f"Lib ID '{lib_id}' not found during invite for {plex_username_or_email}.")
        admin_account.inviteFriend(user=plex_username_or_email, server=plex_server_instance, sections=sections_to_share_plexapi_objects, allowSync=allow_sync)
        num_shared = "all (server default)" if sections_to_share_plexapi_objects is None else (len(sections_to_share_plexapi_objects) if sections_to_share_plexapi_objects else "all (explicitly)")
        log_event(EventType.PLEX_USER_ADDED, f"Plex invite/share processed for '{plex_username_or_email}'.", details={'libs_count': num_shared})
        return True
    except BadRequest as e_br: 
        current_app.logger.warning(f"Plex invite/share for '{plex_username_or_email}' failed (BadRequest): {e_br}.")
        log_event(EventType.ERROR_PLEX_API, f"Plex invite/share for '{plex_username_or_email}' (BadRequest): {e_br}")
        if "already shared" in str(e_br).lower() or "invite is already pending" in str(e_br).lower(): return True 
        raise 
    except Exception as e:
        current_app.logger.error(f"Error inviting/sharing Plex user '{plex_username_or_email}': {e}", exc_info=True); log_event(EventType.ERROR_PLEX_API, f"Error inviting/sharing Plex user '{plex_username_or_email}': {e}"); raise

def remove_user_from_plex_server(plex_username_or_id):
    admin_account = get_plex_admin_account(); plex = get_plex_instance()
    if not admin_account or not plex: raise Exception("Plex admin or server connection failed.")
    try:
        user_to_remove = admin_account.user(plex_username_or_id)
        if not user_to_remove: current_app.logger.warning(f"User '{plex_username_or_id}' not found for removal."); return True 
        admin_account.removeFriend(user_to_remove) 
        log_event(EventType.PLEX_USER_REMOVED, f"Removed Plex friend '{plex_username_or_id}' (revoked all shares).")
        return True
    except NotFound: current_app.logger.warning(f"User '{plex_username_or_id}' not found for removal."); return True 
    except Exception as e:
        current_app.logger.error(f"Error removing Plex friend '{plex_username_or_id}': {e}", exc_info=True); log_event(EventType.ERROR_PLEX_API, f"Error removing Plex friend '{plex_username_or_id}': {e}"); raise

def find_plex_user_by_username_or_email(identifier):
    admin_account = get_plex_admin_account()
    if not admin_account: return None
    try:
        user = admin_account.user(identifier); return user 
    except NotFound: return None
    except Exception as e: current_app.logger.error(f"Error searching for Plex user '{identifier}': {e}"); return None

def get_active_sessions():
    # Uses the global _plex_server_instance if available and valid, or tries to connect
    plex = get_plex_instance() # This uses the cached or new connection
    if plex:
        try:
            current_app.logger.debug("Plex_Service.py - get_active_sessions(): Attempting to fetch sessions.")
            sessions = plex.sessions()
            current_app.logger.debug(f"Plex_Service.py - get_active_sessions(): Found {len(sessions) if sessions else 0} sessions.")
            return sessions
        except Exception as e: 
            current_app.logger.error(f"Plex_Service.py - get_active_sessions(): Error fetching Plex active sessions: {e}", exc_info=True)
            log_event(EventType.ERROR_PLEX_API, f"Error fetching active sessions: {e}")
    else:
        current_app.logger.warning("Plex_Service.py - get_active_sessions(): Plex instance not available.")
    return []

def terminate_plex_session(session_key: str, reason_message: str = None):
    """
    Terminates a specific Plex session.

    :param session_key: The 'sessionKey' of the stream to terminate.
    :param reason_message: Optional message to display to the user on their Plex client.
    :return: True if termination command was attempted, False otherwise (e.g., connection issue).
    :raises: Exception from plexapi if termination fails at the Plex server level.
    """
    plex = get_plex_instance()
    if not plex:
        current_app.logger.error("Plex_Service: Cannot terminate session, Plex instance not available.")
        return False

    try:
        # Find the session. plex.sessions() returns a list of Session objects.
        # Each Session object should have a 'sessionKey' attribute (usually int or str).
        # The session_key from the client will likely be a string.
        session_to_terminate = None
        active_sessions = plex.sessions() # Get fresh list of sessions
        for active_session in active_sessions:
            # sessionKey from plexapi can be int, ensure comparison is flexible
            if str(getattr(active_session, 'sessionKey', None)) == str(session_key):
                session_to_terminate = active_session
                break
        
        if not session_to_terminate:
            current_app.logger.warning(f"Plex_Service: Session with key '{session_key}' not found for termination.")
            # Consider this a success in terms of "it's no longer active" or raise specific error
            raise Exception(f"Session with key '{session_key}' not found or no longer active.")

        current_app.logger.info(f"Plex_Service: Attempting to terminate session key '{session_key}' for user '{getattr(session_to_terminate.user, 'title', 'Unknown')}' with message: '{reason_message}'")
        session_to_terminate.stop(reason=reason_message) # plexapi's stop method
        
        log_event(
            EventType.PLEX_SESSION_DETECTED, # Or a new PLEX_SESSION_TERMINATED type
            f"Admin terminated session for user '{getattr(session_to_terminate.user, 'title', 'Unknown')}' (Player: {getattr(session_to_terminate.player, 'title', 'N/A')}). Reason: {reason_message or 'None provided'}",
            details={'session_key': session_key, 'user': getattr(session_to_terminate.user, 'title', 'Unknown'), 'player': getattr(session_to_terminate.player, 'title', 'N/A'), 'message': reason_message}
        )
        return True
    except Exception as e:
        current_app.logger.error(f"Plex_Service: Error terminating Plex session '{session_key}': {e}", exc_info=True)
        log_event(
            EventType.ERROR_PLEX_API,
            f"Error terminating Plex session for key '{session_key}': {e}",
            details={'session_key': session_key, 'message': reason_message, 'error': str(e)}
        )
        raise # Re-raise to be caught by the route