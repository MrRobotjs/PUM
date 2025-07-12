# File: app/services/user_service.py
from flask import current_app
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone, timedelta
from sqlalchemy import func, case, or_
from app.models import User, EventType, StreamHistory
from app.extensions import db
from app.utils.helpers import log_event, format_duration
from . import plex_service

def sync_users_from_plex():
    current_app.logger.info("User_Service.py - sync_users_from_plex(): Starting Plex user synchronization.")
    
    users_sharing_back_with_admin_ids = plex_service.get_user_ids_sharing_servers_with_admin()
    raw_plex_users_with_access, _ = plex_service.get_plex_server_users_raw(
        users_sharing_back_ids=users_sharing_back_with_admin_ids
    )

    if raw_plex_users_with_access is None:
        current_app.logger.error("User_Service.py - sync_users_from_plex(): Plex user sync failed: Could not retrieve users from Plex service (returned None).")
        # Return a structure indicating failure for the route to handle
        return {'added': [], 'updated': [], 'removed': [], 'errors': 1, 'error_messages': ["Failed to retrieve users from Plex service."]}

    pum_users_all = User.query.all()
    pum_users_map_by_plex_id = {user.plex_user_id: user for user in pum_users_all if user.plex_user_id is not None}
    pum_users_map_by_plex_uuid = {user.plex_uuid: user for user in pum_users_all if user.plex_uuid}
    
    # --- Initialize lists to store details of changes ---
    added_users_details = []
    updated_users_details = [] # List of dicts: {'username': str, 'changes': [str_description_of_change]}
    removed_users_details = [] # List of dicts: {'username': str, 'plex_id': int/str}
    error_count = 0
    error_messages = []
    # --- End init lists ---

    current_plex_user_ids_on_server = set()
    for plex_user_data_item in raw_plex_users_with_access:
        if plex_user_data_item.get('id') is not None:
            current_plex_user_ids_on_server.add(plex_user_data_item['id'])

    for plex_user_data in raw_plex_users_with_access:
        plex_id = plex_user_data.get('id')
        plex_uuid_from_sync = plex_user_data.get('uuid')
        plex_username_from_sync = plex_user_data.get('username')

        if plex_id is None and plex_uuid_from_sync is None:
            msg = f"Plex user data missing 'id' and 'uuid' for potential user: {plex_username_from_sync or 'Unknown'}. Skipping."
            current_app.logger.warning(msg)
            error_count += 1; error_messages.append(msg)
            continue

        pum_user = None
        if plex_id is not None: pum_user = pum_users_map_by_plex_id.get(plex_id)
        if not pum_user and plex_uuid_from_sync: pum_user = pum_users_map_by_plex_uuid.get(plex_uuid_from_sync)
        
        new_library_ids_from_plex_list = list(plex_user_data.get('allowed_library_ids_on_server', []))
        plex_email_from_sync = plex_user_data.get('email')
        plex_thumb_from_sync = plex_user_data.get('thumb')
        is_home_user_from_sync = plex_user_data.get('is_home_user', False)
        shares_back_from_sync = plex_user_data.get('shares_back', False)
        is_friend_from_sync = plex_user_data.get('is_friend', False)

        if pum_user: # Existing user
            changes_for_this_user = []
            original_username = pum_user.plex_username # For logging if username itself changes

            if plex_id is not None and pum_user.plex_user_id != plex_id:
                changes_for_this_user.append(f"Plex User ID corrected from {pum_user.plex_user_id} to {plex_id}")
                pum_user.plex_user_id = plex_id
            if plex_uuid_from_sync and pum_user.plex_uuid != plex_uuid_from_sync:
                changes_for_this_user.append(f"Plex UUID updated from {pum_user.plex_uuid} to {plex_uuid_from_sync}")
                pum_user.plex_uuid = plex_uuid_from_sync
            if pum_user.plex_username != plex_username_from_sync:
                changes_for_this_user.append(f"Username changed from '{pum_user.plex_username}' to '{plex_username_from_sync}'")
                pum_user.plex_username = plex_username_from_sync
            if pum_user.plex_email != plex_email_from_sync:
                changes_for_this_user.append(f"Email updated") # Don't log old/new email for privacy
                pum_user.plex_email = plex_email_from_sync
            if pum_user.plex_thumb_url != plex_thumb_from_sync:
                changes_for_this_user.append("Thumbnail updated")
                pum_user.plex_thumb_url = plex_thumb_from_sync
            
            current_pum_libs = pum_user.allowed_library_ids if pum_user.allowed_library_ids is not None else []
            if set(current_pum_libs) != set(new_library_ids_from_plex_list):
                changes_for_this_user.append(f"Libraries updated (Old: {len(current_pum_libs)}, New: {len(new_library_ids_from_plex_list)})")
                pum_user.allowed_library_ids = new_library_ids_from_plex_list
            if pum_user.is_home_user != is_home_user_from_sync:
                changes_for_this_user.append(f"Home User status changed to {is_home_user_from_sync}")
                pum_user.is_home_user = is_home_user_from_sync
            if pum_user.shares_back != shares_back_from_sync:
                changes_for_this_user.append(f"Shares Back status changed to {shares_back_from_sync}")
                pum_user.shares_back = shares_back_from_sync
            if hasattr(pum_user, 'is_plex_friend') and pum_user.is_plex_friend != is_friend_from_sync:
                changes_for_this_user.append(f"Plex Friend status changed to {is_friend_from_sync}")
                pum_user.is_plex_friend = is_friend_from_sync

            if changes_for_this_user:
                pum_user.last_synced_with_plex = datetime.utcnow()
                pum_user.updated_at = datetime.utcnow()
                updated_users_details.append({'username': plex_username_from_sync or original_username, 'changes': changes_for_this_user})
        else: # New user
            try:
                new_user_obj = User( # Renamed to avoid conflict with User model
                    plex_user_id=plex_id, plex_uuid=plex_uuid_from_sync, 
                    plex_username=plex_username_from_sync, plex_email=plex_email_from_sync,
                    plex_thumb_url=plex_thumb_from_sync, allowed_library_ids=new_library_ids_from_plex_list, 
                    is_home_user=is_home_user_from_sync, shares_back=shares_back_from_sync,
                    is_plex_friend=is_friend_from_sync, last_synced_with_plex=datetime.utcnow()
                )
                db.session.add(new_user_obj)
                added_users_details.append({'username': plex_username_from_sync, 'plex_id': plex_id})
            except IntegrityError as ie: 
                db.session.rollback()
                msg = f"Integrity error adding {plex_username_from_sync}: {ie}."
                current_app.logger.error(msg)
                error_count += 1; error_messages.append(msg)
            except Exception as e:
                db.session.rollback()
                msg = f"Error creating user {plex_username_from_sync}: {e}"
                current_app.logger.error(msg, exc_info=True)
                error_count += 1; error_messages.append(msg)

    for pum_user_obj in pum_users_all:
        # Determine if PUM user should be removed
        is_on_server = False
        if pum_user_obj.plex_user_id and pum_user_obj.plex_user_id in current_plex_user_ids_on_server:
            is_on_server = True
        elif pum_user_obj.plex_uuid and pum_user_obj.plex_uuid in {str(uid) for uid in current_plex_user_ids_on_server}: # Compare string UUIDs
             is_on_server = True

        if not is_on_server:
            removed_users_details.append({'username': pum_user_obj.plex_username, 'pum_id': pum_user_obj.id, 'plex_id': pum_user_obj.plex_user_id})
            db.session.delete(pum_user_obj)
    
    if added_users_details or updated_users_details or removed_users_details or error_count > 0:
        try:
            db.session.commit()
            current_app.logger.info(f"DB commit successful for sync. Added: {len(added_users_details)}, Updated: {len(updated_users_details)}, Removed: {len(removed_users_details)}")
            # Log summary event
            log_event(EventType.PLEX_SYNC_USERS_COMPLETE, 
                      f"Plex user sync complete. Added: {len(added_users_details)}, Updated: {len(updated_users_details)}, Removed: {len(removed_users_details)}, Errors: {error_count}.",
                      details={
                          "added_count": len(added_users_details),
                          "updated_count": len(updated_users_details),
                          "removed_count": len(removed_users_details),
                          "errors": error_count
                      })
        except Exception as e_commit:
            db.session.rollback()
            msg = f"DB commit error during sync: {e_commit}"
            current_app.logger.error(msg, exc_info=True)
            error_count += (len(added_users_details) + len(updated_users_details) + len(removed_users_details)) # Count all attempts as errors if commit fails
            error_messages.append(msg)
            # Clear details lists as the changes were rolled back
            added_users_details = []
            updated_users_details = []
            removed_users_details = []
    
    return {
        'added': added_users_details, 
        'updated': updated_users_details, 
        'removed': removed_users_details, 
        'errors': error_count,
        'error_messages': error_messages
    }

def update_user_details(user_id: int, notes=None, new_library_ids=None,
                        is_discord_bot_whitelisted: bool = None,
                        is_purge_whitelisted: bool = None,
                        allow_downloads: bool = None,
                        allow_4k_transcode: bool = None,
                        admin_id: int = None):
    """
    Updates a user's details in the PUM database and syncs relevant changes to the Plex server.
    This function now correctly handles partial updates by sending the full final state to Plex.
    """
    user = User.query.get_or_404(user_id)
    changes_made_to_pum = False

    # --- PUM-only fields ---
    if notes is not None and user.notes != notes:
        user.notes = notes
        changes_made_to_pum = True

    if is_discord_bot_whitelisted is not None and user.is_discord_bot_whitelisted != is_discord_bot_whitelisted:
        user.is_discord_bot_whitelisted = is_discord_bot_whitelisted
        changes_made_to_pum = True
        log_event(EventType.SETTING_CHANGE, f"User '{user.plex_username}' Discord Bot Whitelist set to {is_discord_bot_whitelisted}", user_id=user.id, admin_id=admin_id)

    if is_purge_whitelisted is not None and user.is_purge_whitelisted != is_purge_whitelisted:
        user.is_purge_whitelisted = is_purge_whitelisted
        changes_made_to_pum = True
        log_event(EventType.SETTING_CHANGE, f"User '{user.plex_username}' Purge Whitelist set to {is_purge_whitelisted}", user_id=user.id, admin_id=admin_id)
        
    if allow_4k_transcode is not None and user.allow_4k_transcode != allow_4k_transcode:
        user.allow_4k_transcode = allow_4k_transcode
        changes_made_to_pum = True
        log_event(EventType.SETTING_CHANGE, f"User '{user.plex_username}' Allow 4K Transcode set to {allow_4k_transcode}", user_id=user.id, admin_id=admin_id)


    # --- Plex-related settings ---
    libraries_changed = False
    if new_library_ids is not None:
        current_pum_libs_set = set(user.allowed_library_ids or [])
        new_library_ids_set = set(new_library_ids)
        if current_pum_libs_set != new_library_ids_set:
            libraries_changed = True
            user.allowed_library_ids = new_library_ids # Update PUM record
            changes_made_to_pum = True
            log_event(EventType.PUM_USER_LIBRARIES_EDITED, f"Manually updated libraries for '{user.plex_username}'.", user_id=user.id, admin_id=admin_id)

    downloads_changed = False
    if allow_downloads is not None and user.allow_downloads != allow_downloads:
        downloads_changed = True
        user.allow_downloads = allow_downloads # Update PUM record
        changes_made_to_pum = True
        log_event(EventType.SETTING_CHANGE, f"User '{user.plex_username}' Allow Downloads set to {allow_downloads}", user_id=user.id, admin_id=admin_id)
        
    # --- Make the API call to Plex ONLY IF a Plex-related setting changed ---
    if libraries_changed or downloads_changed:
        try:
            current_app.logger.info(f"[DEBUG-USER_SVC] Preparing to call plex_service.update_user_plex_access for user '{user.plex_username}'. State to send -> library_ids_to_share: {user.allowed_library_ids}, allow_sync: {user.allow_downloads}")
            # **THE FIX**: We now pass the user's complete, final desired library and download state to the service.
            plex_service.update_user_plex_access(
                plex_username_or_id=user.plex_username,
                library_ids_to_share=user.allowed_library_ids,  # Always send the user's full library list
                allow_sync=user.allow_downloads                 # Always send the user's full download permission
            )
        except Exception as e:
            # Re-raise the exception to be handled by the route, which can flash an error
            raise Exception(f"Failed to update Plex permissions for {user.plex_username}: {e}")

    # If any PUM-only field changed, mark the record as updated
    if changes_made_to_pum:
        user.updated_at = datetime.utcnow()
    
    # The calling route is responsible for db.session.commit()
    return user

def delete_user_from_pum_and_plex(user_id: int, admin_id: int = None):
    user = User.query.get_or_404(user_id); username = user.plex_username
    try:
        plex_service.remove_user_from_plex_server(user.plex_username) # Use username or ID if plex_service supports it
        db.session.delete(user); db.session.commit()
        log_event(EventType.PUM_USER_DELETED_FROM_PUM, f"User '{username}' removed from PUM and Plex server.", admin_id=admin_id, details={'deleted_username': username, 'deleted_user_id_in_pum': user_id, 'deleted_plex_user_id': user.plex_user_id})
        return True
    except Exception as e:
        db.session.rollback(); current_app.logger.error(f"Failed to fully delete user {username}: {e}", exc_info=True);
        # Log event for the failure as well
        log_event(EventType.ERROR_GENERAL, f"Failed to delete user {username}: {e}", admin_id=admin_id, user_id=user_id)
        raise Exception(f"Failed to remove user {username} from Plex or PUM: {e}")

def mass_update_user_libraries(user_ids: list[int], new_library_ids: list, admin_id: int = None):
    processed_count = 0; error_count = 0;
    users_to_update = User.query.filter(User.id.in_(user_ids)).all()
    db_library_value_to_set = list(new_library_ids) if new_library_ids is not None else [] # Ensure it's a list for DB

    for user in users_to_update:
        try:
            current_pum_libs = user.allowed_library_ids if user.allowed_library_ids is not None else []
            needs_plex_update = (set(current_pum_libs) != set(db_library_value_to_set))
            
            if needs_plex_update:
                plex_service.update_user_plex_access(user.plex_username, db_library_value_to_set) 
                user.allowed_library_ids = db_library_value_to_set 
                user.updated_at = datetime.utcnow()
            processed_count += 1
        except Exception as e:
            current_app.logger.error(f"Mass Update Error: User {user.plex_username} (ID: {user.id}): {e}");
            error_count += 1
    if processed_count > 0 or error_count > 0: 
        try:
            db.session.commit()
            log_event(EventType.PUM_USER_LIBRARIES_EDITED, f"Mass update: Libs processed for {processed_count} users.", admin_id=admin_id, details={'attempted_count': len(user_ids), 'success_count': processed_count - error_count, 'errors': error_count})
        except Exception as e:
            db.session.rollback(); current_app.logger.error(f"Mass Update: DB commit error: {e}");
            error_count = len(users_to_update); 
            raise Exception(f"Mass Update: DB commit failed: {e}")
    return processed_count, error_count

def mass_update_bot_whitelist(user_ids: list[int], should_whitelist: bool, admin_id: int = None):
    users_to_update = User.query.filter(User.id.in_(user_ids)).all()
    updated_count = 0
    for user in users_to_update:
        if user.is_discord_bot_whitelisted != should_whitelist:
            user.is_discord_bot_whitelisted = should_whitelist
            user.updated_at = datetime.utcnow()
            updated_count +=1
    if updated_count > 0: db.session.commit()
    log_event(EventType.SETTING_CHANGE, f"Mass updated Discord Bot Whitelist for {updated_count} users to {should_whitelist}.", admin_id=admin_id, details={"count": updated_count, "whitelisted": should_whitelist})
    return updated_count

def mass_update_purge_whitelist(user_ids: list[int], should_whitelist: bool, admin_id: int = None):
    users_to_update = User.query.filter(User.id.in_(user_ids)).all()
    updated_count = 0
    for user in users_to_update:
        if user.is_purge_whitelisted != should_whitelist:
            user.is_purge_whitelisted = should_whitelist
            user.updated_at = datetime.utcnow()
            updated_count +=1
    if updated_count > 0: db.session.commit()
    log_event(EventType.SETTING_CHANGE, f"Mass updated Purge Whitelist for {updated_count} users to {should_whitelist}.", admin_id=admin_id, details={"count": updated_count, "whitelisted": should_whitelist})
    return updated_count

def mass_delete_users(user_ids: list[int], admin_id: int = None):
    processed_count = 0; error_count = 0;
    users_to_delete = User.query.filter(User.id.in_(user_ids)).all()
    usernames_for_log_detail = []

    for user in users_to_delete:
        username_for_log = user.plex_username
        try:
            plex_service.remove_user_from_plex_server(user.plex_username); # or user.plex_user_id if service supports
            db.session.delete(user);
            processed_count += 1
            usernames_for_log_detail.append(username_for_log)
        except Exception as e:
            current_app.logger.error(f"Mass Delete Error: User {username_for_log} (ID: {user.id}): {e}");
            error_count += 1
    
    if processed_count > 0 : # Only commit if there were successful PUM deletions
        try:
            db.session.commit()
            if processed_count > 0: # Log only if actual PUM deletions were committed
                log_event(EventType.PUM_USER_DELETED_FROM_PUM, f"Mass delete: {processed_count} users removed from PUM and Plex.", admin_id=admin_id, details={'deleted_count': processed_count, 'errors': error_count, 'attempted_ids_count': len(user_ids), 'deleted_usernames_sample': usernames_for_log_detail[:10]})
        except Exception as e_commit:
            db.session.rollback(); current_app.logger.error(f"Mass Delete: DB commit error: {e_commit}");
            error_count = len(users_to_delete) 
            processed_count = 0
            log_event(EventType.ERROR_GENERAL, f"Mass delete DB commit failed: {e_commit}", admin_id=admin_id, details={'attempted_count': len(user_ids)})
    elif error_count > 0: # No successes, only errors, still log the attempt
         log_event(EventType.ERROR_GENERAL, f"Mass delete attempt failed for all {error_count} users selected.", admin_id=admin_id, details={'attempted_count': len(user_ids), 'errors': error_count})


    return processed_count, error_count

def update_user_last_streamed(plex_user_id_or_uuid, last_streamed_at_datetime: datetime):
    user = None
    if isinstance(plex_user_id_or_uuid, int):
        user = User.query.filter(User.plex_user_id == plex_user_id_or_uuid).first()
    elif isinstance(plex_user_id_or_uuid, str):
        user = User.query.filter(User.plex_uuid == plex_user_id_or_uuid).first()
        if not user and plex_user_id_or_uuid.isdigit(): # Fallback for stringified int IDs
             user = User.query.filter(User.plex_user_id == int(plex_user_id_or_uuid)).first()
    else:
        current_app.logger.warning(f"User_Service.py - update_user_last_streamed(): Unexpected type for plex_user_id_or_uuid: {type(plex_user_id_or_uuid)}")
        return False

    if user:
        if last_streamed_at_datetime.tzinfo is None: 
            last_streamed_at_datetime = last_streamed_at_datetime.replace(tzinfo=timezone.utc)
        
        db_last_streamed_at_naive = user.last_streamed_at 
        db_last_streamed_at_aware = None
        if db_last_streamed_at_naive:
            db_last_streamed_at_aware = db_last_streamed_at_naive.replace(tzinfo=timezone.utc)
        
        if db_last_streamed_at_aware is None or last_streamed_at_datetime > db_last_streamed_at_aware:
            user.last_streamed_at = last_streamed_at_datetime.replace(tzinfo=None) 
            user.updated_at = datetime.utcnow().replace(tzinfo=None)
            try: 
                db.session.commit()
                current_app.logger.info(f"User_Service.py - update_user_last_streamed(): Updated last_streamed_at for {user.plex_username} to {user.last_streamed_at}")
                return True
            except Exception as e: 
                db.session.rollback()
                current_app.logger.error(f"User_Service.py - update_user_last_streamed(): DB Commit Error for user {user.plex_username} (Plex ID/UUID: {plex_user_id_or_uuid}): {e}", exc_info=True)
        # else:
            # current_app.logger.debug(f"User_Service.py - update_user_last_streamed(): No update needed for {user.plex_username}. DB: {db_last_streamed_at_aware}, Current: {last_streamed_at_datetime}")
    # else:
        # current_app.logger.warning(f"User_Service.py - update_user_last_streamed(): User not found in PUM with Plex ID/UUID: {plex_user_id_or_uuid}.")
    return False

def purge_inactive_users(user_ids_to_purge: list[int], admin_id: int, inactive_days_threshold: int, exclude_sharers: bool, exclude_whitelisted: bool, ignore_creation_date_for_never_streamed: bool):
    """
    Deletes a specific list of users, but only after re-validating them
    against the provided criteria as a final safety check.
    """
    if not user_ids_to_purge:
        return {"message": "No users were selected for purge.", "purged_count": 0, "errors": 0}

    # Re-run the eligibility check on the provided list of users as a safeguard.
    eligible_users_final = get_users_eligible_for_purge(
        inactive_days_threshold, exclude_sharers, exclude_whitelisted, ignore_creation_date_for_never_streamed
    )
    final_ids_to_delete = {user['id'] for user in eligible_users_final}.intersection(set(user_ids_to_purge))
    
    purged_count = 0
    error_count = 0
    
    users_to_process = User.query.filter(User.id.in_(final_ids_to_delete)).all()

    for user in users_to_process:
        try:
            delete_user_from_pum_and_plex(user.id, admin_id=admin_id)
            purged_count += 1
        except Exception as e:
            error_count += 1
            current_app.logger.error(f"User_Service.py - purge_inactive_users(): Error purging user {user.plex_username} (ID: {user.id}): {e}")

    result_message = f"Purge complete: {purged_count} users removed."
    if len(final_ids_to_delete) != len(user_ids_to_purge):
        result_message += f" ({len(user_ids_to_purge) - len(final_ids_to_delete)} skipped by final safety check)."
    if error_count > 0:
        result_message += f" {error_count} errors."

    log_event(EventType.PUM_USER_DELETED_FROM_PUM, result_message, admin_id=admin_id, details={
        "action": "purge_selected_inactive_users", "purged_count": purged_count, "errors": error_count
    })
    
    return {"message": result_message, "purged_count": purged_count, "errors": error_count}

def get_users_eligible_for_purge(inactive_days_threshold: int, exclude_sharers: bool, exclude_whitelisted: bool, ignore_creation_date_for_never_streamed: bool = False):
    if inactive_days_threshold < 1:
        raise ValueError("Inactivity threshold must be at least 1 day.")

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=inactive_days_threshold)
    
    # Base query always excludes home users.
    query = User.query.filter(User.is_home_user == False) 

    # --- START OF FIX ---
    # Conditionally add filters based on the checkboxes.
    # This structure correctly handles the boolean logic.
    if exclude_sharers:
        query = query.filter(User.shares_back == False)
    
    if exclude_whitelisted: 
        query = query.filter(User.is_purge_whitelisted == False)
    # --- END OF FIX ---
        
    eligible_users_list = []
    potential_users = query.all()

    for user in potential_users:
        is_eligible_for_purge = False
        
        if user.last_streamed_at is None:
            if ignore_creation_date_for_never_streamed:
                is_eligible_for_purge = True
            else:
                created_at_aware = user.created_at.replace(tzinfo=timezone.utc) if user.created_at.tzinfo is None else user.created_at
                if created_at_aware < cutoff_date:
                    is_eligible_for_purge = True
        else: 
            last_streamed_aware = user.last_streamed_at.replace(tzinfo=timezone.utc) if user.last_streamed_at.tzinfo is None else user.last_streamed_at
            if last_streamed_aware < cutoff_date:
                is_eligible_for_purge = True
        
        if is_eligible_for_purge:
            eligible_users_list.append({ 'id': user.id, 'plex_username': user.plex_username, 'plex_email': user.plex_email, 'last_streamed_at': user.last_streamed_at, 'created_at': user.created_at })
            
    return eligible_users_list

def get_user_stream_stats(user_id):
    """Aggregates stream history for a user to produce Tautulli-like stats."""
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    # --- Global Stats ---
    # Perform all aggregations in a single query for efficiency
    stats_query = db.session.query(
        func.count(StreamHistory.id).label('all_time_plays'),
        func.sum(StreamHistory.duration_seconds).label('all_time_duration'),
        func.sum(case((StreamHistory.started_at >= day_ago, StreamHistory.duration_seconds), else_=0)).label('duration_24h'),
        func.count(case((StreamHistory.started_at >= day_ago, 1), else_=None)).label('plays_24h'),
        func.sum(case((StreamHistory.started_at >= week_ago, StreamHistory.duration_seconds), else_=0)).label('duration_7d'),
        func.count(case((StreamHistory.started_at >= week_ago, 1), else_=None)).label('plays_7d'),
        func.count(case((StreamHistory.started_at >= month_ago, 1), else_=None)).label('plays_30d'),
        func.sum(case((StreamHistory.started_at >= month_ago, StreamHistory.duration_seconds), else_=0)).label('duration_30d')
    ).filter(StreamHistory.user_id == user_id).first()

    global_stats = {
        'plays_24h': stats_query.plays_24h or 0,
        'duration_24h': format_duration(stats_query.duration_24h or 0),
        'plays_7d': stats_query.plays_7d or 0,
        'duration_7d': format_duration(stats_query.duration_7d or 0),
        'plays_30d': stats_query.plays_30d or 0,
        'duration_30d': format_duration(stats_query.duration_30d or 0),
        'all_time_plays': stats_query.all_time_plays or 0,
        'all_time_duration': format_duration(stats_query.all_time_duration or 0)
    }

    # --- Player Stats ---
    player_stats_query = db.session.query(
        StreamHistory.player,
        func.count(StreamHistory.id).label('play_count')
    ).filter(StreamHistory.user_id == user_id).group_by(StreamHistory.player).order_by(func.count(StreamHistory.id).desc()).all()

    player_stats = [{'name': p.player or 'Unknown', 'plays': p.play_count} for p in player_stats_query]

    return {'global': global_stats, 'players': player_stats}