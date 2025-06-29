# File: app/services/invite_service.py

from flask import current_app
from datetime import datetime, timezone, timedelta
from sqlalchemy.exc import IntegrityError
from app.models import Invite, User, InviteUsage, EventType, Setting
from app.extensions import db
from app.utils.helpers import log_event
from . import plex_service, user_service # Use . to import from current package

def validate_invite_usability(invite_path_or_token):
    """
    Validates an invite based on its path or token.
    Returns (Invite object, None) if valid and usable.
    Returns (None, error_message) if invalid or not usable.
    """
    if not invite_path_or_token:
        return None, "Invite identifier missing."

    # Try finding by custom path first, then by token
    invite = Invite.query.filter(
        (Invite.custom_path == invite_path_or_token) | (Invite.token == invite_path_or_token)
    ).first()

    if not invite:
        log_event(EventType.INVITE_VIEWED, f"Invite '{invite_path_or_token}' not found.", details={'identifier': invite_path_or_token})
        return None, "Invite link is invalid or does not exist."

    if not invite.is_active:
        log_event(EventType.INVITE_VIEWED, f"Invite '{invite_path_or_token}' (ID: {invite.id}) is deactivated.", invite_id=invite.id)
        return None, "This invite link has been deactivated."
    
    if invite.is_expired:
        log_event(EventType.INVITE_EXPIRED, f"Invite '{invite_path_or_token}' (ID: {invite.id}) has expired.", invite_id=invite.id)
        return None, "This invite link has expired."

    if invite.has_reached_max_uses:
        log_event(EventType.INVITE_MAX_USES_REACHED, f"Invite '{invite_path_or_token}' (ID: {invite.id}) has reached its maximum number of uses.", invite_id=invite.id)
        return None, "This invite link has reached its maximum number of uses."
    
    # Log that the valid invite was viewed (attempted to be used)
    # More detailed usage logging happens upon auth attempts or acceptance.
    log_event(EventType.INVITE_VIEWED, f"Invite '{invite_path_or_token}' (ID: {invite.id}) viewed/accessed.", invite_id=invite.id)
    return invite, None


def record_invite_usage_attempt(invite_id, ip_address, plex_user_info=None, discord_user_info=None, status_message=None):
    """Records an attempt to use an invite, even if not fully successful yet."""
    usage = InviteUsage(invite_id=invite_id, ip_address=ip_address, status_message=status_message)
    if plex_user_info:
        usage.plex_user_uuid = plex_user_info.get('uuid')
        usage.plex_username = plex_user_info.get('username')
        usage.plex_email = plex_user_info.get('email')
        usage.plex_thumb = plex_user_info.get('thumb')
        usage.plex_auth_successful = True # Assume if info is passed, auth was okay for this stage
    if discord_user_info:
        usage.discord_user_id = discord_user_info.get('id')
        usage.discord_username = discord_user_info.get('username')
        usage.discord_auth_successful = True
    
    db.session.add(usage)
    db.session.commit()
    return usage # Return the usage record in case it needs to be updated (e.g. with pum_user_id)


def accept_invite_and_grant_access(invite: Invite, plex_user_uuid: str, plex_username: str, plex_email: str, plex_thumb: str,
                                   discord_user_id: str = None, discord_username: str = None, discord_avatar_hash: str = None,
                                   ip_address: str = None):
    """
    Processes invite acceptance:
    1. Checks if Plex user already exists in PUM or on Plex server.
    2. If new, invites/shares with Plex server (respecting allow_downloads from invite).
    3. Creates/updates PUM User record, setting access_expires_at if specified in invite.
    4. Updates Invite usage counts and links PUM user to InviteUsage.
    Returns (True, "Success message" or User object) or (False, "Error message")
    """
    if not invite.is_usable:
        log_event(EventType.INVITE_VIEWED, f"Attempt to use unusable invite '{invite.custom_path or invite.token}' (ID: {invite.id}).", invite_id=invite.id, details={'reason': 'not usable'})
        return False, "This invite is no longer valid (expired, maxed out, or deactivated)."

    existing_pum_user = User.query.filter_by(plex_uuid=plex_user_uuid).first()
    if existing_pum_user:
        # User already exists in PUM.
        # Optionally, update their Discord if not present, or other details.
        updated_existing = False
        if discord_user_id and not existing_pum_user.discord_user_id:
            existing_pum_user.discord_user_id = discord_user_id
            existing_pum_user.discord_username = discord_username
            existing_pum_user.discord_avatar_hash = discord_avatar_hash
            updated_existing = True
        
        # If invite has a membership duration, and user doesn't have one or has an older one, update it?
        # For now, let's assume existing users' expirations aren't modified by new invites.
        # This could be a future enhancement.
        
        if updated_existing:
            existing_pum_user.updated_at = datetime.now(timezone.utc)
            # db.session.commit() # Commit handled later or by calling function

        usage_log = record_invite_usage_attempt(
            invite.id, ip_address,
            plex_user_info={'uuid': plex_user_uuid, 'username': plex_username, 'email': plex_email, 'thumb': plex_thumb},
            discord_user_info={'id': discord_user_id, 'username': discord_username} if discord_user_id else None,
            status_message="User already managed by PUM."
        )
        usage_log.pum_user_id = existing_pum_user.id
        usage_log.accepted_invite = True 
        
        # Increment invite uses even if user exists, as they "used" the link
        invite.current_uses += 1
        db.session.add(usage_log)
        db.session.add(invite)
        try:
            db.session.commit()
            log_event(EventType.INVITE_USED_ACCOUNT_LINKED, f"Existing user {plex_username} used invite {invite.id} (Discord linked/re-confirmed).", user_id=existing_pum_user.id, invite_id=invite.id)
        except Exception as e_commit:
            db.session.rollback()
            current_app.logger.error(f"Error committing usage for existing user on invite {invite.id}: {e_commit}")
            return False, "Database error during invite processing for existing user."

        return False, f"You ({plex_username}) are already a member of this Plex server."

    # User is new to PUM. Grant Plex access.
    try:
        plex_service.invite_user_to_plex_server(
            plex_username_or_email=plex_email or plex_username,
            library_ids_to_share=invite.grant_library_ids,
            allow_sync=invite.allow_downloads  # Pass the allow_downloads flag
        )
        log_event(EventType.PLEX_USER_ADDED, f"User '{plex_username}' invited/shared with Plex. Downloads: {'enabled' if invite.allow_downloads else 'disabled'}.", invite_id=invite.id, details={'plex_user': plex_username, 'allow_downloads': invite.allow_downloads})
    except Exception as e:
        log_event(EventType.ERROR_PLEX_API, f"Failed to grant Plex access for {plex_username} via invite {invite.id}: {e}", invite_id=invite.id)
        return False, f"Could not grant Plex server access: {e}. Please contact admin."

    # Create new PUM User
    try:
        user_access_expires_at = None
        if invite.membership_duration_days and invite.membership_duration_days > 0:
            user_access_expires_at = datetime.now(timezone.utc) + timedelta(days=invite.membership_duration_days)
            current_app.logger.info(f"User {plex_username} access from invite {invite.id} will expire on {user_access_expires_at}.")

        new_user = User(
            plex_uuid=plex_user_uuid,
            plex_username=plex_username,
            plex_email=plex_email,
            plex_thumb_url=plex_thumb,
            allowed_library_ids=list(invite.grant_library_ids), # Make a copy
            used_invite_id=invite.id,
            discord_user_id=discord_user_id,
            discord_username=discord_username,
            discord_avatar_hash=discord_avatar_hash,
            access_expires_at=user_access_expires_at, # Set the expiration date
            last_synced_with_plex=datetime.now(timezone.utc), # Mark as synced
            is_purge_whitelisted=bool(invite.grant_purge_whitelist),
            is_discord_bot_whitelisted=bool(invite.grant_bot_whitelist)
        )
        db.session.add(new_user)
        
        invite.current_uses += 1
        # No need to explicitly check invite.has_reached_max_uses here to deactivate;
        # the invite.is_usable check at the start handles it for subsequent uses.
        
        usage_log = record_invite_usage_attempt(
            invite.id, ip_address,
            plex_user_info={'uuid': plex_user_uuid, 'username': plex_username, 'email': plex_email, 'thumb': plex_thumb},
            discord_user_info={'id': discord_user_id, 'username': discord_username} if discord_user_id else None,
            status_message="Invite accepted successfully."
        )
        # We need the new_user.id, so we have to add it to session before flush/commit
        # or commit in stages. Let's flush to get ID.
        db.session.flush() # Assigns ID to new_user without full commit
        if new_user.id:
            usage_log.pum_user_id = new_user.id
        else: # Should not happen if flush works
            current_app.logger.error(f"Failed to get new_user.id after flush for invite {invite.id}")
        usage_log.accepted_invite = True
        db.session.add(usage_log)
        db.session.add(invite) # ensure invite changes (current_uses) are also staged

        db.session.commit() # Commit user, invite, and usage log changes together

        log_event(EventType.INVITE_USER_ACCEPTED_AND_SHARED, 
                  f"User '{plex_username}' accepted invite '{invite.id}'. Access expires: {user_access_expires_at.strftime('%Y-%m-%d %H:%M UTC') if user_access_expires_at else 'Permanent'}.", 
                  user_id=new_user.id, invite_id=invite.id)
        
        return True, new_user 

    except IntegrityError as ie_user: # Catch potential IntegrityError during User creation specifically
        db.session.rollback()
        current_app.logger.error(f"Database integrity error creating PUM user {plex_username} from invite {invite.id}: {ie_user}", exc_info=True)
        # Log the event before returning
        log_event(EventType.ERROR_GENERAL, f"DB integrity error creating user {plex_username} from invite {invite.id}: {ie_user}", invite_id=invite.id)
        return False, "A database error occurred creating your user account. This could be due to a conflict. Please contact admin."
    except Exception as e_user:
        db.session.rollback()
        current_app.logger.error(f"Failed to create PUM user {plex_username} from invite {invite.id} after Plex share: {e_user}", exc_info=True)
        log_event(EventType.ERROR_GENERAL, f"Error creating PUM user {plex_username} from invite {invite.id} after Plex share: {e_user}", invite_id=invite.id)
        return False, f"An unexpected error occurred creating your user account after Plex access was granted: {e_user}. Please contact admin."