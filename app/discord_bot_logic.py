import discord # Import the discord.py library
from discord.ext import commands
from discord import app_commands # For slash commands
from app.models import get_app_setting, InviteLink, User, HistoryLog, db # Access models and db
from app.plex_utils import remove_plex_friend # For Plex user removal
from datetime import datetime, timedelta
import asyncio # For async operations
from flask import current_app # To access Flask app logger from bot context if needed directly (though bot.flask_app.logger is preferred)

# --- Helper to DM Admin on Error ---
async def dm_admin_on_error(bot: commands.Bot, error_message: str, context_info: str = ""):
    """Sends a DM to the configured admin Discord ID if an error occurs."""
    logger = bot.flask_app.logger if hasattr(bot, 'flask_app') and bot.flask_app else current_app.logger if current_app else print
    admin_discord_id_str = get_app_setting('ADMIN_DISCORD_ID') # This uses app context implicitly via get_app_setting
    log_prefix = f"Discord Bot Alert ({context_info}): " if context_info else "Discord Bot Alert: "

    if admin_discord_id_str and admin_discord_id_str.isdigit():
        try:
            admin_user_id = int(admin_discord_id_str)
            admin_discord_user_obj = await bot.fetch_user(admin_user_id) # Use bot's method
            if admin_discord_user_obj:
                await admin_discord_user_obj.send(f"**Plex Invite Manager Bot Alert:**\n{error_message[:1900]}") # Discord DM limit
                logger.info(f"{log_prefix}DM sent to admin {admin_discord_user_obj.name} about error.")
        except ValueError:
            logger.error(f"{log_prefix}Invalid ADMIN_DISCORD_ID format: {admin_discord_id_str}")
        except discord.NotFound:
            logger.error(f"{log_prefix}Admin Discord user with ID {admin_discord_id_str} not found.")
        except discord.Forbidden: # Bot cannot DM the user
            logger.error(f"{log_prefix}Bot lacks permission to DM admin user {admin_discord_id_str}. Ensure DMs are open from server members.")
        except Exception as e:
            logger.error(f"{log_prefix}Failed to DM admin: {e}", exc_info=True)
    elif admin_discord_id_str: # It's configured but not a digit string
         logger.error(f"{log_prefix}Admin Discord ID '{admin_discord_id_str}' is not a valid ID format. Cannot send DM.")
    # else: Admin Discord ID not configured, logged by calling function usually


# --- Main Bot Setup Function ---
def setup_bot_events_and_commands(bot: commands.Bot):
    logger = bot.flask_app.logger if hasattr(bot, 'flask_app') and bot.flask_app else current_app.logger if current_app else print

    @bot.event
    async def on_ready():
        logger.info(f"Discord bot '{bot.user.name}' (ID: {bot.user.id}) has connected and is ready!")
        
        server_id_str = get_app_setting('DISCORD_SERVER_ID') 
        if not server_id_str or not server_id_str.isdigit():
            logger.warning("DISCORD_SERVER_ID not configured or invalid. Slash commands may not sync correctly to a specific guild.")
            try: # Attempt global sync if no guild ID
                await bot.tree.sync()
                logger.info("Synced slash commands globally (no specific guild ID configured or guild not found).")
            except Exception as e_sync_global:
                logger.error(f"Error syncing slash commands globally: {e_sync_global}", exc_info=True)
                await dm_admin_on_error(bot, f"Failed to sync slash commands globally: {e_sync_global}. Check bot permissions (application.commands).", "on_ready_sync")
            return

        guild_to_sync = discord.Object(id=int(server_id_str))
        logger.info(f"Bot operating for Guild ID: {server_id_str}. Attempting to sync slash commands to this guild.")
        try:
            # When syncing to a specific guild, it's often faster and preferred.
            bot.tree.copy_global_to(guild=guild_to_sync) # Optional: copies global commands to guild
            await bot.tree.sync(guild=guild_to_sync)
            logger.info(f"Successfully synced slash commands for guild {server_id_str}.")
        except discord.Forbidden:
            logger.error(f"Bot lacks 'application.commands' permission to sync slash commands for guild {server_id_str}.")
            await dm_admin_on_error(bot, f"Bot lacks 'application.commands' permission to sync slash commands for guild {server_id_str}. Please re-invite with correct scopes or check server integration settings.", "on_ready_sync")
        except discord.HTTPException as e_sync_guild: # Catch other HTTP errors during sync
             logger.error(f"HTTP error syncing slash commands for guild {server_id_str}: {e_sync_guild}", exc_info=True)
             await dm_admin_on_error(bot, f"HTTP error syncing slash commands for guild {server_id_str}: {e_sync_guild}. This could be a temporary Discord issue or a problem with the guild ID.", "on_ready_sync")
        except Exception as e_sync_other: # Catch any other unexpected errors
            logger.error(f"Unexpected error syncing slash commands for guild {server_id_str}: {e_sync_other}", exc_info=True)
            await dm_admin_on_error(bot, f"Unexpected error syncing slash commands for guild {server_id_str}: {e_sync_other}. Check bot logs.", "on_ready_sync")

    # --- Slash Command for Plex Invite Request ---
    @bot.tree.command(name="request_plex_invite", description="Request an invitation to the Plex server.")
    @app_commands.describe(plex_email="Your Plex email address (case-insensitive)")
    async def request_plex_invite_command(interaction: discord.Interaction, plex_email: str):
        bot_logger = bot.flask_app.logger # Use the Flask app's logger via the bot instance
        await interaction.response.defer(ephemeral=True) 

        async def perform_invite_request_with_context(): 
            with bot.flask_app.app_context(): # Ensure all DB/AppSetting calls have context
                command_channel_id_str = get_app_setting('DISCORD_COMMAND_CHANNEL_ID')
                mention_role_id_str = get_app_setting('DISCORD_MENTION_ROLE_ID')
                server_id_str = get_app_setting('DISCORD_SERVER_ID')
                app_base_url = get_app_setting('APP_BASE_URL') # Must be configured for links

                if not command_channel_id_str or not server_id_str or not app_base_url or \
                   not command_channel_id_str.isdigit() or not server_id_str.isdigit():
                    msg = "Bot invite feature is not fully configured by admin (missing/invalid channel, server ID, or app base URL)."
                    bot_logger.error(f"Invite request failed: {msg}")
                    await dm_admin_on_error(bot, msg, "request_plex_invite_config")
                    return msg, True 

                if str(interaction.guild_id) != server_id_str:
                    return "This command can only be used in the designated server.", True
                
                # Optionally restrict command usage to the command_channel_id if desired
                # if str(interaction.channel_id) != command_channel_id_str:
                #     return f"Please use this command in the designated command channel (configured by admin).", True

                normalized_plex_email = plex_email.strip().lower()
                discord_id_str = str(interaction.user.id)

                existing_user = User.query.filter_by(is_admin=False).filter(
                    db.or_(User.plex_email == normalized_plex_email, User.discord_id == discord_id_str)
                ).first()
                if existing_user:
                    return "Your Discord ID or Plex email is already registered or has an active invite processed by this system.", True

                link_custom_path = f"bot-{discord_id_str}-{int(datetime.now().timestamp())}"
                invite_expiry_hours = int(get_app_setting('BOT_INVITE_EXPIRY_HOURS', '24'))
                
                new_invite_link = InviteLink(
                    custom_path=link_custom_path, max_uses=1,
                    expires_at=datetime.utcnow() + timedelta(hours=invite_expiry_hours),
                    # allowed_libraries: Consider a default set from AppSetting, or leave None for all
                )
                db.session.add(new_invite_link); db.session.commit()
                HistoryLog.create(event_type="INVITE_CREATED_BOT", discord_id=discord_id_str, details=f"Path: {link_custom_path} for Plex email {normalized_plex_email}")

                public_invite_url = f"{app_base_url.rstrip('/')}/invite/{new_invite_link.custom_path}"

                try:
                    target_channel = bot.get_channel(int(command_channel_id_str))
                    if not isinstance(target_channel, discord.TextChannel):
                        msg = f"Configured Command Channel ID ({command_channel_id_str}) is not a valid text channel for creating threads."
                        bot_logger.error(msg); await dm_admin_on_error(bot, msg, "request_plex_invite_channel")
                        return "Channel configuration error. Admin notified.", True
                    
                    thread_name = f"Plex Invite - {interaction.user.display_name}"
                    thread_name = (thread_name[:97] + '...') if len(thread_name) > 100 else thread_name
                    thread_type = discord.ChannelType.private_thread 
                    
                    thread = await target_channel.create_thread(name=thread_name, type=thread_type, reason=f"Plex invite for {interaction.user.name}")
                    await thread.add_user(interaction.user) 

                    mention_content = ""
                    if mention_role_id_str and mention_role_id_str.isdigit():
                        try:
                            role = interaction.guild.get_role(int(mention_role_id_str)) # type: ignore
                            if role: mention_content = f"{role.mention} "
                        except Exception as e_role: bot_logger.warning(f"Could not fetch role {mention_role_id_str} for mention: {e_role}")
                    
                    await thread.send(
                        f"{mention_content}Hello {interaction.user.mention}!\n\n"
                        f"Please use the link below to finalize your Plex server invitation. "
                        f"You'll need to confirm your Plex email (**{normalized_plex_email}**) and Discord ID (**{discord_id_str}**) on the page.\n\n"
                        f"Your personal invite link: {public_invite_url}\n\n"
                        f"This link is for you, is single-use, and expires in {invite_expiry_hours} hours."
                    )
                    return f"A private thread for your invite has been created: {thread.mention}. Please check it!", False

                except discord.Forbidden as e_forbidden:
                    err_msg = (f"Bot lacks permissions for thread creation/messaging in channel ID {command_channel_id_str}. "
                               f"Error: {e_forbidden.text}. Check: Create Private Threads, Send Messages, Send Messages in Threads.")
                    bot_logger.error(err_msg); await dm_admin_on_error(bot, err_msg, "request_plex_invite_perms")
                    return "I couldn't create a thread due to a permission issue. Admin notified.", True
                except Exception as e_thread:
                    bot_logger.error(f"Error creating invite thread for {discord_id_str}: {e_thread}", exc_info=True)
                    await dm_admin_on_error(bot, f"Unexpected error creating invite thread for {interaction.user.display_name}: {e_thread}", "request_plex_invite_thread_error")
                    return "An unexpected error occurred. Admin notified.", True
        
        response_message, is_ephemeral = await perform_invite_request_with_context()
        await interaction.followup.send(response_message, ephemeral=is_ephemeral)

    # --- Event for Member Role Updates ---
    @bot.event
    async def on_member_update(before: discord.Member, after: discord.Member):
        bot_logger = bot.flask_app.logger
        server_id_str = get_app_setting('DISCORD_SERVER_ID')
        if not server_id_str or str(after.guild.id) != server_id_str: return

        plex_access_role_id_str = get_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID')
        if not plex_access_role_id_str or not plex_access_role_id_str.isdigit(): return

        plex_access_role_id = int(plex_access_role_id_str)
        role_in_before = any(r.id == plex_access_role_id for r in before.roles)
        role_in_after = any(r.id == plex_access_role_id for r in after.roles)

        if role_in_before and not role_in_after: # Role was removed
            bot_logger.info(f"Plex access role (ID: {plex_access_role_id}) removed from user {after.display_name} ({after.id}).")
            async def revoke_plex_on_role_remove_with_context():
                with bot.flask_app.app_context():
                    user_to_revoke = User.query.filter_by(discord_id=str(after.id), is_admin=False).first()
                    if user_to_revoke:
                        plex_ident = user_to_revoke.plex_username or user_to_revoke.plex_email
                        if not plex_ident: bot_logger.warning(f"Cannot revoke Plex for Discord ID {after.id}, no Plex identifier."); return
                        bot_logger.info(f"Revoking Plex for '{plex_ident}' (Discord: {after.id}) due to role removal.")
                        success, message = remove_plex_friend(plex_ident)
                        if success:
                            bot_logger.info(f"Successfully removed '{plex_ident}' from Plex: {message}")
                            HistoryLog.create(event_type="USER_REMOVED_DISCORD_ROLE", plex_username=plex_ident, discord_id=str(after.id), details=f"Plex Access Role removed. Plex: {message}")
                            db.session.delete(user_to_revoke); db.session.commit()
                        else:
                            bot_logger.error(f"Failed to remove '{plex_ident}' from Plex after role removal: {message}")
                            HistoryLog.create(event_type="ERROR_REMOVING_USER_DISCORD_ROLE", plex_username=plex_ident, discord_id=str(after.id), details=f"Plex removal failed: {message}")
                            await dm_admin_on_error(bot, f"Failed to remove Plex user {plex_ident} (Discord: {after.id}) after role removal: {message}", "on_member_update_role_remove")
                    else: bot_logger.info(f"User {after.display_name} ({after.id}) had role removed, but no linked account in app DB.")
            await revoke_plex_on_role_remove_with_context()

    # --- Event for Member Leaving Server ---
    @bot.event
    async def on_member_remove(member: discord.Member):
        bot_logger = bot.flask_app.logger
        server_id_str = get_app_setting('DISCORD_SERVER_ID')
        if not server_id_str or str(member.guild.id) != server_id_str: return

        bot_logger.info(f"User {member.display_name} ({member.id}) left Discord server {member.guild.name}.")
        async def revoke_plex_on_leave_with_context():
            with bot.flask_app.app_context():
                user_to_revoke = User.query.filter_by(discord_id=str(member.id), is_admin=False).first()
                if user_to_revoke:
                    plex_ident = user_to_revoke.plex_username or user_to_revoke.plex_email
                    if not plex_ident: bot_logger.warning(f"Cannot revoke Plex for left Discord user {member.id}, no Plex identifier."); return
                    bot_logger.info(f"Revoking Plex for '{plex_ident}' (Discord: {member.id}) because they left server.")
                    success, message = remove_plex_friend(plex_ident)
                    if success:
                        bot_logger.info(f"Successfully removed '{plex_ident}' from Plex: {message}")
                        HistoryLog.create(event_type="USER_LEFT_DISCORD_SERVER", plex_username=plex_ident, discord_id=str(member.id), details=f"Left Discord. Plex: {message}")
                        db.session.delete(user_to_revoke); db.session.commit()
                    else:
                        bot_logger.error(f"Failed to remove '{plex_ident}' from Plex after leaving server: {message}")
                        HistoryLog.create(event_type="ERROR_REMOVING_USER_LEFT_DISCORD", plex_username=plex_ident, discord_id=str(member.id), details=f"Plex removal failed: {message}")
                        await dm_admin_on_error(bot, f"Failed to remove Plex user {plex_ident} (Discord: {member.id}) after they left server: {message}", "on_member_remove_leave")
                else: bot_logger.info(f"User {member.display_name} ({member.id}) left server, but no linked account in app DB.")
        await revoke_plex_on_leave_with_context()

    # --- Callable Function for Flask App to Trigger Discord Role Removal ---
    async def trigger_role_removal_from_app(user_discord_id: str, role_id_to_remove_str: str, reason: str = "Plex access removed via app"):
        bot_logger = bot.flask_app.logger
        if not bot or bot.is_closed(): 
            bot_logger.warning("Bot not running/closed, cannot remove Discord role."); return False, "Bot is not operational."

        server_id_str = get_app_setting('DISCORD_SERVER_ID')
        if not server_id_str or not role_id_to_remove_str or not user_discord_id or \
           not server_id_str.isdigit() or not role_id_to_remove_str.isdigit() or not user_discord_id.isdigit():
            bot_logger.warning(f"Missing/invalid IDs for role removal: Server({server_id_str}), Role({role_id_to_remove_str}), User({user_discord_id})")
            return False, "Missing or invalid server, role, or user ID for role removal."

        try:
            guild = bot.get_guild(int(server_id_str))
            if not guild: bot_logger.error(f"Bot cannot find server ID: {server_id_str}."); return False, f"Bot cannot find server ({server_id_str})."
            
            member = await guild.fetch_member(int(user_discord_id))
            if not member: bot_logger.info(f"User {user_discord_id} not on server {guild.name}. Cannot remove role."); return True, f"User {user_discord_id} not found (already left?)."

            role_to_remove = guild.get_role(int(role_id_to_remove_str))
            if not role_to_remove:
                bot_logger.error(f"Role ID {role_id_to_remove_str} not found on server {guild.name}.")
                await dm_admin_on_error(bot, f"Configured Plex Access Role ID ({role_id_to_remove_str}) not found on server. Cannot remove role from {member.display_name}.", "trigger_role_removal_role_not_found")
                return False, f"Role ID {role_id_to_remove_str} not found."

            if role_to_remove in member.roles:
                await member.remove_roles(role_to_remove, reason=reason)
                bot_logger.info(f"Successfully removed role '{role_to_remove.name}' from {member.display_name} ({member.id}).")
                return True, f"Role '{role_to_remove.name}' removed from {member.display_name}."
            else:
                bot_logger.info(f"User {member.display_name} did not have role '{role_to_remove.name}'. No action.")
                return True, f"User {member.display_name} did not have role '{role_to_remove.name}'."

        except discord.Forbidden:
            err_msg = f"Bot lacks 'Manage Roles' permission to remove role ID {role_id_to_remove_str} from user {user_discord_id}."
            bot_logger.error(err_msg); await dm_admin_on_error(bot, err_msg, "trigger_role_removal_perms")
            return False, "Bot permission error (Manage Roles)."
        except discord.NotFound: 
            bot_logger.info(f"User {user_discord_id} not found on server during role removal (likely left).")
            return True, "User not found on server (already left?)."
        except Exception as e:
            bot_logger.error(f"Unexpected error removing Discord role for {user_discord_id}: {e}", exc_info=True)
            await dm_admin_on_error(bot, f"Unexpected error removing role for user {user_discord_id}: {e}", "trigger_role_removal_error")
            return False, f"Unexpected error: {str(e)[:100]}"

    setattr(bot, 'flask_app_callable_remove_role', trigger_role_removal_from_app)
    logger.info("Discord bot events, commands, and callable functions have been configured.")