# File: discord_bot/bot_core.py
import discord
from discord.ext import commands, tasks # tasks might be useful later
import asyncio
import os
import sys
from datetime import datetime, timezone
import logging

# --- Setup to allow access to Flask app context and models ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
sys.path.insert(0, PROJECT_ROOT)

flask_app_instance_for_bot = None
User, Setting, EventType, SettingValueType, db_session = None, None, None, None, None
log_event_pum, user_service_for_bot, plex_service_for_bot = None, None, None

try:
    from app import create_app as create_flask_app 
    from app.models import User as PUM_User, Setting as PUM_Setting, EventType as PUM_EventType, SettingValueType as PUM_SettingValueType
    from app.extensions import db as pum_db_session # Using the db session from extensions
    from app.utils.helpers import log_event as pum_log_event_func
    from app.services import user_service as pum_user_service_module
    from app.services import plex_service as pum_plex_service_module

    User, Setting, EventType, SettingValueType = PUM_User, PUM_Setting, PUM_EventType, PUM_SettingValueType
    db_session = pum_db_session
    log_event_pum = pum_log_event_func
    user_service_for_bot = pum_user_service_module
    plex_service_for_bot = pum_plex_service_module
    
    # Create a Flask app instance to work with its context
    # This should use the same configuration as your main app
    flask_app_instance_for_bot = create_flask_app(os.environ.get('FLASK_ENV', 'production')) # Or your preferred config
    if not flask_app_instance_for_bot:
        raise ImportError("Bot Core: Failed to create Flask app instance for bot operations.")

except ImportError as e:
    print(f"CRITICAL BOT ERROR: Error importing Flask app components in bot_core.py: {e}")
    print("Ensure this script is run from project root or PYTHONPATH is set, and Flask app is importable.")
    # If these fail, bot cannot function with DB access.
    # For now, script will exit if flask_app_instance_for_bot is None later.
    pass 

# --- Bot Specific Logging ---
bot_logger = logging.getLogger('pum_discord_bot')
bot_logger.setLevel(logging.INFO) # Or DEBUG for more verbosity
if not bot_logger.handlers:
    # Console Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    bot_logger.addHandler(ch)
    # Optional: File Handler for bot-specific logs
    # log_file_path = os.path.join(PROJECT_ROOT, 'logs', 'discord_bot.log')
    # os.makedirs(os.path.join(PROJECT_ROOT, 'logs'), exist_ok=True)
    # fh = logging.FileHandler(log_file_path)
    # fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    # bot_logger.addHandler(fh)


# --- Bot Configuration Variables ---
BOT_TOKEN = None
GUILD_ID = None 
MONITORED_ROLE_ID = None 
THREAD_CHANNEL_ID = None 
LOG_CHANNEL_ID = None 
BOT_ENABLED_IN_SETTINGS = False 
WHITELIST_SHARERS_FOR_BOT = False
APP_BASE_URL_FOR_BOT = None # For constructing invite links

# --- Bot Intents ---
intents = discord.Intents.default()
intents.members = True      
intents.guilds = True       
bot = commands.Bot(command_prefix="!pum>", intents=intents) # commands.Bot for flexibility

async def send_log_to_discord_channel(message: str, level: str = "INFO", embed_title_override=None):
    if not bot.is_ready() or not LOG_CHANNEL_ID: return # Bot not ready or no log channel
    try:
        channel = bot.get_channel(LOG_CHANNEL_ID)
        if channel and isinstance(channel, discord.TextChannel):
            color = discord.Color.blue()
            if level == "WARN": color = discord.Color.orange()
            elif level == "ERROR" or level == "CRITICAL": color = discord.Color.red()
            elif level == "SUCCESS": color = discord.Color.green()
            
            embed = discord.Embed(
                title=embed_title_override or f"PUM Bot Log ({level})",
                description=message[:4090], # Embed description limit
                color=color,
                timestamp=datetime.now(timezone.utc)
            )
            await channel.send(embed=embed)
        else: bot_logger.warning(f"Log channel ID {LOG_CHANNEL_ID} not found or not a TextChannel.")
    except Exception as e: bot_logger.error(f"Error sending log to Discord channel {LOG_CHANNEL_ID}: {e}")

def load_bot_config_from_db():
    global BOT_TOKEN, GUILD_ID, MONITORED_ROLE_ID, THREAD_CHANNEL_ID, LOG_CHANNEL_ID
    global BOT_ENABLED_IN_SETTINGS, WHITELIST_SHARERS_FOR_BOT, APP_BASE_URL_FOR_BOT

    if not flask_app_instance_for_bot or not Setting:
        bot_logger.critical("Flask app components not loaded properly. Cannot load bot configuration from DB.")
        return False
    
    try:
        with flask_app_instance_for_bot.app_context(): 
            bot_logger.info("Loading bot configuration from database...")
            
            bot_enabled_setting = Setting.get('DISCORD_BOT_ENABLED', False)
            BOT_ENABLED_IN_SETTINGS = bot_enabled_setting if isinstance(bot_enabled_setting, bool) else str(bot_enabled_setting).lower() == 'true'

            if not BOT_ENABLED_IN_SETTINGS:
                bot_logger.info("Discord Bot is NOT enabled in PUM settings.")
                return False # Explicitly return False if bot shouldn't run

            BOT_TOKEN = Setting.get('DISCORD_BOT_TOKEN')
            guild_id_str = Setting.get('DISCORD_GUILD_ID')
            GUILD_ID = int(guild_id_str) if guild_id_str and guild_id_str.isdigit() else None
            monitored_role_str = Setting.get('DISCORD_MONITORED_ROLE_ID')
            MONITORED_ROLE_ID = int(monitored_role_str) if monitored_role_str and monitored_role_str.isdigit() else None
            thread_channel_str = Setting.get('DISCORD_THREAD_CHANNEL_ID')
            THREAD_CHANNEL_ID = int(thread_channel_str) if thread_channel_str and thread_channel_str.isdigit() else None
            log_channel_str = Setting.get('DISCORD_BOT_LOG_CHANNEL_ID')
            LOG_CHANNEL_ID = int(log_channel_str) if log_channel_str and log_channel_str.isdigit() else None
            
            wsb_setting = Setting.get('DISCORD_BOT_WHITELIST_SHARERS', False)
            WHITELIST_SHARERS_FOR_BOT = wsb_setting if isinstance(wsb_setting, bool) else str(wsb_setting).lower() == 'true'
            APP_BASE_URL_FOR_BOT = Setting.get('APP_BASE_URL')

            missing_critical = []
            if not BOT_TOKEN: missing_critical.append("Bot Token")
            if not GUILD_ID: missing_critical.append("Guild ID")
            if not MONITORED_ROLE_ID: missing_critical.append("Monitored Role ID")
            if not THREAD_CHANNEL_ID: missing_critical.append("Thread Channel ID for Invites")
            
            if missing_critical:
                error_msg = f"Bot enabled but critical settings missing: {', '.join(missing_critical)}."
                bot_logger.error(error_msg)
                log_event_pum(EventType.DISCORD_BOT_ERROR, error_msg)
                return False # Bot cannot function
            
            bot_logger.info("Bot configuration loaded successfully.")
            return True
    except Exception as e:
        bot_logger.critical(f"CRITICAL ERROR loading bot configuration from DB: {e}", exc_info=True)
        return False

# --- Bot Events ---
@bot.event
async def on_ready():
    bot_logger.info(f'Bot logged in as {bot.user.name} (ID: {bot.user.id})')
    if not BOT_ENABLED_IN_SETTINGS:
        bot_logger.warning("Bot logic disabled via PUM settings. Bot will idle.")
        await send_log_to_discord_channel("Bot connected but is **DISABLED** in PUM settings. No actions will be performed.", level="WARN")
        # Consider bot.close() if you don't want it idling.
        return

    guild = bot.get_guild(GUILD_ID) if GUILD_ID else None
    if not guild:
        err_msg = f"Configured Guild ID ({GUILD_ID}) not found or bot is not a member. Critical bot functions will fail."
        bot_logger.error(err_msg); await send_log_to_discord_channel(err_msg, level="ERROR")
    else:
        bot_logger.info(f"Successfully connected to and monitoring Guild: {guild.name} (ID: {GUILD_ID})")
        await send_log_to_discord_channel(f"Bot connected & ready. Monitoring Guild: {guild.name} ({GUILD_ID})", level="SUCCESS")
        
        # Check monitored role
        if MONITORED_ROLE_ID:
            role = guild.get_role(MONITORED_ROLE_ID)
            if not role:
                err_msg_role = f"Configured Monitored Role ID ({MONITORED_ROLE_ID}) not found in guild '{guild.name}'. Role-based actions will fail."
                bot_logger.error(err_msg_role); await send_log_to_discord_channel(err_msg_role, level="ERROR")
            else:
                bot_logger.info(f"Found Monitored Role: '{role.name}' (ID: {MONITORED_ROLE_ID})")
        else: # Should have been caught by load_bot_config
            bot_logger.error("Monitored Role ID is not configured. Role-based actions will fail.")
            await send_log_to_discord_channel("ERROR: Monitored Role ID not configured!", level="ERROR")


    # Log to PUM History that bot started
    if flask_app_instance_for_bot and log_event_pum:
        try:
            with flask_app_instance_for_bot.app_context():
                log_event_pum(EventType.DISCORD_BOT_START, f"Discord bot '{bot.user.name}' started successfully and connected to Discord.")
        except Exception as e_log:
            bot_logger.error(f"Failed to log bot start to PUM history: {e_log}")


@bot.event
async def on_member_remove(member: discord.Member):
    if not BOT_ENABLED_IN_SETTINGS or not flask_app_instance_for_bot or not GUILD_ID or member.guild.id != GUILD_ID:
        return

    bot_logger.info(f"Member left/removed: {member.display_name} ({member.id}) from Guild {member.guild.name}")
    await send_log_to_discord_channel(f"User {member.display_name} (`{member.id}`) left/was removed from the Discord server.", level="INFO")

    with flask_app_instance_for_bot.app_context():
        log_event_pum(EventType.DISCORD_BOT_USER_LEFT_SERVER, 
                      f"User {member.display_name} (Discord ID: {member.id}) left/removed from Discord server.", 
                      details={'discord_id': member.id, 'discord_name': member.display_name})
        
        pum_user: User = User.query.filter_by(discord_user_id=str(member.id)).first()
        if pum_user:
            if pum_user.is_home_user:
                msg = f"User {member.display_name} ({pum_user.plex_username}) is Plex Home User. No bot removal action."
                bot_logger.info(msg); await send_log_to_discord_channel(msg, level="INFO"); return
            if pum_user.is_discord_bot_whitelisted:
                msg = f"User {member.display_name} ({pum_user.plex_username}) is bot-whitelisted. No removal action."
                bot_logger.info(msg); await send_log_to_discord_channel(msg, level="INFO"); return
            if WHITELIST_SHARERS_FOR_BOT and pum_user.shares_back:
                msg = f"User {member.display_name} ({pum_user.plex_username}) shares Plex back and 'Whitelist Sharers' is ON. No bot removal action."
                bot_logger.info(msg); await send_log_to_discord_channel(msg, level="INFO"); return

            bot_logger.info(f"Attempting to remove Plex access for PUM user {pum_user.plex_username} (Discord: {member.display_name}).")
            try:
                user_service_for_bot.delete_user_from_pum_and_plex(pum_user.id, admin_id=None) # Bot action, admin_id can be None or a system ID
                success_msg = f"Bot removed Plex access for {pum_user.plex_username} (Discord: {member.display_name}) due to leaving server."
                log_event_pum(EventType.DISCORD_BOT_USER_REMOVED_FROM_PLEX, success_msg, user_id=pum_user.id)
                await send_log_to_discord_channel(success_msg, level="WARN")
                try:
                    await member.send(f"Hello {member.display_name},\n\nYour access to the Plex server linked with '{member.guild.name}' has been automatically removed because you are no longer a member of our Discord server. If you believe this is an error, please contact an administrator.")
                    await send_log_to_discord_channel(f"Sent DM to {member.display_name} regarding Plex removal (left server).", level="INFO")
                except discord.Forbidden: await send_log_to_discord_channel(f"Could not send DM to {member.display_name} (DMs likely disabled).", level="WARN")
                except Exception as e_dm: await send_log_to_discord_channel(f"Error sending DM to {member.display_name}: {e_dm}", level="ERROR")
            except Exception as e_remove:
                err_msg_remove = f"ERROR removing Plex access for {pum_user.plex_username} (Discord: {member.display_name}): {e_remove}"
                bot_logger.error(err_msg_remove, exc_info=True)
                await send_log_to_discord_channel(err_msg_remove, level="ERROR")
                log_event_pum(EventType.DISCORD_BOT_ERROR, f"Bot failed to remove user {pum_user.plex_username} (left server): {e_remove}", user_id=pum_user.id)
        else:
            bot_logger.info(f"User {member.display_name} who left Discord was not found in PUM database by Discord ID.")
            await send_log_to_discord_channel(f"User {member.display_name} who left Discord was not found in PUM. No Plex action.", level="INFO")

# Placeholder for on_member_update (role changes)
@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    if not BOT_ENABLED_IN_SETTINGS or not flask_app_instance_for_bot or before.guild.id != GUILD_ID or MONITORED_ROLE_ID is None:
        return
    # ... (Logic for Req #9 and #11 to be implemented here) ...
    # Remember to use `with flask_app_instance_for_bot.app_context():` for DB/service calls
    pass


async def main_bot_runner():
    global flask_app_instance_for_bot # Ensure it's the global one
    if not flask_app_instance_for_bot:
         bot_logger.info("Flask app instance not available at start of main_bot_runner. Attempting to create.")
         flask_app_instance_for_bot = create_flask_app(os.environ.get('FLASK_ENV', 'production'))
         if not flask_app_instance_for_bot:
            bot_logger.critical("Failed to create Flask app instance. Bot cannot run.")
            return

    if load_bot_config_from_db(): 
        if BOT_ENABLED_IN_SETTINGS and BOT_TOKEN:
            try:
                bot_logger.info("Starting Discord bot with loaded token...")
                await bot.start(BOT_TOKEN)
            except discord.LoginFailure:
                bot_logger.critical("BOT LOGIN FAILED: Invalid Discord Bot Token. Please check settings in PUM.")
                with flask_app_instance_for_bot.app_context(): log_event_pum(EventType.DISCORD_BOT_ERROR, "Discord Bot login failed: Invalid token.")
            except Exception as e_start:
                bot_logger.critical(f"An error occurred while starting or running the bot: {e_start}", exc_info=True)
                with flask_app_instance_for_bot.app_context(): log_event_pum(EventType.DISCORD_BOT_ERROR, f"Discord Bot runtime error: {e_start}")
        else:
            bot_logger.info("Discord Bot is not enabled in settings or token is missing. Bot will not start.")
    else:
        bot_logger.error("Failed to load critical bot configuration from database. Bot will not start.")

if __name__ == '__main__':
    bot_logger.info("Attempting to run discord_bot/bot_core.py directly...")
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main_bot_runner())
    except KeyboardInterrupt:
        bot_logger.info("Bot shutdown requested by user (KeyboardInterrupt).")
    except Exception as e_main_loop:
        bot_logger.critical(f"Unhandled exception in asyncio main_bot_runner loop: {e_main_loop}", exc_info=True)
    finally:
        bot_logger.info("Bot process is terminating.")
        if bot and bot.is_ready():
            bot_logger.info("Attempting to close bot connection.")
            loop.run_until_complete(bot.close())
        # loop.close() # Usually not needed if run_until_complete finishes
        # If flask_app_instance_for_bot has any resources to clean up (like DB engine for direct use), do it here.
        # However, create_app() is lightweight.