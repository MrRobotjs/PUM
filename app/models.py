import enum
import json
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy.types import TypeDecorator, TEXT
from sqlalchemy.ext.mutable import MutableDict, MutableList
from app.extensions import db # Removed login_manager, not used here
import secrets
from flask import current_app 

# (JSONEncodedDict, SettingValueType, EventType enums as before - no changes needed there yet for bot)
class JSONEncodedDict(TypeDecorator): # ... (as before)
    impl = TEXT
    def process_bind_param(self, value, dialect):
        if value is not None: return json.dumps(value)
        return value
    def process_result_value(self, value, dialect):
        if value is not None: return json.loads(value)
        return value

class SettingValueType(enum.Enum): # ... (as before)
    STRING = "string"; INTEGER = "integer"; BOOLEAN = "boolean"; JSON = "json"; SECRET = "secret"

class EventType(enum.Enum): # ... (as before, will add bot-specific events later)
    APP_STARTUP = "APP_STARTUP"; APP_SHUTDOWN = "APP_SHUTDOWN"; SETTING_CHANGE = "SETTING_CHANGE"
    ADMIN_LOGIN_SUCCESS = "ADMIN_LOGIN_SUCCESS"; ADMIN_LOGIN_FAIL = "ADMIN_LOGIN_FAIL"; ADMIN_LOGOUT = "ADMIN_LOGOUT"
    ADMIN_PASSWORD_CHANGE = "ADMIN_PASSWORD_CHANGE"; PLEX_CONFIG_TEST_SUCCESS = "PLEX_CONFIG_TEST_SUCCESS"
    PLEX_CONFIG_TEST_FAIL = "PLEX_CONFIG_TEST_FAIL"; PLEX_CONFIG_SAVE = "PLEX_CONFIG_SAVE"
    PLEX_SYNC_USERS_START = "PLEX_SYNC_USERS_START"; PLEX_SYNC_USERS_COMPLETE = "PLEX_SYNC_USERS_COMPLETE"
    PLEX_USER_ADDED = "PLEX_USER_ADDED_TO_SERVER"; PLEX_USER_REMOVED = "PLEX_USER_REMOVED_FROM_SERVER"
    PLEX_USER_LIBS_UPDATED = "PLEX_USER_LIBS_UPDATED_ON_SERVER"; PLEX_SESSION_DETECTED = "PLEX_SESSION_DETECTED"
    PUM_USER_ADDED_FROM_PLEX = "PUM_USER_ADDED_FROM_PLEX"
    PUM_USER_REMOVED_MISSING_IN_PLEX = "PUM_USER_REMOVED_MISSING_IN_PLEX"
    PUM_USER_LIBRARIES_EDITED = "PUM_USER_LIBRARIES_EDITED"
    PUM_USER_DELETED_FROM_PUM = "PUM_USER_DELETED_FROM_PUM"; INVITE_CREATED = "INVITE_CREATED"
    INVITE_DELETED = "INVITE_DELETED"; INVITE_VIEWED = "INVITE_VIEWED"
    INVITE_USED_SUCCESS_PLEX = "INVITE_USED_SUCCESS_PLEX"
    INVITE_USED_SUCCESS_DISCORD = "INVITE_USED_SUCCESS_DISCORD"
    INVITE_USED_ACCOUNT_LINKED = "INVITE_USED_ACCOUNT_LINKED"
    INVITE_USER_ACCEPTED_AND_SHARED = "INVITE_USER_ACCEPTED_AND_SHARED"; INVITE_EXPIRED = "INVITE_EXPIRED"
    INVITE_MAX_USES_REACHED = "INVITE_MAX_USES_REACHED"; DISCORD_CONFIG_SAVE = "DISCORD_CONFIG_SAVE"
    DISCORD_ADMIN_LINK_SUCCESS = "DISCORD_ADMIN_LINK_SUCCESS"
    DISCORD_ADMIN_UNLINK = "DISCORD_ADMIN_UNLINK"; ERROR_GENERAL = "ERROR_GENERAL"
    ERROR_PLEX_API = "ERROR_PLEX_API"; ERROR_DISCORD_API = "ERROR_DISCORD_API"
    DISCORD_BOT_START = "DISCORD_BOT_START"
    DISCORD_BOT_STOP = "DISCORD_BOT_STOP"
    DISCORD_BOT_ERROR = "DISCORD_BOT_ERROR"
    DISCORD_BOT_USER_LEFT_SERVER = "DISCORD_BOT_USER_LEFT_SERVER" # User left Discord
    DISCORD_BOT_USER_REMOVED_FROM_PLEX = "DISCORD_BOT_USER_REMOVED_FROM_PLEX" # Bot removed user from Plex
    DISCORD_BOT_ROLE_ADDED_INVITE_SENT = "DISCORD_BOT_ROLE_ADDED_INVITE_SENT" # Bot sent invite due to role add
    DISCORD_BOT_ROLE_REMOVED_USER_REMOVED = "DISCORD_BOT_ROLE_REMOVED_USER_REMOVED" # Bot removed user due to role removal
    DISCORD_BOT_PURGE_DM_SENT = "DISCORD_BOT_PURGE_DM_SENT" # DM sent for app-initiated purge
    DISCORD_BOT_GUILD_MEMBER_CHECK_FAIL = "DISCORD_BOT_GUILD_MEMBER_CHECK_FAIL" # Failed guild check on invite page
    # Add Bot Specific Event Types Later, e.g., BOT_USER_PURGED, BOT_INVITE_SENT

class Setting(db.Model): # ... (Setting model remains the same structure, new keys will be added via UI/code) ...
    __tablename__ = 'settings'; id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    value_type = db.Column(db.Enum(SettingValueType), default=SettingValueType.STRING, nullable=False)
    name = db.Column(db.String(100), nullable=True); description = db.Column(db.Text, nullable=True)
    is_public = db.Column(db.Boolean, default=False); created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    def __repr__(self): return f'<Setting {self.key}>'
    def get_value(self):
        if self.value is None: return None
        if self.value_type == SettingValueType.INTEGER: return int(self.value)
        elif self.value_type == SettingValueType.BOOLEAN: return self.value.lower() in ['true', '1', 'yes', 'on']
        elif self.value_type == SettingValueType.JSON:
            try: return json.loads(self.value)
            except json.JSONDecodeError: return None
        return self.value
    @staticmethod
    def get(key_name, default=None):
        if current_app:
            engine_conn_setting_get = None
            try:
                engine_conn_setting_get = db.engine.connect()
                if db.engine.dialect.has_table(engine_conn_setting_get, Setting.__tablename__):
                    setting_obj = Setting.query.filter_by(key=key_name).first()
                    if setting_obj: return setting_obj.get_value()
            except Exception as e: current_app.logger.debug(f"Setting.get({key_name}): DB query failed: {e}")
            finally:
                if engine_conn_setting_get: engine_conn_setting_get.close()
            if key_name in current_app.config: return current_app.config.get(key_name, default)
        return default
    @staticmethod
    def set(key_name, value, v_type=SettingValueType.STRING, name=None, description=None, is_public=False):
        setting = Setting.query.filter_by(key=key_name).first()
        if not setting: setting = Setting(key=key_name); db.session.add(setting)
        setting.value_type = v_type; setting.name = name or setting.name; setting.description = description or setting.description; setting.is_public = is_public
        if v_type == SettingValueType.JSON and not isinstance(value, str): setting.value = json.dumps(value)
        elif isinstance(value, bool) and v_type == SettingValueType.BOOLEAN: setting.value = 'true' if value else 'false'
        elif isinstance(value, int) and v_type == SettingValueType.INTEGER: setting.value = str(value)
        elif value is None: setting.value = None # Allow unsetting/nulling a value
        else: setting.value = str(value)
        db.session.commit()
        if current_app and key_name.isupper(): current_app.config[key_name] = setting.get_value()
        return setting
    @staticmethod
    def get_bool(key_name, default=False):
        val_str = Setting.get(key_name) # Setting.get already handles defaults and app.config fallback
        if val_str is None: # If Setting.get returned None (meaning not found and no default from .get itself)
            return default
        if isinstance(val_str, bool): # If Setting.get somehow returned a bool already
            return val_str
        return str(val_str).lower() in ['true', '1', 'yes', 'on']
    # --- END OF get_bool ---

class AdminAccount(db.Model, UserMixin): # ... (no changes needed for bot feature yet) ...
    __tablename__ = 'admin_accounts'; id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(256), nullable=True)
    plex_uuid = db.Column(db.String(255), unique=True, nullable=True); plex_username = db.Column(db.String(255), nullable=True)
    plex_thumb = db.Column(db.String(512), nullable=True); email = db.Column(db.String(120), unique=True, nullable=True)
    is_plex_sso_only = db.Column(db.Boolean, default=False); created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    discord_user_id = db.Column(db.String(255), unique=True, nullable=True); discord_username = db.Column(db.String(255), nullable=True)
    discord_avatar_hash = db.Column(db.String(255), nullable=True); discord_access_token = db.Column(db.String(255), nullable=True)
    discord_refresh_token = db.Column(db.String(255), nullable=True); discord_token_expires_at = db.Column(db.DateTime, nullable=True)
    discord_email = db.Column(db.String(255), nullable=True)
    discord_email_verified = db.Column(db.Boolean, nullable=True)
    force_password_change = db.Column(db.Boolean, default=False, nullable=False)
    permissions = db.Column(MutableList.as_mutable(JSONEncodedDict), nullable=True, default=list)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password) if self.password_hash else False
    def __repr__(self): return f'<AdminAccount {self.username or self.plex_username}>'
    def has_permission(self, permission_name):
        # A simple check. You might want a super-admin rule later.
        # For now, if permissions list is None or empty, assume full access for the primary admin.
        # Or check for a specific 'superuser' permission.
        if self.permissions is None:
             # This can happen for the very first admin created. We can treat them as a superuser.
             # Let's assume the first admin (id=1) is always a superuser.
            return self.id == 1 
        return permission_name in self.permissions


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True) 
    plex_user_id = db.Column(db.Integer, unique=True, nullable=True, index=True)
    plex_username = db.Column(db.String(255), unique=True, nullable=False, index=True)
    plex_email = db.Column(db.String(255), nullable=True)
    plex_thumb_url = db.Column(db.String(512), nullable=True) 
    plex_uuid = db.Column(db.String(255), unique=True, nullable=False, index=True) 
    is_home_user = db.Column(db.Boolean, default=False, nullable=False) # Added nullable=False
    shares_back = db.Column(db.Boolean, default=False, nullable=False) # Added nullable=False
    is_plex_friend = db.Column(db.Boolean, default=False, nullable=False) # For Req related to "friends" specifically
    discord_email = db.Column(db.String(255), nullable=True)
    discord_email_verified = db.Column(db.Boolean, nullable=True)
    allowed_library_ids = db.Column(MutableList.as_mutable(JSONEncodedDict), default=list)
    allowed_servers = db.Column(MutableList.as_mutable(JSONEncodedDict), default=list) 
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_synced_with_plex = db.Column(db.DateTime, nullable=True)
    last_streamed_at = db.Column(db.DateTime, nullable=True)
    access_expires_at = db.Column(db.DateTime, nullable=True, index=True) # When this user's access (from an invite) expires

    used_invite_id = db.Column(db.Integer, db.ForeignKey('invites.id'), nullable=True)
    invite = db.relationship('Invite', back_populates='redeemed_users')

    discord_user_id = db.Column(db.String(255), unique=True, nullable=True) 
    discord_username = db.Column(db.String(255), nullable=True)
    discord_avatar_hash = db.Column(db.String(255), nullable=True)

    # New fields for Bot and Purge Whitelisting
    is_discord_bot_whitelisted = db.Column(db.Boolean, default=False, nullable=False) # Req #13
    is_purge_whitelisted = db.Column(db.Boolean, default=False, nullable=False)      # Req #16

    def __repr__(self): return f'<User {self.plex_username}>'
    def get_avatar(self, fallback='/static/img/default_avatar.png'): return self.plex_thumb_url or fallback

# (Invite, InviteUsage, HistoryLog models as before - no immediate changes for bot setup yet)
class Invite(db.Model):
    __tablename__ = 'invites'; id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True, default=lambda: secrets.token_urlsafe(8))
    custom_path = db.Column(db.String(100), unique=True, nullable=True, index=True); expires_at = db.Column(db.DateTime, nullable=True)
    max_uses = db.Column(db.Integer, nullable=True); current_uses = db.Column(db.Integer, default=0, nullable=False) # Added nullable=False
    grant_library_ids = db.Column(MutableList.as_mutable(JSONEncodedDict), default=list)
    allow_downloads = db.Column(db.Boolean, default=False, nullable=False)
    created_by_admin_id = db.Column(db.Integer, db.ForeignKey('admin_accounts.id')); admin_creator = db.relationship('AdminAccount')
    created_at = db.Column(db.DateTime, default=datetime.utcnow); updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True); redeemed_users = db.relationship('User', back_populates='invite') # Added nullable=False
    invite_usages = db.relationship('InviteUsage', back_populates='invite', cascade="all, delete-orphan")
    membership_duration_days = db.Column(db.Integer, nullable=True) # Duration in days set at invite creation
    force_discord_auth = db.Column(db.Boolean, nullable=True)
    force_guild_membership = db.Column(db.Boolean, nullable=True)
    grant_purge_whitelist = db.Column(db.Boolean, nullable=True, default=False)
    grant_bot_whitelist = db.Column(db.Boolean, nullable=True, default=False)
    def __repr__(self): return f'<Invite {self.custom_path or self.token}>'
    @property
    def is_expired(self): return self.expires_at and datetime.utcnow() > self.expires_at
    @property
    def has_reached_max_uses(self): return self.max_uses is not None and self.current_uses >= self.max_uses
    @property
    def is_usable(self): return self.is_active and not self.is_expired and not self.has_reached_max_uses
    def get_full_url(self, app_base_url):
        if not app_base_url: return "#INVITE_URL_NOT_CONFIGURED"
        path_part = self.custom_path if self.custom_path else self.token
        return f"{app_base_url.rstrip('/')}/invite/{path_part}"

class InviteUsage(db.Model): # ... (as before)
    __tablename__ = 'invite_usages'; id = db.Column(db.Integer, primary_key=True)
    invite_id = db.Column(db.Integer, db.ForeignKey('invites.id'), nullable=False); invite = db.relationship('Invite', back_populates='invite_usages')
    used_at = db.Column(db.DateTime, default=datetime.utcnow); ip_address = db.Column(db.String(45), nullable=True)
    plex_user_uuid = db.Column(db.String(255), nullable=True); plex_username = db.Column(db.String(255), nullable=True)
    plex_email = db.Column(db.String(120), nullable=True); plex_thumb = db.Column(db.String(512), nullable=True)
    plex_auth_successful = db.Column(db.Boolean, default=False, nullable=False); discord_user_id = db.Column(db.String(255), nullable=True) # Added nullable=False
    discord_username = db.Column(db.String(255), nullable=True); discord_auth_successful = db.Column(db.Boolean, default=False, nullable=False) # Added nullable=False
    pum_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True); pum_user = db.relationship('User')
    accepted_invite = db.Column(db.Boolean, default=False, nullable=False); status_message = db.Column(db.String(255), nullable=True) # Added nullable=False

class HistoryLog(db.Model): # ... (as before)
    __tablename__ = 'history_logs'; id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    event_type = db.Column(db.Enum(EventType), nullable=False, index=True); message = db.Column(db.Text, nullable=False)
    details = db.Column(MutableDict.as_mutable(JSONEncodedDict), nullable=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin_accounts.id'), nullable=True); admin = db.relationship('AdminAccount')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True); affected_user = db.relationship('User')
    invite_id = db.Column(db.Integer, db.ForeignKey('invites.id'), nullable=True); related_invite = db.relationship('Invite')
    def __repr__(self): return f'<HistoryLog {self.timestamp} [{self.event_type.name}]: {self.message[:50]}>'