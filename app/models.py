# app/models.py
from app import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime, timezone # Ensure timezone is imported
from cachetools import cached, TTLCache
from flask import current_app 
import logging

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=True) 
    email = db.Column(db.String(120), index=True, unique=True, nullable=True) 
    password_hash = db.Column(db.String(256), nullable=True) 
    is_admin = db.Column(db.Boolean, default=False)
    plex_thumb_url = db.Column(db.String(255), nullable=True)

    plex_user_id = db.Column(db.Integer, unique=True, nullable=True) 
    plex_username = db.Column(db.String(80), index=True, unique=True, nullable=True) 
    plex_email = db.Column(db.String(120), index=True, unique=True, nullable=True) 
    discord_id = db.Column(db.String(80), index=True, unique=True, nullable=True)
    discord_username = db.Column(db.String(100), nullable=True) 
    
    # This field remains but will no longer be updated by the removed scheduled task.
    # It will default to None for new users.
    last_streamed_at = db.Column(db.DateTime(timezone=True), nullable=True) 
    
    joined_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    invite_link_id = db.Column(db.Integer, db.ForeignKey('invite_link.id'), nullable=True)
    shares_back = db.Column(db.Boolean, default=False, nullable=False) 
    is_plex_home_user = db.Column(db.Boolean, default=False, nullable=False) 
    is_purge_whitelisted = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        if self.is_admin:
            return f'<AdminUser {self.username or self.id}>'
        return f'<PlexUser {self.plex_username or self.plex_email or self.id}>'

class InviteLink(db.Model):
    __tablename__ = 'invite_link'
    id = db.Column(db.Integer, primary_key=True)
    custom_path = db.Column(db.String(80), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    current_uses = db.Column(db.Integer, default=0)
    max_uses = db.Column(db.Integer, nullable=True, default=None)
    allowed_libraries = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    users_invited = db.relationship('User', backref='used_invite_link_ref', lazy='selectin') # Or 'select'

    def is_valid(self):
        now_utc = datetime.now(timezone.utc)
        if self.expires_at and now_utc > self.expires_at:
            return False
        if self.max_uses is not None and self.max_uses > 0 and self.current_uses >= self.max_uses:
            return False
        return True

    def __repr__(self):
        return f'<InviteLink {self.custom_path}>'

class AppSetting(db.Model):
    __tablename__ = 'app_setting'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False, index=True)
    value = db.Column(db.String(500), nullable=True)

    def __repr__(self):
        display_value = self.value
        if self.key and ('TOKEN' in self.key.upper() or 'SECRET' in self.key.upper()) and self.value:
            display_value = "[SENSITIVE]"
        elif self.value and len(self.value) > 30:
            display_value = self.value[:30] + "..."
        return f'<AppSetting {self.key}={display_value}>'

class HistoryLog(db.Model):
    __tablename__ = 'history_log'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    plex_username = db.Column(db.String(80), nullable=True)
    discord_id = db.Column(db.String(80), nullable=True)
    details = db.Column(db.String(255), nullable=True) 

    @staticmethod
    def create(event_type, plex_username=None, discord_id=None, details=None):
        logger = current_app.logger if current_app else logging.getLogger(__name__)
        try:
            entry = HistoryLog(
                event_type=event_type,
                plex_username=plex_username,
                discord_id=discord_id,
                details=str(details)[:254] if details else None 
            )
            db.session.add(entry)
            db.session.commit() 
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error logging history event '{event_type}': {e}", exc_info=True)
    
    def __repr__(self):
        return f'<HistoryLog {self.timestamp.strftime("%Y-%m-%d %H:%M")} - {self.event_type}>'

settings_cache = TTLCache(maxsize=128, ttl=300) 

@cached(settings_cache)
def get_app_setting(key, default=None):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    try:
        setting = AppSetting.query.filter_by(key=key).first()
        # Special handling for DISCORD_BOT_ENABLED default if not found
        if setting is None and key == 'DISCORD_BOT_ENABLED' and default is None:
            return 'false' # Default to 'false' string if key doesn't exist
        return setting.value if setting else default
    except Exception as e: 
        logger.warning(f"get_app_setting: DB query for '{key}' failed: {str(e)[:100]}. Returning default.")
        if key == 'DISCORD_BOT_ENABLED' and default is None: return 'false'
        return default

@cached(settings_cache) 
def get_all_app_settings():
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    try:
        return {s.key: s.value for s in AppSetting.query.all()}
    except Exception as e:
        logger.warning(f"get_all_app_settings: DB query failed: {str(e)[:100]}. Returning empty dict.")
        return {}

def update_app_setting(key, value):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    setting = AppSetting.query.filter_by(key=key).first()
    valueChanged = False
    if setting:
        if setting.value != value: 
            setting.value = value
            db.session.add(setting) 
            valueChanged = True
    else: 
        setting = AppSetting(key=key, value=value)
        db.session.add(setting)
        valueChanged = True
    
    if valueChanged:
        try:
            db.session.commit()
            settings_cache.clear() 
            logger.info(f"AppSetting '{key}' updated to '{value}'.")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating app setting '{key}': {e}", exc_info=True)
            raise 

@login_manager.user_loader
def load_user(user_id):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    try:
        return User.query.get(int(user_id))
    except ValueError: 
        logger.warning(f"load_user: Invalid user_id format received: {user_id}")
        return None