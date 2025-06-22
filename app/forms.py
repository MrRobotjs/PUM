# File: app/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, EqualTo, Length, Optional, URL, NumberRange, Regexp
from wtforms import SelectMultipleField
from app.models import Setting # For custom validator if checking existing secrets
from wtforms.widgets import ListWidget, CheckboxInput # <--- ADDED THIS IMPORT
import urllib.parse 

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class PlexSSOLoginForm(FlaskForm): # This might just be a button, not a full form if handled by redirect
    submit = SubmitField('Sign In with Plex')

class AccountSetupForm(FlaskForm):
    login_method = SelectField('Admin Account Setup Method', choices=[('plex_sso', 'Sign in with Plex (Recommended)'), ('username_password', 'Create Username and Password')], validators=[DataRequired()])
    username = StringField('Username', validators=[Optional(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[Optional(), Length(min=8, max=128)])
    confirm_password = PasswordField('Confirm Password', validators=[Optional(), EqualTo('password', message='Passwords must match.')])
    submit_username_password = SubmitField('Create Admin Account')
    submit_plex_sso = SubmitField('Continue with Plex')

class PlexConfigForm(FlaskForm):
    plex_url = StringField('Plex URL', validators=[DataRequired(), URL(message="Invalid URL format. Include http(s)://")])
    plex_token = StringField('Plex Token', validators=[DataRequired(), Length(min=19, max=24, message="Plex token is usually 19-24 characters long.")])
    connection_tested_successfully = HiddenField(default="false")
    submit = SubmitField('Save Plex Configuration')

class AppBaseUrlForm(FlaskForm):
    app_base_url = StringField('Application Base URL', validators=[DataRequired(message="This URL is required."), URL(message="Invalid URL. Must be full public URL (e.g., https://pum.example.com).")], description="Full public URL where this application is accessible.")
    submit = SubmitField('Save Application URL')

# --- Updated DiscordConfigForm ---
class DiscordConfigForm(FlaskForm):
    # --- Section 1: OAuth Settings ---
    enable_discord_oauth = BooleanField(
        'Enable Discord OAuth for Invitees & Admin Link', 
        default=False,
        description="Allows users to link their Discord on public invites and enables admin account linking. If disabled, the settings below are ignored."
    )
    discord_client_id = StringField(
        'Discord Application Client ID', 
        validators=[Optional(), Length(min=15, message="Client ID is typically a long string of digits.")],
        description="Get this from your Discord Developer Application's 'OAuth2' page."
    )
    discord_client_secret = PasswordField(
        'Discord Application Client Secret', 
        validators=[Optional(), Length(min=30, message="Client Secret is typically a long string.")],
        description="OAuth2 Client Secret. Only enter if you need to update it; leave blank to keep the existing saved secret."
    )
    discord_oauth_auth_url = StringField(
        'Discord OAuth Authorization URL (for User Invites)',
        validators=[Optional(), URL(message="Must be a valid URL.")],
        render_kw={"placeholder": "e.g., https://discord.com/oauth2/authorize?client_id=...&scope=...&response_type=code&redirect_uri=..."},
        description="Construct this URL from your Discord App's OAuth2 URL Generator. Ensure it includes 'identify', 'email', and 'guilds' in the 'scope' parameter. The 'redirect_uri' in this URL MUST exactly match PUM's 'Redirect URI (Invites)' displayed on this page."
    )
    discord_bot_require_sso_on_invite = BooleanField(
        'Make Discord Login Mandatory on Public Invite Page', 
        default=False, 
        description="If checked, users must link Discord to accept an invite (requires 'Enable Discord OAuth' above to be active). This is automatically forced ON if 'Discord Bot Features' (Section 2) are enabled."
    ) 

    # --- Section 2: Bot Feature Settings ---
    enable_discord_bot = BooleanField(
        'Enable Discord Bot Features', 
        default=False,
        description="Enables automated actions based on Discord activity (e.g., removing users from Plex if they leave the Discord server). Requires OAuth (Section 1) to be enabled and correctly configured with necessary credentials."
    )
    discord_bot_token = PasswordField(
        'Discord Bot Token', 
        validators=[Optional(), Length(min=50, message="Bot token is a very long string.")], 
        description="Token for your Discord Bot from the 'Bot' page in your Discord Developer Application. Only enter if you need to update it; leave blank to keep existing."
    )
    discord_guild_id = StringField(
        'Your Discord Server ID (Guild ID)', 
        validators=[Optional(), Regexp(r'^\d{17,20}$', message="Must be a valid Discord ID (typically 17-20 digits).")],
        description="The ID of the Discord server (guild) this bot will operate on. Enable Developer Mode in Discord to copy IDs."
    )
    discord_monitored_role_id = StringField(
        'Monitored Role ID (Grants Plex Access via Bot)', 
        validators=[Optional(), Regexp(r'^\d{17,20}$', message="Must be a valid Discord Role ID.")],
        description="The Discord Role ID that, when assigned, can trigger the bot to send a Plex invite." # Simplified
    )
    discord_thread_channel_id = StringField(
        'Channel ID for Bot-Created Invite Threads', 
        validators=[Optional(), Regexp(r'^\d{17,20}$', message="Must be a valid Discord Channel ID.")],
        description="ID of a channel where the bot can create private threads for sending Plex invites." # Simplified
    )
    discord_bot_log_channel_id = StringField(
        'Bot Action Log Channel ID (Optional)', 
        validators=[Optional(), Regexp(r'^\d{17,20}$', message="Must be a valid Discord Channel ID.")],
        description="If provided, the bot will log significant actions to this channel."
    )
    discord_server_invite_url = StringField(
        'Your Discord Server Invite URL (Optional)', 
        validators=[Optional(), URL()],
        description="A general, non-expiring invite link to your Discord server. Shown on Plex invite page if guild membership is required."
    )
    discord_bot_whitelist_sharers = BooleanField(
        'Bot: Whitelist Users Who Share Plex Servers Back?', 
        default=False,
        description="If checked, users detected as sharing their own Plex server(s) back will be immune to automated removal by the Discord Bot."
    )
    
    submit = SubmitField('Save Discord Settings')

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators): # Call superclass validate
            return False 

        # If bot is enabled, OAuth itself must be enabled.
        if self.enable_discord_bot.data and not self.enable_discord_oauth.data:
            self.enable_discord_oauth.errors.append("Discord OAuth (Section 1) must be enabled if Bot Features (Section 2) are enabled.")
        
        # Determine if OAuth is effectively enabled (either directly or because bot requires it)
        oauth_should_be_enabled = self.enable_discord_oauth.data or self.enable_discord_bot.data
        
        if oauth_should_be_enabled:
            # Client ID is required if OAuth is on and no ID is already saved in DB
            if not self.discord_client_id.data and not Setting.get('DISCORD_CLIENT_ID'):
                 self.discord_client_id.errors.append("OAuth Client ID is required if enabling OAuth/Bot features and no ID is already saved.")
            
            # Client Secret is required if OAuth is on and no secret is already saved in DB
            # (If user is updating, they might leave it blank to keep existing)
            if not self.discord_client_secret.data and not Setting.get('DISCORD_CLIENT_SECRET'):
                 self.discord_client_secret.errors.append("OAuth Client Secret is required if enabling OAuth/Bot features and no secret is already saved.")
            
            # Auth URL is required if OAuth is on and no URL is already saved
            if not self.discord_oauth_auth_url.data and not Setting.get('DISCORD_OAUTH_AUTH_URL'):
                self.discord_oauth_auth_url.errors.append("Discord OAuth Authorization URL for invites is required when OAuth/Bot is enabled and no URL is saved.")
            elif self.discord_oauth_auth_url.data: # If URL is provided, validate its scopes
                try:
                    parsed_url = urllib.parse.urlparse(self.discord_oauth_auth_url.data.lower())
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    scopes_in_url = query_params.get('scope', [''])[0].split()
                    required_scopes = ["identify", "email", "guilds"]
                    missing_scopes = [s for s in required_scopes if s not in scopes_in_url]
                    if missing_scopes:
                        self.discord_oauth_auth_url.errors.append(f"OAuth URL is missing required scope(s): {', '.join(missing_scopes)}. Must include 'identify', 'email', and 'guilds'.")
                except Exception:
                    self.discord_oauth_auth_url.errors.append("Could not parse scopes from the provided OAuth Authorization URL. Ensure it's well-formed.")

        # If "Make Discord Login Mandatory" is checked, then "Enable Discord OAuth" must also be checked.
        # This check is important as the field is now grouped with OAuth settings.
        if self.discord_bot_require_sso_on_invite.data and not self.enable_discord_oauth.data:
            # This error should ideally be on enable_discord_oauth or discord_bot_require_sso_on_invite
            self.enable_discord_oauth.errors.append("If 'Make Discord Login Mandatory' is checked, 'Enable Discord OAuth' must also be enabled.")
            # Alternatively, or additionally:
            # self.discord_bot_require_sso_on_invite.errors.append("'Enable Discord OAuth' must be active to make SSO mandatory.")


        # If bot is enabled, certain bot-specific fields become required (if not already saved in DB)
        if self.enable_discord_bot.data:
            required_bot_fields = {
                'Bot Token': (self.discord_bot_token, 'DISCORD_BOT_TOKEN'),
                'Guild ID': (self.discord_guild_id, 'DISCORD_GUILD_ID'),
                'Monitored Role ID': (self.discord_monitored_role_id, 'DISCORD_MONITORED_ROLE_ID'),
                'Thread Channel ID': (self.discord_thread_channel_id, 'DISCORD_THREAD_CHANNEL_ID')
            }
            for field_label, (field_instance, setting_key) in required_bot_fields.items():
                if not field_instance.data and not Setting.get(setting_key):
                    field_instance.errors.append(f"{field_label} is required when Discord Bot is enabled and no value is already saved.")
        
        # Check for any errors accumulated
        has_errors = any(field.errors for field_name, field in self._fields.items())
        return not has_errors


# --- UserEditForm & MassUserEditForm ---
class UserEditForm(FlaskForm): # As updated for whitelist fields
    plex_username = StringField('Plex Username', render_kw={'readonly': True})
    plex_email = StringField('Plex Email', render_kw={'readonly': True})
    is_home_user = BooleanField('Plex Home User', render_kw={'disabled': True})
    notes = TextAreaField('Notes', validators=[Optional(), Length(max=1000)])
    libraries = SelectMultipleField(
        'Accessible Libraries',
        coerce=str,
        validators=[Optional()],
        widget=ListWidget(prefix_label=False),  # <<< ADDED WIDGET
        option_widget=CheckboxInput()           # <<< ADDED OPTION_WIDGET
    )
    is_discord_bot_whitelisted = BooleanField('Whitelist from Discord Bot Actions')
    is_purge_whitelisted = BooleanField('Whitelist from Inactivity Purge')

    access_expires_in_days = IntegerField(
        'Set/Update Access Expiration (days from now)',
        validators=[Optional(), NumberRange(min=1, message="Must be at least 1 day, or leave blank for no change / to use 'Clear' option.")],
        render_kw={"placeholder": "e.g., 30 (updates from today)"},
        description="Enter days from today for new expiry, or leave blank. Use checkbox below to clear existing expiry."
    )
    clear_access_expiration = BooleanField(
        'Clear Existing Access Expiration (Grant Permanent Access)',
        default=False,
        description="Check this to remove any current access expiration date for this user."
    )
    
    submit = SubmitField('Save Changes')

class MassUserEditForm(FlaskForm): # As updated
    user_ids = HiddenField(validators=[DataRequired()])
    action = SelectField('Action', choices=[
            ('', '-- Select Action --'), ('update_libraries', 'Update Libraries'),
            ('delete_users', 'Delete Users from PUM & Plex'),
            ('add_to_bot_whitelist', 'Add to Discord Bot Whitelist'), 
            ('remove_from_bot_whitelist', 'Remove from Discord Bot Whitelist'),
            ('add_to_purge_whitelist', 'Add to Purge Whitelist'),
            ('remove_from_purge_whitelist', 'Remove from Purge Whitelist')],
        validators=[DataRequired(message="Please select an action.")])
    libraries = SelectMultipleField('Set Access to Libraries (for "Update Libraries")', coerce=str, validators=[Optional()])
    confirm_delete = BooleanField('Confirm Deletion (for "Delete Users")', validators=[Optional()])
    submit = SubmitField('Apply Changes')

# --- InviteCreateForm ---
class InviteCreateForm(FlaskForm): # As before
    custom_path = StringField('Custom Invite Path (Optional)', validators=[Optional(), Length(min=3, max=100), Regexp(r'^[a-zA-Z0-9_-]*$', message="Letters, numbers, hyphens, underscores only.")], description="e.g., 'friends' -> /invite/friends")
    expires_in_days = IntegerField('Expires in (days)', validators=[Optional(), NumberRange(min=0)], default=0, description="0 for no expiry.")
    number_of_uses = IntegerField('Number of Uses', validators=[Optional(), NumberRange(min=0)], default=0, description="0 for unlimited uses.")
    libraries = SelectMultipleField('Grant Access to Libraries', coerce=str, validators=[Optional()], description="Default: all libraries.")
    submit = SubmitField('Create Invite')
    allow_downloads = BooleanField('Enable Downloads (Allow Sync)', default=False, description="Allow the invited user to download/sync content from shared libraries.")
    membership_duration_days = IntegerField(
        'Membership Duration (days)', 
        validators=[Optional(), NumberRange(min=1, message="Must be at least 1 day, or leave blank for permanent access from this invite.")], 
        default=None, # Explicitly None to allow placeholder to show
        render_kw={"placeholder": "e.g., 30 or 365 (blank = permanent)"},
        description="Access duration for the user after accepting. Blank for permanent (until manually removed)."
    )
    
# --- GeneralSettingsForm, PlexSettingsForm ---
class GeneralSettingsForm(FlaskForm): # As before
    app_name = StringField("Application Name", validators=[Optional(), Length(max=100)])
    submit = SubmitField('Save General Settings')

class PlexSettingsForm(FlaskForm): # As before
    plex_url = StringField('Plex URL', validators=[DataRequired(), URL()])
    plex_token = StringField('Plex Token', validators=[DataRequired(), Length(min=19, max=24)])
    connection_tested_successfully = HiddenField(default="false")
    session_monitoring_interval = IntegerField('Session Monitoring Interval (seconds)', default=60, validators=[DataRequired(), NumberRange(min=10)])
    submit = SubmitField('Save Plex Settings')

class PurgeUsersForm(FlaskForm):
    inactive_days = IntegerField(
        'Inactive for at least (days)', 
        validators=[DataRequired(), NumberRange(min=7)], 
        default=90
    )
    exclude_sharers = BooleanField('Exclude users who share back their servers', default=True)
    # No submit button here, it's handled by the modal interaction triggering HTMX on the main form
    # csrf_token is handled by form.hidden_tag() if this form is rendered