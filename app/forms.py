# File: app/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, EqualTo, Length, Optional, URL, NumberRange, Regexp, ValidationError
from wtforms import SelectMultipleField, RadioField
from app.models import Setting, AdminAccount # For custom validator if checking existing secrets
from wtforms.widgets import ListWidget, CheckboxInput # <--- ADDED THIS IMPORT
import urllib.parse 
from flask_login import current_user

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

# ... The old AppBaseUrlForm is now redundant, but we can leave it for now ...
class AppBaseUrlForm(FlaskForm): # This form is no longer used on a dedicated page
    app_base_url = StringField('Application Base URL', validators=[DataRequired(message="This URL is required."), URL(message="Invalid URL. Must be full public URL (e.g., https://pum.example.com).")], description="Full public URL where this application is accessible.")
    submit = SubmitField('Save Application URL')

class DiscordConfigForm(FlaskForm):
    # --- Section 1: OAuth Settings & Invite Page Options ---
    enable_discord_oauth = BooleanField(
        'Enable Discord OAuth for Invitees & Admin Link', 
        default=False,
        description="Allows users to link Discord on public invites and enables admin account linking. If disabled, related settings below are ignored."
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
        validators=[Optional(), URL(message="Must be a valid URL if provided.")],
        render_kw={"placeholder": "e.g., https://discord.com/oauth2/authorize?client_id=...&scope=..."},
        description="Construct from Discord App's OAuth2 URL Generator. MUST include 'identify', 'email', and 'guilds' scopes. 'redirect_uri' MUST match PUM's Invite Callback URI."
    )
    discord_bot_require_sso_on_invite = BooleanField(
        'Make Discord Login Mandatory on Public Invite Page', 
        default=False, 
        description="If checked, users must link Discord to accept an invite (requires 'Enable Discord OAuth' above to be active). This is automatically forced ON if 'Discord Bot Features' (Section 2) are also enabled."
    ) 
    discord_require_guild_membership = BooleanField(
        'Require Discord Server Membership to Accept Invite',
        default=False,
        description="If checked, users authenticating via Discord on the invite page MUST be a member of the 'Your Discord Server ID' specified below. Requires 'Enable Discord OAuth' to be active."
    )
    discord_guild_id = StringField( # Used by "Require Guild Membership" and/or Bot Features
        'Your Discord Server ID (Guild ID)', 
        validators=[Optional(), Regexp(r'^\d{17,20}$', message="Must be a valid Discord ID (typically 17-20 digits).")],
        description="ID of your Discord server. Required if 'Require Guild Membership' is ON OR if Bot Features are ON (and OAuth is active)."
    )
    discord_server_invite_url = StringField( # Used if "Require Guild Membership" is ON
        'Your Discord Server Invite URL (Public)', 
        validators=[Optional(), URL(message="Must be a valid URL if provided.")],
        description="A general, non-expiring public invite link to your Discord server. Shown on Plex invite page if guild membership is required and user is not a member."
    )
    # --- Section 2: Bot Feature Settings ---
    enable_discord_bot = BooleanField(
        'Enable Discord Bot Features', 
        default=False,
        description="Enables automated actions based on Discord activity. Requires OAuth (Section 1) to be enabled and correctly configured with necessary credentials."
    )
    discord_bot_token = PasswordField(
        'Discord Bot Token', 
        validators=[Optional(), Length(min=50, message="Bot token is a very long string.")], 
        description="Token for your Discord Bot from the 'Bot' page in Discord Dev Portal. Only enter to update; leave blank to keep existing."
    )
    discord_monitored_role_id = StringField(
        'Monitored Role ID (for Bot)', 
        validators=[Optional(), Regexp(r'^\d{17,20}$', message="Must be a valid Discord Role ID.")],
        description="The Discord Role ID that, when assigned, can trigger the bot to send a Plex invite."
    )
    discord_thread_channel_id = StringField(
        'Channel ID for Bot-Created Invite Threads', 
        validators=[Optional(), Regexp(r'^\d{17,20}$', message="Must be a valid Discord Channel ID.")],
        description="ID of a channel where the bot can create private threads for Plex invites."
    )
    discord_bot_log_channel_id = StringField(
        'Bot Action Log Channel ID (Optional)', 
        validators=[Optional(), Regexp(r'^\d{17,20}$', message="Must be a valid Discord Channel ID.")],
        description="If provided, the bot will log significant actions to this channel."
    )
    discord_bot_whitelist_sharers = BooleanField(
        'Bot: Whitelist Users Who Share Plex Servers Back?', 
        default=False,
        description="If checked, users detected as sharing their own Plex server(s) back will be immune to automated removal by the Discord Bot."
    )
    submit = SubmitField('Save Discord Settings')
    def validate(self, extra_validators=None): # ... (no change to validation logic)
        if not super().validate(extra_validators): return False
        is_oauth_enabled_form = self.enable_discord_oauth.data
        is_bot_enabled_form = self.enable_discord_bot.data
        is_require_guild_form = self.discord_require_guild_membership.data
        oauth_functionality_should_be_active = is_oauth_enabled_form or is_bot_enabled_form or is_require_guild_form
        if is_bot_enabled_form and not is_oauth_enabled_form: self.enable_discord_oauth.errors.append("Enable 'Discord OAuth' (Section 1) if 'Bot Features' (Section 2) are enabled.")
        if is_require_guild_form and not is_oauth_enabled_form: self.enable_discord_oauth.errors.append("Enable 'Discord OAuth' (Section 1) if 'Require Discord Server Membership' is checked.")
        if self.discord_bot_require_sso_on_invite.data and not is_oauth_enabled_form: self.enable_discord_oauth.errors.append("Enable 'Discord OAuth' (Section 1) if 'Make Discord Login Mandatory' is checked.")
        if oauth_functionality_should_be_active:
            if not self.discord_client_id.data and not Setting.get('DISCORD_CLIENT_ID'): self.discord_client_id.errors.append("OAuth Client ID is required if any Discord linking/bot feature is enabled and no ID is currently saved.")
            if not self.discord_client_secret.data and not Setting.get('DISCORD_CLIENT_SECRET'): self.discord_client_secret.errors.append("OAuth Client Secret is required if any Discord linking/bot feature is enabled and no secret is currently saved.")
            if not self.discord_oauth_auth_url.data and not Setting.get('DISCORD_OAUTH_AUTH_URL'): self.discord_oauth_auth_url.errors.append("Discord OAuth Authorization URL is required if any Discord linking/bot feature is enabled and no URL is currently saved.")
            elif self.discord_oauth_auth_url.data:
                try:
                    parsed_url = urllib.parse.urlparse(self.discord_oauth_auth_url.data.lower()); query_params = urllib.parse.parse_qs(parsed_url.query)
                    scopes_in_url = query_params.get('scope', [''])[0].split(); required_scopes = ["identify", "email", "guilds"]
                    missing_scopes = [s for s in required_scopes if s not in scopes_in_url]
                    if missing_scopes: self.discord_oauth_auth_url.errors.append(f"OAuth URL is missing required scope(s): {', '.join(missing_scopes)}. Must include 'identify', 'email', and 'guilds'.")
                except Exception: self.discord_oauth_auth_url.errors.append("Could not parse scopes from the OAuth Authorization URL. Ensure it's well-formed.")
        if (is_bot_enabled_form or is_require_guild_form) and oauth_functionality_should_be_active:
            if not self.discord_guild_id.data and not Setting.get('DISCORD_GUILD_ID'): self.discord_guild_id.errors.append("'Your Discord Server ID' is required if 'Bot Features' or 'Require Guild Membership' is enabled (and OAuth is active) and no ID is currently saved.")
        if is_bot_enabled_form:
            required_bot_fields_when_active = {'Bot Token': (self.discord_bot_token, 'DISCORD_BOT_TOKEN'), 'Monitored Role ID': (self.discord_monitored_role_id, 'DISCORD_MONITORED_ROLE_ID'), 'Thread Channel ID': (self.discord_thread_channel_id, 'DISCORD_THREAD_CHANNEL_ID')}
            for field_label, (field_instance, setting_key) in required_bot_fields_when_active.items():
                if not field_instance.data and not Setting.get(setting_key): field_instance.errors.append(f"{field_label} is required when Discord Bot is enabled and no value is currently saved.")
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
    #user_ids = HiddenField(validators=[DataRequired()])
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
class InviteCreateForm(FlaskForm):
    custom_path = StringField('Custom Invite Path (Optional)', validators=[Optional(), Length(min=3, max=100), Regexp(r'^[a-zA-Z0-9_-]*$', message="Letters, numbers, hyphens, underscores only.")], description="e.g., 'friends' -> /invite/friends")
    expires_in_days = IntegerField('Expires in (days)', validators=[Optional(), NumberRange(min=0)], default=0, description="0 for no expiry.")
    number_of_uses = IntegerField('Number of Uses', validators=[Optional(), NumberRange(min=0)], default=0, description="0 for unlimited uses.")
    libraries = SelectMultipleField('Grant Access to Libraries', coerce=str, validators=[Optional()], description="Default: all libraries.")
    allow_downloads = BooleanField('Enable Downloads (Allow Sync)', default=False, description="Allow the invited user to download/sync content from shared libraries.")
    membership_duration_days = IntegerField(
        'Membership Duration (days)', 
        validators=[Optional(), NumberRange(min=1, message="Must be at least 1 day, or leave blank for permanent access from this invite.")], 
        default=None,
        render_kw={"placeholder": "e.g., 30 or 365 (blank = permanent)"},
        description="Access duration for the user after accepting. Blank for permanent (until manually removed)."
    )
    override_force_discord_auth = BooleanField(
        "Override 'Make Discord Login Mandatory'",
        default=False, # The route will set the default based on global settings
        description="Override the global setting for requiring Discord login for this specific invite."
    )
    override_force_guild_membership = BooleanField(
        "Override 'Require Discord Server Membership'",
        default=False, # The route will set the default based on global settings
        description="Override the global setting for requiring server membership for this specific invite."
    )
    grant_purge_whitelist = BooleanField(
        'Whitelist user from Inactivity Purge',
        default=False,
        description="The created user will be automatically whitelisted from inactivity purges."
    )
    grant_bot_whitelist = BooleanField(
        'Whitelist user from Discord Bot Actions',
        default=False,
        description="The created user will be immune to automated Discord Bot actions."
    )
    
    submit = SubmitField('Create Invite')
    
# --- GeneralSettingsForm, PlexSettingsForm ---
class GeneralSettingsForm(FlaskForm): # As before
    app_name = StringField("Application Name", validators=[Optional(), Length(max=100)])
    app_base_url = StringField(
        'Application Base URL', 
        validators=[DataRequired(message="This URL is required."), URL(message="Invalid URL. Must be full public URL (e.g., https://pum.example.com).")],
        description="Full public URL where this application is accessible. Essential for generating correct invite and callback links."
    )
    submit = SubmitField('Save General Settings')


class InviteEditForm(FlaskForm):
    # Note: custom_path is intentionally omitted as it should not be editable.
    expires_in_days = IntegerField('Expires in (days)', validators=[Optional(), NumberRange(min=0)], default=0)
    clear_expiry = BooleanField('Clear Expiration (Set to Never Expire)', default=False)
    
    number_of_uses = IntegerField('Number of Uses', validators=[Optional(), NumberRange(min=0)], default=0)
    clear_max_uses = BooleanField('Clear Max Uses (Set to Unlimited)', default=False)
    
    membership_duration_days = IntegerField('Membership Duration (days)', validators=[Optional(), NumberRange(min=1)], default=None)
    clear_membership_duration = BooleanField('Clear Membership Duration (Set to Permanent)', default=False)
    
    libraries = SelectMultipleField('Grant Access to Libraries', coerce=str, validators=[Optional()])
    allow_downloads = BooleanField('Enable Downloads (Allow Sync)', default=False)
    
    override_force_discord_auth = BooleanField("Override 'Make Discord Login Mandatory'")
    override_force_guild_membership = BooleanField("Override 'Require Discord Server Membership'")
    grant_purge_whitelist = BooleanField('Whitelist user from Inactivity Purge')
    grant_bot_whitelist = BooleanField('Whitelist user from Discord Bot Actions')
    
    submit = SubmitField('Save Changes')

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

class SetPasswordForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit_set_password = SubmitField('Set Username & Password')

    def validate_username(self, username):
        # Ensure the new username isn't already taken by another admin account
        user = AdminAccount.query.filter(
            AdminAccount.username == username.data,
            AdminAccount.id != current_user.id # Exclude the current user from the check
        ).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')
        
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField(
        'Confirm New Password', 
        validators=[DataRequired(), EqualTo('new_password', message='New passwords must match.')]
    )
    submit_change_password = SubmitField('Change Password')

class AdminCreateForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Temporary Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Temporary Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create Admin')
    
    def validate_username(self, username):
        if AdminAccount.query.filter_by(username=username.data).first():
            raise ValidationError('That username is already taken.')

class AdminEditForm(FlaskForm):
    username = StringField('Username', render_kw={'readonly': True})
    
    # THIS IS THE CORRECTED FIELD DEFINITION
    roles = SelectMultipleField(
        'Assigned Roles', 
        coerce=int, 
        validators=[Optional()],
        widget=ListWidget(prefix_label=False), 
        option_widget=CheckboxInput()
    )
    # END CORRECTION

    submit = SubmitField('Save Changes')

class RoleCreateForm(FlaskForm):
    name = StringField('Role Name', validators=[DataRequired(), Length(min=3, max=80)])
    description = StringField('Description', validators=[Optional(), Length(max=255)])
    color = StringField('Badge Color', default='#808080', validators=[
        Optional(), Regexp(r'^#[0-9a-fA-F]{6}$', message='Must be a valid hex color code, e.g., #RRGGBB')
    ])
    submit = SubmitField('Create Role')

    def validate_name(self, name):
        # We need the Role model here, so import it locally to avoid circular dependencies
        from app.models import Role
        if Role.query.filter_by(name=name.data).first():
            raise ValidationError('A role with this name already exists.')

class RoleEditForm(FlaskForm):
    name = StringField('Role Name', validators=[DataRequired(), Length(min=3, max=80)])
    description = StringField('Description', validators=[Optional(), Length(max=255)])
    color = StringField('Badge Color', default='#808080', validators=[
        Optional(), Regexp(r'^#[0-9a-fA-F]{6}$', message='Must be a valid hex color code, e.g., #RRGGBB')
    ])

    # This will be a group of checkboxes for the available permissions
    # We will define a list of all possible permissions in the app.
    # For now, let's start with 'manage_users'.
    permissions = SelectMultipleField(
        'Permissions', 
        coerce=str, 
        validators=[Optional()],
        widget=ListWidget(prefix_label=False), 
        option_widget=CheckboxInput()
    )

    submit = SubmitField('Save Changes')

    def __init__(self, original_name, *args, **kwargs):
        super(RoleEditForm, self).__init__(*args, **kwargs)
        self.original_name = original_name

    def validate_name(self, name):
        if name.data != self.original_name:
            from app.models import Role
            if Role.query.filter_by(name=name.data).first():
                raise ValidationError('A role with this name already exists.')