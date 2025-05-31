# app/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, TextAreaField, SelectMultipleField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Optional, URL, NumberRange, Length, Regexp, ValidationError
from app.models import User 

def path_safe_string_validator(form, field):
    if field.data and not all(c.isalnum() or c in ['-', '_'] for c in field.data):
        raise ValidationError('Path can only contain letters, numbers, hyphens (-), and underscores (_). No spaces or other special characters.')

class LoginForm(FlaskForm):
    username = StringField('Admin Username', validators=[DataRequired(message="Username is required.")])
    password = PasswordField('Password', validators=[DataRequired(message="Password is required.")])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class SetupAdminForm(FlaskForm):
    username = StringField('Admin Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=4, max=64, message="Username must be between 4 and 64 characters.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password."),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Create Admin Account')

class SetupPlexAndAppForm(FlaskForm): 
    plex_url = StringField('Plex URL (e.g., http://localhost:32400 or https://plex.yourdomain.com)', validators=[
        DataRequired(message="Plex URL is required."), 
        URL(message="Invalid URL format. Must include http:// or https://")
    ])
    plex_token = StringField('Plex Token (X-Plex-Token)', validators=[
        DataRequired(message="Plex Token is required.")
    ])
    app_base_url = StringField('Application Base URL (e.g., http://localhost:5699 or https://pum.yourdomain.com)',
                               validators=[
                                   DataRequired(message="Application Base URL is required for constructing public links."), 
                                   URL(message="Invalid URL format. Must be the full public URL of this application.")
                               ],
                               description="The full public URL where this application is accessible. Used by the Discord bot and for generating full invite links.")
    submit_step2_settings = SubmitField('Next: Discord Config (Optional)') 

class PlexSettingsForm(FlaskForm): 
    plex_url = StringField('Plex URL (e.g., http://localhost:32400 or https://plex.yourdomain.com)', validators=[
        DataRequired(message="Plex URL is required."),
        URL(message="Invalid URL format. Must include http:// or https://")
    ])
    plex_token = StringField('Plex Token (X-Plex-Token)', validators=[
        DataRequired(message="Plex Token is required.")
    ])
    submit_plex_server_settings = SubmitField('Save and Test Plex Server Settings')


class GeneralAppSettingsForm(FlaskForm):
    app_base_url = StringField('Application Base URL (e.g., http://localhost:5699 or https://pum.yourdomain.com)',
                               validators=[
                                   DataRequired(message="Application Base URL is required for constructing public links."),
                                   URL(message="Invalid URL format. Must be the full public URL of this application.")
                               ],
                               description="The full public URL where this application is accessible. Used by the Discord bot and for generating full invite links.")

    sync_remove_stale_users = BooleanField('Auto-remove users from this app if not found in Plex sync',
                                           default=False, # Changed default to False as it's a destructive action
                                           description="If checked, the 'Sync Users from Plex' feature will remove users from THIS APP'S DATABASE if they are no longer found in the list of users your Plex account is friends with or has in Plex Home. This does NOT remove them from your Plex server itself. Use with caution.")

    # REMOVED: activity_poll_interval_minutes field
    # activity_poll_interval_minutes = IntegerField(
    #     'Plex Activity Check Interval (minutes)',
    #     validators=[
    #         DataRequired(message="Interval is required."), 
    #         NumberRange(min=1, max=1440, message="Interval must be between 1 and 1440 minutes (24 hours).")
    #     ],
    #     default=5, 
    #     description="How often to check Plex for active user streams (updates 'Last Active'). Lower values are more real-time but increase server load. Must be at least 1 minute."
    # )
    submit_general_app_settings = SubmitField('Save Application Settings')


class DiscordSettingsForm(FlaskForm):
    discord_oauth_client_id = StringField('Discord OAuth2 Client ID',
        validators=[Optional(), Regexp(r'^\d{17,20}$', message="Client ID must be a 17-20 digit number.")],
        description="Client ID from your Discord Application's OAuth2 settings. Used for 'Login with Discord' button.")
    discord_oauth_client_secret = StringField('Discord OAuth2 Client Secret',
        validators=[Optional(), Length(min=30)],
        description="Client Secret from your Discord Application's OAuth2 settings. Keep this confidential.",
        render_kw={'type': 'password'})
    discord_bot_enabled = BooleanField('Enable Discord Bot Features (e.g., role monitoring, server checks, bot commands)')
    discord_bot_token = StringField('Discord Bot Token*', validators=[Optional(), Length(min=50, max=100, message="Token seems an unusual length.")])
    discord_server_id = StringField('Discord Server ID*', validators=[Optional(), Regexp(r'^\d{17,20}$', message="Server ID must be a 17-20 digit number.")])
    discord_bot_app_id = StringField('Discord Bot Application ID* (for bot slash commands)', validators=[Optional(), Regexp(r'^\d{17,20}$', message="Application ID must be a 17-20 digit number.")])
    admin_discord_id = StringField('Your Admin Discord ID* (for bot DMs to you)', validators=[Optional(), Regexp(r'^\d{17,20}$', message="Your Discord User ID must be a 17-20 digit number.")])
    discord_command_channel_id = StringField('Command Channel ID* (for bot invite requests/threads)', validators=[Optional(), Regexp(r'^\d{17,20}$', message="Channel ID must be a 17-20 digit number.")])
    discord_mention_role_id = StringField('Role ID to Mention in Invite Threads (Optional, if bot enabled)', validators=[Optional(), Regexp(r'^\d{17,20}$', message="Role ID must be a 17-20 digit number.")])
    discord_plex_access_role_id = StringField('Plex Access Role ID* (Role monitored by bot for Plex access changes)', validators=[Optional(), Regexp(r'^\d{17,20}$', message="Role ID must be a 17-20 digit number.")])
    discord_bot_user_whitelist = TextAreaField('Discord Bot User Whitelist (Plex Usernames - for bot features)',
                                               description="Optional: If bot features are enabled, list PLEX USERNAMES whose linked Discord users have special bot permissions. One per line or comma-separated.",
                                               render_kw={"rows": 3},
                                               validators=[Optional()])
    submit_discord_settings = SubmitField('Save Discord Settings')

    def validate_discord_bot_user_whitelist(self, field):
        if not self.discord_bot_enabled.data: return
        if field.data and field.data.strip():
            raw_list = field.data or ""; identifiers_to_check = {item.strip() for item in raw_list.replace('\n', ',').split(',') if item.strip()}
            invalid_plex_usernames = []; users_needing_discord_id = []
            for identifier in identifiers_to_check:
                user_obj = User.query.filter(User.plex_username.ilike(identifier)).first()
                if not user_obj: invalid_plex_usernames.append(identifier)
                elif not user_obj.discord_id or not user_obj.discord_id.strip(): users_needing_discord_id.append(identifier)
            error_messages = []
            if invalid_plex_usernames: error_messages.append(f"Bot Whitelist: Plex Usernames not found: {', '.join(invalid_plex_usernames)}.")
            if users_needing_discord_id: error_messages.append(f"Bot Whitelist: Plex Users need Discord ID linked: {', '.join(users_needing_discord_id)}.")
            if error_messages: raise ValidationError(" ".join(error_messages))

    def validate(self, extra_validators=None): # Keep validate for Discord form
        initial_validation = super(DiscordSettingsForm, self).validate(extra_validators)
        is_form_globally_valid = initial_validation
        if (self.discord_oauth_client_id.data and not self.discord_oauth_client_secret.data) or \
           (not self.discord_oauth_client_id.data and self.discord_oauth_client_secret.data):
            if not self.discord_oauth_client_id.data: self.discord_oauth_client_id.errors.append("OAuth Client ID is required if Client Secret is provided.")
            if not self.discord_oauth_client_secret.data: self.discord_oauth_client_secret.errors.append("OAuth Client Secret is required if Client ID is provided.")
            is_form_globally_valid = False
        if self.discord_bot_enabled.data:
            critical_bot_fields_map = { self.discord_bot_token: "Discord Bot Token", self.discord_server_id: "Discord Server ID", self.discord_bot_app_id: "Discord Bot Application ID", self.admin_discord_id: "Admin Discord ID", self.discord_command_channel_id: "Command Channel ID", self.discord_plex_access_role_id: "Plex Access Role ID" }
            for field_object, field_label_text in critical_bot_fields_map.items():
                if not field_object.data or not field_object.data.strip(): field_object.errors.append(f"This field is required when 'Enable Discord Bot Features' is checked."); is_form_globally_valid = False
            if not is_form_globally_valid and not initial_validation : return False
            elif not is_form_globally_valid and initial_validation : return False
            if self.discord_bot_token.data and self.discord_bot_token.data.strip() and is_form_globally_valid:
                from app.discord_utils import test_discord_bot_token 
                is_token_ok, token_msg = test_discord_bot_token(self.discord_bot_token.data)
                if not is_token_ok: self.discord_bot_token.errors.append(f"Token validation failed: {token_msg}"); is_form_globally_valid = False
                else: setattr(self.discord_bot_token, 'description', token_msg) 
        return is_form_globally_valid

class InviteCreateForm(FlaskForm):
    custom_path = StringField('Custom Invite Path (e.g., mycoolinvite)', validators=[DataRequired(message="Custom path is required."), Length(min=3, max=80), path_safe_string_validator])
    expires_days = IntegerField('Expires in Days (0 or empty for indefinite)', validators=[Optional(), NumberRange(min=0)])
    max_uses = IntegerField('Max Uses (0 or empty for unlimited)', validators=[Optional(), NumberRange(min=0)])
    allowed_libraries = SelectMultipleField('Allowed Libraries (Ctrl/Cmd+Click to select multiple)', coerce=str, validators=[Optional()], choices=[])
    submit = SubmitField('Create Invite Link')

class UserInviteForm(FlaskForm):
    discord_id = StringField('Your Discord User ID', validators=[Optional(), Regexp(r'^\d{17,20}$', message="If provided, Discord ID must be a 17-20 digit number.")])
    plex_email = StringField('Your Plex Email Address', validators=[DataRequired(message="Your Plex email address is required."), Email(message="Invalid email address format.")])
    submit = SubmitField('Request Plex Invitation')

class EditUserForm(FlaskForm):
    discord_id = StringField('Discord ID (leave empty to clear)', validators=[Optional(), Regexp(r'^\d{17,20}$', message="If provided, Discord ID must be a 17-20 digit number.")])
    shares_back = BooleanField('User Shares Their Plex Server Back With You')
    is_purge_whitelisted = BooleanField('Whitelist this user from automatic purging (Individual Setting)')
    plex_libraries = SelectMultipleField('Shared Plex Libraries (Ctrl/Cmd+Click to select multiple)', coerce=str, validators=[Optional()], description="Select which libraries this user has access to. If none selected, access might be removed or fall back to Plex defaults.", choices=[])
    submit = SubmitField('Save Changes')

class PurgeSettingsForm(FlaskForm):
    days_inactive = IntegerField('Purge users inactive for at least this many days', validators=[DataRequired(message="Number of days inactive is required."), NumberRange(min=1)], default=30, description="Users who never streamed OR last streamed before this many days ago will be purged.")
    exempt_sharers = BooleanField('Do NOT purge users who share their server back', default=True)
    exempt_home_users = BooleanField('Do NOT purge Plex Home users', default=True)
    submit_purge_users = SubmitField('Purge Inactive Users')

class GlobalWhitelistSettingsForm(FlaskForm): # This form seems unused currently, might be for future use
    purge_whitelist_users = TextAreaField('Global Purge Whitelist (Plex Usernames or Emails)', description="One Plex Username or Email per line, or comma-separated. These users will NOT be purged.", render_kw={"rows": 5, "placeholder": "user1@example.com\nPlexUsername\nanother@example.com, OtherPlexUser"}, validators=[Optional()])
    submit_whitelists = SubmitField('Save Whitelist Settings')

class UserFilterSortForm(FlaskForm):
    search = StringField('Search Users', validators=[Optional(), Length(max=100)])
    sort_by = SelectField('Sort By', choices=[('plex_username', 'Plex Username'), ('plex_email', 'Plex Email'), ('discord_username', 'Discord Username'), ('last_streamed_at', 'Last Active (Plex)'), ('shares_back', 'Shares Back Status'), ('is_plex_home_user', 'Plex Home Status'), ('is_purge_whitelisted', 'Purge Whitelist Status')], default='plex_username', validators=[Optional()])
    sort_order = SelectField('Order', choices=[('asc', 'Ascending'), ('desc', 'Descending')], default='asc', validators=[Optional()])
    filter_is_home_user = SelectField('Plex Home User', choices=[('', 'Any'), ('yes', 'Yes'), ('no', 'No')], default='', validators=[Optional()])
    filter_shares_back = SelectField('Shares Back', choices=[('', 'Any'), ('yes', 'Yes'), ('no', 'No')], default='', validators=[Optional()])
    filter_is_purge_whitelisted = SelectField('Purge Whitelisted', choices=[('', 'Any'), ('yes', 'Yes'), ('no', 'No')], default='', validators=[Optional()])
    filter_is_discord_bot_whitelisted = SelectField('Discord Bot Whitelisted', choices=[('', 'Any'), ('yes', 'Yes'), ('no', 'No')], default='', validators=[Optional()])
    filter_submit = SubmitField('Apply Filters & Sort')
    clear_filters = SubmitField('Clear All') # This button might not be used if clear is an <a> tag

class MassEditUserForm(FlaskForm): # From previous step
    libraries_to_apply = SelectMultipleField('Apply these libraries to selected users (Ctrl/Cmd+Click to select multiple)', coerce=str, validators=[Optional()], description="Selected libraries will REPLACE existing shares for all chosen users. Leave empty to remove all direct shares from selected users.", choices=[])
    submit_update_libraries = SubmitField('Update Libraries for Selected Users')

class CSRFOnlyForm(FlaskForm):
    pass