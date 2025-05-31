from flask import Blueprint, render_template, redirect, url_for, flash, request, g, current_app, jsonify
from flask_login import login_required, current_user
from sqlalchemy import asc, desc, or_, and_, func 
from app import db, bot_instance 
from app.models import User, InviteLink, AppSetting, HistoryLog, get_app_setting, update_app_setting, get_all_app_settings
from app.forms import (
    SetupAdminForm, PlexSettingsForm, DiscordSettingsForm, InviteCreateForm,
    UserInviteForm, EditUserForm, PurgeSettingsForm, CSRFOnlyForm, UserFilterSortForm 
    # GlobalWhitelistSettingsForm removed
)
from app.plex_utils import (
    test_plex_connection, get_plex_libraries, invite_to_plex, remove_plex_friend,
    get_shared_plex_users_info, get_plex_server, get_users_sharing_servers_with_me 
)
from app.discord_utils import (
    test_discord_bot_token, is_discord_user_on_server,
    get_discord_user_details_by_id_sync
)
from functools import wraps
from datetime import datetime, timedelta
import asyncio 

bp = Blueprint('main', __name__)

# --- Decorators ---
def setup_complete_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if get_app_setting('SETUP_COMPLETED') != 'true':
            flash('Application setup is not yet complete. Please finish the setup wizard.', 'warning')
            return redirect(url_for('main.setup_wizard'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required 
    @setup_complete_required 
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Admin access is required to view this page.', 'danger')
            return redirect(url_for('main.index_or_setup')) 
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Routes ---
@bp.route('/entrypoint') 
def index_or_setup():
    if get_app_setting('SETUP_COMPLETED') == 'true':
        if current_user.is_authenticated and current_user.is_admin:
            return redirect(url_for('main.dashboard'))
        else:
            return redirect(url_for('auth.login'))
    else:
        return redirect(url_for('main.setup_wizard'))

# --- Setup Wizard ---
@bp.route('/setup/wizard', methods=['GET', 'POST'])
@bp.route('/setup/wizard/<int:step>', methods=['GET', 'POST'])
def setup_wizard(step=1):
    force_setup = request.args.get('force', 'false').lower() == 'true'
    if get_app_setting('SETUP_COMPLETED') == 'true' and not force_setup:
        flash('Application setup is already complete. Manage settings from the admin panel.', 'info')
        return redirect(url_for('auth.login'))

    if step == 1: 
        if User.query.filter_by(is_admin=True).first() and not force_setup:
            return redirect(url_for('main.setup_wizard', step=2))
        form = SetupAdminForm()
        if form.validate_on_submit():
            try:
                admin_user = User(username=form.username.data.strip(), is_admin=True)
                admin_user.set_password(form.password.data)
                db.session.add(admin_user); db.session.commit()
                flash('Admin user created. Next, configure Plex.', 'success')
                HistoryLog.create(event_type="SETUP_ADMIN_CREATED", plex_username=admin_user.username)
                return redirect(url_for('main.setup_wizard', step=2))
            except Exception as e:
                db.session.rollback(); flash(f'Error creating admin: {str(e)[:200]}', 'danger')
                current_app.logger.error(f"Setup admin error: {e}", exc_info=True)
        return render_template('setup/wizard_step_1_admin.html', title='Setup: Admin Account', form=form)

    elif step == 2: 
        if not User.query.filter_by(is_admin=True).first() and not force_setup:
            flash("Admin account needed. Complete Step 1.", "warning"); return redirect(url_for('main.setup_wizard', step=1))
        
        form_data_source = request.form if request.method == 'POST' else None
        form = PlexSettingsForm(form_data_source) # Populate with request.form if POST
        if request.method == 'GET' or not form_data_source : # Populate with DB data for GET
            form.plex_url.data = get_app_setting('PLEX_URL')
            form.plex_token.data = get_app_setting('PLEX_TOKEN')
            form.app_base_url.data = get_app_setting('APP_BASE_URL', request.url_root.rstrip('/'))
        
        if form.validate_on_submit(): 
            plex_url = form.plex_url.data.strip(); plex_token = form.plex_token.data.strip()
            app_base_url = form.app_base_url.data.strip().rstrip('/')
            is_valid, message = test_plex_connection(plex_url, plex_token)
            if is_valid:
                try:
                    update_app_setting('PLEX_URL', plex_url); update_app_setting('PLEX_TOKEN', plex_token)
                    update_app_setting('APP_BASE_URL', app_base_url)
                    flash(f'Plex settings saved. Conn: {message}. Next, Discord (optional).', 'success')
                    HistoryLog.create(event_type="SETUP_PLEX_CONFIGURED", details=f"URL: {plex_url[:30]}...")
                    return redirect(url_for('main.setup_wizard', step=3))
                except Exception as e:
                    flash(f'Error saving Plex settings: {str(e)[:200]}', 'danger')
                    current_app.logger.error(f"Setup Plex save error: {e}", exc_info=True)
            else:
                flash(f'Plex connection failed: {message}. Check URL/Token.', 'danger')
        return render_template('setup/wizard_step_2_plex.html', title='Setup: Plex Configuration', form=form)

    elif step == 3: 
        if not User.query.filter_by(is_admin=True).first() and not force_setup: return redirect(url_for('main.setup_wizard', step=1))
        if not get_app_setting('PLEX_URL') and not force_setup:
            flash("Plex settings needed. Complete Step 2.", "warning"); return redirect(url_for('main.setup_wizard', step=2))

        csrf_skip_form = CSRFOnlyForm(prefix="skip_discord_") 
        form_data_source = request.form if request.method == 'POST' else None
        form = DiscordSettingsForm(form_data_source) 
        if request.method == 'GET' or not form_data_source : 
            form.discord_bot_enabled.data = (get_app_setting('DISCORD_BOT_ENABLED') == 'true')
            form.discord_bot_token.data = get_app_setting('DISCORD_BOT_TOKEN')
            form.discord_server_id.data = get_app_setting('DISCORD_SERVER_ID')
            form.discord_bot_app_id.data = get_app_setting('DISCORD_BOT_APP_ID')
            form.admin_discord_id.data = get_app_setting('ADMIN_DISCORD_ID')
            form.discord_command_channel_id.data = get_app_setting('DISCORD_COMMAND_CHANNEL_ID')
            form.discord_mention_role_id.data = get_app_setting('DISCORD_MENTION_ROLE_ID')
            form.discord_plex_access_role_id.data = get_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID')
            form.discord_bot_user_whitelist.data = get_app_setting('DISCORD_BOT_USER_WHITELIST')
        
        if form.validate_on_submit(): 
            try:
                is_bot_being_enabled_from_form = form.discord_bot_enabled.data
                bot_token_from_form = form.discord_bot_token.data.strip() if form.discord_bot_token.data else ""

                update_app_setting('DISCORD_BOT_ENABLED', 'true' if is_bot_being_enabled_from_form else 'false')
                if is_bot_being_enabled_from_form:
                    update_app_setting('DISCORD_BOT_TOKEN', bot_token_from_form) 
                    update_app_setting('DISCORD_SERVER_ID', form.discord_server_id.data.strip() or "")
                    update_app_setting('DISCORD_BOT_APP_ID', form.discord_bot_app_id.data.strip() or "")
                    update_app_setting('ADMIN_DISCORD_ID', form.admin_discord_id.data.strip() or "")
                    update_app_setting('DISCORD_COMMAND_CHANNEL_ID', form.discord_command_channel_id.data.strip() or "")
                    update_app_setting('DISCORD_MENTION_ROLE_ID', form.discord_mention_role_id.data.strip() or "")
                    update_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID', form.discord_plex_access_role_id.data.strip() or "")
                    raw_bot_wl = form.discord_bot_user_whitelist.data or ""
                    processed_bot_wl = [item.strip() for item in raw_bot_wl.replace('\n',',').split(',') if item.strip()]
                    update_app_setting('DISCORD_BOT_USER_WHITELIST', ",".join(set(processed_bot_wl)))
                else: 
                    keys_to_clear_on_discord_disable = ['DISCORD_BOT_TOKEN', 'DISCORD_SERVER_ID', 'DISCORD_BOT_APP_ID',
                                                        'ADMIN_DISCORD_ID', 'DISCORD_COMMAND_CHANNEL_ID',
                                                        'DISCORD_MENTION_ROLE_ID', 'DISCORD_PLEX_ACCESS_ROLE_ID', 'DISCORD_BOT_USER_WHITELIST']
                    for key_to_clear in keys_to_clear_on_discord_disable: update_app_setting(key_to_clear, "")

                update_app_setting('SETUP_COMPLETED', 'true')
                
                flash_msg = 'Discord settings saved. '
                token_validation_message = getattr(form.discord_bot_token, 'description', None)
                if token_validation_message: flash_msg += f"{token_validation_message}. "
                
                if is_bot_being_enabled_from_form and bot_token_from_form:
                    flash_msg += 'Bot will attempt to start (app restart may be needed). '
                    from app.__init__ import initialize_app_services 
                    initialize_app_services(current_app._get_current_object())
                flash_msg += 'Setup is complete! Please login.'
                flash(flash_msg, 'success')
                HistoryLog.create(event_type="SETUP_DISCORD_CONFIGURED", details=f"Bot Enabled: {is_bot_being_enabled_from_form}")
                HistoryLog.create(event_type="SETUP_COMPLETED")
                return redirect(url_for('auth.login'))
            except Exception as e:
                flash(f'Error saving Discord settings: {str(e)[:200]}', 'danger')
                current_app.logger.error(f"Setup Discord save error: {e}", exc_info=True)
        
        return render_template('setup/wizard_step_3_discord.html', title='Setup: Discord', form=form, csrf_skip_form=csrf_skip_form)
    
    else: 
        return redirect(url_for('main.setup_wizard', step=1))

@bp.route('/setup/wizard/skip_discord_and_complete', methods=['POST'])
def skip_discord_and_complete_setup():
    # ... (as before) ...
    csrf_form = CSRFOnlyForm(prefix="skip_discord_") 
    if not csrf_form.validate_on_submit(): 
        flash("Invalid request. Try again.", "danger"); return redirect(url_for('main.setup_wizard', step=3))

    if not User.query.filter_by(is_admin=True).first(): return redirect(url_for('main.setup_wizard', step=1))
    if not get_app_setting('PLEX_URL'): return redirect(url_for('main.setup_wizard', step=2))

    try:
        update_app_setting('DISCORD_BOT_ENABLED', 'false')
        keys_to_clear = ['DISCORD_BOT_TOKEN', 'DISCORD_SERVER_ID', 'DISCORD_BOT_APP_ID', 
                         'ADMIN_DISCORD_ID', 'DISCORD_COMMAND_CHANNEL_ID', 
                         'DISCORD_MENTION_ROLE_ID', 'DISCORD_PLEX_ACCESS_ROLE_ID',
                         'DISCORD_BOT_USER_WHITELIST'] 
        for key in keys_to_clear: update_app_setting(key, "")
        update_app_setting('SETUP_COMPLETED', 'true')

        flash('Discord config skipped. Setup complete! Please login.', 'success')
        HistoryLog.create(event_type="SETUP_DISCORD_SKIPPED"); HistoryLog.create(event_type="SETUP_COMPLETED")
        from app.__init__ import initialize_app_services 
        initialize_app_services(current_app._get_current_object()) 
        return redirect(url_for('auth.login'))
    except Exception as e:
        flash(f'Error finalizing setup: {str(e)[:200]}', 'danger')
        current_app.logger.error(f"Setup skip discord error: {e}", exc_info=True)
        return redirect(url_for('main.setup_wizard', step=3))

# --- Main Admin Pages ---
@bp.route('/') 
@admin_required
def dashboard():
    # ... (as before) ...
    total_users, active_invites, plex_is_connected, plex_server_name = 0, 0, False, "N/A"
    recent_logs = []
    try: total_users = User.query.filter_by(is_admin=False).count()
    except Exception as e: current_app.logger.error(f"Dashboard: Err total_users: {e}", exc_info=True);
    try:
        active_invites = InviteLink.query.filter(
            db.or_(InviteLink.expires_at.is_(None), InviteLink.expires_at > datetime.utcnow()), 
            db.or_(InviteLink.max_uses.is_(None), InviteLink.current_uses < InviteLink.max_uses)
        ).count()
    except Exception as e: current_app.logger.error(f"Dashboard: Err active_invites: {e}", exc_info=True);
    try: recent_logs = HistoryLog.query.order_by(HistoryLog.timestamp.desc()).limit(5).all()
    except Exception as e: current_app.logger.error(f"Dashboard: Err recent_logs: {e}", exc_info=True);
    
    if get_app_setting('PLEX_URL') and get_app_setting('PLEX_TOKEN'):
        try:
            plex = get_plex_server() 
            if plex:
                plex_is_connected = True
                try: plex_server_name = plex.friendlyName
                except Exception: plex_server_name = "Error fetching name"
        except Exception as e: current_app.logger.warning(f"Dashboard: Err Plex connection check: {e}", exc_info=False)
            
    return render_template('admin/dashboard.html', title='Admin Dashboard',
                           total_users=total_users, active_invites=active_invites, 
                           recent_logs=recent_logs, 
                           plex_utils_get_plex_server_status_is_connected=plex_is_connected,
                           plex_server_name=plex_server_name)

@bp.route('/invites', methods=['GET', 'POST'])
@admin_required
def manage_invites():
    # ... (as before) ...
    form = InviteCreateForm()
    csrf_form = CSRFOnlyForm() 
    try:
        plex_libs = get_plex_libraries()
        form.allowed_libraries.choices = [(lib['title'], lib['title']) for lib in plex_libs] if plex_libs else []
    except Exception as e:
        flash(f"Could not fetch Plex libraries: {str(e)[:100]}. Check Plex settings.", "warning")
        current_app.logger.warning(f"Err fetching Plex libs for invite form: {e}")
        form.allowed_libraries.choices = []

    if form.validate_on_submit():
        if InviteLink.query.filter_by(custom_path=form.custom_path.data.strip()).first():
            flash('Custom path already exists.', 'danger')
        else:
            try:
                expires_at = None
                if form.expires_days.data is not None and form.expires_days.data > 0: expires_at = datetime.utcnow() + timedelta(days=form.expires_days.data)
                max_uses_val = None 
                if form.max_uses.data is not None and form.max_uses.data > 0: max_uses_val = form.max_uses.data
                new_invite = InviteLink(
                    custom_path=form.custom_path.data.strip(), expires_at=expires_at, max_uses=max_uses_val,
                    allowed_libraries=",".join(form.allowed_libraries.data) if form.allowed_libraries.data else None
                )
                db.session.add(new_invite); db.session.commit()
                flash('Invite link created!', 'success'); HistoryLog.create(event_type="INVITE_CREATED", details=f"Path: {new_invite.custom_path}")
                return redirect(url_for('main.manage_invites'))
            except Exception as e:
                db.session.rollback(); flash(f"Error creating invite: {str(e)[:200]}", "danger")
                current_app.logger.error(f"Error creating invite: {e}", exc_info=True)
        
    invites = InviteLink.query.order_by(InviteLink.created_at.desc()).all()
    return render_template('admin/invites.html', title='Manage Invites', form=form, invites=invites, csrf_form=csrf_form)


@bp.route('/invites/delete/<int:invite_id>', methods=['POST'])
@admin_required
def delete_invite(invite_id):
    # ... (as before) ...
    csrf_form = CSRFOnlyForm()
    if csrf_form.validate_on_submit():
        invite = InviteLink.query.get_or_404(invite_id)
        try:
            HistoryLog.create(event_type="INVITE_DELETED", details=f"Path: {invite.custom_path}, ID: {invite.id}")
            db.session.delete(invite); db.session.commit()
            flash('Invite link deleted.', 'success')
        except Exception as e:
            db.session.rollback(); flash(f"Error deleting invite: {str(e)[:200]}", "danger")
            current_app.logger.error(f"Error deleting invite {invite_id}: {e}", exc_info=True)
    else: flash("CSRF validation failed. Try again.", "danger")
    return redirect(url_for('main.manage_invites'))


@bp.route('/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    filter_sort_form = UserFilterSortForm(request.args, meta={'csrf': False}) 
    purge_form_data = request.form if request.method == 'POST' and request.form.get('action') == 'purge' else None
    purge_form = PurgeSettingsForm(purge_form_data) 
    csrf_form = CSRFOnlyForm()

    # --- Get filter/sort parameters ---
    if filter_sort_form.filter_submit.data and filter_sort_form.validate():
        search_term = filter_sort_form.search.data.strip() if filter_sort_form.search.data else ''
        sort_by = filter_sort_form.sort_by.data
        sort_order = filter_sort_form.sort_order.data
        filter_is_home = filter_sort_form.filter_is_home_user.data
        filter_shares_back = filter_sort_form.filter_shares_back.data
        filter_is_purge_wl = filter_sort_form.filter_is_purge_whitelisted.data
        filter_is_discord_bot_wl = filter_sort_form.filter_is_discord_bot_whitelisted.data
        page = request.args.get('page', 1, type=int)
        return redirect(url_for('main.manage_users', search=search_term, sort_by=sort_by, sort_order=sort_order,
                                filter_home=filter_is_home, filter_shares=filter_shares_back, 
                                filter_p_wl=filter_is_purge_wl, filter_d_wl=filter_is_discord_bot_wl,
                                page=page))
    else: 
        search_term = request.args.get('search', '').strip()
        sort_by = request.args.get('sort_by', 'plex_username') 
        sort_order = request.args.get('sort_order', 'asc')
        filter_is_home = request.args.get('filter_home', '')
        filter_shares_back = request.args.get('filter_shares', '')
        filter_is_purge_wl = request.args.get('filter_p_wl', '')
        filter_is_discord_bot_wl = request.args.get('filter_d_wl', '')
        
        if not (request.method == 'POST' and filter_sort_form.filter_submit.data and filter_sort_form.is_submitted()):
            filter_sort_form.search.data = search_term
            filter_sort_form.sort_by.data = sort_by
            filter_sort_form.sort_order.data = sort_order
            filter_sort_form.filter_is_home_user.data = filter_is_home
            filter_sort_form.filter_shares_back.data = filter_shares_back
            filter_sort_form.filter_is_purge_whitelisted.data = filter_is_purge_wl
            filter_sort_form.filter_is_discord_bot_whitelisted.data = filter_is_discord_bot_wl

    valid_sort_columns = {
        'plex_username': User.plex_username, 'plex_email': User.plex_email,
        'discord_username': User.discord_username, 'last_streamed_at': User.last_streamed_at,
        'shares_back': User.shares_back, 'is_plex_home_user': User.is_plex_home_user,
        'is_purge_whitelisted': User.is_purge_whitelisted
    }
    current_sort_column_attr = valid_sort_columns.get(sort_by, User.plex_username)
    
    raw_discord_bot_whitelist_str = get_app_setting('DISCORD_BOT_USER_WHITELIST', '') 
    discord_bot_whitelist_plex_usernames_set = { name.strip().lower() for name in raw_discord_bot_whitelist_str.replace('\n',',').split(',') if name.strip()}

    if request.method == 'POST' and request.form.get('action') == 'purge':
        # ... (Purge logic remains the same as before) ...
        if purge_form.validate(): 
            days_inactive = purge_form.days_inactive.data
            exempt_sharers = purge_form.exempt_sharers.data 
            exempt_home_users = purge_form.exempt_home_users.data 
            cutoff_date = datetime.utcnow() - timedelta(days=days_inactive)
            query = User.query.filter(User.is_admin == False)
            query = query.filter(User.is_purge_whitelisted == False) 
            if exempt_sharers: query = query.filter(User.shares_back == False)
            if exempt_home_users: query = query.filter(User.is_plex_home_user == False) 
            query = query.filter(db.or_((User.last_streamed_at.is_(None)) & (User.joined_at < cutoff_date), (User.last_streamed_at < cutoff_date)))
            users_to_purge = query.all()
            purged_count = 0; errors = []
            for user_obj_to_purge in users_to_purge:
                plex_ident = user_obj_to_purge.plex_username or user_obj_to_purge.plex_email
                success, message = remove_plex_friend(plex_ident)
                if success:
                    HistoryLog.create(event_type="USER_PURGED", plex_username=plex_ident, discord_id=user_obj_to_purge.discord_id, details=f"Inactive {days_inactive} days. Plex: {message}")
                    db.session.delete(user_obj_to_purge); purged_count += 1
                else:
                    errors.append(f"Plex removal for {plex_ident}: {message}")
                    HistoryLog.create(event_type="ERROR_PURGING_USER", plex_username=plex_ident, discord_id=user_obj_to_purge.discord_id, details=f"Plex removal failed: {message}")
            try:
                db.session.commit()
                if purged_count > 0 : flash(f"Purged {purged_count} inactive users.", 'success')
                else: flash("No users matched purge criteria (respecting all exemptions & individual whitelists).", "info")
                if errors: flash(f"Purge errors: {'; '.join(errors)}", 'warning')
            except Exception as e:
                db.session.rollback(); flash(f"DB error during purge: {str(e)[:200]}", "danger")
                current_app.logger.error(f"DB error user purge: {e}", exc_info=True)
            return redirect(url_for('main.manage_users', search=search_term, sort_by=sort_by, sort_order=sort_order, 
                                    filter_home=filter_is_home, filter_shares=filter_shares_back, 
                                    filter_p_wl=filter_is_purge_wl, filter_d_wl=filter_is_discord_bot_wl))
        else: 
            for field_name_str, error_list in purge_form.errors.items():
                field_label = getattr(getattr(purge_form, field_name_str), 'label', None)
                label_text = field_label.text if field_label else field_name_str.replace("_", " ").title()
                for error in error_list: flash(f"Purge form error in '{label_text}': {error}", "danger")


    # --- Build the base query for displaying users ---
    users_base_query = User.query.filter(User.is_admin == False)
    if search_term:
        search_like = f"%{search_term}%"
        users_base_query = users_base_query.filter(
            db.or_( User.plex_username.ilike(search_like), User.plex_email.ilike(search_like),
                    User.discord_username.ilike(search_like), User.discord_id.ilike(search_like) )
        )
    if filter_is_home == 'yes': users_base_query = users_base_query.filter(User.is_plex_home_user == True)
    elif filter_is_home == 'no': users_base_query = users_base_query.filter(User.is_plex_home_user == False)
    if filter_shares_back == 'yes': users_base_query = users_base_query.filter(User.shares_back == True)
    elif filter_shares_back == 'no': users_base_query = users_base_query.filter(User.shares_back == False)
    if filter_is_purge_wl == 'yes': users_base_query = users_base_query.filter(User.is_purge_whitelisted == True)
    elif filter_is_purge_wl == 'no': users_base_query = users_base_query.filter(User.is_purge_whitelisted == False)
    if filter_is_discord_bot_wl == 'yes':
        if discord_bot_whitelist_plex_usernames_set: 
            conditions = [User.plex_username.ilike(name) for name in discord_bot_whitelist_plex_usernames_set]
            if conditions: users_base_query = users_base_query.filter(or_(*conditions))
            else: users_base_query = users_base_query.filter(db.false()) 
        else: users_base_query = users_base_query.filter(db.false()) 
    elif filter_is_discord_bot_wl == 'no':
        if discord_bot_whitelist_plex_usernames_set:
            conditions = [User.plex_username.ilike(name) for name in discord_bot_whitelist_plex_usernames_set]
            if conditions: users_base_query = users_base_query.filter(db.not_(or_(*conditions)))

    # --- Apply sorting with SQLite compatible NULLS LAST/FIRST ---
    # Determine the actual column object to sort by (e.g., User.plex_username)
    sort_column_sql_obj = current_sort_column_attr

    # For text-based sorting, apply lower for case-insensitivity
    if sort_by in ['plex_username', 'plex_email', 'discord_username']:
        sort_expression = func.lower(sort_column_sql_obj)
    else:
        sort_expression = sort_column_sql_obj

    if sort_order == 'asc':
        # ASC order: NULLs are typically first in SQLite. To make them last:
        # Order by (CASE WHEN column IS NULL THEN 1 ELSE 0 END), then by column
        users_base_query = users_base_query.order_by(sort_column_sql_obj.is_(None), asc(sort_expression))
    else: # sort_order == 'desc'
        # DESC order: NULLs are typically last in SQLite. To make them last (which is default):
        # Order by column DESC. If you wanted NULLS FIRST for DESC, it would be:
        # users_base_query = users_base_query.order_by(sort_column_sql_obj.isnot(None), desc(sort_expression))
        users_base_query = users_base_query.order_by(desc(sort_expression)) # SQLite default for DESC usually puts NULLs last
        sort_order = 'desc' # Ensure consistent value for template links
            
    plex_users = users_base_query.all()
    
    if request.method == 'GET' and not (request.args.get('action') == 'purge' and purge_form.errors): 
        purge_form = PurgeSettingsForm() 

    return render_template('admin/users.html', title='Manage Users', users=plex_users,
                           purge_form=purge_form, csrf_form=csrf_form, filter_sort_form=filter_sort_form,
                           discord_bot_whitelist_plex_usernames=discord_bot_whitelist_plex_usernames_set)

@bp.route('/users/sync_from_plex', methods=['POST'])
@admin_required
def sync_plex_users():
    csrf_form = CSRFOnlyForm()
    if not csrf_form.validate_on_submit():
        flash("CSRF fail. Try again.", "danger"); return redirect(url_for('main.manage_users'))
    
    current_app.logger.info("Starting Plex user sync...")
    users_who_share_back_set = get_users_sharing_servers_with_me()
    plex_users_from_api, message = get_shared_plex_users_info() 
    
    if not message.startswith("Fetched"):
        flash(f"Plex Sync (My Shared Users): {message}", "danger" if not plex_users_from_api else "info")

    new_c, updated_c, skipped_api_c, stale_removed_c = 0, 0, 0, 0
    api_user_identifiers = set() 
    api_users_data_map = {} 

    for p_user_data in plex_users_from_api:
        p_id = p_user_data.get('plex_id')
        p_email = p_user_data.get('email', "").lower() if p_user_data.get('email') else None
        if p_id: identifier = f"plexid_{p_id}"; api_users_data_map[identifier] = p_user_data
        elif p_email: identifier = f"email_{p_email}"; api_users_data_map[identifier] = p_user_data
        else: skipped_api_c +=1; continue
        api_user_identifiers.add(identifier)

    for identifier, p_user_data in api_users_data_map.items():
        p_email = p_user_data.get('email', "").lower() if p_user_data.get('email') else None
        p_username = p_user_data.get('username') 
        p_id = p_user_data.get('plex_id')
        p_is_home = bool(p_user_data.get('is_home_user', False))
        p_last_seen = p_user_data.get('last_seen_on_server') 

        existing_user = None
        if p_id: existing_user = User.query.filter_by(plex_user_id=p_id, is_admin=False).first()
        if not existing_user and p_email: existing_user = User.query.filter_by(plex_email=p_email, is_admin=False).first()
        if not existing_user and p_username and not p_id and not p_email: 
            existing_user = User.query.filter_by(plex_username=p_username, is_admin=False).first()
        
        plex_username_lower_for_check = (p_username or "").lower()
        plex_email_lower_for_check = (p_email or "").lower()
        does_share_back = False 
        if users_who_share_back_set:
            if (plex_username_lower_for_check and plex_username_lower_for_check in users_who_share_back_set) or \
               (plex_email_lower_for_check and plex_email_lower_for_check in users_who_share_back_set):
                does_share_back = True
        
        if existing_user:
            changed = False
            if p_id is not None and existing_user.plex_user_id != p_id: existing_user.plex_user_id = p_id; changed = True
            if p_username and existing_user.plex_username != p_username: existing_user.plex_username = p_username; changed = True
            if p_email and existing_user.plex_email != p_email: existing_user.plex_email = p_email; changed = True
            if existing_user.is_plex_home_user != p_is_home: existing_user.is_plex_home_user = p_is_home; changed = True
            if p_last_seen and existing_user.last_streamed_at != p_last_seen : 
                existing_user.last_streamed_at = p_last_seen; changed = True
            current_shares_back_val = bool(does_share_back)
            if existing_user.shares_back != current_shares_back_val: 
                existing_user.shares_back = current_shares_back_val; changed = True
            if changed: updated_c += 1; db.session.add(existing_user)
        else: 
            new_user = User(plex_user_id=p_id, plex_username=p_username, plex_email=p_email, 
                            is_plex_home_user=bool(p_is_home), is_admin=False, joined_at=datetime.utcnow(),
                            last_streamed_at=p_last_seen, shares_back=bool(does_share_back)) 
            db.session.add(new_user); new_c += 1
    
    if get_app_setting('SYNC_REMOVE_STALE_USERS', 'false') == 'true': 
        app_db_users = User.query.filter_by(is_admin=False).all()
        for app_user in app_db_users:
            app_user_present_in_api = False
            if app_user.plex_user_id and f"plexid_{app_user.plex_user_id}" in api_user_identifiers: app_user_present_in_api = True
            elif app_user.plex_email and f"email_{app_user.plex_email.lower()}" in api_user_identifiers: app_user_present_in_api = True
            if not app_user_present_in_api:
                current_app.logger.info(f"Stale user for removal from app DB: {app_user.plex_username or app_user.plex_email} (AppDB ID: {app_user.id}). Not in current Plex source list.")
                HistoryLog.create(event_type="STALE_USER_REMOVED_SYNC", plex_username=app_user.plex_username, discord_id=app_user.discord_id, details="User no longer in Plex source list. Removed from app DB.")
                db.session.delete(app_user); stale_removed_c += 1
    else: current_app.logger.info("SYNC_REMOVE_STALE_USERS is off. No stale users removed from app DB.")

    try:
        db.session.commit()
        flash_msg = f"User sync complete. My Server Users: {message}."
        if users_who_share_back_set: flash_msg += f" Found {len(users_who_share_back_set)} users sharing their servers back."
        flash_msg += f" Processed: {new_c} new app users, {updated_c} app users updated."
        if skipped_api_c > 0: flash_msg += f" {skipped_api_c} from Plex API skipped."
        if stale_removed_c > 0: flash_msg += f" {stale_removed_c} stale users removed from app."
        flash(flash_msg + " Review users.", "success")
        HistoryLog.create(event_type="PLEX_USERS_SYNCED", details=f"{new_c} new, {updated_c} updated, {skipped_api_c} skipped, {stale_removed_c} stale removed. Sharers: {len(users_who_share_back_set)}")
    except Exception as e:
        db.session.rollback(); flash(f"DB error Plex sync: {str(e)[:200]}", "danger")
        current_app.logger.error(f"DB error Plex sync: {e}", exc_info=True)
        HistoryLog.create(event_type="ERROR_PLEX_SYNC_COMMIT", details=str(e)[:250])
    return redirect(url_for('main.manage_users'))

@bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user_obj = User.query.get_or_404(user_id)
    if user_obj.is_admin: 
        flash("Admin user profile cannot be edited here.", "danger"); return redirect(url_for('main.manage_users'))
    
    form = EditUserForm(request.form if request.method == 'POST' else None)
    if request.method == 'GET' or not form.is_submitted(): 
        form.discord_id.data = user_obj.discord_id
        form.shares_back.data = user_obj.shares_back
        form.is_purge_whitelisted.data = user_obj.is_purge_whitelisted

    if form.validate_on_submit():
        original_discord_id = user_obj.discord_id
        original_shares_back = user_obj.shares_back
        original_is_purge_whitelisted = user_obj.is_purge_whitelisted
        new_discord_id_str = form.discord_id.data.strip() if form.discord_id.data else None
        
        if new_discord_id_str and new_discord_id_str != original_discord_id:
            existing_link = User.query.filter(User.discord_id == new_discord_id_str, User.id != user_obj.id, User.is_admin == False).first()
            if existing_link:
                flash(f"Discord ID {new_discord_id_str} is already linked to another user.", "danger")
                return render_template('admin/edit_user.html', title=f"Edit User", form=form, user=user_obj)

        user_obj.discord_id = new_discord_id_str
        user_obj.shares_back = form.shares_back.data 
        user_obj.is_purge_whitelisted = form.is_purge_whitelisted.data 
        new_disc_uname = user_obj.discord_username 

        if new_discord_id_str:
            if get_app_setting('DISCORD_BOT_ENABLED') == 'true' and get_app_setting('DISCORD_BOT_TOKEN'):
                fetched_uname, err_msg = get_discord_user_details_by_id_sync(new_discord_id_str)
                if fetched_uname: user_obj.discord_username = fetched_uname; new_disc_uname = fetched_uname;
                else: user_obj.discord_username = None; flash(f"Could not fetch Discord username for {new_discord_id_str}: {err_msg}. ID saved, username not updated.", "warning")
            elif user_obj.discord_id: user_obj.discord_username = None; 
        else: user_obj.discord_username = None
        
        try:
            db.session.commit()
            details_log = (f"Admin updated. Old Discord ID: {original_discord_id or 'N/A'}, New: {new_discord_id_str or 'N/A'}. "
                           f"Discord Username: {new_disc_uname or 'N/A'}. "
                           f"Shares Back: {user_obj.shares_back} (was {original_shares_back}). "
                           f"Purge Whitelisted (Indiv): {user_obj.is_purge_whitelisted} (was {original_is_purge_whitelisted}).")
            HistoryLog.create(event_type="USER_PROFILE_UPDATED", plex_username=user_obj.plex_username, discord_id=user_obj.discord_id, details=details_log)
            flash(f'User {user_obj.plex_username or user_obj.plex_email} updated successfully.', 'success')
            return redirect(url_for('main.manage_users', 
                                    search=request.args.get('search', ''), 
                                    sort_by=request.args.get('sort_by', 'plex_username'), 
                                    sort_order=request.args.get('sort_order', 'asc'),
                                    filter_home=request.args.get('filter_home', ''),
                                    filter_shares=request.args.get('filter_shares', ''),
                                    filter_p_wl=request.args.get('filter_p_wl', ''),
                                    filter_d_wl=request.args.get('filter_d_wl', '')
                                    ))
        except Exception as e:
            db.session.rollback(); flash(f"Error updating user: {str(e)[:200]}", "danger")
            current_app.logger.error(f"Error updating user {user_id}: {e}", exc_info=True)
            
    return render_template('admin/edit_user.html', title=f"Edit User: {user_obj.plex_username or user_obj.plex_email}", form=form, user=user_obj)

@bp.route('/users/remove/<int:user_id>', methods=['POST'])
@admin_required
def remove_user(user_id):
    csrf_form = CSRFOnlyForm()
    if not csrf_form.validate_on_submit(): flash("CSRF fail.", "danger"); return redirect(url_for('main.manage_users'))
        
    user_obj = User.query.get_or_404(user_id)
    if user_obj.is_admin: flash("Admin cannot be removed.", "danger"); return redirect(url_for('main.manage_users'))
        
    plex_ident, user_discord_id = user_obj.plex_username or user_obj.plex_email, user_obj.discord_id
    success_plex, message_plex = remove_plex_friend(plex_ident)
    if success_plex:
        HistoryLog.create(event_type="USER_REMOVED_MANUAL_PLEX", plex_username=plex_ident, discord_id=user_discord_id, details=message_plex)
        db.session.delete(user_obj)
        try:
            db.session.commit()
            flash(f'User {plex_ident} removed from Plex & DB. {message_plex}', 'success')
            if user_discord_id and get_app_setting('DISCORD_BOT_ENABLED') == 'true':
                role_id = get_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID')
                if role_id and bot_instance and hasattr(bot_instance, 'flask_app_callable_remove_role') and hasattr(bot_instance, 'thread_loop') and bot_instance.thread_loop and not bot_instance.is_closed(): # type: ignore
                    if bot_instance.thread_loop.is_running(): # type: ignore
                         asyncio.run_coroutine_threadsafe(
                            bot_instance.flask_app_callable_remove_role(user_discord_id, role_id, reason="Plex access manually revoked"),
                            bot_instance.thread_loop # type: ignore
                        ) 
                         flash(f"Attempting to remove Discord role for {user_discord_id} (async).", "info")
                    else: flash(f"Bot loop not running for Discord ID {user_discord_id} role removal.", "warning")
                elif user_discord_id and role_id and (not bot_instance or bot_instance.is_closed()): # type: ignore
                     flash(f"Discord bot not operational, cannot remove role for {user_discord_id}.", "warning")
        except Exception as e:
            db.session.rollback(); flash(f"DB error after Plex removal for {plex_ident}: {str(e)[:200]}", "danger")
            current_app.logger.error(f"DB error after Plex removal {user_id}: {e}", exc_info=True)
    else:
        flash(f'Failed to remove {plex_ident} from Plex: {message_plex}', 'danger')
        HistoryLog.create(event_type="ERROR_REMOVING_MANUAL_PLEX", plex_username=plex_ident, discord_id=user_discord_id, details=message_plex)
    return redirect(url_for('main.manage_users'))

@bp.route('/users/bulk_remove', methods=['POST'])
@admin_required
def bulk_remove_users():
    csrf_form = CSRFOnlyForm()
    if not csrf_form.validate_on_submit(): flash("CSRF fail.", "danger"); return redirect(url_for('main.manage_users'))

    selected_ids_str = request.form.getlist('selected_users')
    if not selected_ids_str: flash('No users selected.', 'warning'); return redirect(url_for('main.manage_users'))

    removed_c, errors, discord_infos = 0, [], []
    role_id = get_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID')
    bot_on = get_app_setting('DISCORD_BOT_ENABLED') == 'true'

    for uid_str in selected_ids_str:
        try:
            uid = int(uid_str)
            user = User.query.get(uid)
            if not user or user.is_admin:
                if user and user.is_admin: errors.append(f"Admin ({user.username}) skipped.")
                else: errors.append(f"User ID {uid} not found.")
                continue
            ident, disc_id = user.plex_username or user.plex_email, user.discord_id
            succ_plex, msg_plex = remove_plex_friend(ident)
            if succ_plex:
                HistoryLog.create(event_type="USER_BULK_REMOVED_PLEX", plex_username=ident, discord_id=disc_id, details=msg_plex)
                db.session.delete(user); removed_c += 1
                if disc_id and bot_on and role_id and bot_instance and hasattr(bot_instance, 'flask_app_callable_remove_role') and hasattr(bot_instance, 'thread_loop') and bot_instance.thread_loop and not bot_instance.is_closed(): # type: ignore
                    if bot_instance.thread_loop.is_running(): # type: ignore
                        asyncio.run_coroutine_threadsafe(bot_instance.flask_app_callable_remove_role(disc_id, role_id, reason="Plex access bulk revoked"), bot_instance.thread_loop) # type: ignore
                        discord_infos.append(f"Role removal queued for Discord ID {disc_id}.")
                    else: errors.append(f"Bot loop not running for Discord ID {disc_id} role removal.")
            else:
                errors.append(f"Plex removal fail for {ident}: {msg_plex}")
                HistoryLog.create(event_type="ERROR_BULK_REMOVING_PLEX", plex_username=ident, discord_id=disc_id, details=msg_plex)
        except ValueError: errors.append(f"Invalid user ID '{uid_str}'.")
        except Exception as e_loop: errors.append(f"Error for ID {uid_str}: {str(e_loop)[:100]}"); current_app.logger.error(f"Bulk remove loop error ID {uid_str}: {e_loop}", exc_info=True)
    
    try: db.session.commit()
    except Exception as e_commit:
        db.session.rollback(); flash(f"DB error bulk commit: {str(e_commit)[:200]}", "danger")
        current_app.logger.error(f"DB Commit error bulk remove: {e_commit}", exc_info=True); return redirect(url_for('main.manage_users'))

    if removed_c > 0: flash(f"Successfully removed {removed_c} users.", "success")
    if discord_infos: flash("Discord Role Removals Queued: " + "; ".join(discord_infos), "info")
    if errors:
        for err in errors: flash(err, "danger")
    if removed_c == 0 and not errors and selected_ids_str: flash("No users were removed.", "info")
    return redirect(url_for('main.manage_users'))

@bp.route('/history') 
@admin_required
def view_history():
    page = request.args.get('page', 1, type=int)
    try:
        per_page_setting = get_app_setting('ITEMS_PER_PAGE', '25')
        per_page = int(per_page_setting)
    except ValueError: per_page = 25; current_app.logger.warning(f"Invalid ITEMS_PER_PAGE, defaulting to {per_page}.")
    try:
        logs_pagination = HistoryLog.query.order_by(HistoryLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
        return render_template('admin/history.html', title='Activity History', logs_pagination=logs_pagination)
    except Exception as e:
        current_app.logger.error(f"Error fetching history: {e}", exc_info=True); flash("Could not load activity history.", "danger")
        return render_template('admin/history.html', title='Activity History', logs_pagination=None, error_message="Failed to load logs.")

@bp.route('/settings', methods=['GET', 'POST'])
@admin_required
def app_settings_page():
    if request.method == 'POST':
        plex_form = PlexSettingsForm(request.form if 'submit_plex_settings' in request.form else None, prefix="plex")
        discord_form = DiscordSettingsForm(request.form if 'submit_discord_settings' in request.form else None, prefix="discord")
        # GlobalWhitelistSettingsForm is removed, so no whitelist_form here for direct POST handling
    else: # GET request
        plex_form = PlexSettingsForm(prefix="plex", data={'plex_url': get_app_setting('PLEX_URL'), 'plex_token': get_app_setting('PLEX_TOKEN'),'app_base_url': get_app_setting('APP_BASE_URL', request.url_root.rstrip('/')), 'sync_remove_stale_users': (get_app_setting('SYNC_REMOVE_STALE_USERS', 'false') == 'true')})
        discord_form = DiscordSettingsForm(prefix="discord", data={'discord_bot_enabled': (get_app_setting('DISCORD_BOT_ENABLED') == 'true'), 'discord_bot_token': get_app_setting('DISCORD_BOT_TOKEN'), 'discord_server_id': get_app_setting('DISCORD_SERVER_ID'), 'discord_bot_app_id': get_app_setting('DISCORD_BOT_APP_ID'), 'admin_discord_id': get_app_setting('ADMIN_DISCORD_ID'), 'discord_command_channel_id': get_app_setting('DISCORD_COMMAND_CHANNEL_ID'), 'discord_mention_role_id': get_app_setting('DISCORD_MENTION_ROLE_ID'), 'discord_plex_access_role_id': get_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID'), 'discord_bot_user_whitelist': get_app_setting('DISCORD_BOT_USER_WHITELIST')})
    
    form_processed_successfully = False
    if request.method == 'POST':
        if 'submit_plex_settings' in request.form:
            if plex_form.validate():
                is_valid, message = test_plex_connection(plex_form.plex_url.data.strip(), plex_form.plex_token.data.strip())
                if is_valid:
                    try:
                        update_app_setting('PLEX_URL', plex_form.plex_url.data.strip()); update_app_setting('PLEX_TOKEN', plex_form.plex_token.data.strip())
                        update_app_setting('APP_BASE_URL', plex_form.app_base_url.data.strip().rstrip('/'))
                        update_app_setting('SYNC_REMOVE_STALE_USERS', 'true' if plex_form.sync_remove_stale_users.data else 'false')
                        flash(f'Plex settings updated. Conn: {message}', 'success'); HistoryLog.create(event_type="SETTINGS_PLEX_UPDATED")
                        from app.plex_utils import _plex_instance # type: ignore 
                        if _plex_instance is not None: _plex_instance = None 
                        form_processed_successfully = True
                    except Exception as e: flash(f'Error saving Plex: {str(e)[:200]}', 'danger'); current_app.logger.error(f"Error saving Plex settings: {e}", exc_info=True)
                else: flash(f'Plex connection failed: {message}', 'danger')

        elif 'submit_discord_settings' in request.form:
            if discord_form.validate(): 
                try:
                    old_bot_on = get_app_setting('DISCORD_BOT_ENABLED') == 'true'; new_bot_on = discord_form.discord_bot_enabled.data
                    update_app_setting('DISCORD_BOT_ENABLED', 'true' if new_bot_on else 'false')
                    if new_bot_on: 
                        update_app_setting('DISCORD_BOT_TOKEN', discord_form.discord_bot_token.data.strip() or "")
                        update_app_setting('DISCORD_SERVER_ID', discord_form.discord_server_id.data.strip() or "")
                        update_app_setting('DISCORD_BOT_APP_ID', discord_form.discord_bot_app_id.data.strip() or "")
                        update_app_setting('ADMIN_DISCORD_ID', discord_form.admin_discord_id.data.strip() or "")
                        update_app_setting('DISCORD_COMMAND_CHANNEL_ID', discord_form.discord_command_channel_id.data.strip() or "")
                        update_app_setting('DISCORD_MENTION_ROLE_ID', discord_form.discord_mention_role_id.data.strip() or "")
                        update_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID', discord_form.discord_plex_access_role_id.data.strip() or "")
                        raw_bot_wl = discord_form.discord_bot_user_whitelist.data or ""
                        processed_bot_wl_items = {item.strip() for item in raw_bot_wl.split(',') if item.strip()}
                        update_app_setting('DISCORD_BOT_USER_WHITELIST', ",".join(sorted(list(processed_bot_wl_items))))
                    else: 
                        update_app_setting('DISCORD_BOT_TOKEN', "")
                        update_app_setting('DISCORD_BOT_USER_WHITELIST', "")
                    
                    token_message = getattr(discord_form.discord_bot_token, 'description', "Settings processed.")
                    flash_msg = f'Discord settings updated. {token_message}'
                    if old_bot_on != new_bot_on: flash_msg += " App restart required for Bot Enable/Disable."
                    flash(flash_msg, 'success'); HistoryLog.create(event_type="SETTINGS_DISCORD_UPDATED", details=f"Bot Enabled: {new_bot_on}")
                    if old_bot_on != new_bot_on: 
                        from app.__init__ import initialize_app_services
                        initialize_app_services(current_app._get_current_object())
                    form_processed_successfully = True
                except Exception as e: flash(f'Error saving Discord: {str(e)[:200]}', 'danger'); current_app.logger.error(f"Error saving Discord settings: {e}", exc_info=True)
        
        if form_processed_successfully:
             return redirect(url_for('main.app_settings_page'))
        
        # Re-populate non-submitted forms if one form failed validation
        if request.method == 'POST' and not form_processed_successfully: # Only if a form was actually submitted and failed
            if 'submit_plex_settings' not in request.form:
                 plex_form = PlexSettingsForm(prefix="plex", data={'plex_url': get_app_setting('PLEX_URL'), 'plex_token': get_app_setting('PLEX_TOKEN'),'app_base_url': get_app_setting('APP_BASE_URL', request.url_root.rstrip('/')), 'sync_remove_stale_users': (get_app_setting('SYNC_REMOVE_STALE_USERS', 'false') == 'true')})
            if 'submit_discord_settings' not in request.form:
                 discord_form = DiscordSettingsForm(prefix="discord", data={'discord_bot_enabled': (get_app_setting('DISCORD_BOT_ENABLED') == 'true'), 'discord_bot_token': get_app_setting('DISCORD_BOT_TOKEN'), 'discord_server_id': get_app_setting('DISCORD_SERVER_ID'), 'discord_bot_app_id': get_app_setting('DISCORD_BOT_APP_ID'), 'admin_discord_id': get_app_setting('ADMIN_DISCORD_ID'), 'discord_command_channel_id': get_app_setting('DISCORD_COMMAND_CHANNEL_ID'), 'discord_mention_role_id': get_app_setting('DISCORD_MENTION_ROLE_ID'), 'discord_plex_access_role_id': get_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID'), 'discord_bot_user_whitelist': get_app_setting('DISCORD_BOT_USER_WHITELIST')})

    return render_template('admin/settings.html', title='Application Settings', 
                           plex_form=plex_form, discord_form=discord_form, 
                           whitelist_form=None, # GlobalWhitelistSettingsForm is no longer rendered
                           current_settings=get_all_app_settings())


# --- Public Invite Link ---
@bp.route('/invite/<custom_path>', methods=['GET', 'POST'])
@setup_complete_required
def use_invite_link(custom_path):
    # ... (as before) ...
    invite = InviteLink.query.filter_by(custom_path=custom_path).first()
    if not invite or not invite.is_valid():
        flash('Invite link is invalid, expired, or used.', 'danger')
        return render_template('public/invite_invalid.html', title="Invalid Invite")
    
    form = UserInviteForm() 
    discord_bot_is_active_for_server_checks = (
        get_app_setting('DISCORD_BOT_ENABLED') == 'true' and \
        get_app_setting('DISCORD_SERVER_ID') and \
        get_app_setting('DISCORD_BOT_TOKEN') 
    )

    plex_email_from_form_submission = None 
    discord_id_from_form_submission = None

    if form.validate_on_submit():
        plex_email_from_form_submission = form.plex_email.data.strip().lower()
        discord_id_from_form_submission = form.discord_id.data.strip() if form.discord_id.data else None

        if discord_bot_is_active_for_server_checks:
            if not discord_id_from_form_submission:
                form.discord_id.errors.append("Discord ID is required as Discord integration is active.")
            elif not (discord_id_from_form_submission.isdigit() and 17 <= len(discord_id_from_form_submission) <= 20): 
                 form.discord_id.errors.append("Invalid Discord ID format.")
            
            if form.discord_id.errors: 
                 flash("Please correct the errors below.", "danger")
                 return render_template('public/invite_landing.html', title=f"Join Plex Server", form=form, invite=invite, discord_bot_active=discord_bot_is_active_for_server_checks, discord_server_invite_url=get_app_setting('DISCORD_SERVER_INVITE_URL'))

            is_on_server, discord_msg = is_discord_user_on_server(discord_id_from_form_submission) # type: ignore
            if not is_on_server:
                flash(f'Discord Verification Failed: {discord_msg}. You must be a member of our Discord server. Please join and try again.', 'danger')
                return render_template('public/invite_landing.html', title=f"Join Plex Server", form=form, invite=invite, discord_bot_active=discord_bot_is_active_for_server_checks, discord_server_invite_url=get_app_setting('DISCORD_SERVER_INVITE_URL'))
        
        query_filter_conditions = [User.plex_email == plex_email_from_form_submission]
        if discord_id_from_form_submission: query_filter_conditions.append(User.discord_id == discord_id_from_form_submission)
        existing_user = User.query.filter(User.is_admin == False).filter(db.or_(*query_filter_conditions)).first()
        
        if existing_user:
            flash_msg = "This "
            if existing_user.plex_email == plex_email_from_form_submission: flash_msg += f"Plex email ({plex_email_from_form_submission})"
            if discord_id_from_form_submission and existing_user.discord_id == discord_id_from_form_submission:
                if existing_user.plex_email == plex_email_from_form_submission: flash_msg += " and "
                flash_msg += f"Discord ID ({discord_id_from_form_submission})"
            flash_msg += " is already associated with an account."
            flash(flash_msg, 'warning')
            return render_template('public/invite_landing.html', title=f"Join Plex", form=form, invite=invite, discord_bot_active=discord_bot_is_active_for_server_checks, discord_server_invite_url=get_app_setting('DISCORD_SERVER_INVITE_URL'))

        libs = invite.allowed_libraries.split(',') if invite.allowed_libraries else None
        succ_plex, msg_plex = invite_to_plex(plex_email_from_form_submission, library_titles=libs)
        if succ_plex:
            try:
                new_user = User(plex_email=plex_email_from_form_submission, plex_username=plex_email_from_form_submission, discord_id=discord_id_from_form_submission, invite_link_id=invite.id, joined_at=datetime.utcnow())
                if discord_id_from_form_submission and get_app_setting('DISCORD_BOT_ENABLED') == 'true' and get_app_setting('DISCORD_BOT_TOKEN'):
                    fetched_uname, _ = get_discord_user_details_by_id_sync(discord_id_from_form_submission)
                    if fetched_uname: new_user.discord_username = fetched_uname
                
                db.session.add(new_user); invite.current_uses += 1; db.session.commit()
                HistoryLog.create(event_type="USER_INVITED_PLEX", plex_username=plex_email_from_form_submission, discord_id=discord_id_from_form_submission, details=f"Via {invite.custom_path}. {msg_plex}")
                flash(f'{msg_plex} Check your email to accept.', 'success')
                return render_template('public/invite_success.html', title="Invite Sent")
            except Exception as e:
                db.session.rollback()
                log_email = plex_email_from_form_submission if plex_email_from_form_submission else "Unknown Email"
                flash(f"Error saving user record after Plex invite: {str(e)[:200]}", "danger")
                current_app.logger.error(f"Error saving user after invite for {log_email}: {e}", exc_info=True)
                HistoryLog.create(event_type="ERROR_SAVING_APP_USER", plex_username=log_email, discord_id=discord_id_from_form_submission, details=f"DB save failed: {str(e)[:100]}")
        else:
            flash(f'Failed to send Plex invite: {msg_plex}', 'danger')
            HistoryLog.create(event_type="ERROR_SENDING_PLEX_INVITE", plex_username=plex_email_from_form_submission, discord_id=discord_id_from_form_submission, details=msg_plex)
            
    return render_template('public/invite_landing.html', title=f"Join Plex Server", form=form, invite=invite,
                           discord_bot_active=discord_bot_is_active_for_server_checks,
                           discord_server_invite_url=get_app_setting('DISCORD_SERVER_INVITE_URL'))

@bp.route('/health/status')
def health_status():
    db_ok = False
    try: db.session.execute(db.text('SELECT 1 AS db_check')).first(); db_ok = True
    except Exception as e: current_app.logger.warning(f"Healthcheck DB error: {e}", exc_info=False)
    setup_ok = get_app_setting('SETUP_COMPLETED', 'false') == 'true'
    status_payload = {"status": "ok" if setup_ok and db_ok else "error", "setup_completed": setup_ok, "database_connected": db_ok}
    http_status_code = 200 if status_payload["status"] == "ok" else 503
    return status_payload, http_status_code

# --- API Endpoint for User Autocomplete (for Tagify) ---
@bp.route('/api/users/autocomplete', methods=['GET'])
@admin_required 
def user_autocomplete_api():
    search_term = request.args.get('term', '').strip().lower()
    limit = request.args.get('limit', 10, type=int)
    
    if not search_term or len(search_term) < 1: 
        return jsonify([])

    users_query = User.query.filter(User.is_admin == False).filter(
        User.plex_username.isnot(None), 
        User.plex_username != ""        
    ).filter(
        db.or_(
            User.plex_username.ilike(f"%{search_term}%"),
            User.plex_email.ilike(f"%{search_term}%") 
        )
    ).limit(limit).all()

    suggestions = []
    for user in users_query:
        plex_username_val = user.plex_username 
        plex_email_val = user.plex_email or ""     
        tag_value, display_name = "", ""

        if plex_username_val.strip(): 
            tag_value = user.plex_username 
            if plex_email_val.strip() and plex_username_val.lower() != plex_email_val.lower():
                display_name = f"{user.plex_username} ({user.plex_email})"
            else: display_name = user.plex_username
        elif plex_email_val.strip(): # Fallback for users who might only have an email as their main identifier
            tag_value = user.plex_email 
            display_name = user.plex_email
        else: continue 

        if tag_value: 
            suggestions.append({
                "value": tag_value, 
                "name": display_name,  
                "email_for_search": plex_email_val.lower(), 
                "username_for_search": plex_username_val.lower() 
            })
            
    return jsonify(suggestions)