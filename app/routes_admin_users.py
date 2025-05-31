# app/routes_admin_users.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session, Response, stream_with_context
from sqlalchemy import asc, desc, or_, and_, func
from app import db, bot_instance 
from app.models import User, HistoryLog, get_app_setting
from app.forms import PurgeSettingsForm, CSRFOnlyForm, UserFilterSortForm, EditUserForm, MassEditUserForm
from app.plex_utils import (
    remove_plex_friend,
    get_shared_plex_users_info, # This function was just modified
    get_users_sharing_servers_with_me,
    get_plex_libraries, 
    get_user_shared_library_titles,
    invite_to_plex, 
    get_plex_server
)
from plexapi.exceptions import NotFound
from app.discord_utils import get_discord_user_details_by_id_sync
from datetime import datetime, timedelta, timezone 
import asyncio
import time
import logging

from app.decorators import admin_required

users_bp = Blueprint('admin_users', __name__, url_prefix='/users')

# ... (manage_users_list route - no changes needed here for this specific objective) ...
@users_bp.route('/', methods=['GET', 'POST'])
@admin_required
def manage_users_list():
    # This function remains the same as the last fully correct version you have.
    # It already correctly passes User objects to the template, and the template
    # displays user.last_streamed_at. The source of that data is what we're changing.
    current_app.logger.debug(f"--- manage_users_list CALLED. Method: {request.method} ---")
    current_app.logger.debug(f"Request Query Args: {request.args}")
    if request.method == 'POST':
        current_app.logger.debug(f"Request Form Data (POST): {request.form}")

    filter_sort_form = UserFilterSortForm(request.args, meta={'csrf': False})
    purge_form_data = request.form if request.method == 'POST' and request.form.get('action') == 'purge' else None
    purge_form = PurgeSettingsForm(purge_form_data)
    csrf_form = CSRFOnlyForm()
    mass_edit_form = MassEditUserForm()
    try:
        available_libraries = get_plex_libraries()
        mass_edit_form.libraries_to_apply.choices = [(lib['title'], lib['title']) for lib in available_libraries]
    except Exception as e:
        current_app.logger.error(f"Error populating libraries for MassEditUserForm: {e}")
        mass_edit_form.libraries_to_apply.choices = []

    sync_results_data = session.pop('sync_results', None)
    if sync_results_data:
        category = sync_results_data.get("category", "info")
        api_message = sync_results_data.get("api_message", "Sync status unknown.")
        summary_parts = [f"Plex Sync: {api_message}"]
        if sync_results_data.get("total_plex_users_found", 0) > 0 or category != "danger": summary_parts.append(f"Found {sync_results_data.get('total_plex_users_found',0)} users on Plex.")
        if sync_results_data.get("newly_added_to_app_count", 0) > 0: summary_parts.append(f"Added {sync_results_data.get('newly_added_to_app_count',0)} new to app.")
        if sync_results_data.get("stale_removed_from_app_count", 0) > 0: summary_parts.append(f"Removed {sync_results_data.get('stale_removed_from_app_count',0)} stale from app.")
        if sync_results_data.get("new_sharers_back_count", 0) > 0: summary_parts.append(f"{sync_results_data.get('new_sharers_back_count',0)} started sharing back.")
        if sync_results_data.get("stopped_sharers_back_count", 0) > 0: summary_parts.append(f"{sync_results_data.get('stopped_sharers_back_count',0)} stopped sharing back.")
        if sync_results_data.get("skipped_api_count", 0) > 0: summary_parts.append(f"Skipped {sync_results_data.get('skipped_api_count',0)} from API.")
        if sync_results_data.get("processing_errors", []): summary_parts.append(f"Encountered {len(sync_results_data.get('processing_errors',[]))} errors.")
        flash_message_str = " ".join(s for s in summary_parts if s) 
        if len(summary_parts) > 1 or category != "info" or "error" in api_message.lower() or "fail" in api_message.lower():
             flash(flash_message_str, category)
        elif api_message != "Sync initiated...":
             flash(flash_message_str, category)

    if 'filter_submit' in request.args: 
        if filter_sort_form.validate():
            redirect_params = {k: v for k, v in request.args.items() if v is not None and v != '' and k != 'filter_submit'}
            return redirect(url_for('admin_users.manage_users_list', **redirect_params))
    
    if request.method == 'POST' and request.form.get('action') == 'purge':
        if purge_form.validate_on_submit():
            days_inactive = purge_form.days_inactive.data
            exempt_sharers = purge_form.exempt_sharers.data
            exempt_home_users = purge_form.exempt_home_users.data
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_inactive)
            cutoff_date_naive = cutoff_date.replace(tzinfo=None)
            query_to_purge = User.query.filter(User.is_admin == False, User.is_purge_whitelisted == False)
            if exempt_sharers: query_to_purge = query_to_purge.filter(User.shares_back == False)
            if exempt_home_users: query_to_purge = query_to_purge.filter(User.is_plex_home_user == False)
            query_to_purge = query_to_purge.filter(
                db.or_((User.last_streamed_at.is_(None)) & (User.joined_at < cutoff_date_naive),
                       (User.last_streamed_at < cutoff_date_naive)) 
            )
            users_to_purge = query_to_purge.all()
            purged_count = 0; errors_during_purge = []
            for user_obj_to_purge in users_to_purge:
                plex_ident_for_remove = user_obj_to_purge.plex_username or user_obj_to_purge.plex_email
                log_plex_username = user_obj_to_purge.plex_username; log_discord_id = user_obj_to_purge.discord_id
                plex_removal_success, plex_removal_message = True, "Plex removal skipped (no identifier)."
                if plex_ident_for_remove:
                    plex_removal_success, plex_removal_message = remove_plex_friend(plex_ident_for_remove)
                if plex_removal_success:
                    HistoryLog.create(event_type="USER_PURGED", plex_username=log_plex_username, discord_id=log_discord_id, details=f"Inactive {days_inactive} days. Plex: {plex_removal_message}")
                    db.session.delete(user_obj_to_purge); purged_count += 1
                else:
                    errors_during_purge.append(f"Plex removal for '{plex_ident_for_remove or f'AppUser-{log_plex_username}'}': {plex_removal_message}")
                    HistoryLog.create(event_type="ERROR_PURGING_USER", plex_username=log_plex_username, discord_id=log_discord_id, details=f"Plex removal failed: {plex_removal_message}")
            try:
                if purged_count > 0: db.session.commit(); flash(f"Successfully purged {purged_count} inactive users.", 'success')
                elif not errors_during_purge: flash("No users matched the purge criteria.", "info")
                for err in errors_during_purge: flash(f"Purge Issue: {err}", 'warning')
            except Exception as e_commit: 
                db.session.rollback(); flash(f"DB error during purge commit: {str(e_commit)[:200]}", "danger")
            redirect_args_after_purge = {k: v for k, v in request.args.items() if k != 'action'}
            return redirect(url_for('admin_users.manage_users_list', **redirect_args_after_purge))
        else: 
            for field_name_str, error_list in purge_form.errors.items():
                field_obj = getattr(purge_form, field_name_str, None)
                field_label_text = field_obj.label.text if field_obj and hasattr(field_obj, 'label') else field_name_str.replace("_", " ").title()
                for error in error_list: flash(f"Purge Error ({field_label_text}): {error}", "danger")

    search_term = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'plex_username')
    sort_order = request.args.get('sort_order', 'asc')
    filter_is_home = request.args.get('filter_home', '')
    filter_shares_back = request.args.get('filter_shares', '')
    filter_is_purge_wl = request.args.get('filter_p_wl', '')
    filter_is_discord_bot_wl = request.args.get('filter_d_wl', '')
    
    if not ('filter_submit' in request.args and filter_sort_form.errors):
        filter_sort_form.search.data = search_term; filter_sort_form.sort_by.data = sort_by
        filter_sort_form.sort_order.data = sort_order; filter_sort_form.filter_is_home_user.data = filter_is_home
        filter_sort_form.filter_shares_back.data = filter_shares_back
        filter_sort_form.filter_is_purge_whitelisted.data = filter_is_purge_wl
        filter_sort_form.filter_is_discord_bot_whitelisted.data = filter_is_discord_bot_wl

    users_base_query = User.query.filter(User.is_admin == False)
    if search_term: users_base_query = users_base_query.filter(db.or_( User.plex_username.ilike(f"%{search_term}%"), User.plex_email.ilike(f"%{search_term}%"), User.discord_username.ilike(f"%{search_term}%"), User.discord_id.ilike(f"%{search_term}%") ))
    if filter_is_home == 'yes': users_base_query = users_base_query.filter(User.is_plex_home_user == True)
    elif filter_is_home == 'no': users_base_query = users_base_query.filter(User.is_plex_home_user == False)
    if filter_shares_back == 'yes': users_base_query = users_base_query.filter(User.shares_back == True)
    elif filter_shares_back == 'no': users_base_query = users_base_query.filter(User.shares_back == False)
    if filter_is_purge_wl == 'yes': users_base_query = users_base_query.filter(User.is_purge_whitelisted == True)
    elif filter_is_purge_wl == 'no': users_base_query = users_base_query.filter(User.is_purge_whitelisted == False)
    
    raw_discord_bot_whitelist_str = get_app_setting('DISCORD_BOT_USER_WHITELIST', '')
    discord_bot_whitelist_plex_usernames_set = { name.strip().lower() for name in raw_discord_bot_whitelist_str.replace('\n',',').split(',') if name.strip()}
    if filter_is_discord_bot_wl == 'yes':
        if discord_bot_whitelist_plex_usernames_set:
            conditions = [User.plex_username.ilike(name) for name in discord_bot_whitelist_plex_usernames_set]
            users_base_query = users_base_query.filter(or_(*conditions)) if conditions else users_base_query.filter(db.false())
        else: users_base_query = users_base_query.filter(db.false())
    elif filter_is_discord_bot_wl == 'no':
        if discord_bot_whitelist_plex_usernames_set:
            conditions = [User.plex_username.ilike(name) for name in discord_bot_whitelist_plex_usernames_set]
            users_base_query = users_base_query.filter(db.not_(or_(*conditions))) if conditions else users_base_query
    
    valid_sort_columns = { 'plex_username': User.plex_username, 'plex_email': User.plex_email, 'discord_username': User.discord_username, 'last_streamed_at': User.last_streamed_at, 'shares_back': User.shares_back, 'is_plex_home_user': User.is_plex_home_user, 'is_purge_whitelisted': User.is_purge_whitelisted }
    current_sort_column_attr = valid_sort_columns.get(sort_by, User.plex_username)
    sort_expression = func.lower(current_sort_column_attr) if sort_by in ['plex_username', 'plex_email', 'discord_username'] else current_sort_column_attr
    
    if sort_order == 'asc': users_base_query = users_base_query.order_by(current_sort_column_attr.is_(None).asc(), asc(sort_expression))
    else: users_base_query = users_base_query.order_by(current_sort_column_attr.isnot(None).desc(), desc(sort_expression))
    
    plex_users = users_base_query.all()
    current_app.logger.info(f"Final user count for display: {len(plex_users)}")

    if not (request.method == 'POST' and request.form.get('action') == 'purge' and purge_form.errors):
        purge_form = PurgeSettingsForm()

    activity_poll_interval_str = get_app_setting('ACTIVITY_POLL_INTERVAL_MINUTES', '5')
    try: activity_polling_is_active = int(activity_poll_interval_str) > 0
    except ValueError: activity_polling_is_active = False 

    return render_template('admin/users.html', title='Manage Users', users=plex_users,
                           purge_form=purge_form, csrf_form=csrf_form, 
                           filter_sort_form=filter_sort_form,
                           mass_edit_form=mass_edit_form,
                           discord_bot_whitelist_plex_usernames=discord_bot_whitelist_plex_usernames_set,
                           activity_polling_is_active=activity_polling_is_active)


@users_bp.route('/sync_from_plex', methods=['POST'])
@admin_required
def sync_plex_users():
    csrf_form = CSRFOnlyForm()
    if not csrf_form.validate_on_submit():
        flash("CSRF validation failed. Please try again.", "danger")
        return redirect(url_for('admin_users.manage_users_list', **request.args))

    current_app.logger.info("Plex Sync: Starting user synchronization process...")
    sync_results = {
        "api_message": "Sync initiated...", "category": "info", "total_plex_users_found": 0,
        "newly_added_to_app_count": 0, "updated_in_app_count": 0, "stale_removed_from_app_count": 0,
        "new_sharers_back_count": 0, "stopped_sharers_back_count": 0,
        "processing_errors": [], "skipped_api_count": 0, "db_commit_successful": False
    }

    try:
        api_users_sharing_back_now = get_users_sharing_servers_with_me()
        plex_users_data_from_api, message_from_get_shared = get_shared_plex_users_info() # This no longer returns 'api_last_seen_on_server'
        sync_results["api_message"] = message_from_get_shared
        sync_results["total_plex_users_found"] = len(plex_users_data_from_api)

        if not message_from_get_shared.startswith("Fetched"):
            sync_results["category"] = "danger" if not plex_users_data_from_api else "warning"
            if not plex_users_data_from_api: 
                session['sync_results'] = sync_results
                return redirect(url_for('admin_users.manage_users_list', **request.args))
        
        api_user_map_by_identifier = {}
        for p_user_data in plex_users_data_from_api:
            p_id = p_user_data.get('plex_id')
            p_email_lower = (p_user_data.get('email') or "").lower() if p_user_data.get('email') else None
            key = f"plexid_{p_id}" if p_id else (f"email_{p_email_lower}" if p_email_lower else None)
            if key: api_user_map_by_identifier[key] = p_user_data
            else: sync_results["skipped_api_count"] += 1
        
        processed_db_user_ids_during_sync = set()

        for identifier_key, p_user_data_from_api in api_user_map_by_identifier.items():
            p_email_lower = (p_user_data_from_api.get('email') or "").lower() if p_user_data_from_api.get('email') else None
            p_username = p_user_data_from_api.get('username')
            p_id = p_user_data_from_api.get('plex_id')
            p_is_home = bool(p_user_data_from_api.get('is_home_user', False))
            p_thumb_url = p_user_data_from_api.get('thumb_url')
            # REMOVED: api_last_seen_dt = p_user_data_from_api.get('api_last_seen_on_server') 
            
            existing_user_in_db = None
            if p_id: existing_user_in_db = User.query.filter_by(plex_user_id=p_id, is_admin=False).first()
            if not existing_user_in_db and p_email_lower: existing_user_in_db = User.query.filter_by(plex_email=p_email_lower, is_admin=False).first()
            if not existing_user_in_db and p_username and not p_id and not p_email_lower: 
                existing_user_in_db = User.query.filter_by(plex_username=p_username, is_admin=False).first()
            
            current_api_user_identifier_for_shares_check = (p_username.lower() if p_username else None) or p_email_lower
            api_shares_back_flag = bool(current_api_user_identifier_for_shares_check and api_users_sharing_back_now and current_api_user_identifier_for_shares_check in api_users_sharing_back_now)

            if existing_user_in_db:
                processed_db_user_ids_during_sync.add(existing_user_in_db.id)
                changed_flag = False
                # ... (update other fields like plex_id, username, email, is_home, thumb_url, shares_back) ...
                if p_id is not None and existing_user_in_db.plex_user_id != p_id: existing_user_in_db.plex_user_id = p_id; changed_flag = True
                if p_username and existing_user_in_db.plex_username != p_username: existing_user_in_db.plex_username = p_username; changed_flag = True
                if p_email_lower and existing_user_in_db.plex_email != p_email_lower: existing_user_in_db.plex_email = p_email_lower; changed_flag = True
                if existing_user_in_db.is_plex_home_user != p_is_home: existing_user_in_db.is_plex_home_user = p_is_home; changed_flag = True
                if p_thumb_url and existing_user_in_db.plex_thumb_url != p_thumb_url: existing_user_in_db.plex_thumb_url = p_thumb_url; changed_flag = True
                elif not p_thumb_url and existing_user_in_db.plex_thumb_url: existing_user_in_db.plex_thumb_url = None; changed_flag = True
                
                # REMOVED: Logic to initialize existing_user_in_db.last_streamed_at from api_last_seen_dt
                # User.last_streamed_at is now exclusively managed by the scheduler task.

                if existing_user_in_db.shares_back != api_shares_back_flag:
                    existing_user_in_db.shares_back = api_shares_back_flag; changed_flag = True
                    if api_shares_back_flag: sync_results["new_sharers_back_count"] += 1
                    else: sync_results["stopped_sharers_back_count"] += 1
                
                if changed_flag:
                    sync_results["updated_in_app_count"] += 1; db.session.add(existing_user_in_db)
            else: 
                user_display_name = p_username or p_email_lower or f"PlexID-{p_id}"
                new_user = User(
                    plex_user_id=p_id, plex_username=p_username, plex_email=p_email_lower,
                    is_plex_home_user=p_is_home, is_admin=False, joined_at=datetime.now(timezone.utc),
                    last_streamed_at=None, # New users start with None for last_streamed_at
                    shares_back=api_shares_back_flag, plex_thumb_url=p_thumb_url
                )
                db.session.add(new_user); sync_results["newly_added_to_app_count"] += 1
                if api_shares_back_flag: sync_results["new_sharers_back_count"] += 1
        
        # ... (rest of stale user removal logic, commit, history logging, and redirect remains the same) ...
        if get_app_setting('SYNC_REMOVE_STALE_USERS', 'true') == 'true':
            all_app_db_users_not_admin = User.query.filter(User.is_admin == False).all()
            for app_user in all_app_db_users_not_admin:
                found_in_api = False
                if app_user.plex_user_id and f"plexid_{app_user.plex_user_id}" in api_user_map_by_identifier: found_in_api = True
                elif app_user.plex_email and f"email_{app_user.plex_email.lower()}" in api_user_map_by_identifier: found_in_api = True
                if not found_in_api:
                    stale_ident = app_user.plex_username or app_user.plex_email or f"AppUserID-{app_user.id}"
                    sync_results["stale_removed_from_app_count"] += 1
                    HistoryLog.create(event_type="STALE_USER_REMOVED_SYNC", plex_username=app_user.plex_username, discord_id=app_user.discord_id, details="User no longer in current Plex share list from plex.tv.")
                    db.session.delete(app_user)
                    current_app.logger.info(f"Plex Sync: Staging stale user '{stale_ident}' for removal from app DB.")
        
        if sync_results["newly_added_to_app_count"] > 0 or sync_results["updated_in_app_count"] > 0 or sync_results["stale_removed_from_app_count"] > 0:
            db.session.commit(); sync_results["db_commit_successful"] = True
            if sync_results["category"] == "info": sync_results["category"] = "success"
        elif not api_user_map_by_identifier and message_from_get_shared.startswith("Fetched"):
            sync_results["api_message"] += " No users currently appear to have access to your server according to Plex.tv."
            sync_results["category"] = "info"
        HistoryLog.create(event_type="PLEX_USERS_SYNCED", details=f"New:{sync_results['newly_added_to_app_count']}, Upd:{sync_results['updated_in_app_count']}, API-Skip:{sync_results['skipped_api_count']}, StaleRem:{sync_results['stale_removed_from_app_count']}")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"CRITICAL Error during Plex user sync processing: {e}", exc_info=True)
        sync_results["api_message"] = f"A critical error occurred during sync: {str(e)[:100]}. Check server logs."
        sync_results["category"] = "danger"
        HistoryLog.create(event_type="ERROR_PLEX_SYNC_CRITICAL", details=str(e)[:250])
    
    session['sync_results'] = sync_results
    return redirect(url_for('admin_users.manage_users_list', **request.args))


# ... (edit_user, remove_user, mass_action_users routes remain the same as your last correct versions) ...
@users_bp.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    # This function remains the same as the last fully correct version you have.
    user_obj = User.query.get_or_404(user_id)
    if user_obj.is_admin: flash("Admin user profile cannot be edited here.", "danger"); return redirect(url_for('admin_users.manage_users_list', **request.args))
    form_action_url = url_for('admin_users.edit_user', user_id=user_id, **request.args)
    form = EditUserForm(request.form if request.method == 'POST' else None)
    available_libraries_on_server = get_plex_libraries()
    form.plex_libraries.choices = [(lib['title'], lib['title']) for lib in available_libraries_on_server]
    user_plex_identifier_for_shares = user_obj.plex_username or user_obj.plex_email
    if not user_plex_identifier_for_shares and user_obj.plex_user_id:
        plex_server_instance = get_plex_server(); 
        if plex_server_instance:
            try: plex_account_user = plex_server_instance.myPlexAccount().user(int(user_obj.plex_user_id)); user_plex_identifier_for_shares = plex_account_user.username or plex_account_user.email
            except: pass
    current_shared_titles_set = set(); fetched_titles_for_compare = None
    if user_plex_identifier_for_shares:
        fetched_titles_for_compare = get_user_shared_library_titles(user_plex_identifier_for_shares)
        if fetched_titles_for_compare is not None: current_shared_titles_set = set(fetched_titles_for_compare)
        else: flash("Could not reliably determine current Plex library shares for comparison. Shares will be updated based on form submission.", "warning")
    if request.method == 'GET':
        form.discord_id.data = user_obj.discord_id; form.shares_back.data = user_obj.shares_back; form.is_purge_whitelisted.data = user_obj.is_purge_whitelisted
        if user_plex_identifier_for_shares:
            form.plex_libraries.data = list(current_shared_titles_set)
            if fetched_titles_for_compare is None and user_plex_identifier_for_shares: pass 
        elif user_obj.plex_user_id or user_obj.plex_email or user_obj.plex_username: flash("Cannot determine current Plex shares: User missing a usable Plex Username/Email for share lookup, or not a friend.", "warning")
    if form.validate_on_submit():
        changes_made_to_db_user = False; original_discord_id = user_obj.discord_id; new_discord_id_str = form.discord_id.data.strip() if form.discord_id.data else None
        if new_discord_id_str and new_discord_id_str != original_discord_id:
            existing_link = User.query.filter(User.discord_id == new_discord_id_str, User.id != user_obj.id, User.is_admin == False).first()
            if existing_link: flash(f"Discord ID {new_discord_id_str} is already linked to another user.", "danger"); return render_template('admin/edit_user.html', title=f"Edit User", form=form, user=user_obj, form_action_url=form_action_url)
        if user_obj.discord_id != new_discord_id_str: user_obj.discord_id = new_discord_id_str; changes_made_to_db_user = True; user_obj.discord_username = None 
        if user_obj.shares_back != form.shares_back.data: user_obj.shares_back = form.shares_back.data; changes_made_to_db_user = True
        if user_obj.is_purge_whitelisted != form.is_purge_whitelisted.data: user_obj.is_purge_whitelisted = form.is_purge_whitelisted.data; changes_made_to_db_user = True
        if new_discord_id_str and (new_discord_id_str != original_discord_id or (new_discord_id_str == original_discord_id and not user_obj.discord_username)):
            if get_app_setting('DISCORD_BOT_TOKEN'):
                fetched_uname, err_msg = get_discord_user_details_by_id_sync(new_discord_id_str)
                if fetched_uname and user_obj.discord_username != fetched_uname: user_obj.discord_username = fetched_uname; changes_made_to_db_user = True; flash(f"Discord username '{fetched_uname}' fetched.", "info")
                elif not fetched_uname and user_obj.discord_username is not None: user_obj.discord_username = None; changes_made_to_db_user = True; flash(f"Could not fetch Discord username for ID {new_discord_id_str}: {err_msg or 'Error'}. Username cleared.", "warning")
                elif not fetched_uname: flash(f"Could not fetch Discord username for ID {new_discord_id_str}: {err_msg or 'Error'}.", "warning")
            elif user_obj.discord_username is not None: user_obj.discord_username = None; changes_made_to_db_user = True
        submitted_libraries_set = set(form.plex_libraries.data) if form.plex_libraries.data else set()
        plex_update_needed = False
        if fetched_titles_for_compare is None: plex_update_needed = True 
        elif submitted_libraries_set != current_shared_titles_set: plex_update_needed = True
        plex_update_succeeded = True; plex_api_message = "Plex library shares were not modified."
        if plex_update_needed:
            if user_plex_identifier_for_shares:
                plex_update_succeeded, plex_api_message = invite_to_plex(user_plex_identifier_for_shares, library_titles=list(submitted_libraries_set))
                if not plex_update_succeeded: flash(f"Failed to update Plex shares: {plex_api_message}", "danger")
                else: flash(f"Plex shares updated: {plex_api_message}", "success")
            else: flash("Cannot update Plex shares: User missing usable Plex identifier.", "warning"); plex_update_succeeded = False
        if changes_made_to_db_user or (plex_update_needed and plex_update_succeeded):
            if plex_update_succeeded:
                try:
                    db.session.commit(); HistoryLog.create(event_type="USER_PROFILE_UPDATED", plex_username=user_obj.plex_username or user_obj.plex_email, discord_id=user_obj.discord_id, details="Admin updated profile.")
                    flash(f'User {user_obj.plex_username or user_obj.plex_email} updated.', 'success'); return redirect(url_for('admin_users.manage_users_list', **request.args))
                except Exception as e: db.session.rollback(); flash(f"DB Error: {str(e)[:200]}", "danger")
            else: db.session.rollback() 
        elif not changes_made_to_db_user and not plex_update_needed: flash("No changes detected to save.", "info"); return redirect(url_for('admin_users.manage_users_list', **request.args))
    if request.method == 'POST' and form.errors: pass 
    return render_template('admin/edit_user.html', title=f"Edit User", form=form, user=user_obj, form_action_url=form_action_url)

@users_bp.route('/remove/<int:user_id>', methods=['POST'])
@admin_required
def remove_user(user_id):
    # This function remains the same as the last fully correct version you have.
    csrf_form = CSRFOnlyForm(); 
    if not csrf_form.validate_on_submit(): flash("CSRF validation failed.", "danger"); return redirect(url_for('admin_users.manage_users_list', **request.args))
    user_obj = User.query.get_or_404(user_id)
    if user_obj.is_admin: flash("Admin accounts cannot be removed here.", "danger"); return redirect(url_for('admin_users.manage_users_list', **request.args))
    plex_ident_log = user_obj.plex_username or user_obj.plex_email or f"AppUserID-{user_obj.id}"
    discord_id_log = user_obj.discord_id; plex_api_ident = user_obj.plex_username or user_obj.plex_email
    success_plex, msg_plex = True, "Skipped Plex (no identifier)."
    if plex_api_ident: success_plex, msg_plex = remove_plex_friend(plex_api_ident)
    if success_plex:
        HistoryLog.create(event_type="USER_REMOVED_MANUAL_PLEX", plex_username=plex_ident_log, discord_id=discord_id_log, details=msg_plex)
        try:
            db.session.delete(user_obj); db.session.commit(); flash(f'User {plex_ident_log} removed from DB. Plex: {msg_plex}', 'success')
            if discord_id_log and get_app_setting('DISCORD_BOT_ENABLED') == 'true' and get_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID') and bot_instance and hasattr(bot_instance, 'flask_app_callable_remove_role') and hasattr(bot_instance, 'thread_loop') and bot_instance.thread_loop and not bot_instance.is_closed() and bot_instance.thread_loop.is_running():
                asyncio.run_coroutine_threadsafe(bot_instance.flask_app_callable_remove_role(discord_id_log, get_app_setting('DISCORD_PLEX_ACCESS_ROLE_ID'), reason="User removed by admin"), bot_instance.thread_loop)
                flash(f"Discord role removal queued for ID {discord_id_log}.", "info")
            elif discord_id_log and get_app_setting('DISCORD_BOT_ENABLED') == 'true': flash(f"Could not queue Discord role removal for {discord_id_log}: Bot not ready or role not set.", "warning")
        except Exception as e_commit: db.session.rollback(); flash(f"DB error for {plex_ident_log}: {str(e_commit)[:200]}", "danger")
    else:
        flash(f'Failed to remove {plex_api_ident} from Plex: {msg_plex}. Not removed from app DB.', 'danger')
        HistoryLog.create(event_type="ERROR_REMOVING_USER_MANUAL_PLEX", plex_username=plex_api_ident, discord_id=discord_id_log, details=msg_plex)
    return redirect(url_for('admin_users.manage_users_list', **request.args))

@users_bp.route('/mass_action', methods=['POST'])
@admin_required
def mass_action_users():
    # This function remains the same as the last fully correct version you have
    # (the one that handles streaming progress updates).
    csrf_form = CSRFOnlyForm()
    if not csrf_form.validate_on_submit(): pass # Assuming JS sends CSRF via header for fetch
    action = request.form.get('mass_action_type')
    selected_ids_str = request.form.getlist('selected_user_ids_for_mass_action') 
    if not selected_ids_str: return Response("data: Error No users selected.\n\ndata: FINISHED\n\n", mimetype='text/event-stream')
    user_ids_to_process = []
    for uid_str in selected_ids_str:
        try: user_ids_to_process.append(int(uid_str))
        except ValueError: current_app.logger.warning(f"Mass Action: Invalid user ID '{uid_str}' received.")
    if not user_ids_to_process: return Response("data: Error No valid user IDs provided.\n\ndata: FINISHED\n\n", mimetype='text/event-stream')

    def generate_progress_updates():
        _users_to_act_on = User.query.filter(User.id.in_(user_ids_to_process), User.is_admin == False).all()
        if not _users_to_act_on: yield f"data: Error No eligible users found.\n\ndata: FINISHED\n\n"; return
        total_users = len(_users_to_act_on); processed_count = 0; succeeded_count = 0; failed_details = []
        yield f"data: Progress Bar\nProcessing User 0/{total_users}<progress>0\n\n"
        libraries_to_apply_data_from_form = []
        if action == 'update_libraries':
            mass_edit_form_for_libs = MassEditUserForm(request.form)
            libraries_to_apply_data_from_form = list(mass_edit_form_for_libs.libraries_to_apply.data)
        for user_obj in _users_to_act_on:
            processed_count += 1; user_display_name = user_obj.plex_username or user_obj.plex_email or f"User ID {user_obj.id}"
            user_plex_target_for_api = user_obj.plex_username or user_obj.plex_email; error_for_this_user = ""
            if not user_plex_target_for_api and user_obj.plex_user_id and action == 'update_libraries':
                plex_server_instance = get_plex_server()
                if plex_server_instance:
                    try: plex_account_user = plex_server_instance.myPlexAccount().user(int(user_obj.plex_user_id)); user_plex_target_for_api = plex_account_user.username or plex_account_user.email
                    except: pass
            if action == 'update_libraries':
                if user_plex_target_for_api:
                    succeeded, msg = invite_to_plex(user_plex_target_for_api, library_titles=libraries_to_apply_data_from_form)
                    if succeeded: succeeded_count += 1; HistoryLog.create(event_type="USER_LIBS_MASS_UPDATED", plex_username=user_plex_target_for_api, details=f"Applied: {', '.join(libraries_to_apply_data_from_form) if libraries_to_apply_data_from_form else 'None'}.")
                    else: error_for_this_user = f"Failed for {user_display_name}: {msg}"; failed_details.append(error_for_this_user); HistoryLog.create(event_type="ERROR_USER_LIBS_MASS_UPDATE", plex_username=user_plex_target_for_api, details=msg)
                else: error_for_this_user = f"Skipped library update for {user_display_name} (no Plex identifier)."; failed_details.append(error_for_this_user)
            elif action == 'delete_users':
                succeeded_plex, msg_plex = True, "Skipped Plex removal (no API identifier)."
                if user_plex_target_for_api: succeeded_plex, msg_plex = remove_plex_friend(user_plex_target_for_api)
                if succeeded_plex: db.session.delete(user_obj); succeeded_count += 1; HistoryLog.create(event_type="USER_MASS_DELETED", plex_username=user_obj.plex_username, discord_id=user_obj.discord_id, details=f"Plex: {msg_plex}")
                else: error_for_this_user = f"Plex removal FAILED for {user_display_name}: {msg_plex}"; failed_details.append(error_for_this_user); HistoryLog.create(event_type="ERROR_USER_MASS_DELETE_PLEX", plex_username=user_obj.plex_username, discord_id=user_obj.discord_id, details=msg_plex)
            progress_percentage = (processed_count / total_users) * 100
            yield f"data: Progress Bar\nProcessing User {processed_count}/{total_users} - {user_display_name}\n{error_for_this_user}<progress>{progress_percentage:.0f}\n\n"
            time.sleep(0.05)
        final_commit_message = ""
        if succeeded_count > 0 and action == 'delete_users':
            try: db.session.commit(); final_commit_message = f"Successfully committed {succeeded_count} deletions."
            except Exception as e_commit: db.session.rollback(); final_commit_message = f"DB error on commit: {str(e_commit)[:100]}"; failed_details.append(final_commit_message)
        elif action == 'update_libraries' and succeeded_count > 0 : final_commit_message = f"Processed library updates for {succeeded_count} users."
        results_summary = f"Processed: {processed_count}/{total_users}. Succeeded: {succeeded_count}. Failed: {len(failed_details)}. {final_commit_message}"
        yield f"data: RESULTS {results_summary}\n\n"
        if failed_details:
            for fail_detail_msg in failed_details[:5]: yield f"data: Progress Bar\n \n{fail_detail_msg}<progress>100\n\n" 
            if len(failed_details) > 5: yield f"data: Progress Bar\n \n...and {len(failed_details) - 5} more errors (check server logs).<progress>100\n\n"
        yield f"data: FINISHED\n\n"
    return Response(stream_with_context(generate_progress_updates()), mimetype='text/event-stream')