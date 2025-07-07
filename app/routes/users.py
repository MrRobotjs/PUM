# File: app/routes/users.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session, make_response 
from flask_login import login_required, current_user
from sqlalchemy import or_
from app.utils.helpers import log_event 
from app.models import User, Setting, EventType, AdminAccount # AdminAccount might not be needed directly here
from app.forms import UserEditForm, MassUserEditForm
from app.extensions import db
from app.utils.helpers import log_event, setup_required, permission_required
from app.services import plex_service, user_service 
import json
from datetime import datetime, timezone, timedelta # Ensure these are imported

bp = Blueprint('users', __name__)

@bp.route('/')
@login_required
@setup_required
def list_users():
    page = request.args.get('page', 1, type=int)
    view_mode = request.args.get('view', Setting.get('DEFAULT_USER_VIEW', 'cards')) 
    
    session_per_page_key = 'users_list_per_page' 
    default_per_page_config = current_app.config.get('DEFAULT_USERS_PER_PAGE', 12)
    # Attempt to get per_page from request, then session, then config default
    try:
        items_per_page = int(request.args.get('per_page'))
        if items_per_page not in [12, 24, 48, 96]: # Validate against allowed values
            raise ValueError("Invalid per_page value from request.args")
        session[session_per_page_key] = items_per_page
    except (TypeError, ValueError): # Handles if per_page is not in args, or not an int, or not in allowed list
        items_per_page = session.get(session_per_page_key, default_per_page_config)
        if items_per_page not in [12, 24, 48, 96]: # Final validation for session/default value
            items_per_page = default_per_page_config
            session[session_per_page_key] = items_per_page # Correct session if invalid

    query = User.query
    search_term = request.args.get('search', '').strip()
    if search_term: query = query.filter(or_(User.plex_username.ilike(f"%{search_term}%"), User.plex_email.ilike(f"%{search_term}%")))
    
    filter_type = request.args.get('filter_type', '')
    if filter_type == 'home_user': query = query.filter(User.is_home_user == True)
    elif filter_type == 'shares_back': query = query.filter(User.shares_back == True)
    elif filter_type == 'has_discord': query = query.filter(User.discord_user_id != None)
    elif filter_type == 'no_discord': query = query.filter(User.discord_user_id == None)
    
    sort_by = request.args.get('sort_by', 'username_asc')
    if sort_by == 'username_desc': query = query.order_by(User.plex_username.desc())
    elif sort_by == 'last_streamed_desc': query = query.order_by(User.last_streamed_at.desc().nullslast())
    elif sort_by == 'last_streamed_asc': query = query.order_by(User.last_streamed_at.asc().nullsfirst())
    elif sort_by == 'created_at_desc': query = query.order_by(User.created_at.desc())
    elif sort_by == 'created_at_asc': query = query.order_by(User.created_at.asc())
    else: query = query.order_by(User.plex_username.asc()) # Default 'username_asc'

    admin_accounts = AdminAccount.query.filter(AdminAccount.plex_uuid.isnot(None)).all()
    admins_by_uuid = {admin.plex_uuid: admin for admin in admin_accounts}
    users_pagination = query.paginate(page=page, per_page=items_per_page, error_out=False)
    users_count = query.count() 

    available_libraries = plex_service.get_plex_libraries_dict()
    mass_edit_form = MassUserEditForm()
    mass_edit_form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]
    if mass_edit_form.libraries.data is None: 
        mass_edit_form.libraries.data = []   

    # Define default/current purge settings
    # These could be fetched from Setting model if you want them configurable globally
    # For example:
    # default_inactive_days = int(Setting.get('PURGE_DEFAULT_INACTIVE_DAYS', 90))
    # default_exclude_sharers = Setting.get('PURGE_DEFAULT_EXCLUDE_SHARERS', True) # Expects bool
    default_inactive_days = 90
    default_exclude_sharers = True # Python boolean

    admin_plex_uuids = {admin.plex_uuid for admin in AdminAccount.query.filter(AdminAccount.plex_uuid.isnot(None)).all()}

    purge_settings_context = {
        'inactive_days': request.form.get('inactive_days', default_inactive_days, type=int),
        'exclude_sharers': request.form.get('exclude_sharers', 'true' if default_exclude_sharers else 'false').lower() == 'true'
    }
    # Note: For a GET request, request.form will be empty. So these will use defaults.
    # If you want these to persist across GET requests (e.g., from session or DB settings),
    # you'd fetch them here like you do for 'per_page'.
    # For now, they will reset to defaults on each GET load of the users list page.
    # If purge form submission fails and re-renders via this route, request.form might have old values.

    if request.headers.get('HX-Request'):
        # This partial is for list updates like after sync or mass edit.
        # It usually re-renders the core list content, not necessarily the filter forms.
        # Ensure _users_list_content.html can handle the context it's given.
        return render_template('users/_users_list_content.html', 
                               users=users_pagination,
                               available_libraries=available_libraries,
                               # mass_edit_form might not be needed by this partial if modal is separate
                               current_view=view_mode,
                               current_per_page=items_per_page, 
                               users_count=users_count,
                               admin_plex_uuids=admin_plex_uuids,
                               admins_by_uuid=admins_by_uuid) # Pass users_count for the partial

    return render_template('users/list.html',
                           title="Managed Users",
                           users=users_pagination, 
                           users_count=users_count, 
                           current_view=view_mode,
                           available_libraries=available_libraries,
                           mass_edit_form=mass_edit_form,
                           selected_users_count=0, 
                           current_per_page=items_per_page,
                           purge_settings=purge_settings_context,
                           admin_plex_uuids=admin_plex_uuids,
                           admins_by_uuid=admins_by_uuid) # Pass purge settings

@bp.route('/sync', methods=['POST'])
@login_required
@setup_required
def sync_plex_users():
    current_app.logger.info(f"User_Routes.py - sync_plex_users(): Sync process started by admin ID {current_user.id}")
    log_event(EventType.PLEX_SYNC_USERS_START, "Plex user synchronization started by admin.", admin_id=current_user.id)
    
    sync_results = {} # Initialize to an empty dict
    try:
        sync_results = user_service.sync_users_from_plex()
    except Exception as e:
        current_app.logger.error(f"User_Routes.py - sync_plex_users(): Critical error calling user_service.sync_users_from_plex: {e}", exc_info=True)
        # Populate sync_results with error information for consistent handling
        sync_results = {
            'added': [], 
            'updated': [], 
            'removed': [], 
            'errors': 1, # Indicate at least one error
            'error_messages': [f"A critical error occurred during the sync process: {str(e)}"]
        }

    added_list = sync_results.get('added', [])
    updated_list = sync_results.get('updated', [])
    removed_list = sync_results.get('removed', [])
    error_count = sync_results.get('errors', 0)
    error_messages = sync_results.get('error_messages', []) # Ensure this is fetched

    has_changes_or_errors = bool(added_list or updated_list or removed_list or error_count > 0)
    
    response_headers = {}
    
    if has_changes_or_errors:
        current_app.logger.info(f"Sync results: Added: {len(added_list)}, Updated: {len(updated_list)}, Removed: {len(removed_list)}, Errors: {error_count}")
        if error_messages:
            current_app.logger.warning(f"Sync error messages: {error_messages}")

        modal_html = render_template('users/_sync_results_modal_content.html', 
                                     added_users=added_list,
                                     updated_users=updated_list,
                                     removed_users=removed_list,
                                     error_count=error_count,
                                     error_messages=error_messages)
        
        response_headers['HX-Retarget'] = '#syncResultModalContainer'
        response_headers['HX-Reswap'] = 'innerHTML' # Swaps the content of the modal's container
        
        toast_message_for_modal = "Sync complete. Changes detected, see details."
        toast_category_for_modal = "success" # Default to success
        
        if error_count > 0 and not (added_list or updated_list or removed_list):
            # Only errors, no other changes
            toast_message_for_modal = f"Sync encountered {error_count} error(s). See details."
            toast_category_for_modal = "error"
        elif error_count > 0:
            # Changes AND errors
            toast_message_for_modal = f"Sync complete with {error_count} error(s) and other changes. See details."
            toast_category_for_modal = "warning"
        
        trigger_payload = {
            "showToastEvent": {"message": toast_message_for_modal, "category": toast_category_for_modal},
            "openSyncResultsModal": True, # Custom event for JS to open the modal
            "refreshUserList": True       # Custom event for JS/HTMX to refresh the main user list
        }
        response_headers['HX-Trigger-After-Swap'] = json.dumps(trigger_payload)
        
        # The main content of the response will be the modal's HTML
        return make_response(modal_html, 200, response_headers)
    else: 
        # No changes and no errors
        toast_message = "Sync complete. No changes were made."
        toast_category = "success" # Changed from "info" to "success" for a successful no-op
        trigger_payload = {
            "showToastEvent": {"message": toast_message, "category": toast_category},
            "refreshUserList": True 
        }
        # Use HX-Trigger because we are not swapping any primary content from this branch
        response_headers['HX-Trigger'] = json.dumps(trigger_payload) 
        
        current_app.logger.info(f"Sync results: No changes and no errors. Sending toast trigger.")
        # Return an empty 200 OK response, as HTMX will act on the HX-Trigger header.
        return make_response("", 200, response_headers)

@bp.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@setup_required
@permission_required('edit_user')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user if request.method == 'GET' else None)
    
    available_libraries = plex_service.get_plex_libraries_dict()
    form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]
    
    # --- FIX: Ensure both datetime objects for comparison are timezone-aware ---
    now_utc_for_template = datetime.now(timezone.utc)
    aware_expiry_for_template = None
    if user.access_expires_at:
        # Assume the naive time from the database is UTC and make it timezone-aware
        aware_expiry_for_template = user.access_expires_at.replace(tzinfo=timezone.utc)
    # --- END FIX ---

    admin_account = None
    if user.plex_uuid:
        admin_account = AdminAccount.query.filter_by(plex_uuid=user.plex_uuid).first()

    if request.method == 'GET':
        form.libraries.data = list(user.allowed_library_ids or [])
        form.is_discord_bot_whitelisted.data = user.is_discord_bot_whitelisted
        form.is_purge_whitelisted.data = user.is_purge_whitelisted
        form.notes.data = user.notes
        
        if user.access_expires_at:
            # For pre-populating the form, use the newly created aware objects
            if aware_expiry_for_template:
                remaining_time = aware_expiry_for_template - now_utc_for_template

                if remaining_time.total_seconds() > 0:
                    duration_left = abs(remaining_time)
                    days_remaining = duration_left.days
                    if duration_left.seconds > 0 or duration_left.microseconds > 0:
                        days_remaining += 1
                    form.access_expires_in_days.data = days_remaining
                else:
                    form.access_expires_in_days.data = 0
    
    if form.validate_on_submit():
        original_library_ids = set(user.allowed_library_ids or [])
        new_library_ids_from_form = set(form.libraries.data or [])
        libraries_changed = (new_library_ids_from_form != original_library_ids)

        update_data_for_service = {
            'notes': form.notes.data,
            'is_discord_bot_whitelisted': form.is_discord_bot_whitelisted.data,
            'is_purge_whitelisted': form.is_purge_whitelisted.data,
            'admin_id': current_user.id,
            'new_library_ids': list(new_library_ids_from_form) if libraries_changed else None
        }

        access_expiration_changed = False
        if form.clear_access_expiration.data:
            if user.access_expires_at is not None:
                user.access_expires_at = None
                access_expiration_changed = True
        elif form.access_expires_in_days.data is not None and form.access_expires_in_days.data > 0:
            new_expiry_date = datetime.now(timezone.utc) + timedelta(days=form.access_expires_in_days.data)
            
            # The current user.access_expires_at is naive, make it aware for comparison
            current_expiry_aware = None
            if user.access_expires_at:
                current_expiry_aware = user.access_expires_at.replace(tzinfo=timezone.utc)
            
            # Compare just the date part to avoid small time differences
            if current_expiry_aware is None or current_expiry_aware.date() != new_expiry_date.date():
                user.access_expires_at = new_expiry_date
                access_expiration_changed = True
        
        try:
            user_service.update_user_details(user_id=user.id, **update_data_for_service)
            if access_expiration_changed:
                db.session.commit()
                log_event(EventType.SETTING_CHANGE,
                          f"User '{user.plex_username}' access expiration set to: {user.access_expires_at.strftime('%Y-%m-%d') if user.access_expires_at else 'Permanent'}.",
                          user_id=user.id, admin_id=current_user.id)

            flash(f"User '{user.plex_username}' updated successfully.", "success")
            preserved_args = {k:v for k,v in request.args.items() if k not in ['user_id']}
            return redirect(url_for('users.list_users', **preserved_args))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating user {user.plex_username}: {e}", exc_info=True)
            flash(f"Error updating user: {e}", "danger")

    return render_template('users/edit.html', 
                           title=f"Edit User {user.plex_username}", 
                           form=form, 
                           user=user,
                           current_access_expires_at_for_display=aware_expiry_for_template, 
                           now_utc=now_utc_for_template,
                           admin_account=admin_account)


@bp.route('/delete/<int:user_id>', methods=['DELETE'])
@login_required
@setup_required
@permission_required('delete_user')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    username = user.plex_username
    try:
        user_service.delete_user_from_pum_and_plex(user_id, admin_id=current_user.id)
        
        # Create a toast message payload
        toast = {
            "showToastEvent": {
                "message": f"User '{username}' has been successfully removed.",
                "category": "success"
            }
        }
        
        # Create an empty response and add the HX-Trigger header
        response = make_response("", 200)
        response.headers['HX-Trigger'] = json.dumps(toast)
        return response

    except Exception as e:
        current_app.logger.error(f"Route Error deleting user {username}: {e}", exc_info=True)
        log_event(EventType.ERROR_GENERAL, f"Route: Failed to delete user {username}: {e}", user_id=user_id, admin_id=current_user.id)
        
        # Create an error toast message payload
        toast = {
            "showToastEvent": {
                "message": f"Error deleting user '{username}': {str(e)[:100]}",
                "category": "error"
            }
        }
        
        # Respond with an error status and the trigger header
        # Note: HTMX will NOT swap the target on a 500 error unless told to.
        # But it WILL process the trigger header, showing the toast.
        response = make_response("", 500)
        response.headers['HX-Trigger'] = json.dumps(toast)
        return response

@bp.route('/mass_edit', methods=['POST'])
@login_required
@setup_required
@permission_required('mass_edit_users')
def mass_edit_users():
    current_app.logger.debug("--- MASS EDIT ROUTE START ---")
    
    # DEBUG 1: Print the raw form data received by Flask
    print(f"[SERVER DEBUG 1] Raw request.form: {request.form.to_dict()}")

    # We get user_ids manually from the request now
    user_ids_str = request.form.get('user_ids')
    toast_message = ""
    toast_category = "error"

    # Instantiate form for the other fields that DO need validation
    form = MassUserEditForm(request.form)
    
    # We still must populate the dynamic choices for the libraries field
    available_libraries = plex_service.get_plex_libraries_dict()
    form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]

    # Manual validation for user_ids, then form validation for the rest
    if not user_ids_str:
        toast_message = "Validation Error: User Ids: This field is required."
        print("[SERVER DEBUG 2] user_ids_str is missing or empty.")
    elif form.validate():
        print(f"[SERVER DEBUG 3] Form validation PASSED. User IDs from request: '{user_ids_str}'")
        user_ids = [int(uid) for uid in user_ids_str.split(',') if uid.isdigit()]
        action = form.action.data
        try:
            if action == 'update_libraries':
                new_library_ids = form.libraries.data or []
                processed_count, error_count = user_service.mass_update_user_libraries(user_ids, new_library_ids, admin_id=current_user.id)
                toast_message = f"Mass library update: {processed_count} processed, {error_count} errors."
                toast_category = "success" if error_count == 0 else "warning"
            elif action == 'delete_users':
                if not form.confirm_delete.data:
                    toast_message = "Deletion was not confirmed. No action taken."
                    toast_category = "warning"
                else:
                    processed_count, error_count = user_service.mass_delete_users(user_ids, admin_id=current_user.id)
                    toast_message = f"Mass delete: {processed_count} removed, {error_count} errors."
                    toast_category = "success" if error_count == 0 else "warning"
            elif action.endswith('_whitelist'):
                should_add = action.startswith('add_to')
                whitelist_type = "Bot" if "bot" in action else "Purge"
                if whitelist_type == "Bot":
                    count = user_service.mass_update_bot_whitelist(user_ids, should_add, current_user.id)
                else: # Purge
                    count = user_service.mass_update_purge_whitelist(user_ids, should_add, current_user.id)
                action_text = "added to" if should_add else "removed from"
                toast_message = f"{count} user(s) {action_text} the {whitelist_type} Whitelist."
                toast_category = "success"
            else:
                toast_message = "Invalid action."
        except Exception as e:
            toast_message = f"Server Error: {str(e)[:100]}"
            print(f"[SERVER DEBUG 5] Exception during action '{action}': {e}")
            import traceback
            traceback.print_exc()
    else:
        # Form validation failed for other fields (e.g., action)
        error_list = []
        for field, errors in form.errors.items():
            field_label = getattr(form, field).label.text
            for error in errors:
                error_list.append(f"{field_label}: {error}")
                print(f"[SERVER DEBUG 4] Validation Error for '{field_label}': {error}")
        toast_message = "Validation Error: " + "; ".join(error_list)

    # Re-rendering logic (unchanged)
    page = request.args.get('page', 1, type=int)
    view_mode = request.args.get('view', Setting.get('DEFAULT_USER_VIEW', 'cards'))
    items_per_page = session.get('users_list_per_page', int(current_app.config.get('DEFAULT_USERS_PER_PAGE', 12)))
    
    query = User.query
    search_term = request.args.get('search', '').strip()
    if search_term: query = query.filter(or_(User.plex_username.ilike(f"%{search_term}%"), User.plex_email.ilike(f"%{search_term}%")))
    
    filter_type = request.args.get('filter_type', '')
    if filter_type == 'home_user': query = query.filter(User.is_home_user == True)
    elif filter_type == 'shares_back': query = query.filter(User.shares_back == True)
    elif filter_type == 'has_discord': query = query.filter(User.discord_user_id != None)
    elif filter_type == 'no_discord': query = query.filter(User.discord_user_id == None)
    
    sort_by = request.args.get('sort_by', 'username_asc')
    if sort_by == 'username_desc': query = query.order_by(User.plex_username.desc())
    elif sort_by == 'last_streamed_desc': query = query.order_by(User.last_streamed_at.desc().nullslast())
    elif sort_by == 'last_streamed_asc': query = query.order_by(User.last_streamed_at.asc().nullsfirst())
    elif sort_by == 'created_at_desc': query = query.order_by(User.created_at.desc())
    elif sort_by == 'created_at_asc': query = query.order_by(User.created_at.asc())
    else: query = query.order_by(User.plex_username.asc())
    
    users_pagination = query.paginate(page=page, per_page=items_per_page, error_out=False)
    users_count = query.count()
    
    response_html = render_template('users/_users_list_content.html',
                                    users=users_pagination,
                                    users_count=users_count,
                                    available_libraries=available_libraries,
                                    current_view=view_mode,
                                    current_per_page=items_per_page)
    
    response = make_response(response_html)
    toast_payload = {"showToastEvent": {"message": toast_message, "category": toast_category}}
    response.headers['HX-Trigger-After-Swap'] = json.dumps(toast_payload)
    
    return response

@bp.route('/purge_inactive', methods=['POST'])
@login_required
@setup_required
@permission_required('purge_users')
def purge_inactive_users():
    try:
        inactive_days = request.form.get('inactive_days', type=int)
        exclude_sharers = request.form.get('exclude_sharers') == 'true'
        exclude_whitelisted = request.form.get('exclude_purge_whitelisted') == 'true' # Get new field

        if inactive_days is None or inactive_days < 7:
            return render_template('partials/_alert_message.html', message="Inactivity period must be at least 7 days.", category='error'), 400
        
        results = user_service.purge_inactive_users(
            inactive_days_threshold=inactive_days,
            exclude_sharers=exclude_sharers,
            exclude_whitelisted=exclude_whitelisted, # Pass to service
            admin_id=current_user.id
        )
        return render_template('partials/_alert_message.html', 
                               message=results['message'], 
                               category='success' if results['errors'] == 0 else 'warning')
    except ValueError as ve: # For bad inactive_days from form
        return render_template('partials/_alert_message.html', message=str(ve), category='error'), 400
    except Exception as e:
        current_app.logger.error(f"Error during purge inactive users route: {e}", exc_info=True)
        return render_template('partials/_alert_message.html', message=f"An unexpected error occurred: {e}", category='error'), 500
    
@bp.route('/purge_inactive/preview', methods=['POST'])
@login_required
@setup_required
def preview_purge_inactive_users():
    inactive_days_str = request.form.get('inactive_days')
    
    # For checkboxes, if they are not in request.form, it means they were unchecked.
    # The value is 'true' only if they are checked and sent.
    exclude_sharers_val = request.form.get('exclude_sharers') # Will be 'true' or None
    exclude_whitelisted_val = request.form.get('exclude_purge_whitelisted') # Will be 'true' or None

    current_app.logger.info(f"User_Routes.py - preview_purge_inactive_users(): Received form data: inactive_days='{inactive_days_str}', exclude_sharers='{exclude_sharers_val}', exclude_whitelisted='{exclude_whitelisted_val}'")
    
    try:
        inactive_days = int(inactive_days_str) if inactive_days_str and inactive_days_str.isdigit() else 90 # Default if empty or non-digit
        
        # If checkbox is checked, request.form.get() will be 'true' (matching the value="true" in HTML)
        # If unchecked, request.form.get() will be None.
        exclude_sharers = (exclude_sharers_val == 'true')
        exclude_whitelisted = (exclude_whitelisted_val == 'true')

        current_app.logger.info(f"User_Routes.py - preview_purge_inactive_users(): Parsed criteria: inactive_days={inactive_days}, exclude_sharers={exclude_sharers}, exclude_whitelisted={exclude_whitelisted}")

        if inactive_days < 7:
            return render_template('partials/_alert_message.html', message="Inactivity period must be at least 7 days.", category='error'), 400
        
        eligible_users = user_service.get_users_eligible_for_purge(
            inactive_days_threshold=inactive_days,
            exclude_sharers=exclude_sharers,
            exclude_whitelisted=exclude_whitelisted
        )
        
        current_app.logger.info(f"User_Routes.py - preview_purge_inactive_users(): Found {len(eligible_users)} users eligible for purge based on criteria.")

        purge_criteria = {
            'inactive_days': inactive_days,
            'exclude_sharers': exclude_sharers,
            'exclude_whitelisted': exclude_whitelisted
        }

        return render_template('users/_purge_preview_modal_content.html', 
                               eligible_users=eligible_users, 
                               purge_criteria=purge_criteria)
    except ValueError as ve: # For int conversion error if any
        current_app.logger.error(f"User_Routes.py - preview_purge_inactive_users(): ValueError parsing form: {ve}")
        return render_template('partials/_alert_message.html', message=f"Invalid input: {ve}", category='error'), 400
    except Exception as e:
        current_app.logger.error(f"User_Routes.py - preview_purge_inactive_users(): Error generating purge preview: {e}", exc_info=True)
        return render_template('partials/_alert_message.html', message=f"An unexpected error occurred generating purge preview: {e}", category='error'), 500