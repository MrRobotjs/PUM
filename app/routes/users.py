# File: app/routes/users.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session, make_response 
from flask_login import login_required, current_user
from sqlalchemy import or_
from app.models import User, Setting, EventType, AdminAccount  # AdminAccount might not be needed directly here
from app.forms import UserEditForm, MassUserEditForm
from app.extensions import db
from app.utils.helpers import log_event, setup_required, permission_required
from app.services import plex_service, user_service 
import json
from datetime import datetime, timezone, timedelta # Ensure these are imported
from sqlalchemy.exc import IntegrityError

bp = Blueprint('users', __name__)

@bp.route('/')
@login_required
@setup_required
def list_users():
    page = request.args.get('page', 1, type=int)
    view_mode = request.args.get('view', Setting.get('DEFAULT_USER_VIEW', 'cards')) 
    
    session_per_page_key = 'users_list_per_page' 
    default_per_page_config = current_app.config.get('DEFAULT_USERS_PER_PAGE', 12)
    try:
        items_per_page = int(request.args.get('per_page'))
        if items_per_page not in [12, 24, 48, 96]:
            raise ValueError("Invalid per_page value from request.args")
        session[session_per_page_key] = items_per_page
    except (TypeError, ValueError):
        items_per_page = session.get(session_per_page_key, default_per_page_config)
        if items_per_page not in [12, 24, 48, 96]:
            items_per_page = default_per_page_config
            session[session_per_page_key] = items_per_page

    query = User.query
    search_term = request.args.get('search', '').strip()
    if search_term:
        query = query.filter(or_(User.plex_username.ilike(f"%{search_term}%"), User.plex_email.ilike(f"%{search_term}%")))
    
    filter_type = request.args.get('filter_type', '')
    if filter_type == 'home_user': query = query.filter(User.is_home_user == True)
    elif filter_type == 'shares_back': query = query.filter(User.shares_back == True)
    elif filter_type == 'has_discord': query = query.filter(User.discord_user_id != None)
    elif filter_type == 'no_discord': query = query.filter(User.discord_user_id == None)
    
    # --- START OF NEW SORTING LOGIC ---
    sort_by_param = request.args.get('sort_by', 'username_asc')
    sort_parts = sort_by_param.rsplit('_', 1)
    sort_column = sort_parts[0]
    sort_direction = 'desc' if len(sort_parts) > 1 and sort_parts[1] == 'desc' else 'asc'

    sort_map = {
        'username': User.plex_username,
        'email': User.plex_email,
        'last_streamed': User.last_streamed_at,
        'created_at': User.created_at # Added for completeness if you want to sort by date added
    }
    
    # Default to sorting by username if the column is invalid
    sort_field = sort_map.get(sort_column, User.plex_username)

    if sort_direction == 'desc':
        # Use .nullslast() to ensure users with no data (e.g., never streamed) appear at the end
        query = query.order_by(sort_field.desc().nullslast())
    else:
        # Use .nullsfirst() to ensure users with no data appear at the beginning
        query = query.order_by(sort_field.asc().nullsfirst())
    # --- END OF NEW SORTING LOGIC ---

    admin_accounts = AdminAccount.query.filter(AdminAccount.plex_uuid.isnot(None)).all()
    admins_by_uuid = {admin.plex_uuid: admin for admin in admin_accounts}
    users_pagination = query.paginate(page=page, per_page=items_per_page, error_out=False)
    users_count = query.count() 

    available_libraries = plex_service.get_plex_libraries_dict()
    mass_edit_form = MassUserEditForm()
    mass_edit_form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]
    if mass_edit_form.libraries.data is None: 
        mass_edit_form.libraries.data = []   

    default_inactive_days = 90
    default_exclude_sharers = True

    purge_settings_context = {
        'inactive_days': request.form.get('inactive_days', default_inactive_days, type=int),
        'exclude_sharers': request.form.get('exclude_sharers', 'true' if default_exclude_sharers else 'false').lower() == 'true'
    }
    
    # We will build a single context dictionary to pass to the templates
    template_context = {
        'title': "Managed Users",
        'users': users_pagination,
        'users_count': users_count,
        'current_view': view_mode,
        'available_libraries': available_libraries,
        'mass_edit_form': mass_edit_form,
        'selected_users_count': 0,
        'current_per_page': items_per_page,
        'purge_settings': purge_settings_context,
        'admin_plex_uuids': {admin.plex_uuid for admin in admin_accounts},
        'admins_by_uuid': admins_by_uuid,
        'sort_column': sort_column,      # Pass sorting info to the template
        'sort_direction': sort_direction # Pass sorting info to the template
    }

    if request.headers.get('HX-Request'):
        return render_template('users/_users_list_content.html', **template_context)

    return render_template('users/list.html', **template_context)

@bp.route('/sync', methods=['POST'])
@login_required
@setup_required
def sync_plex_users():
    current_app.logger.info(f"User_Routes.py - sync_plex_users(): Sync process started by admin ID {current_user.id}")
    log_event(EventType.PLEX_SYNC_USERS_START, "Plex user synchronization started by admin.", admin_id=current_user.id)
    
    sync_results = user_service.sync_users_from_plex()

    added_list = sync_results.get('added', [])
    updated_list = sync_results.get('updated', [])
    removed_list = sync_results.get('removed', [])
    error_count = sync_results.get('errors', 0)
    error_messages = sync_results.get('error_messages', [])

    has_changes_or_errors = bool(added_list or updated_list or removed_list or error_count > 0)
    
    if has_changes_or_errors:
        # Render the HTML for the modal's content using the results.
        modal_html = render_template('users/_sync_results_modal_content.html', 
                                     added_users=added_list,
                                     updated_users=updated_list,
                                     removed_users=removed_list,
                                     error_count=error_count,
                                     error_messages=error_messages)
        
        # Prepare headers to tell HTMX to show the modal AND refresh the user list.
        trigger_payload = {"openSyncResultsModal": True, "refreshUserList": True}
        response_headers = {
            'HX-Retarget': '#syncResultModalContainer',
            'HX-Reswap': 'innerHTML',
            'HX-Trigger-After-Swap': json.dumps(trigger_payload)
        }
        
        # Return the rendered HTML with the special headers.
        return make_response(modal_html, 200, response_headers)
    else:
        # This logic for "no changes" is correct and will show a toast.
        toast_payload = {"showToastEvent": {"message": "Sync complete. No changes were made.", "category": "success"}}
        response = make_response("<!-- no-op -->", 200)
        response.headers['HX-Trigger'] = json.dumps(toast_payload)
        return response

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
    ignore_creation_date_val = request.form.get('ignore_creation_date')

    current_app.logger.info(f"User_Routes.py - preview_purge_inactive_users(): Received form data: inactive_days='{inactive_days_str}', exclude_sharers='{exclude_sharers_val}', exclude_whitelisted='{exclude_whitelisted_val}'")
    
    try:
        inactive_days = int(inactive_days_str) if inactive_days_str and inactive_days_str.isdigit() else 90 # Default if empty or non-digit
        
        # If checkbox is checked, request.form.get() will be 'true' (matching the value="true" in HTML)
        # If unchecked, request.form.get() will be None.
        exclude_sharers = (exclude_sharers_val == 'true')
        exclude_whitelisted = (exclude_whitelisted_val == 'true')
        ignore_creation_date = (ignore_creation_date_val == 'true')

        current_app.logger.info(f"User_Routes.py - preview_purge_inactive_users(): Parsed criteria: inactive_days={inactive_days}, exclude_sharers={exclude_sharers}, exclude_whitelisted={exclude_whitelisted}")

        if inactive_days < 7:
            return render_template('partials/_alert_message.html', message="Inactivity period must be at least 7 days.", category='error'), 400
        
        eligible_users = user_service.get_users_eligible_for_purge(
            inactive_days_threshold=inactive_days,
            exclude_sharers=exclude_sharers,
            exclude_whitelisted=exclude_whitelisted,
            ignore_creation_date_for_never_streamed=ignore_creation_date
        )
        
        current_app.logger.info(f"User_Routes.py - preview_purge_inactive_users(): Found {len(eligible_users)} users eligible for purge based on criteria.")

        purge_criteria = {
            'inactive_days': inactive_days,
            'exclude_sharers': exclude_sharers,
            'exclude_whitelisted': exclude_whitelisted,
            'ignore_creation_date': ignore_creation_date
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
    
@bp.route('/quick_edit_form/<int:user_id>')
@login_required
@permission_required('edit_user')
def get_quick_edit_form(user_id):
    user = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user) # Pre-populate form with existing data

    # Populate dynamic choices
    available_libraries = plex_service.get_plex_libraries_dict()
    form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]
    
    # Pre-populate the fields with the user's current settings
    form.libraries.data = list(user.allowed_library_ids or [])
    form.allow_downloads.data = user.allow_downloads
    form.allow_4k_transcode.data = user.allow_4k_transcode
    form.is_discord_bot_whitelisted.data = user.is_discord_bot_whitelisted
    form.is_purge_whitelisted.data = user.is_purge_whitelisted
    
    if user.access_expires_at:
        now_utc = datetime.now(timezone.utc)
        user_expiry_aware = user.access_expires_at.replace(tzinfo=timezone.utc)
        if user_expiry_aware > now_utc:
            remaining_time = user_expiry_aware - now_utc
            form.access_expires_in_days.data = remaining_time.days + (1 if remaining_time.seconds > 0 else 0)
    
    # We pass the _settings_tab partial, which contains the form we need.
    return render_template(
        'users/_settings_tab.html',
        form=form,
        user=user
    )