# File: app/routes/user.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, make_response
from flask_login import login_required, current_user
from datetime import datetime, timezone, timedelta
from app.models import User, AdminAccount, StreamHistory, EventType
from app.forms import UserEditForm
from app.extensions import db
from app.utils.helpers import permission_required, log_event
from app.services import plex_service, user_service
import json

# Note the new blueprint name and singular URL prefix
bp = Blueprint('user', __name__, url_prefix='/user')

@bp.route('/<int:user_id>', methods=['GET', 'POST'])
@login_required
@permission_required('view_user')
def view_user(user_id):
    # Get the active tab from the URL query. Default to 'profile' for GET, 'settings' for POST context.
    tab = request.args.get('tab', 'settings' if request.method == 'POST' else 'profile')
    
    user = User.query.get_or_404(user_id)
    
    # Correctly instantiate the form:
    # On POST, it's populated from request.form.
    # On GET, it's populated from the user object.
    form = UserEditForm(request.form if request.method == 'POST' else None, obj=user)
    
    # Populate dynamic choices for the form, required for both GET and failed POST validation
    available_libraries = plex_service.get_plex_libraries_dict()
    form.libraries.choices = [(lib_id, name) for lib_id, name in available_libraries.items()]

    # Handle form submission for the settings tab
    if form.validate_on_submit(): # This handles (if request.method == 'POST' and form.validate())
        try:
            # Updated expiration logic to handle DateField calendar picker
            access_expiration_changed = False
            
            if form.clear_access_expiration.data:
                if user.access_expires_at is not None:
                    user.access_expires_at = None
                    access_expiration_changed = True
            elif form.access_expires_at.data:
                # WTForms gives a date object. Combine with max time to set expiry to end of day.
                new_expiry_datetime = datetime.combine(form.access_expires_at.data, datetime.max.time())
                # Only update if the date is actually different
                if user.access_expires_at is None or user.access_expires_at.date() != new_expiry_datetime.date():
                    user.access_expires_at = new_expiry_datetime
                    access_expiration_changed = True
            
            original_library_ids = set(user.allowed_library_ids or [])
            new_library_ids_from_form = set(form.libraries.data or [])
            libraries_changed = (original_library_ids != new_library_ids_from_form)

            update_data = {
                'notes': form.notes.data,
                'is_discord_bot_whitelisted': form.is_discord_bot_whitelisted.data,
                'is_purge_whitelisted': form.is_purge_whitelisted.data,
                'admin_id': current_user.id,
                'new_library_ids': list(new_library_ids_from_form) if libraries_changed else None,
                'allow_downloads': form.allow_downloads.data,
                'allow_4k_transcode': form.allow_4k_transcode.data
            }
            
            user_service.update_user_details(user_id=user.id, **update_data)
            
            if access_expiration_changed:
                if user.access_expires_at is None:
                    log_event(EventType.SETTING_CHANGE, f"User '{user.plex_username}' access expiration cleared.", user_id=user.id, admin_id=current_user.id)
                else:
                    log_event(EventType.SETTING_CHANGE, f"User '{user.plex_username}' access expiration set to {user.access_expires_at.strftime('%Y-%m-%d')}.", user_id=user.id, admin_id=current_user.id)
            
            # This commit saves all changes from user_service and the expiration date
            db.session.commit()
            
            if request.headers.get('HX-Request'):
                # Re-fetch user data to ensure the form is populated with the freshest data after save
                user_after_save = User.query.get(user_id)
                form_after_save = UserEditForm(obj=user_after_save)
                
                # Re-populate the dynamic choices and data for the re-rendered form
                form_after_save.libraries.choices = list(available_libraries.items())
                form_after_save.libraries.data = list(user_after_save.allowed_library_ids or [])

                # Create the toast message payload
                toast_payload = {
                    "showToastEvent": {
                        "message": f"User '{user_after_save.plex_username}' updated successfully.",
                        "category": "success"
                    }
                }
                
                # Render the form partial again to get the updated HTML for the swap
                updated_form_html = render_template('users/_settings_tab.html', form=form_after_save, user=user_after_save)
                
                # Create the response and add the HX-Trigger header
                response = make_response(updated_form_html)
                response.headers['HX-Trigger'] = json.dumps(toast_payload)
                return response
            else:
                # Fallback for standard form submissions remains the same
                flash(f"User '{user.plex_username}' updated successfully.", "success")
                return redirect(url_for('user.view_user', user_id=user.id, tab='settings'))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating user {user.plex_username}: {e}", exc_info=True)
            flash(f"Error updating user: {e}", "danger")

    if request.method == 'POST' and form.errors:
        if request.headers.get('HX-Request'):
            return render_template('users/_settings_tab.html', form=form, user=user), 422

    if request.method == 'GET':
        form.libraries.data = list(user.allowed_library_ids or [])
        # Remove the old access_expires_in_days logic since we're now using DateField
        # The form will automatically populate access_expires_at from the user object via obj=user

    stream_history_pagination = None
    stream_stats = None
    active_session_keys = []
    
    if tab == 'history':
        page = request.args.get('page', 1, type=int)
        stream_history_pagination = StreamHistory.query.filter_by(user_id=user.id).order_by(StreamHistory.started_at.desc()).paginate(page=page, per_page=15, error_out=False)
        
        # Get current active session keys for this user's history
        try:
            active_sessions = plex_service.get_active_sessions()
            active_session_keys = [str(session.sessionKey) for session in active_sessions if hasattr(session, 'sessionKey')]
            current_app.logger.debug(f"Active session keys for history display: {active_session_keys}")
        except Exception as e:
            current_app.logger.warning(f"Could not fetch active sessions for history display: {e}")
            active_session_keys = []
            
    elif tab == 'profile':
        stream_stats = user_service.get_user_stream_stats(user_id)

    if request.headers.get('HX-Request') and tab == 'history':
        return render_template('users/_history_tab_content.html', 
                             user=user, 
                             history_logs=stream_history_pagination,
                             active_session_keys=active_session_keys)
        
    return render_template(
        'users/profile.html',
        title=f"User Profile: {user.plex_username}",
        user=user,
        form=form,
        history_logs=stream_history_pagination,
        active_session_keys=active_session_keys,
        active_tab=tab,
        is_admin=AdminAccount.query.filter_by(plex_uuid=user.plex_uuid).first() is not None if user.plex_uuid else False,
        stream_stats=stream_stats,
        now_utc=datetime.now(timezone.utc)
    )

@bp.route('/<int:user_id>/delete_history', methods=['POST'])
@login_required
@permission_required('edit_user') # Or a more specific permission if you add one
def delete_stream_history(user_id):
    history_ids_to_delete = request.form.getlist('history_ids[]')
    if not history_ids_to_delete:
        # This can happen if the form is submitted with no boxes checked
        return make_response("<!-- no-op -->", 200)

    try:
        # Convert IDs to integers for safe querying
        ids_as_int = [int(id_str) for id_str in history_ids_to_delete]
        
        # Perform the bulk delete
        num_deleted = db.session.query(StreamHistory).filter(
            StreamHistory.user_id == user_id, # Security check: only delete for the specified user
            StreamHistory.id.in_(ids_as_int)
        ).delete(synchronize_session=False)
        
        db.session.commit()
        
        current_app.logger.info(f"Admin {current_user.id} deleted {num_deleted} history entries for user {user_id}.")
        
        # This payload will show a success toast.
        toast_payload = {
            "showToastEvent": {
                "message": f"Successfully deleted {num_deleted} history entries.",
                "category": "success"
            }
        }
        
        # This will trigger both the toast and a custom event to refresh the table.
        # Note: We now use htmx.trigger() in the template itself for a cleaner flow.
        response = make_response("", 200)
        response.headers['HX-Trigger'] = json.dumps(toast_payload)
        
        return response

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting stream history for user {user_id}: {e}", exc_info=True)
        # Send an error toast on failure
        toast_payload = {
            "showToastEvent": {
                "message": "Error deleting history records.",
                "category": "error"
            }
        }
        response = make_response("", 500)
        response.headers['HX-Trigger'] = json.dumps(toast_payload)
        return response