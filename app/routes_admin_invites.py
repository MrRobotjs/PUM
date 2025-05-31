# app/routes_admin_invites.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from app import db
from app.models import InviteLink, HistoryLog, User, get_app_setting # Added User
from app.forms import InviteCreateForm, CSRFOnlyForm
from app.plex_utils import get_plex_libraries
from datetime import datetime, timedelta, timezone
from app.decorators import admin_required

invites_bp = Blueprint('admin_invites', __name__, url_prefix='/invites')

@invites_bp.route('/', methods=['GET', 'POST'])
@admin_required
def manage_invites_list():
    form = InviteCreateForm()
    csrf_form = CSRFOnlyForm()

    try:
        plex_libs = get_plex_libraries()
        form.allowed_libraries.choices = [(lib['title'], lib['title']) for lib in plex_libs] if plex_libs else []
    except Exception as e:
        flash(f"Could not fetch Plex libraries: {str(e)[:100]}. Check Plex settings.", "warning")
        current_app.logger.warning(f"Err fetching Plex libs for invite form: {e}")
        form.allowed_libraries.choices = []

    if request.method == 'POST' and form.validate_on_submit(): # Ensure this only runs for the creation form POST
        if InviteLink.query.filter_by(custom_path=form.custom_path.data.strip()).first():
            flash('That custom path already exists. Please choose a different one.', 'danger')
        else:
            try:
                expires_at = None
                if form.expires_days.data is not None and form.expires_days.data > 0:
                    expires_at = datetime.now(timezone.utc) + timedelta(days=form.expires_days.data) # Use timezone.utc

                max_uses_val = None
                if form.max_uses.data is not None and form.max_uses.data > 0:
                    max_uses_val = form.max_uses.data
                elif form.max_uses.data == 0: # If 0 is entered, it's treated as None (unlimited)
                    max_uses_val = None

                new_invite = InviteLink(
                    custom_path=form.custom_path.data.strip(),
                    expires_at=expires_at,
                    max_uses=max_uses_val,
                    allowed_libraries=",".join(form.allowed_libraries.data) if form.allowed_libraries.data else None
                )
                db.session.add(new_invite)
                db.session.commit()
                flash('New invite link created successfully!', 'success')
                HistoryLog.create(event_type="INVITE_CREATED", details=f"Path: {new_invite.custom_path}")
                # Redirect to clear form and apply any current filters
                redirect_args = {k: v for k, v in request.args.items()}
                return redirect(url_for('admin_invites.manage_invites_list', **redirect_args))
            except Exception as e:
                db.session.rollback()
                flash(f"An error occurred while creating the invite: {str(e)[:200]}", "danger")
                current_app.logger.error(f"Error creating invite: {e}", exc_info=True)
    
    # Filter logic
    status_filter = request.args.get('status_filter', 'active') # Default to 'active'
    query = InviteLink.query

    now_utc = datetime.now(timezone.utc)
    if status_filter == 'active':
        query = query.filter(
            db.or_(InviteLink.expires_at.is_(None), InviteLink.expires_at > now_utc),
            db.or_(InviteLink.max_uses.is_(None), InviteLink.current_uses < InviteLink.max_uses)
        )
    elif status_filter == 'expired': # Or 'invalid' or 'used_expired'
        query = query.filter(
            db.or_(
                (InviteLink.expires_at.isnot(None) & (InviteLink.expires_at <= now_utc)),
                (InviteLink.max_uses.isnot(None) & (InviteLink.max_uses > 0) & (InviteLink.current_uses >= InviteLink.max_uses))
            )
        )
    # If status_filter == 'all' or anything else, no additional status filter is applied initially by query.

    invites = query.order_by(InviteLink.created_at.desc()).options(db.selectinload(InviteLink.users_invited)).all()
    
    app_base_url = get_app_setting('APP_BASE_URL', request.url_root.rstrip('/'))
    default_avatar_path = url_for('static', filename='images/default_avatar.png')

    return render_template('admin/invites.html', title='Manage Invite Links',
                           form=form, invites=invites, csrf_form=csrf_form,
                           app_base_url=app_base_url,
                           default_avatar_path=default_avatar_path,
                           current_status_filter=status_filter) # Pass current filter to template


@invites_bp.route('/delete/<int:invite_id>', methods=['POST'])
@admin_required
def delete_invite_link(invite_id):
    csrf_form = CSRFOnlyForm()
    if csrf_form.validate_on_submit():
        invite = InviteLink.query.get_or_404(invite_id)
        try:
            # Before deleting, you might want to nullify User.invite_link_id for associated users
            # This depends on your db.ForeignKey ondelete behavior. If it's SET NULL, this is automatic.
            # If not, you might need:
            # for user in invite.users_invited:
            #     user.invite_link_id = None
            # db.session.flush() # or commit here if you want this separate
            
            HistoryLog.create(event_type="INVITE_DELETED", details=f"Path: {invite.custom_path}, ID: {invite.id}")
            db.session.delete(invite)
            db.session.commit()
            flash(f'Invite link "{invite.custom_path}" deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while deleting the invite: {str(e)[:200]}", "danger")
            current_app.logger.error(f"Error deleting invite {invite_id}: {e}", exc_info=True)
    else:
        flash("CSRF validation failed. Action aborted.", "danger")
    return redirect(url_for('admin_invites.manage_invites_list'))