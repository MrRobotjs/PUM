# File: app/routes/admins.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, make_response
from flask_login import login_required, current_user
from functools import wraps
from app.models import AdminAccount
from app.forms import AdminCreateForm, AdminEditForm
from app.extensions import db
from app.utils.helpers import log_event # We'll need to update helpers for a permission decorator
import json

bp = Blueprint('admins', __name__, url_prefix='/admins')

# For now, we will assume only the first admin (ID=1) can access this page.
# Later, we will replace this with a real permission decorator.
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.id == 1:
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/')
@login_required
@super_admin_required
def list_admins():
    # If the request is from HTMX (i.e., for refreshing the list),
    # render only the list partial.
    if request.headers.get('HX-Request'):
        admins = AdminAccount.query.order_by(AdminAccount.id).all()
        return render_template('admins/_admins_list_content.html', admins=admins)

    # For a full page load, render the main template with the form for the modal.
    form = AdminCreateForm()
    return render_template('admins/list.html', title="Manage Admins", form=form)

@bp.route('/create', methods=['POST'])
@login_required
@super_admin_required
def create_admin():
    form = AdminCreateForm()
    if form.validate_on_submit():
        new_admin = AdminAccount(
            username=form.username.data,
            force_password_change=True,
            permissions=['manage_users']
        )
        new_admin.set_password(form.password.data)
        db.session.add(new_admin)
        db.session.commit()
        
        # On success, prepare a toast and a trigger to refresh the list
        toast = {"showToastEvent": {"message": f"Admin '{new_admin.username}' created.", "category": "success"}}
        response = make_response("", 204) # 204 No Content is perfect for successful HTMX action
        response.headers['HX-Trigger'] = json.dumps({"refreshAdminList": True, **toast})
        return response
    
    # If validation fails, re-render the form partial with errors
    return render_template('admins/_create_admin_modal_form_content.html', form=form), 422

@bp.route('/edit/<int:admin_id>', methods=['GET', 'POST'])
@login_required
@super_admin_required
def edit_admin(admin_id):
    admin = AdminAccount.query.get_or_404(admin_id)
    if admin.id == 1: # Prevent editing the super-admin's permissions
        flash("The primary admin's permissions cannot be edited.", "warning")
        return redirect(url_for('admins.list_admins'))

    form = AdminEditForm(obj=admin)
    # Populate checkbox based on current permissions
    if request.method == 'GET':
        form.permission_manage_users.data = admin.has_permission('manage_users')

    if form.validate_on_submit():
        new_permissions = []
        if form.permission_manage_users.data:
            new_permissions.append('manage_users')
        
        admin.permissions = new_permissions
        db.session.commit()
        flash(f"Permissions for '{admin.username}' updated.", "success")
        return redirect(url_for('admins.list_admins'))

    return render_template('admins/edit.html', title=f"Edit Admin {admin.username}", admin=admin, form=form)


@bp.route('/delete/<int:admin_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_admin(admin_id):
    if admin_id == 1:
        flash("The primary admin account cannot be deleted.", "danger")
        return redirect(url_for('admins.list_admins'))
    
    admin_to_delete = AdminAccount.query.get_or_404(admin_id)
    db.session.delete(admin_to_delete)
    db.session.commit()
    flash(f"Admin '{admin_to_delete.username}' has been deleted.", "success")
    return redirect(url_for('admins.list_admins'))