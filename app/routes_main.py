# app/routes_main.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, g, current_app, jsonify, session
from flask_login import current_user
from app import db
from app.models import User, InviteLink, HistoryLog, get_app_setting
from app.forms import UserInviteForm
from app.plex_utils import get_plex_server, invite_to_plex, get_plex_libraries
from app.discord_utils import is_discord_user_on_server, get_discord_user_details_by_id_sync
from datetime import datetime

from app.decorators import setup_complete_required, admin_required

main_bp = Blueprint('main', __name__)

@main_bp.route('/entrypoint')
def index_or_setup():
    # ... (remains the same) ...
    if get_app_setting('SETUP_COMPLETED') == 'true':
        if current_user.is_authenticated and current_user.is_admin:
            return redirect(url_for('main.dashboard'))
        else:
            return redirect(url_for('auth.login'))
    else:
        return redirect(url_for('setup.setup_wizard'))

@main_bp.route('/')
@admin_required
def dashboard():
    # ... (remains the same) ...
    total_users, active_invites, plex_is_connected, plex_server_name = 0, 0, False, "N/A"
    recent_logs = []
    try: total_users = User.query.filter_by(is_admin=False).count()
    except Exception as e: current_app.logger.error(f"Dashboard: Err total_users: {e}", exc_info=True)
    try:
        active_invites = InviteLink.query.filter(
            db.or_(InviteLink.expires_at.is_(None), InviteLink.expires_at > datetime.utcnow()),
            db.or_(InviteLink.max_uses.is_(None), InviteLink.current_uses < InviteLink.max_uses)
        ).count()
    except Exception as e: current_app.logger.error(f"Dashboard: Err active_invites: {e}", exc_info=True)
    try: recent_logs = HistoryLog.query.order_by(HistoryLog.timestamp.desc()).limit(5).all()
    except Exception as e: current_app.logger.error(f"Dashboard: Err recent_logs: {e}", exc_info=True)

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

@main_bp.route('/invite/<custom_path>', methods=['GET', 'POST'])
@setup_complete_required
def use_invite_link(custom_path):
    invite = InviteLink.query.filter_by(custom_path=custom_path).first()
    if not invite or not invite.is_valid():
        flash('Invite link is invalid, expired, or used.', 'danger')
        return render_template('public/invite_invalid.html', title="Invalid Invite")

    form = UserInviteForm(request.form if request.method == 'POST' else None)
    
    # Data for template, sourced from session for GET requests
    sso_plex_email_init = None
    sso_plex_username_init = None
    sso_discord_id_init = None
    sso_discord_username_init = None
    discord_sso_server_warning = None
    display_libraries_str = None # For libraries to show on the page

    discord_bot_features_active = (
        get_app_setting('DISCORD_BOT_ENABLED') == 'true' and
        get_app_setting('DISCORD_SERVER_ID') and
        get_app_setting('DISCORD_BOT_TOKEN')
    )

    # Determine libraries to display on the invite landing page (for both GET and re-render on POST error)
    if invite.allowed_libraries:
        display_libraries_str = invite.allowed_libraries.replace(',', ', ')
    else:
        all_server_libs = get_plex_libraries() # Returns list of dicts: [{'title': 'Movies'}, ...]
        if all_server_libs:
            display_libraries_str = ", ".join(sorted([lib['title'] for lib in all_server_libs])) # Sorted for consistency
        else:
            display_libraries_str = "all available libraries (unable to fetch specific list at this time)"
            current_app.logger.warning(f"Invite {custom_path}: Defaulting to 'all libraries' display message because get_plex_libraries() returned empty or error.")


    if request.method == 'GET':
        sso_plex_email_init = session.get('sso_plex_email')
        sso_plex_username_init = session.get('sso_plex_username')
        sso_discord_id_init = session.get('sso_discord_id')
        sso_discord_username_init = session.get('sso_discord_username')

        current_app.logger.info(f"Invite GET for '{custom_path}': Session SSO Data - Plex Email: {sso_plex_email_init}, Plex User: {sso_plex_username_init}, Discord ID: {sso_discord_id_init}, Discord User: {sso_discord_username_init}")

        if request.referrer:
            if 'sso/plex/callback' in request.referrer.lower() and sso_plex_email_init:
                 flash(f"Plex details for '{sso_plex_username_init or sso_plex_email_init}' successfully retrieved!", 'info')
            if 'sso/discord/callback' in request.referrer.lower() and sso_discord_id_init:
                flash(f"Discord details for '{sso_discord_username_init or sso_discord_id_init}' successfully retrieved!", 'info')

        if sso_discord_id_init and discord_bot_features_active:
            is_on_server, check_message = is_discord_user_on_server(sso_discord_id_init)
            if not is_on_server:
                discord_sso_server_warning = f"Warning: We couldn't verify you're on our Discord server ({check_message}). Membership might be required."
                if request.referrer and 'sso/discord/callback' in request.referrer.lower():
                    flash(discord_sso_server_warning, "warning")
            else:
                if request.referrer and 'sso/discord/callback' in request.referrer.lower():
                     flash(f"Discord server membership confirmed for '{sso_discord_username_init or sso_discord_id_init}'.", "info")
        
    # --- POST Request handling ---
    if form.validate_on_submit(): 
        plex_email_from_form = form.plex_email.data.strip().lower() if form.plex_email.data else None
        discord_id_from_form = form.discord_id.data.strip() if form.discord_id.data else None
        current_app.logger.info(f"Invite POST for '{custom_path}': Form submitted with Plex Email: '{plex_email_from_form}', Discord ID: '{discord_id_from_form}'")

        if not plex_email_from_form:
            flash("Plex email is required. Please use 'Login with Plex' or ensure it was provided.", "danger")
            # When re-rendering, pass all necessary _init and display variables again
            return render_template('public/invite_landing.html', title="Join Plex Server", form=form, invite=invite,
                                   display_libraries=display_libraries_str,
                                   sso_plex_email_init=session.get('sso_plex_email'), sso_plex_username_init=session.get('sso_plex_username'),
                                   sso_discord_id_init=session.get('sso_discord_id'), sso_discord_username_init=session.get('sso_discord_username'),
                                   discord_sso_server_warning=discord_sso_server_warning, 
                                   discord_server_invite_url=get_app_setting('DISCORD_SERVER_INVITE_URL'))

        if discord_bot_features_active:
            if not discord_id_from_form:
                form.discord_id.errors.append("Discord ID is required as Discord server integration is active.")
            elif not (discord_id_from_form.isdigit() and 17 <= len(discord_id_from_form) <= 20):
                 form.discord_id.errors.append("Invalid Discord ID format.")
            
            if form.discord_id.errors:
                 flash("Please correct the errors with your Discord ID.", "danger")
                 return render_template('public/invite_landing.html', title="Join Plex Server", form=form, invite=invite,
                                       display_libraries=display_libraries_str,
                                       sso_plex_email_init=session.get('sso_plex_email'), sso_plex_username_init=session.get('sso_plex_username'),
                                       sso_discord_id_init=session.get('sso_discord_id'), sso_discord_username_init=session.get('sso_discord_username'),
                                       discord_sso_server_warning=None,
                                       discord_server_invite_url=get_app_setting('DISCORD_SERVER_INVITE_URL'))

            if discord_id_from_form:
                is_on_server, discord_check_msg = is_discord_user_on_server(discord_id_from_form)
                if not is_on_server:
                    flash(f'Discord Verification Failed: {discord_check_msg}. You must be a member of our Discord server to request a Plex invite.', 'danger')
                    return render_template('public/invite_landing.html', title=f"Join Plex Server", form=form, invite=invite,
                                          display_libraries=display_libraries_str,
                                          sso_plex_email_init=session.get('sso_plex_email'), sso_plex_username_init=session.get('sso_plex_username'),
                                          sso_discord_id_init=session.get('sso_discord_id'), sso_discord_username_init=session.get('sso_discord_username'),
                                          discord_sso_server_warning=f"Server membership check failed: {discord_check_msg}",
                                          discord_server_invite_url=get_app_setting('DISCORD_SERVER_INVITE_URL'))
        
        query_filter_conditions = [User.plex_email == plex_email_from_form]
        if discord_id_from_form: query_filter_conditions.append(User.discord_id == discord_id_from_form)
        existing_user = User.query.filter(User.is_admin == False).filter(db.or_(*query_filter_conditions)).first()

        if existing_user:
            flash("An account with this Plex email or Discord ID already exists in our system.", 'warning')
            return render_template('public/invite_landing.html', title=f"Join Plex", form=form, invite=invite,
                                   display_libraries=display_libraries_str,
                                   sso_plex_email_init=session.get('sso_plex_email'), sso_plex_username_init=session.get('sso_plex_username'),
                                   sso_discord_id_init=session.get('sso_discord_id'), sso_discord_username_init=session.get('sso_discord_username'),
                                   discord_sso_server_warning=discord_sso_server_warning,
                                   discord_server_invite_url=get_app_setting('DISCORD_SERVER_INVITE_URL'))

        # Determine actual libraries to pass to Plex based on invite object
        libraries_to_share_titles = None 
        if invite.allowed_libraries: # If invite link has specific libraries
            libraries_to_share_titles = invite.allowed_libraries.split(',')
        # If invite.allowed_libraries is None/empty, libraries_to_share_titles remains None,
        # telling invite_to_plex to share all server defaults.
        
        succ_plex, msg_plex = invite_to_plex(plex_email_from_form, library_titles=libraries_to_share_titles)

        if succ_plex:
            try:
                final_plex_username = session.get('sso_plex_username')
                final_discord_username = session.get('sso_discord_username')
                new_user = User(
                    plex_email=plex_email_from_form, plex_username=final_plex_username,
                    discord_id=discord_id_from_form, discord_username=final_discord_username,
                    invite_link_id=invite.id, joined_at=datetime.utcnow()
                )
                if discord_id_from_form and not final_discord_username and get_app_setting('DISCORD_BOT_ENABLED') == 'true' and get_app_setting('DISCORD_BOT_TOKEN'):
                    fetched_uname, _ = get_discord_user_details_by_id_sync(discord_id_from_form)
                    if fetched_uname: new_user.discord_username = fetched_uname
                db.session.add(new_user); invite.current_uses += 1; db.session.commit()
                
                session['invite_success_email'] = plex_email_from_form
                session.pop('sso_plex_email', None); session.pop('sso_plex_username', None)
                session.pop('sso_discord_id', None); session.pop('sso_discord_username', None)
                session.pop('plex_sso_auth_token', None); session.pop('plex_sso_pin_id_for_callback', None); session.pop('plex_sso_client_id_for_callback', None); session.pop('plex_sso_origin_invite_path', None)
                session.pop('discord_oauth_state', None); session.pop('sso_discord_invite_path', None)

                HistoryLog.create(event_type="USER_INVITED_PLEX", plex_username=plex_email_from_form, discord_id=discord_id_from_form, details=f"Via {invite.custom_path}. {msg_plex}")
                return redirect(url_for('main.invite_success_page_route'))
            except Exception as e:
                db.session.rollback()
                flash(f"Error saving user record: {str(e)[:100]}", "danger")
                current_app.logger.error(f"Error saving user after invite for {plex_email_from_form}: {e}", exc_info=True)
        else: 
            flash(f'Failed to send Plex invite to Plex: {msg_plex}', 'danger')
            HistoryLog.create(event_type="ERROR_SENDING_PLEX_INVITE", plex_username=plex_email_from_form, discord_id=discord_id_from_form, details=msg_plex)

    # Render for GET or if POST had validation errors before actual invite attempt
    return render_template('public/invite_landing.html', title=f"Join Plex Server", 
                           form=form, 
                           invite=invite,
                           display_libraries=display_libraries_str, # For display on landing page
                           sso_plex_email_init=session.get('sso_plex_email'), 
                           sso_plex_username_init=session.get('sso_plex_username'),
                           sso_discord_id_init=session.get('sso_discord_id'),
                           sso_discord_username_init=session.get('sso_discord_username'),
                           discord_sso_server_warning=discord_sso_server_warning,
                           discord_server_invite_url=get_app_setting('DISCORD_SERVER_INVITE_URL'))


@main_bp.route('/invite/success')
@setup_complete_required # Or remove if success page is very minimal and doesn't need base layout context
def invite_success_page_route():
    invited_email = session.pop('invite_success_email', None) # Get and clear email for one-time display
    # If accessed directly or session lost, invited_email will be None
    # The template handles the 'if invited_plex_email' condition
    return render_template('public/invite_success.html', 
                           title="Invitation Sent!", 
                           invited_plex_email=invited_email)


@main_bp.route('/health/status')
def health_status():
    # ... (remains the same) ...
    db_ok = False
    try:
        db.session.execute(db.text('SELECT 1 AS db_check')).first()
        db_ok = True
    except Exception as e:
        current_app.logger.error(f"Healthcheck DB error: {e}", exc_info=False)
    setup_ok = get_app_setting('SETUP_COMPLETED', 'false') == 'true'
    status_payload = { "status": "ok" if setup_ok and db_ok else "error", "setup_completed": setup_ok, "database_connected": db_ok }
    http_status_code = 200 if status_payload["status"] == "ok" else 503
    return jsonify(status_payload), http_status_code


@main_bp.route('/api/users/autocomplete', methods=['GET'])
@admin_required
def user_autocomplete_api():
    # ... (remains the same) ...
    search_term = request.args.get('term', '').strip().lower()
    limit = request.args.get('limit', 10, type=int)
    if not search_term or len(search_term) < 1: return jsonify([])
    users_query = User.query.filter(User.is_admin == False).filter(User.plex_username.isnot(None), User.plex_username != "").filter(
        db.or_(User.plex_username.ilike(f"%{search_term}%"), User.plex_email.ilike(f"%{search_term}%"))
    ).limit(limit).all()
    suggestions = []
    for user in users_query:
        # ... (logic to build suggestions)
        plex_username_val = user.plex_username 
        plex_email_val = user.plex_email or ""     
        tag_value, display_name = "", ""
        if plex_username_val.strip(): 
            tag_value = user.plex_username 
            if plex_email_val.strip() and plex_username_val.lower() != plex_email_val.lower():
                display_name = f"{user.plex_username} ({user.plex_email})"
            else: display_name = user.plex_username
        elif plex_email_val.strip(): 
            tag_value = user.plex_email 
            display_name = user.plex_email
        else: continue 
        if tag_value: 
            suggestions.append({"value": tag_value, "name": display_name, "email_for_search": plex_email_val.lower(), "username_for_search": plex_username_val.lower() })
    return jsonify(suggestions)