from flask import session, current_app, redirect, url_for, render_template, request, flash
from . import main_bp
import hashlib
import bleach
import json
import re
from ..config import save_config as _save_config, load_config as _load_config


def _admin_enabled() -> bool:
    cfg = current_app.config.get('HOMEHUB_CONFIG', {})
    return bool(cfg.get('admin_password_hash'))


def _is_admin() -> bool:
    return bool(session.get('is_admin'))


@main_bp.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    cfg = current_app.config.get('HOMEHUB_CONFIG', {})
    if not _admin_enabled():
        flash('Admin password is not configured. Add admin_password to config.yml', 'error')
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        supplied = bleach.clean(request.form.get('password', ''))
        good_hash = cfg.get('admin_password_hash')
        if supplied and hashlib.sha256(supplied.encode()).hexdigest() == good_hash:
            session['is_admin'] = True
            flash('Admin mode enabled.', 'success')
            next_url = request.args.get('next') or url_for('main.settings')
            return redirect(next_url)
        flash('Invalid admin password', 'error')
    return render_template('admin_login.html', config=cfg, hide_user_ui=True)


@main_bp.route('/admin-logout', methods=['POST'])
def admin_logout():
    if session.get('is_admin'):
        session.pop('is_admin', None)
        flash('Admin mode disabled.', 'info')
    return redirect(url_for('main.index'))


@main_bp.route('/settings')
def settings():
    cfg = current_app.config.get('HOMEHUB_CONFIG', {})
    if not _admin_enabled():
        flash('Admin password is not configured. Add admin_password to config.yml', 'error')
        return redirect(url_for('main.index'))
    if not _is_admin():
        flash('Admin access required.', 'error')
        return redirect(url_for('main.admin_login', next=request.path))
    return render_template('settings.html', config=cfg)


def _clean_color(val: str) -> str | None:
    v = (val or '').strip()
    if not v:
        return None
    if re.fullmatch(r'#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})', v):
        return v
    return None


@main_bp.route('/settings', methods=['POST'])
def settings_update():
    cfg = current_app.config.get('HOMEHUB_CONFIG', {})
    if not _admin_enabled() or not _is_admin():
        flash('Admin access required.', 'error')
        return redirect(url_for('main.index'))

    # Basic strings
    instance_name = bleach.clean(request.form.get('instance_name', '')).strip()
    admin_name = bleach.clean(request.form.get('admin_name', '')).strip()

    # Passwords: if provided, set; if clear_* checked, clear; else leave unchanged
    new_password = request.form.get('new_password', None)
    clear_password = request.form.get('clear_password') == 'on'
    new_admin_password = request.form.get('new_admin_password', None)
    clear_admin_password = request.form.get('clear_admin_password') == 'on'

    # Feature toggles: use keys from current config
    ft = {}
    for k in (cfg.get('feature_toggles') or {}).keys():
        ft[k] = request.form.get(f'ft_{k}') == 'on'

    # Family members: one per line
    fam_raw = request.form.get('family_members', '')
    family_members = [line.strip() for line in fam_raw.splitlines() if line.strip()]

    # Reminders basic settings
    time_format = request.form.get('rem_time_format') or ''
    cal_start = request.form.get('rem_calendar_start_day') or ''

    # Reminders categories JSON (optional)
    categories_json = request.form.get('rem_categories_json', '').strip()
    categories = None
    if categories_json:
        try:
            parsed = json.loads(categories_json)
            if isinstance(parsed, list):
                categories = parsed
            else:
                raise ValueError('Categories must be a JSON array')
        except Exception as e:
            flash(f'Invalid categories JSON: {e}', 'error')
            return render_template('settings.html', config=cfg), 400

    # Theme colors
    theme_updates = {}
    for key in (
        'primary_color','secondary_color','background_color','card_background_color',
        'text_color','sidebar_background_color','sidebar_text_color',
        'sidebar_link_color','sidebar_link_border_color','sidebar_active_color'):
        val = request.form.get(f'theme_{key}', '').strip()
        # Accept raw rgba strings for link colors; hex for others
        if key in ('sidebar_link_color','sidebar_link_border_color'):
            if val:
                theme_updates[key] = val
        else:
            col = _clean_color(val)
            if col:
                theme_updates[key] = col

    # Calendar OAuth credentials
    calendar_oauth_updates = {}
    for key in ('google_client_id', 'google_client_secret', 'outlook_client_id', 'outlook_client_secret'):
        val = request.form.get(f'calendar_oauth_{key}', '').strip()
        if val:
            calendar_oauth_updates[key] = val

    # Weather settings
    weather_updates = {}
    weather_enabled = request.form.get('weather_enabled') == 'on'
    weather_api_key = request.form.get('weather_api_key', '').strip()
    weather_location = request.form.get('weather_location', '').strip()
    weather_units = request.form.get('weather_units', 'imperial').strip()
    weather_interval = request.form.get('weather_update_interval', '30').strip()
    
    weather_updates['enabled'] = weather_enabled
    if weather_api_key:
        weather_updates['api_key'] = weather_api_key
    if weather_location:
        weather_updates['location'] = weather_location
    if weather_units in ('metric', 'imperial'):
        weather_updates['units'] = weather_units
    try:
        interval = int(weather_interval)
        if 10 <= interval <= 120:
            weather_updates['update_interval'] = interval
    except (ValueError, TypeError):
        pass

    # Build updates dict (deep structure)
    updates: dict = {}
    if instance_name:
        updates['instance_name'] = instance_name
    if admin_name:
        updates['admin_name'] = admin_name
    updates['feature_toggles'] = ft
    updates['family_members'] = family_members
    updates.setdefault('reminders', {})
    if time_format:
        updates['reminders']['time_format'] = time_format
    if cal_start:
        updates['reminders']['calendar_start_day'] = cal_start
    if categories is not None:
        updates['reminders']['categories'] = categories
    if theme_updates:
        updates['theme'] = theme_updates
    if calendar_oauth_updates:
        updates['calendar_oauth'] = calendar_oauth_updates
    if weather_updates:
        updates['weather'] = weather_updates

    # Password handling
    # Household password
    if clear_password:
        updates['password'] = ''
    elif new_password is not None and new_password != '':
        updates['password'] = new_password
    else:
        updates['password'] = None  # no change
    # Admin password
    if clear_admin_password:
        updates['admin_password'] = ''
    elif new_admin_password is not None and new_admin_password != '':
        updates['admin_password'] = new_admin_password
    else:
        updates['admin_password'] = None  # no change

    # Persist and reload
    try:
        _save_config(updates)
        # force reload for subsequent requests
        current_app.config['HOMEHUB_CONFIG'] = _load_config()
        flash('Settings saved.', 'success')
    except Exception as e:
        current_app.logger.exception('Failed to save settings')
        flash(f'Failed to save settings: {e}', 'error')
        return render_template('settings.html', config=cfg), 500

    return redirect(url_for('main.settings'))
