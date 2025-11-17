import yaml
import os
import hashlib


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CONFIG_PATH = os.path.join(BASE_DIR, 'config.yml')

def load_config():
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f'config.yml not found at {CONFIG_PATH}.')
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f) or {}
    # Hash password if present
    if 'password' in config and config['password']:
        config['password_hash'] = hashlib.sha256(config['password'].encode()).hexdigest()
        del config['password']
    # Optional: separate admin password for privileged routes
    if 'admin_password' in config and config['admin_password']:
        config['admin_password_hash'] = hashlib.sha256(config['admin_password'].encode()).hexdigest()
        del config['admin_password']
    # Ensure feature_toggles exists
    config.setdefault('feature_toggles', {})
    # Ensure Who is Home widget is enabled by default unless explicitly disabled in config.yml
    config['feature_toggles'].setdefault('who_is_home', True)
    # Personal status feature toggle (new)
    config['feature_toggles'].setdefault('personal_status', True)
    # Reminders defaults & calendar start day (supports sunday..saturday or 0-6)
    rem = config.setdefault('reminders', {})
    # Do not overwrite existing user value
    if 'calendar_start_day' not in rem or rem.get('calendar_start_day') in (None, ''):
        rem.setdefault('calendar_start_day', 'sunday')  # default Sunday to align with expense tracker
    # Admin name default
    config.setdefault('admin_name', 'Administrator')
    # Family members default list
    config.setdefault('family_members', [])
    # Theme defaults
    theme = config.setdefault('theme', {})
    theme.setdefault('primary_color', '#1d4ed8')
    theme.setdefault('secondary_color', '#a0aec0')
    theme.setdefault('background_color', '#f7fafc')
    theme.setdefault('card_background_color', '#ffffff')
    theme.setdefault('text_color', '#333333')
    theme.setdefault('sidebar_background_color', '#2563eb')
    theme.setdefault('sidebar_text_color', '#ffffff')
    theme.setdefault('sidebar_link_color', 'rgba(255,255,255,0.95)')
    theme.setdefault('sidebar_link_border_color', 'rgba(255,255,255,0.18)')
    return config


def _deep_merge(dst: dict, src: dict) -> dict:
    for k, v in (src or {}).items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def save_config(updates: dict) -> None:
    """Safely merge and persist updates into config.yml.
    Rules:
    - Merge deeply into existing YAML (preserve unknown keys)
    - If updates contains special markers for passwords:
        - 'password' and/or 'admin_password' set to strings to update
        - If value is None, leave as-is; if value is '', clear
    - Do NOT write computed *_hash keys
    """
    # Load current raw YAML (not normalized) to preserve structure
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            current = yaml.safe_load(f) or {}
    else:
        current = {}

    # Remove computed hash keys from both sides if present
    for hk in ('password_hash', 'admin_password_hash'):
        current.pop(hk, None)
        updates.pop(hk, None)

    # Handle passwords explicitly if provided in updates
    for pw_key in ('password', 'admin_password'):
        if pw_key in updates:
            new_val = updates[pw_key]
            if new_val is None:
                # skip change
                updates.pop(pw_key, None)
            else:
                # allow empty string to clear
                pass

    merged = _deep_merge(current, updates)

    # Write atomically
    tmp_path = CONFIG_PATH + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(merged, f, sort_keys=False, allow_unicode=True)
    os.replace(tmp_path, CONFIG_PATH)
