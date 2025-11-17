from flask import session, current_app, redirect, url_for, render_template, request, flash, jsonify
from . import main_bp
from .. import db
from ..models import CalendarConnection, CalendarEvent
from datetime import datetime, timedelta
import requests
import json
from urllib.parse import urlencode


def _get_current_user():
    """Get current user from localStorage (passed via header or form)"""
    return request.form.get('user') or request.args.get('user') or session.get('calendar_user', 'Administrator')


def _get_oauth_config():
    """Get OAuth client IDs/secrets from config"""
    cfg = current_app.config.get('HOMEHUB_CONFIG', {})
    return cfg.get('calendar_oauth', {})


def _get_user_color(username):
    """Generate a consistent color for a user based on their name"""
    # Predefined color palette for better visual distinction
    colors = [
        '#3b82f6',  # blue
        '#ec4899',  # pink
        '#10b981',  # green
        '#f59e0b',  # orange
        '#8b5cf6',  # purple
        '#ef4444',  # red
        '#06b6d4',  # cyan
        '#84cc16',  # lime
        '#f97316',  # orange-alt
        '#a855f7',  # purple-alt
    ]
    # Use hash of username to pick color consistently
    index = hash(username) % len(colors)
    return colors[index]


def _get_user_colors():
    """Get color mapping for all family members"""
    cfg = current_app.config.get('HOMEHUB_CONFIG', {})
    all_users = ['Administrator'] + cfg.get('family_members', [])
    return {user: _get_user_color(user) for user in all_users}


@main_bp.route('/calendar')
def calendar_view():
    """Main calendar view showing all family members' availability"""
    cfg = current_app.config.get('HOMEHUB_CONFIG', {})
    user = _get_current_user()
    
    # Get all connections for display
    connections = CalendarConnection.query.all()
    
    # Get events for wider range (3 months for better calendar view)
    start = datetime.utcnow() - timedelta(days=30)  # Include past month
    end = start + timedelta(days=120)  # Show 4 months total
    events = CalendarEvent.query.filter(
        CalendarEvent.start_time >= start,
        CalendarEvent.start_time <= end
    ).order_by(CalendarEvent.start_time).all()
    
    # Get color mappings for all users
    user_colors = _get_user_colors()
    
    return render_template('calendar.html', 
                         config=cfg, 
                         connections=connections,
                         events=events,
                         current_user=user,
                         user_colors=user_colors)


@main_bp.route('/calendar/connect/<provider>')
def calendar_connect(provider):
    """Initiate OAuth flow for Google or Outlook"""
    if provider not in ('google', 'outlook'):
        flash('Invalid provider', 'error')
        return redirect(url_for('main.calendar_view'))
    
    oauth_cfg = _get_oauth_config()
    
    # Get user from query parameter or fall back to current user
    user = request.args.get('for_user', _get_current_user())
    
    # Store user in session for callback
    session['calendar_oauth_user'] = user
    session['calendar_oauth_provider'] = provider
    
    if provider == 'google':
        client_id = oauth_cfg.get('google_client_id')
        if not client_id:
            flash('Google Calendar not configured. Add credentials in Settings.', 'error')
            return redirect(url_for('main.calendar_view'))
        # Force localhost redirect to avoid 127.0.0.1 vs localhost mismatch in Google console
        redirect_uri = 'http://localhost:5000/calendar/oauth-callback'
        current_app.logger.info(f'[calendar] Initiating Google OAuth for user="{user}" redirect_uri="{redirect_uri}"')
        params = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'https://www.googleapis.com/auth/calendar.readonly openid email',
            'access_type': 'offline',
            'prompt': 'consent'
        }
        auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params)
        return redirect(auth_url)
    
    elif provider == 'outlook':
        client_id = oauth_cfg.get('outlook_client_id')
        if not client_id:
            flash('Outlook Calendar not configured. Add credentials in Settings.', 'error')
            return redirect(url_for('main.calendar_view'))
        redirect_uri = 'http://localhost:5000/calendar/oauth-callback'
        current_app.logger.info(f'[calendar] Initiating Outlook OAuth for user="{user}" redirect_uri="{redirect_uri}"')
        params = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'Calendars.Read User.Read offline_access',
            'response_mode': 'query'
        }
        auth_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' + urlencode(params)
        return redirect(auth_url)


@main_bp.route('/calendar/oauth-callback')
def calendar_oauth_callback():
    """Handle OAuth callback from Google or Outlook"""
    code = request.args.get('code')
    error = request.args.get('error')
    current_app.logger.info(f'[calendar] OAuth callback hit provider="{session.get("calendar_oauth_provider")}" code_present={bool(code)} error={error}')
    
    if error:
        flash(f'Authorization failed: {error}', 'error')
        return redirect(url_for('main.calendar_view'))
    
    if not code:
        flash('No authorization code received', 'error')
        return redirect(url_for('main.calendar_view'))
    
    user = session.get('calendar_oauth_user')
    provider = session.get('calendar_oauth_provider')
    
    if not user or not provider:
        flash('Session expired. Please try again.', 'error')
        return redirect(url_for('main.calendar_view'))
    
    oauth_cfg = _get_oauth_config()
    redirect_uri = url_for('main.calendar_oauth_callback', _external=True)
    # Normalize redirect_uri to localhost to match OAuth console configuration
    redirect_uri = redirect_uri.replace('127.0.0.1', 'localhost')
    current_app.logger.info(f'[calendar] Using redirect_uri="{redirect_uri}" for token exchange')
    
    try:
        if provider == 'google':
            # Exchange code for tokens
            token_url = 'https://oauth2.googleapis.com/token'
            data = {
                'code': code,
                'client_id': oauth_cfg.get('google_client_id'),
                'client_secret': oauth_cfg.get('google_client_secret'),
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            }
            current_app.logger.info('[calendar] Exchanging Google auth code for tokens')
            resp = requests.post(token_url, data=data, timeout=15)
            if not resp.ok:
                current_app.logger.warning(f'[calendar] Google token exchange failed status={resp.status_code} body={resp.text[:400]}')
            resp.raise_for_status()
            tokens = resp.json()
            
            access_token = tokens.get('access_token')
            refresh_token = tokens.get('refresh_token')
            expires_in = tokens.get('expires_in', 3600)
            
            # Get user email from ID token or userinfo endpoint
            email = None
            id_token_data = tokens.get('id_token')
            if id_token_data:
                # Parse JWT payload (base64 decode middle segment)
                try:
                    import base64
                    payload_segment = id_token_data.split('.')[1]
                    # Add padding if needed
                    padding = 4 - len(payload_segment) % 4
                    if padding != 4:
                        payload_segment += '=' * padding
                    payload = json.loads(base64.urlsafe_b64decode(payload_segment))
                    email = payload.get('email')
                    current_app.logger.info(f'[calendar] Extracted email from id_token: {email}')
                except Exception as e:
                    current_app.logger.warning(f'[calendar] Failed to parse id_token: {e}')
            
            # Fallback: try userinfo endpoint if email not yet retrieved
            if not email:
                try:
                    profile_url = 'https://openidconnect.googleapis.com/v1/userinfo'
                    headers = {'Authorization': f'Bearer {access_token}'}
                    profile_resp = requests.get(profile_url, headers=headers, timeout=10)
                    if profile_resp.ok:
                        profile = profile_resp.json()
                        email = profile.get('email')
                        current_app.logger.info(f'[calendar] Got email from userinfo: {email}')
                    else:
                        current_app.logger.warning(f'[calendar] Userinfo fetch failed status={profile_resp.status_code}')
                except Exception as e:
                    current_app.logger.warning(f'[calendar] Userinfo request exception: {e}')
            
            # Final fallback: use user identifier from calendar API
            if not email:
                email = f'{user}@calendar'
                current_app.logger.info(f'[calendar] Using fallback email: {email}')
            
        elif provider == 'outlook':
            # Exchange code for tokens
            token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
            data = {
                'code': code,
                'client_id': oauth_cfg.get('outlook_client_id'),
                'client_secret': oauth_cfg.get('outlook_client_secret'),
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            }
            current_app.logger.info('[calendar] Exchanging Outlook auth code for tokens')
            resp = requests.post(token_url, data=data, timeout=15)
            if not resp.ok:
                current_app.logger.warning(f'[calendar] Outlook token exchange failed status={resp.status_code} body={resp.text[:400]}')
            resp.raise_for_status()
            tokens = resp.json()
            
            access_token = tokens.get('access_token')
            refresh_token = tokens.get('refresh_token')
            expires_in = tokens.get('expires_in', 3600)
            
            # Get user email from Microsoft Graph
            me_url = 'https://graph.microsoft.com/v1.0/me'
            headers = {'Authorization': f'Bearer {access_token}'}
            me_resp = requests.get(me_url, headers=headers, timeout=10)
            if not me_resp.ok:
                current_app.logger.warning(f'[calendar] Outlook profile fetch failed status={me_resp.status_code} body={me_resp.text[:400]}')
            me_resp.raise_for_status()
            me_data = me_resp.json()
            email = me_data.get('mail') or me_data.get('userPrincipalName')
        
        # Save connection
        conn = CalendarConnection.query.filter_by(user=user, provider=provider).first()
        if not conn:
            conn = CalendarConnection(user=user, provider=provider)
            db.session.add(conn)
        
        conn.access_token = access_token
        conn.refresh_token = refresh_token
        conn.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
        conn.email = email
        conn.connected_at = datetime.utcnow()
        
        db.session.commit()
        
        # Clear session
        session.pop('calendar_oauth_user', None)
        session.pop('calendar_oauth_provider', None)
        
        flash(f'{provider.capitalize()} calendar connected successfully!', 'success')
        
        # Trigger initial sync
        return redirect(url_for('main.calendar_sync', connection_id=conn.id))
        
    except Exception as e:
        # Try to include response body for easier debugging
        body = ''
        try:
            if 'resp' in locals() and hasattr(resp, 'text'):
                body = resp.text[:500]
        except Exception:
            body = ''
        current_app.logger.exception(f'OAuth callback failed provider={provider} body_snippet="{body}"')
        flash(f'Failed to connect calendar: {str(e)}', 'error')
        return redirect(url_for('main.calendar_view'))


@main_bp.route('/calendar/disconnect/<int:connection_id>', methods=['POST'])
def calendar_disconnect(connection_id):
    """Disconnect a calendar connection"""
    conn = CalendarConnection.query.get_or_404(connection_id)
    
    # Delete associated events
    CalendarEvent.query.filter_by(connection_id=connection_id).delete()
    
    # Delete connection
    db.session.delete(conn)
    db.session.commit()
    
    flash('Calendar disconnected', 'info')
    return redirect(url_for('main.calendar_view'))


@main_bp.route('/calendar/sync/<int:connection_id>')
def calendar_sync(connection_id):
    """Sync events from a connected calendar"""
    conn = CalendarConnection.query.get_or_404(connection_id)
    
    try:
        # Check if token needs refresh
        if conn.token_expiry and conn.token_expiry < datetime.utcnow():
            _refresh_token(conn)
        
        # Fetch events
        start = datetime.utcnow()
        end = start + timedelta(days=30)
        
        if conn.provider == 'google':
            events = _fetch_google_events(conn, start, end)
        elif conn.provider == 'outlook':
            events = _fetch_outlook_events(conn, start, end)
        else:
            flash('Unknown provider', 'error')
            return redirect(url_for('main.calendar_view'))
        
        # Clear old events for this connection
        CalendarEvent.query.filter_by(connection_id=conn.id).delete()
        
        # Save new events
        for evt in events:
            db.session.add(evt)
        
        conn.last_sync = datetime.utcnow()
        db.session.commit()
        
        flash(f'Synced {len(events)} events from {conn.provider.capitalize()}', 'success')
        
    except Exception as e:
        current_app.logger.exception('Calendar sync failed')
        flash(f'Sync failed: {str(e)}', 'error')
    
    return redirect(url_for('main.calendar_view'))


def _refresh_token(conn: CalendarConnection):
    """Refresh expired access token"""
    oauth_cfg = _get_oauth_config()
    
    if conn.provider == 'google':
        token_url = 'https://oauth2.googleapis.com/token'
        data = {
            'client_id': oauth_cfg.get('google_client_id'),
            'client_secret': oauth_cfg.get('google_client_secret'),
            'refresh_token': conn.refresh_token,
            'grant_type': 'refresh_token'
        }
    elif conn.provider == 'outlook':
        token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
        data = {
            'client_id': oauth_cfg.get('outlook_client_id'),
            'client_secret': oauth_cfg.get('outlook_client_secret'),
            'refresh_token': conn.refresh_token,
            'grant_type': 'refresh_token'
        }
    else:
        raise ValueError('Unknown provider')
    
    resp = requests.post(token_url, data=data, timeout=10)
    resp.raise_for_status()
    tokens = resp.json()
    
    conn.access_token = tokens.get('access_token')
    expires_in = tokens.get('expires_in', 3600)
    conn.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    db.session.commit()


def _fetch_google_events(conn: CalendarConnection, start: datetime, end: datetime):
    """Fetch events from Google Calendar"""
    url = 'https://www.googleapis.com/calendar/v3/calendars/primary/events'
    headers = {'Authorization': f'Bearer {conn.access_token}'}
    params = {
        'timeMin': start.isoformat() + 'Z',
        'timeMax': end.isoformat() + 'Z',
        'singleEvents': 'true',
        'orderBy': 'startTime'
    }
    
    current_app.logger.info(f'[calendar] Fetching Google events from {start} to {end}')
    resp = requests.get(url, headers=headers, params=params, timeout=10)
    
    if not resp.ok:
        current_app.logger.error(f'[calendar] Google Calendar API error: {resp.status_code} - {resp.text[:500]}')
        current_app.logger.info('[calendar] Hint: Ensure Google Calendar API is enabled in Google Cloud Console')
    
    resp.raise_for_status()
    data = resp.json()
    
    events = []
    for item in data.get('items', []):
        start_dt = item.get('start', {})
        end_dt = item.get('end', {})
        
        # Parse start/end
        if 'dateTime' in start_dt:
            start_time = datetime.fromisoformat(start_dt['dateTime'].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(end_dt['dateTime'].replace('Z', '+00:00'))
            is_all_day = False
        else:
            # All-day event
            start_time = datetime.fromisoformat(start_dt['date'])
            end_time = datetime.fromisoformat(end_dt['date'])
            is_all_day = True
        
        evt = CalendarEvent(
            connection_id=conn.id,
            user=conn.user,
            provider_event_id=item.get('id'),
            summary=item.get('summary', 'Busy'),
            start_time=start_time,
            end_time=end_time,
            is_all_day=is_all_day,
            status=item.get('status', 'confirmed')
        )
        events.append(evt)
    
    return events


def _fetch_outlook_events(conn: CalendarConnection, start: datetime, end: datetime):
    """Fetch events from Outlook/Microsoft Graph"""
    url = 'https://graph.microsoft.com/v1.0/me/calendarview'
    headers = {'Authorization': f'Bearer {conn.access_token}'}
    params = {
        'startDateTime': start.isoformat() + 'Z',
        'endDateTime': end.isoformat() + 'Z',
        '$orderby': 'start/dateTime'
    }
    
    resp = requests.get(url, headers=headers, params=params, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    
    events = []
    for item in data.get('value', []):
        start_dt = item.get('start', {})
        end_dt = item.get('end', {})
        
        # Parse start/end
        start_time = datetime.fromisoformat(start_dt['dateTime'])
        end_time = datetime.fromisoformat(end_dt['dateTime'])
        is_all_day = item.get('isAllDay', False)
        
        evt = CalendarEvent(
            connection_id=conn.id,
            user=conn.user,
            provider_event_id=item.get('id'),
            summary=item.get('subject', 'Busy'),
            start_time=start_time,
            end_time=end_time,
            is_all_day=is_all_day,
            status='confirmed'  # Outlook doesn't return status in same format
        )
        events.append(evt)
    
    return events
