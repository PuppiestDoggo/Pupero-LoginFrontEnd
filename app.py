from flask import Flask, render_template, request, redirect, url_for, make_response, flash
import requests
from config import BACKEND_URL, SECRET_KEY, REMEMBER_ME_DAYS
import logging
import json
import time

app = Flask(__name__)
app.secret_key = SECRET_KEY

# JSON logger setup
logger = logging.getLogger("pupero_frontend")
if not logger.handlers:
    handler = logging.StreamHandler()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

# Basic request logging
@app.before_request
def _start_timer():
    request._start_time = time.time()

@app.after_request
def _log_request(response):
    try:
        duration = int((time.time() - getattr(request, "_start_time", time.time())) * 1000)
        log = {
            "event": "http_request",
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "latency_ms": duration,
            "client": request.remote_addr,
            "has_token": bool(request.cookies.get('access_token')),
        }
        logger.info(json.dumps(log))
    except Exception:
        pass
    return response

# Helper to get auth headers with token from cookie
def get_auth_headers():
    token = request.cookies.get('access_token')
    if token:
        return {'Authorization': f'Bearer {token}'}
    return {}

# Home
@app.route('/')
def home():
    return render_template('home.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = {
            'email': request.form['email'],
            'username': request.form.get('username', ''),
            'password': request.form['password']
        }
        try:
            response = requests.post(f'{BACKEND_URL}/register', json=data, timeout=10)
        except Exception as e:
            flash(f'Registration failed: {e}', 'error')
            return render_template('register.html')
        if response.status_code == 200:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            try:
                detail = response.json().get('detail', 'Registration failed')
            except Exception:
                detail = 'Registration failed'
            flash(detail, 'error')
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Backend accepts username or email in JSON
        identifier = request.form.get('identifier', '').strip()
        payload = {
            'password': request.form.get('password', '')
        }
        # Decide whether it's an email or username (simple check for '@')
        if '@' in identifier:
            payload['email'] = identifier
        else:
            payload['username'] = identifier
        totp = request.form.get('totp')
        if totp:
            payload['totp'] = totp
        remember_flag = request.form.get('remember_me') == 'yes'
        payload['remember_me'] = remember_flag
        try:
            response = requests.post(f'{BACKEND_URL}/login', json=payload, timeout=10)
        except Exception as e:
            flash(f'Login failed: {e}', 'error')
            return render_template('login.html')
        if response.status_code == 200:
            try:
                tokens = response.json()
            except Exception:
                flash('Login failed: Invalid response from server', 'error')
                return render_template('login.html')
            resp = make_response(redirect(url_for('profile')))
            # Use secure cookie only on HTTPS; add SameSite and max_age
            secure_flag = request.is_secure
            max_age = REMEMBER_ME_DAYS*24*60*60 if remember_flag else 60*60
            resp.set_cookie(
                'access_token',
                tokens.get('access_token', ''),
                httponly=True,
                secure=secure_flag,
                samesite='Lax',
                max_age=max_age
            )
            # Persist remember flag to reuse on token refreshes/updates
            resp.set_cookie(
                'remember',
                '1' if remember_flag else '0',
                secure=secure_flag,
                samesite='Lax',
                max_age=max_age
            )
            try:
                logger.info(json.dumps({"event": "login_cookie_set", "remember": remember_flag, "client": request.remote_addr}))
            except Exception:
                pass
            flash('Login successful!', 'success')
            return resp
        else:
            # Safely extract error details
            detail = None
            try:
                body = response.json()
                detail = body.get('detail') or body
            except Exception:
                detail = response.text
            flash(f'Login failed: {detail}', 'error')
    return render_template('login.html')

# Profile
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    headers = get_auth_headers()
    if not headers:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        action = request.form.get('action', 'update_phrase')
        payload = {}
        if action == 'update_phrase':
            payload['phrase'] = request.form.get('phrase', '')
        elif action == 'change_username':
            payload['username'] = request.form.get('username', '')
        elif action == 'change_email':
            payload['new_email'] = request.form.get('new_email', '')
            payload['current_password'] = request.form.get('current_password', '')
        elif action == 'change_password':
            payload['new_password'] = request.form.get('new_password', '')
            payload['current_password'] = request.form.get('current_password', '')
        try:
            response = requests.put(f'{BACKEND_URL}/user/update', json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                except Exception:
                    data = {'message': 'Profile updated'}
                # If tokens returned (email/password change), update cookie
                if data.get('access_token'):
                    resp = make_response(redirect(url_for('profile')))
                    secure_flag = request.is_secure
                    remember_cookie = request.cookies.get('remember') == '1'
                    max_age = REMEMBER_ME_DAYS*24*60*60 if remember_cookie else 60*60
                    resp.set_cookie(
                        'access_token',
                        data.get('access_token', ''),
                        httponly=True,
                        secure=secure_flag,
                        samesite='Lax',
                        max_age=max_age
                    )
                    try:
                        logger.info(json.dumps({"event": "token_refreshed_cookie_set", "remember": remember_cookie, "client": request.remote_addr}))
                    except Exception:
                        pass
                    flash(data.get('message', 'Profile updated!'), 'success')
                    return resp
                flash(data.get('message', 'Profile updated!'), 'success')
            else:
                try:
                    detail = response.json().get('detail', response.text)
                except Exception:
                    detail = 'Update failed'
                flash('Update failed: ' + str(detail), 'error')
        except Exception as e:
            flash(f'Update failed: {e}', 'error')
    
    try:
        response = requests.get(f'{BACKEND_URL}/user/profile', headers=headers, timeout=10)
    except Exception as e:
        flash(f'Could not load profile: {e}', 'error')
        return redirect(url_for('login'))
    if response.status_code == 200:
        try:
            user_data = response.json()
        except Exception:
            flash('Invalid profile response', 'error')
            return redirect(url_for('login'))
        sessions = [{
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'current': True
        }]
        return render_template('profile.html', user=user_data, sessions=sessions)
    else:
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))

# Enable TOTP
@app.route('/totp/enable', methods=['GET', 'POST'])
def totp_enable():
    headers = get_auth_headers()
    if not headers:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            response = requests.post(f'{BACKEND_URL}/totp/enable/start', headers=headers, timeout=10)
        except Exception as e:
            flash(f'Failed to enable TOTP: {e}', 'error')
            return render_template('totp_enable.html')
        if response.status_code == 200:
            try:
                data = response.json()
                qr_data_url = f"data:image/png;base64,{data['qr_code']}"
                return render_template('totp_enable.html', secret=data.get('secret'), qr_url=qr_data_url)
            except Exception:
                flash('Failed to enable TOTP: invalid response', 'error')
        else:
            try:
                detail = response.json().get('detail', response.text)
            except Exception:
                detail = response.text
            flash('Failed to enable TOTP: ' + str(detail), 'error')
    return render_template('totp_enable.html')

# Confirm TOTP Enable
@app.route('/totp/enable/confirm', methods=['POST'])
def totp_enable_confirm():
    headers = get_auth_headers()
    if not headers:
        return redirect(url_for('login'))
    secret = request.form.get('secret')
    code = request.form.get('code')
    qr_url = request.form.get('qr_url')
    payload = {'secret': secret, 'code': code}
    try:
        response = requests.post(f"{BACKEND_URL}/totp/enable/confirm", json=payload, headers=headers, timeout=10)
    except Exception as e:
        flash(f'Failed to confirm TOTP: {e}', 'error')
        if secret and qr_url:
            return render_template('totp_enable.html', secret=secret, qr_url=qr_url)
        return redirect(url_for('totp_enable'))
    if response.status_code == 200:
        try:
            msg = response.json().get('message', 'TOTP enabled')
        except Exception:
            msg = 'TOTP enabled'
        flash(msg, 'success')
        return redirect(url_for('profile'))
    else:
        try:
            detail = response.json().get('detail', 'Failed to confirm TOTP')
        except Exception:
            detail = 'Failed to confirm TOTP'
        flash(detail, 'error')
        if secret and qr_url:
            return render_template('totp_enable.html', secret=secret, qr_url=qr_url)
        return redirect(url_for('totp_enable'))

# Password Reset Request
@app.route('/password/reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == 'POST':
        data = {'email': request.form['email']}
        try:
            response = requests.post(f'{BACKEND_URL}/password/reset', json=data, timeout=10)
            try:
                msg = response.json().get('message', 'Request processed')
            except Exception:
                msg = 'Request processed'
            flash(msg, 'info')
        except Exception as e:
            flash(f'Reset request failed: {e}', 'error')
        return redirect(url_for('login'))
    return render_template('reset.html')

# Sessions management (UI stubs)
@app.route('/sessions/close', methods=['POST'])
def close_session():
    ip = request.form.get('ip')
    is_current = request.form.get('current') == '1'
    try:
        logger.info(json.dumps({
            "event": "session_close_request",
            "ip": ip,
            "current": is_current,
            "client": request.remote_addr,
            "has_token": bool(request.cookies.get('access_token')),
        }))
    except Exception:
        pass
    resp = make_response(redirect(url_for('profile')))
    if is_current:
        resp.delete_cookie('access_token')
        resp.delete_cookie('remember')
        flash(f'Closed current session ({ip})', 'info')
    else:
        flash(f'Requested close for session {ip} (stub)', 'info')
    return resp

@app.route('/sessions/report', methods=['POST'])
def report_session():
    ip = request.form.get('ip')
    ua = request.headers.get('User-Agent', '')
    try:
        logger.info(json.dumps({
            "event": "session_report_request",
            "ip": ip,
            "user_agent": ua,
            "client": request.remote_addr,
        }))
    except Exception:
        pass
    flash(f'Reported session {ip} to admin (stub)', 'warning')
    return redirect(url_for('profile'))

# Logout
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('home')))
    resp.delete_cookie('access_token')
    resp.delete_cookie('remember')
    try:
        logger.info(json.dumps({
            "event": "logout",
            "client": request.remote_addr,
            "had_token": True,
        }))
    except Exception:
        pass
    flash('Logged out', 'info')
    return resp

if __name__ == '__main__':
    app.run(debug=True)

