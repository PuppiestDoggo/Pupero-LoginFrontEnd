from flask import Flask, render_template, request, redirect, url_for, make_response, flash, Response, g
import requests
from config import (
    BACKEND_URL,
    OFFERS_SERVICE_URL,
    TRANSACTIONS_SERVICE_URL,
    SECRET_KEY,
    REMEMBER_ME_DAYS,
    SECURE_COOKIES,
    SESSION_COOKIE_SAMESITE,
    MATRIX_ENABLED,
    MATRIX_HS_URL_BACKEND,
    MATRIX_ELEMENT_URL,
    MATRIX_SERVER_NAME,
    MATRIX_USER_PREFIX,
    MATRIX_DEFAULT_PASSWORD_SECRET,
)
import logging
import json
import time
import secrets
import base64
from urllib.parse import urlencode
import os

# Short-lived cache for user profile by access token (improves reliability for AJAX calls)
# { token: {"id": int, "username": str, "ts": epoch_seconds} }
PROFILE_CACHE: dict[str, dict] = {}


def _get_logged_in_username() -> str:
    """
    Return the username of the current logged-in user by calling Login service /user/profile
    using the access_token cookie. Uses a short-lived in-memory cache to improve reliability
    for AJAX chat calls. Returns empty string if unavailable.
    """
    token = None
    try:
        token = request.cookies.get('access_token')
    except Exception:
        token = None
    # Try cache first
    try:
        if token:
            ent = PROFILE_CACHE.get(token)
            if ent and (time.time() - float(ent.get('ts', 0))) < 300:
                return ent.get('username') or ""
    except Exception:
        pass
    # Fetch from backend
    try:
        if not token:
            return ""
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get(f"{BACKEND_URL}/user/profile", headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json() or {}
            uname = data.get('username') or ''
            if not uname:
                email = data.get('email') or ''
                uname = email.split('@')[0] if '@' in email else email
            # Update cache
            try:
                uid = int(data.get('id') or 0)
                PROFILE_CACHE[token] = {"id": uid, "username": uname or "", "ts": time.time()}
            except Exception:
                pass
            return uname or ""
    except Exception:
        # Fallback to stale cache if present
        try:
            if token and PROFILE_CACHE.get(token):
                return PROFILE_CACHE[token].get('username') or ""
        except Exception:
            pass
    return ""


def _fetch_user_info(user_id: int) -> dict | None:
    """Fetch public user info (username, matrix_localpart) from backend."""
    try:
        r = requests.get(f"{BACKEND_URL}/users/{user_id}/public", timeout=4)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _attach_seller_name(offer: dict) -> dict:
    """Parse offer['desc'] if JSON to pull seller_name and attach as offer['seller_name']"""
    seller_name = ""
    try:
        desc = offer.get('desc')
        if isinstance(desc, str):
            obj = json.loads(desc)
            seller_name = obj.get('seller_name', '')
    except Exception:
        seller_name = ""
    offer['seller_name'] = seller_name
    return offer


def _parse_offer_desc(desc_str: str) -> dict:
    """Return a normalized ad dict from the offer desc JSON string."""
    data = {}
    try:
        data = json.loads(desc_str or "{}") if isinstance(desc_str, str) else (desc_str or {})
    except Exception:
        data = {}
    # Normalize fields
    side = data.get('side') or ''
    crypto = data.get('crypto') or 'XMR'
    fiat = data.get('fiat') or 'EUR'
    price_mode = data.get('price_mode') or 'market'
    margin = float(str(data.get('margin') or '0') or 0)
    fixed_price = data.get('fixed_price')
    try:
        fixed_price = float(fixed_price) if fixed_price is not None and str(fixed_price) != '' else None
    except Exception:
        fixed_price = None
    equation_enabled = bool(data.get('equation_enabled', False))
    pricing_equation = data.get('pricing_equation') or ''
    # Payment methods may be a list or a single string 'payment'
    pms = data.get('payment_methods')
    single_pm = data.get('payment')
    if not pms:
        pms = [single_pm] if single_pm else []
    payment_method = (single_pm or (pms[0] if pms else ''))
    # Limits
    limits = data.get('limits') or {}
    min_limit = limits.get('min') or ''
    max_limit = limits.get('max') or ''
    # Requirements
    req = data.get('requirements') or {}
    req_phone = bool(req.get('phone'))
    req_id = bool(req.get('id'))
    # Schedule
    schedule = data.get('schedule') or {}
    # Country
    country = data.get('country') or ''
    # Promo / conditions
    promo_text = data.get('promo') or ''
    trade_conditions = data.get('conditions') or ''
    return {
        'side': side,
        'crypto': crypto,
        'fiat': fiat,
        'price_mode': price_mode,
        'margin': margin,
        'fixed_price': fixed_price,
        'equation_enabled': equation_enabled,
        'pricing_equation': pricing_equation,
        'payment_method': payment_method,
        'payment_methods': pms,
        'min_limit': min_limit,
        'max_limit': max_limit,
        'req_phone': req_phone,
        'req_id': req_id,
        'schedule': schedule,
        'country': country,
        'promo_text': promo_text,
        'trade_conditions': trade_conditions,
    }


# --- Cached market price fetcher (internal API) ---
_PRICE_CACHE = {"ts": 0.0, "prices": {}}


def _get_market_price(fiat: str = "EUR") -> float:
    # Small local cache to avoid even internal calls too often
    import time as _t
    now = _t.time()
    if now - float(_PRICE_CACHE.get("ts", 0.0)) < 120 and _PRICE_CACHE.get("prices"):
        pass
    else:
        try:
            r = requests.get(f"{OFFERS_SERVICE_URL}/price", timeout=5)
            if r.status_code == 200:
                data = r.json() or {}
                prices = data.get("prices") or {}
                if isinstance(prices, dict) and prices:
                    _PRICE_CACHE["prices"] = {k.upper(): float(v) for k, v in prices.items() if v is not None}
                    _PRICE_CACHE["ts"] = now
        except Exception:
            pass
    try:
        return float(_PRICE_CACHE.get("prices", {}).get((fiat or "EUR").upper(), 0.0))
    except Exception:
        return 0.0


def _compute_price_per_xmr(ad: dict, market_base: float = 250.0) -> float:
    mode = (ad.get('price_mode') or 'market').lower()
    if mode == 'fixed' and ad.get('fixed_price'):
        return float(ad['fixed_price'])
    if mode == 'market':
        try:
            m = float(ad.get('margin') or 0.0)
        except Exception:
            m = 0.0
        return round(market_base * (1.0 + m / 100.0), 2)
    # equation placeholder -> use baseline
    return float(market_base)


def _humanize_schedule(s: dict) -> str:
    if not s:
        return 'unspecified'
    mode = s.get('mode')
    if mode == '24h':
        return '24/7'
    if mode == 'weekly':
        days = s.get('days') or {}
        # Build compact string like: Mon, Tue: 08:00-18:00
        parts = []
        for d in ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']:
            if d in days:
                ranges = days[d]
                if isinstance(ranges, list) and ranges:
                    parts.append(f"{d} {ranges[0].get('start', '00:00')}-{ranges[0].get('end', '23:59')}")
        return ', '.join(parts) if parts else 'weekly (unspecified)'
    # Fallback for old schema {start,end}
    if 'start' in s and 'end' in s:
        return f"{s.get('start')} to {s.get('end')}"
    return 'unspecified'


app = Flask(__name__)
# Secret key handling: use env if provided, otherwise generate an ephemeral dev key
if SECRET_KEY:
    app.secret_key = SECRET_KEY
else:
    app.secret_key = secrets.token_hex(32)
    logging.getLogger("pupero_frontend").warning(
        "SECRET_KEY not set; using ephemeral dev key (development only). Set SECRET_KEY in environment for production.")

# Session cookie hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE=SECURE_COOKIES,
)

# JSON logger setup
logger = logging.getLogger("pupero_frontend")
if not logger.handlers:
    handler = logging.StreamHandler()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

# --- Auth token refresh helper ---

def _jwt_exp(token: str) -> float | None:
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return None
        pad = '=' * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad).decode('utf-8'))
        return float(payload.get('exp')) if payload.get('exp') is not None else None
    except Exception:
        return None


def _maybe_refresh_access_token(force: bool = False) -> None:
    """Attempt to refresh the access token using refresh_token cookie via API Manager /auth/refresh.
    On success, stores new tokens in flask.g so @after_request can persist them as cookies.
    """
    try:
        current = getattr(g, 'current_access_token', None) or request.cookies.get('access_token')
        # If we already have an access token and not forced, refresh only when expiring soon (<2 minutes)
        if current and not force:
            exp = _jwt_exp(current)
            if exp and (exp - time.time()) > 120:
                g.current_access_token = current
                return
        refresh_tok = request.cookies.get('refresh_token')
        if not refresh_tok:
            return
        r = requests.post(f"{BACKEND_URL}/refresh", json={"refresh_token": refresh_tok}, timeout=6)
        if r.status_code == 200:
            data = r.json() or {}
            at = data.get('access_token')
            rt = data.get('refresh_token')
            if at:
                g.current_access_token = at
                g.new_access_token = at
            if rt:
                g.new_refresh_token = rt
    except Exception:
        # Silent on purpose to keep UX smooth
        return


# Basic request logging
@app.before_request
def _start_timer():
    request._start_time = time.time()
    # Attempt proactive refresh if access token is missing but a refresh token exists and user chose remember me
    try:
        if not request.cookies.get('access_token') and request.cookies.get('refresh_token'):
            _maybe_refresh_access_token(force=True)
    except Exception:
        pass


@app.after_request
def _log_request(response):
    try:
        # If a new token was obtained during this request, set cookies on the response
        secure_flag = SECURE_COOKIES or request.is_secure
        samesite = SESSION_COOKIE_SAMESITE
        remember = (request.cookies.get('remember') == '1')
        max_age_access = REMEMBER_ME_DAYS * 24 * 60 * 60 if remember else 60 * 60
        max_age_refresh = REMEMBER_ME_DAYS * 24 * 60 * 60 if remember else (12 * 60 * 60)
        if getattr(g, 'new_access_token', None):
            response.set_cookie('access_token', g.new_access_token or '', httponly=True, secure=secure_flag, samesite=samesite, max_age=max_age_access)
        if getattr(g, 'new_refresh_token', None):
            response.set_cookie('refresh_token', g.new_refresh_token or '', httponly=True, secure=secure_flag, samesite=samesite, max_age=max_age_refresh)
    except Exception:
        pass
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
    # Try to ensure we have a fresh-enough access token
    try:
        _maybe_refresh_access_token(force=False)
    except Exception:
        pass
    # Prefer a freshly refreshed token stored in g during this request
    token = getattr(g, 'current_access_token', None) or request.cookies.get('access_token')
    # If still no token but we have a refresh cookie, force refresh
    if not token and request.cookies.get('refresh_token'):
        try:
            _maybe_refresh_access_token(force=True)
            token = getattr(g, 'current_access_token', None)
        except Exception:
            token = None
    if token:
        return {'Authorization': f'Bearer {token}'}
    return {}


# Helper to fetch current user's TOTP status (True if enabled)
# Kept lightweight; called only when a token cookie exists
def _fetch_totp_enabled() -> bool:
    try:
        headers = get_auth_headers()
        if not headers:
            return False
        resp = requests.get(f"{BACKEND_URL}/totp/status", headers=headers, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return bool(data.get('enabled'))
    except Exception:
        pass
    return False


# Inject totp_enabled into all templates when logged in
@app.context_processor
def inject_totp():
    enabled = False
    if request.cookies.get('access_token'):
        enabled = _fetch_totp_enabled()
    return dict(totp_enabled=enabled)


# Home
@app.route('/')
def home():
    return render_template('home.html')

@app.route("/health")
def health():
    return "OK", 200

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
    """
    Multi-step login on the same page without redirects.
    Steps:
      1) Ask identifier (username/email)
      2) Ask password
      3) Ask TOTP if backend requires it
    """
    stage = 'identifier'
    identifier = ''
    remember_flag = False

    if request.method == 'POST':
        stage = request.form.get('stage', 'identifier')
        remember_flag = request.form.get('remember_me') == 'yes'

        # Normalize identifier across stages
        identifier = request.form.get('identifier', '').strip()

        # Stage 1 -> move to password stage (no backend call yet)
        if stage == 'identifier':
            if not identifier:
                flash('Please enter your username or email.', 'error')
                stage = 'identifier'
            else:
                stage = 'password'
            return render_template('login.html', stage=stage, identifier=identifier, remember_me=remember_flag)

        # Stage 2: submit password, try to login; backend may require TOTP
        if stage == 'password':
            password = request.form.get('password', '')
            if not identifier:
                flash('Missing identifier. Please start again.', 'error')
                stage = 'identifier'
                return render_template('login.html', stage=stage)
            if not password:
                flash('Please enter your password.', 'error')
                return render_template('login.html', stage='password', identifier=identifier, remember_me=remember_flag)

            payload = {'password': password, 'remember_me': remember_flag}
            if '@' in identifier:
                payload['email'] = identifier
            else:
                payload['username'] = identifier
            try:
                response = requests.post(f'{BACKEND_URL}/login', json=payload, timeout=10)
            except Exception as e:
                flash(f'Login failed: {e}', 'error')
                return render_template('login.html', stage='password', identifier=identifier, remember_me=remember_flag)

            # Success straight away (no TOTP required)
            if response.status_code == 200:
                try:
                    tokens = response.json()
                except Exception:
                    flash('Login failed: Invalid response from server', 'error')
                    return render_template('login.html', stage='password', identifier=identifier, remember_me=remember_flag)
                # Set cookies then redirect to home to force full UI refresh (header)
                resp = make_response(redirect(url_for('home')))
                secure_flag = SECURE_COOKIES or request.is_secure
                samesite = SESSION_COOKIE_SAMESITE
                max_age_access = REMEMBER_ME_DAYS * 24 * 60 * 60 if remember_flag else 60 * 60
                max_age_refresh = REMEMBER_ME_DAYS * 24 * 60 * 60 if remember_flag else (12 * 60 * 60)
                resp.set_cookie('access_token', tokens.get('access_token', ''), httponly=True, secure=secure_flag, samesite=samesite, max_age=max_age_access)
                if tokens.get('refresh_token'):
                    resp.set_cookie('refresh_token', tokens.get('refresh_token', ''), httponly=True, secure=secure_flag, samesite=samesite, max_age=max_age_refresh)
                # Optional Matrix token cookie
                mtx = tokens.get('matrix_access_token') if isinstance(tokens, dict) else None
                if mtx:
                    resp.set_cookie('matrix_access_token', mtx, httponly=True, secure=secure_flag, samesite=samesite, max_age=max_age_access)
                resp.set_cookie('remember', '1' if remember_flag else '0', secure=secure_flag, samesite=samesite, max_age=max_age_access)
                try:
                    logger.info(json.dumps({"event": "login_cookie_set", "remember": remember_flag, "client": request.remote_addr}))
                except Exception:
                    pass
                flash('Login successful!', 'success')
                return resp

            # Check if TOTP is required by examining response
            totp_required = False
            detail = ''
            body = None
            try:
                body = response.json()
                detail = body.get('detail') or ''
                totp_required = bool(body.get('totp_required'))
            except Exception:
                detail = response.text or ''

            if response.status_code in (400, 401) and (totp_required or 'TOTP' in str(detail).upper() or '2FA' in str(detail).upper()):
                # Move to TOTP step, keep password in a hidden field
                stage = 'totp'
                return render_template('login.html', stage=stage, identifier=identifier, password_cached=password, remember_me=remember_flag)

            # Other errors: remain on password stage
            if detail:
                flash(f'Login failed: {detail}', 'error')
            else:
                flash('Login failed. Please try again.', 'error')
            return render_template('login.html', stage='password', identifier=identifier, remember_me=remember_flag)

        # Stage 3: TOTP verification (submit identifier + password (hidden) + totp)
        if stage == 'totp':
            totp_code = request.form.get('totp', '').strip()
            password = request.form.get('password_cached', '') or request.form.get('password', '')
            if not identifier or not password:
                flash('Session expired. Please start again.', 'error')
                return render_template('login.html', stage='identifier')
            if not totp_code:
                flash('Please enter your 2FA code.', 'error')
                return render_template('login.html', stage='totp', identifier=identifier, password_cached=password, remember_me=remember_flag)

            payload = {'remember_me': remember_flag, 'totp': totp_code, 'password': password}
            if '@' in identifier:
                payload['email'] = identifier
            else:
                payload['username'] = identifier
            try:
                response = requests.post(f'{BACKEND_URL}/login', json=payload, timeout=10)
            except Exception as e:
                flash(f'Login failed: {e}', 'error')
                return render_template('login.html', stage='totp', identifier=identifier, password_cached=password, remember_me=remember_flag)

            if response.status_code == 200:
                try:
                    tokens = response.json()
                except Exception:
                    flash('Login failed: Invalid response from server', 'error')
                    return render_template('login.html', stage='totp', identifier=identifier, password_cached=password, remember_me=remember_flag)
                # Set cookies then redirect to home to force full UI refresh (header)
                resp = make_response(redirect(url_for('home')))
                secure_flag = SECURE_COOKIES or request.is_secure
                samesite = SESSION_COOKIE_SAMESITE
                max_age_access = REMEMBER_ME_DAYS * 24 * 60 * 60 if remember_flag else 60 * 60
                max_age_refresh = REMEMBER_ME_DAYS * 24 * 60 * 60 if remember_flag else (12 * 60 * 60)
                resp.set_cookie('access_token', tokens.get('access_token', ''), httponly=True, secure=secure_flag, samesite=samesite, max_age=max_age_access)
                if tokens.get('refresh_token'):
                    resp.set_cookie('refresh_token', tokens.get('refresh_token', ''), httponly=True, secure=secure_flag, samesite=samesite, max_age=max_age_refresh)
                # Optional Matrix token cookie
                mtx = tokens.get('matrix_access_token') if isinstance(tokens, dict) else None
                if mtx:
                    resp.set_cookie('matrix_access_token', mtx, httponly=True, secure=secure_flag, samesite=samesite, max_age=max_age_access)
                resp.set_cookie('remember', '1' if remember_flag else '0', secure=secure_flag, samesite=samesite, max_age=max_age_access)
                try:
                    logger.info(json.dumps({"event": "login_cookie_set", "remember": remember_flag, "client": request.remote_addr}))
                except Exception:
                    pass
                flash('Login successful!', 'success')
                return resp
            else:
                # Failure: remain on TOTP stage
                try:
                    detail = response.json().get('detail', response.text)
                except Exception:
                    detail = response.text or 'Login failed'
                flash(f'Login failed: {detail}', 'error')
                return render_template('login.html', stage='totp', identifier=identifier, password_cached=password, remember_me=remember_flag)

    # GET request or fall-through
    remember_flag = request.cookies.get('remember') == '1'
    return render_template('login.html', stage=stage, identifier=identifier, remember_me=remember_flag)


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
            payload['current_password'] = request.form.get('current_password', '')
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
                    secure_flag = SECURE_COOKIES or request.is_secure
                    samesite = SESSION_COOKIE_SAMESITE
                    remember_cookie = request.cookies.get('remember') == '1'
                    max_age = REMEMBER_ME_DAYS * 24 * 60 * 60 if remember_cookie else 60 * 60
                    resp.set_cookie(
                        'access_token',
                        data.get('access_token', ''),
                        httponly=True,
                        secure=secure_flag,
                        samesite=samesite,
                        max_age=max_age
                    )
                    try:
                        logger.info(json.dumps({"event": "token_refreshed_cookie_set", "remember": remember_cookie,
                                                "client": request.remote_addr}))
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
        # Fetch 2FA (TOTP) status
        totp_enabled = False
        try:
            status_resp = requests.get(f'{BACKEND_URL}/totp/status', headers=headers, timeout=10)
            if status_resp.status_code == 200:
                try:
                    totp_enabled = bool(status_resp.json().get('enabled'))
                except Exception:
                    totp_enabled = False
        except Exception:
            totp_enabled = False
        
        # Fetch reviews
        reviews_summary = None
        try:
             r_rev = requests.get(f'{BACKEND_URL}/users/{user_data["id"]}/reviews', headers=headers, timeout=5)
             if r_rev.status_code == 200:
                 reviews_summary = r_rev.json()
        except Exception:
             pass

        sessions = [{
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'current': True
        }]
        return render_template('profile.html', user=user_data, sessions=sessions, totp_enabled=totp_enabled, reviews_summary=reviews_summary)
    else:
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))


@app.route('/user/<username>')
def public_profile(username: str):
    # Fetch user info
    user_info = {}
    try:
        r = requests.get(f"{BACKEND_URL}/users/by-username/{username}", timeout=5)
        if r.status_code != 200:
            flash(f"User {username} not found", "error")
            return redirect(url_for('offers'))
        user_info = r.json()
    except Exception as e:
        flash(f"Error fetching user profile: {e}", "error")
        return redirect(url_for('offers'))

    # Fetch reviews
    reviews_summary = None
    if user_info.get('id'):
        try:
            r_rev = requests.get(f'{BACKEND_URL}/users/{user_info["id"]}/reviews', timeout=5)
            if r_rev.status_code == 200:
                reviews_summary = r_rev.json()
        except Exception:
            pass
    
    # Check if current user is admin (for moderation buttons)
    is_admin = False
    try:
        headers = get_auth_headers()
        if headers:
            resp = requests.get(f'{BACKEND_URL}/user/profile', headers=headers, timeout=5)
            if resp.status_code == 200:
                u = resp.json() or {}
                if u.get('role') in ('admin', 'superadmin'):
                    is_admin = True
    except Exception:
        pass

    return render_template('public_profile.html', user=user_info, reviews_summary=reviews_summary, is_admin=is_admin)


# Enable TOTP
@app.route('/totp/enable', methods=['GET', 'POST'])
def totp_enable():
    headers = get_auth_headers()
    if not headers:
        return redirect(url_for('login'))
    # If TOTP is already enabled, don't show enable page again
    if _fetch_totp_enabled():
        flash('Two-Factor Authentication is already enabled.', 'info')
        return redirect(url_for('profile'))
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


# Disable TOTP
@app.route('/totp/disable', methods=['POST'])
def totp_disable():
    headers = get_auth_headers()
    if not headers:
        return redirect(url_for('login'))
    try:
        response = requests.post(f"{BACKEND_URL}/totp/disable", headers=headers, timeout=10)
        if response.status_code == 200:
            try:
                msg = response.json().get('message', 'TOTP disabled')
            except Exception:
                msg = 'TOTP disabled'
            flash(msg, 'success')
        else:
            try:
                detail = response.json().get('detail', response.text)
            except Exception:
                detail = 'Failed to disable TOTP'
            flash(str(detail), 'error')
    except Exception as e:
        flash(f'Failed to disable TOTP: {e}', 'error')
    return redirect(url_for('profile'))


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
        resp.delete_cookie('refresh_token')
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
    resp.delete_cookie('refresh_token')
    resp.delete_cookie('remember')
    resp.delete_cookie('matrix_access_token')
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


# --- Admin UI ---

def _is_admin_user(headers: dict) -> bool:
    try:
        r = requests.get(f"{BACKEND_URL}/user/profile", headers=headers, timeout=6)
        if r.status_code == 200:
            role = (r.json() or {}).get('role') or ''
            return str(role).lower() in {'admin','superadmin'}
    except Exception:
        pass
    return False

@app.route('/admin', methods=['GET','POST'])
def admin_page():
    headers = get_auth_headers()
    if not headers:
        flash('Please log in as an administrator.', 'warning')
        return redirect(url_for('login'))
    # Determine real admin vs demo admin (cookie-based)
    real_admin = _is_admin_user(headers)
    demo_admin = False
    try:
        demo_admin = (request.cookies.get('isadmin') or '').strip().lower() in {'1','true','yes','on'}
    except Exception:
        demo_admin = False
    if not real_admin and not demo_admin:
        flash('Administrator privileges required.', 'error')
        return redirect(url_for('home'))

    # Handle actions (only allowed for real admins)
    if request.method == 'POST' and not real_admin:
        flash('Demo mode: actions are disabled. Toggle is for viewing only.', 'warning')
        return redirect(url_for('admin_page'))

    # Handle actions
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        try:
            uid = int(user_id)
        except Exception:
            uid = 0
        try:
            if action in {'disable','enable'} and uid:
                disabled = (action == 'disable')
                r = requests.post(f"{BACKEND_URL}/admin/users/{uid}/disable", json={"disabled": disabled}, headers=headers, timeout=10)
                if r.status_code == 200:
                    flash(('User disabled' if disabled else 'User enabled'), 'success')
                else:
                    flash(r.text or 'Operation failed', 'error')
            elif action == 'set_role' and uid:
                role = (request.form.get('role') or '').strip().lower()
                r = requests.post(f"{BACKEND_URL}/admin/users/{uid}/role", json={"role": role}, headers=headers, timeout=10)
                flash('Role updated' if r.status_code == 200 else (r.text or 'Role update failed'), 'info' if r.status_code == 200 else 'error')
            elif action == 'reset_password' and uid:
                new_password = request.form.get('new_password')
                r = requests.post(f"{BACKEND_URL}/admin/users/{uid}/password", json={"new_password": new_password}, headers=headers, timeout=10)
                flash('Password reset' if r.status_code == 200 else (r.text or 'Password reset failed'), 'info' if r.status_code == 200 else 'error')
            elif action == 'logout' and uid:
                r = requests.post(f"{BACKEND_URL}/admin/users/{uid}/logout", headers=headers, timeout=10)
                flash('User sessions closed' if r.status_code == 200 else (r.text or 'Operation failed'), 'info' if r.status_code == 200 else 'error')
        except Exception as e:
            flash(f'Action failed: {e}', 'error')
        return redirect(url_for('admin_page'))

    # GET: load users
    users = []
    # In demo mode without real admin rights, do not call protected admin APIs
    if not real_admin:
        flash('Demo mode: viewing only. Data may be limited; actions are disabled.', 'info')
        element_base = f"{MATRIX_ELEMENT_URL}/#/room/"
        return render_template('admin.html', users=users, element_base=element_base, balance=None, last_user_id=None)
    try:
        r = requests.get(f"{BACKEND_URL}/admin/users", headers=headers, timeout=10)
        if r.status_code == 200:
            users = (r.json() or {}).get('users') or []
        else:
            flash(r.text or 'Failed to load users', 'error')
    except Exception as e:
        flash(f'Failed to load users: {e}', 'error')
    element_base = f"{MATRIX_ELEMENT_URL}/#/room/"
    return render_template('admin.html', users=users, element_base=element_base, balance=None, last_user_id=None)


@app.route('/admin/balance', methods=['GET','POST'])
def admin_balance():
    headers = get_auth_headers()
    if not headers:
        flash('Please log in as an administrator.', 'warning')
        return redirect(url_for('login'))
    real_admin = _is_admin_user(headers)
    demo_admin = False
    try:
        demo_admin = (request.cookies.get('isadmin') or '').strip().lower() in {'1','true','yes','on'}
    except Exception:
        demo_admin = False
    if not real_admin and not demo_admin:
        flash('Administrator privileges required.', 'error')
        return redirect(url_for('home'))

    bal = None
    last_user_id = None
    if request.method == 'GET':
        try:
            uid = int(request.args.get('user_id') or 0)
        except Exception:
            uid = 0
        last_user_id = uid or None
        if uid and real_admin:
            try:
                r = requests.get(f"{TRANSACTIONS_SERVICE_URL}/balance/{uid}", timeout=10)
                if r.status_code == 200:
                    bal = r.json()
                else:
                    flash(r.text or 'Failed to load balance', 'error')
            except Exception as e:
                flash(f'Failed to load balance: {e}', 'error')
        elif uid and not real_admin:
            flash('Demo mode: cannot fetch balances without admin privileges.', 'info')
    else:
        if not real_admin:
            flash('Demo mode: balance changes are disabled.', 'warning')
        else:
            try:
                uid = int(request.form.get('user_id') or 0)
                amt = float(request.form.get('amount_xmr') or '0')
                kind = request.form.get('kind') or 'fake'
                op = request.form.get('op')
                url = f"{TRANSACTIONS_SERVICE_URL}/balance/{uid}/increase" if op == 'increase' else f"{TRANSACTIONS_SERVICE_URL}/balance/{uid}/decrease"
                r = requests.post(url, json={"amount_xmr": amt, "kind": kind}, timeout=10)
                if r.status_code == 200:
                    bal = r.json()
                    flash('Balance updated', 'success')
                else:
                    flash(r.text or 'Balance update failed', 'error')
                last_user_id = uid
            except Exception as e:
                flash(f'Balance operation failed: {e}', 'error')
    # Load user list too for the table
    users = []
    if real_admin:
        try:
            r = requests.get(f"{BACKEND_URL}/admin/users", headers=headers, timeout=10)
            if r.status_code == 200:
                users = (r.json() or {}).get('users') or []
        except Exception:
            pass
    else:
        flash('Demo mode: user list hidden (requires real admin).', 'info')
    element_base = f"{MATRIX_ELEMENT_URL}/#/room/"
    return render_template('admin.html', users=users, element_base=element_base, balance=bal, last_user_id=last_user_id)


# Debug/admin switch (frontend only)
@app.route('/debug/isadmin/toggle')
def debug_isadmin_toggle():
    current = (request.cookies.get('isadmin') or '').strip().lower()
    new = '0'
    if current not in {'1', 'true', 'yes', 'on'}:
        new = '1'
    resp = make_response(redirect(request.referrer or url_for('home')))
    try:
        resp.set_cookie('isadmin', new, max_age=60 * 60 * 24 * 30, samesite=SESSION_COOKIE_SAMESITE,
                        secure=SECURE_COOKIES)
    except Exception:
        resp.set_cookie('isadmin', new)
    flash(('Admin mode enabled' if new == '1' else 'Admin mode disabled'), 'info')
    return resp


@app.route('/debug/isadmin/on')
def debug_isadmin_on():
    resp = make_response(redirect(request.referrer or url_for('home')))
    try:
        resp.set_cookie('isadmin', '1', max_age=60 * 60 * 24 * 30, samesite=SESSION_COOKIE_SAMESITE,
                        secure=SECURE_COOKIES)
    except Exception:
        resp.set_cookie('isadmin', '1')
    flash('Admin mode enabled', 'info')
    return resp


@app.route('/debug/isadmin/off')
def debug_isadmin_off():
    resp = make_response(redirect(request.referrer or url_for('home')))
    try:
        resp.set_cookie('isadmin', '0', max_age=60 * 60 * 24 * 30, samesite=SESSION_COOKIE_SAMESITE,
                        secure=SECURE_COOKIES)
    except Exception:
        resp.set_cookie('isadmin', '0')
    flash('Admin mode disabled', 'info')
    return resp


# Offers integration
@app.route('/offers', methods=['GET'])
def offers():
    # Require login to view offers
    if not request.cookies.get('access_token'):
        flash('Please log in to view offers.', 'warning')
        return redirect(url_for('login'))
    status = request.args.get('status')
    try:
        params = {'status': status} if status else {}
        resp = requests.get(f"{OFFERS_SERVICE_URL}/offers", params=params, timeout=10)
        offers = resp.json() if resp.status_code == 200 else []
        # Attach seller_name and parse side for clarity badges
        enriched = []
        for o in offers:
            o = _attach_seller_name(o)
            try:
                ad = _parse_offer_desc(o.get('desc'))
                o['__side'] = (ad.get('side') or 'sell').lower()
            except Exception:
                o['__side'] = 'sell'
            enriched.append(o)
        offers = enriched
    except Exception as e:
        offers = []
        flash(f'Failed to load offers: {e}', 'error')
    return render_template('offers.html', offers=offers)


@app.route('/offers/<offer_id>', methods=['GET'])
def offer_detail(offer_id: str):
    # Require login to view offer details
    if not request.cookies.get('access_token'):
        flash('Please log in to view offers.', 'warning')
        return redirect(url_for('login'))
    try:
        r = requests.get(f"{OFFERS_SERVICE_URL}/offers/{offer_id}", timeout=10)
        if r.status_code != 200:
            flash('Offer not found', 'error')
            return redirect(url_for('offers'))
        offer = r.json()
        offer = _attach_seller_name(offer)
        ad = _parse_offer_desc(offer.get('desc'))
        price_per_xmr = _compute_price_per_xmr(ad)
        ad['schedule_human'] = _humanize_schedule(ad.get('schedule'))
        # Compute clear role context for the current user
        uid = _get_logged_in_user_id() or 0
        seller_id, buyer_id, side = _resolve_roles_for_offer(offer, uid)
        is_user_buyer = (int(uid) == int(buyer_id))
        is_user_seller = (int(uid) == int(seller_id))
        # Self-trade guard: if roles resolve to the same user, block trade init
        self_trade_block = (int(seller_id or 0) == int(buyer_id or 0) and int(seller_id or 0) != 0)

        # Fetch reviews for the offer owner (who is always the one creating the offer)
        # offer owner id is what matters. 
        # _resolve_roles_for_offer: if offer is SELL side, owner is seller_id. If BUY side, owner is buyer_id.
        # But wait, logic in _resolve_roles_for_offer might be complex.
        # Let's rely on offer['user_id'] if available?
        # The offer dict from OFFERS_SERVICE usually has user_id.
        owner_id = offer.get('user_id')
        reviews_summary = None
        if owner_id:
            try:
                # We reuse headers if available or public endpoint?
                # /users/{id}/reviews is public in backend?
                # Backend: @app.get("/users/{user_id}/reviews", response_model=ReviewsSummary) -> public (no Depends(get_current_user))?
                # Check backend code: "def get_user_reviews(... session ...)" - It does NOT depend on current_user!
                # So we don't need auth headers necessarily, but using them is fine.
                r_rev = requests.get(f'{BACKEND_URL}/users/{owner_id}/reviews', timeout=5)
                if r_rev.status_code == 200:
                    reviews_summary = r_rev.json()
            except Exception:
                pass

        is_admin = False
        try:
            headers = get_auth_headers()
            if headers:
                resp = requests.get(f'{BACKEND_URL}/user/profile', headers=headers, timeout=5)
                if resp.status_code == 200:
                    u = resp.json() or {}
                    if u.get('role') in ('admin', 'superadmin'):
                        is_admin = True
        except Exception:
            pass

    except Exception as e:
        flash(f'Failed to load offer: {e}', 'error')
        return redirect(url_for('offers'))
    # Hide SELL offers from public when seller has no available XMR
    try:
        if (str(side).lower() == 'sell') and (not is_user_seller):
            sid = int(seller_id or 0)
            fb = _get_fake_balance(sid) if sid else None
            if fb is not None and fb <= 0.0:
                flash(
                    'This offer is temporarily hidden because the seller has insufficient XMR. It will be back when they have enough XMR.',
                    'info')
                return redirect(url_for('buy'))
    except Exception:
        pass
    return render_template('offer_detail.html', offer=offer, ad=ad, price_per_xmr=price_per_xmr, offer_side=side,
                           is_user_buyer=is_user_buyer, is_user_seller=is_user_seller,
                           self_trade_block=self_trade_block, reviews_summary=reviews_summary, is_admin=is_admin)


@app.route('/offers/<offer_id>/bid', methods=['POST'])
def offer_bid(offer_id: str):
    # Require login to start a trade
    if not request.cookies.get('access_token'):
        flash('Please log in to start a trade.', 'warning')
        return redirect(url_for('login'))

    # Prefer new dual-inputs
    fiat_amount_raw = request.form.get('fiat_amount')
    xmr_amount_raw = request.form.get('xmr_amount')
    viewer_id = _get_logged_in_user_id()

    def _to_float(val):
        try:
            return float(val)
        except Exception:
            return None

    fiat_amount = _to_float(fiat_amount_raw) if fiat_amount_raw not in (None, '') else None
    xmr_amount = _to_float(xmr_amount_raw) if xmr_amount_raw not in (None, '') else None

    # Fallback to legacy single-field format
    if fiat_amount is None and xmr_amount is None:
        amount_mode = request.form.get('amount_mode', 'fiat')  # 'fiat' or 'xmr'
        amount_value = _to_float(request.form.get('amount_value'))
        if amount_value is None or amount_value <= 0:
            flash('Invalid amount', 'error')
            return redirect(url_for('offer_detail', offer_id=offer_id))
        if amount_mode == 'xmr':
            xmr_amount = amount_value
        else:
            fiat_amount = amount_value

    # Fetch offer to compute price and XMR amount if needed
    try:
        r_offer = requests.get(f"{OFFERS_SERVICE_URL}/offers/{offer_id}", timeout=10)
        if r_offer.status_code != 200:
            flash('Offer not found', 'error')
            return redirect(url_for('offers'))
        offer = r_offer.json()
        ad = _parse_offer_desc(offer.get('desc'))
        price_per_xmr = _compute_price_per_xmr(ad)

        if (xmr_amount is None or xmr_amount <= 0) and fiat_amount is not None and fiat_amount > 0:
            xmr_amount = fiat_amount / price_per_xmr if price_per_xmr > 0 else 0

        if xmr_amount is None or xmr_amount <= 0:
            flash('Invalid amount', 'error')
            return redirect(url_for('offer_detail', offer_id=offer_id))

        # Enforce fiat min/max limits if provided in the offer description
        try:
            def _as_float(v):
                try:
                    s = (v or '').strip()
                    if s == '':
                        return None
                    return float(s)
                except Exception:
                    return None
            min_limit = _as_float(ad.get('min_limit'))
            max_limit = _as_float(ad.get('max_limit'))
            fiat_total = float(xmr_amount) * float(price_per_xmr)
            if min_limit is not None and fiat_total < min_limit:
                flash(f'Amount below minimum limit: {min_limit} {ad.get("fiat", "").upper()}', 'warning')
                return redirect(url_for('offer_detail', offer_id=offer_id))
            if max_limit is not None and fiat_total > max_limit:
                flash(f'Amount exceeds maximum limit: {max_limit} {ad.get("fiat", "").upper()}', 'warning')
                return redirect(url_for('offer_detail', offer_id=offer_id))
        except Exception:
            pass
    except Exception as e:
        flash(f'Failed to prepare trade: {e}', 'error')
        return redirect(url_for('offer_detail', offer_id=offer_id))

    # Call backend to create transaction
    # Prevent self-trade bids at UI level as well
    try:
        ro = requests.get(f"{OFFERS_SERVICE_URL}/offers/{offer_id}", timeout=10)
        if ro.status_code == 200:
            off = ro.json() or {}
            try:
                if int(off.get('seller_id') or 0) == int(viewer_id or 0):
                    flash("You cannot trade with yourself.", 'warning')
                    return redirect(url_for('offer_detail', offer_id=offer_id))
            except Exception:
                pass
    except Exception:
        pass
    try:
        r = requests.post(f"{OFFERS_SERVICE_URL}/offers/{offer_id}/bid",
                          json={'bid': xmr_amount, 'buyer_id': int(viewer_id or 0)}, timeout=10)
        if r.status_code == 200:
            tx_id = r.json().get('tx_id', '')
            flash(f'Trade started. Reference={tx_id}', 'success')
        else:
            try:
                detail = r.json().get('detail', r.text)
            except Exception:
                detail = r.text
            flash(f'Trade failed: {detail}', 'error')
    except Exception as e:
        flash(f'Trade failed: {e}', 'error')
    return redirect(url_for('offer_detail', offer_id=offer_id))


# --- Cached balance lookup (to avoid excessive API calls) ---
_BAL_CACHE: dict[int, dict] = {}


def _get_fake_balance(user_id: int) -> float | None:
    try:
        uid = int(user_id)
    except Exception:
        return None
    import time as _t
    now = _t.time()
    ent = _BAL_CACHE.get(uid)
    if ent and now - float(ent.get('ts', 0.0)) < 60.0:
        try:
            return float(ent.get('fake'))
        except Exception:
            return ent.get('fake')
    try:
        r = requests.get(f"{TRANSACTIONS_SERVICE_URL}/balance/{uid}", timeout=6)
        if r.status_code == 200:
            data = r.json() or {}
            fake = float(data.get('fake_xmr') or 0.0)
            _BAL_CACHE[uid] = {'ts': now, 'fake': fake}
            return fake
    except Exception:
        pass
    return None


# Bitpapa-like pages
@app.route('/buy', methods=['GET'])
def buy():
    # Require login to access buy offers page
    if not request.cookies.get('access_token'):
        flash('Please log in to view offers.', 'warning')
        return redirect(url_for('login'))
    # Capture filters for UI only (backend minimal)
    filters = {
        'crypto': request.args.get('crypto', 'XMR'),
        'amount': request.args.get('amount', ''),
        'fiat': request.args.get('fiat', 'EUR'),
        'payment': request.args.get('payment', ''),
        'no_id': request.args.get('no_id', '1'),
        'online_only': request.args.get('online_only', '1'),
    }
    # Fetch open offers
    offers = []
    try:
        resp = requests.get(f"{OFFERS_SERVICE_URL}/offers", params={'status': 'open'}, timeout=10)
        if resp.status_code == 200:
            raw = resp.json()
            viewer_id = _get_logged_in_user_id()
            # Show only offers where counterparty is selling (user wants to buy),
            # and hide SELL offers whose owner has no available XMR (fake_xmr <= 0)
            filtered = []
            for o in raw:
                try:
                    ad = _parse_offer_desc(o.get('desc'))
                    if (ad.get('side') or '').lower() != 'sell':
                        continue
                    # Hide if seller has no available XMR, except show to the owner themself
                    sid = 0
                    try:
                        sid = int(o.get('seller_id') or 0)
                    except Exception:
                        sid = 0
                    if sid and viewer_id and sid != viewer_id:
                        fb = _get_fake_balance(sid)
                        if fb is not None and fb <= 0.0:
                            # skip offers from sellers with no available XMR
                            continue
                    filtered.append(o)
                except Exception:
                    continue
            offers = [_attach_seller_name(o) for o in filtered]
    except Exception as e:
        flash(f'Failed to load offers: {e}', 'error')
    return render_template('buy.html', offers=offers, filters=filters)


@app.route('/sell', methods=['GET'])
def sell():
    # Require login to access sell offers page
    if not request.cookies.get('access_token'):
        flash('Please log in to view offers.', 'warning')
        return redirect(url_for('login'))
    filters = {
        'crypto': request.args.get('crypto', 'XMR'),
        'amount': request.args.get('amount', ''),
        'fiat': request.args.get('fiat', 'EUR'),
        'payment': request.args.get('payment', ''),
        'no_id': request.args.get('no_id', '1'),
        'online_only': request.args.get('online_only', '1'),
    }
    offers = []
    try:
        resp = requests.get(f"{OFFERS_SERVICE_URL}/offers", params={'status': 'open'}, timeout=10)
        if resp.status_code == 200:
            raw = resp.json()
            # Show only offers where counterparty is buying (user wants to sell)
            filtered = []
            for o in raw:
                try:
                    ad = _parse_offer_desc(o.get('desc'))
                    if (ad.get('side') or '').lower() == 'buy':
                        filtered.append(o)
                except Exception:
                    continue
            offers = [_attach_seller_name(o) for o in filtered]
    except Exception as e:
        flash(f'Failed to load offers: {e}', 'error')
    return render_template('sell.html', offers=offers, filters=filters)


@app.route('/ads/new', methods=['GET', 'POST'])
def create_ad():
    # Require login to access create ad page
    if not request.cookies.get('access_token'):
        flash('Please log in to create an ad.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        step = request.form.get('step', 'preview')
        # Collect fields
        # Build schedule structure
        schedule_mode = request.form.get('schedule_mode', '24h')
        if schedule_mode == '24h':
            schedule = {'mode': '24h'}
        else:
            days_map = {}
            for d in ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']:
                if request.form.get(f'day_{d}'):
                    t_start = (request.form.get(f'{d}_start') or '00:00')
                    t_end = (request.form.get(f'{d}_end') or '23:59')
                    days_map[d] = [{'start': t_start, 'end': t_end}]
            schedule = {'mode': 'weekly', 'days': days_map}
        payment_method = request.form.get('payment_method', '')
        price_mode = request.form.get('price_mode', 'market')
        ad = {
            'side': request.form.get('side', 'buy'),
            'crypto': request.form.get('crypto', 'XMR'),
            'country': request.form.get('country', ''),
            'fiat': request.form.get('fiat', 'EUR'),
            'price_mode': price_mode,
            'margin': request.form.get('margin', '0'),
            'fixed_price': request.form.get('fixed_price', ''),
            'pricing_equation': request.form.get('pricing_equation', ''),
            'schedule': schedule,
            'payment_method': payment_method,
            'payment_methods': [payment_method] if payment_method else [],
            'promo_text': request.form.get('promo_text', ''),
            'min_limit': request.form.get('min_limit', ''),
            'max_limit': request.form.get('max_limit', ''),
            'escrow_minutes': request.form.get('escrow_minutes', '60'),
            'req_phone': 'req_phone' in request.form,
            'req_id': 'req_id' in request.form,
            'trade_conditions': request.form.get('trade_conditions', ''),
        }
        # Human readable schedule for preview
        try:
            ad['schedule_human'] = _humanize_schedule(schedule)
        except Exception:
            ad['schedule_human'] = ''
        if step == 'confirm':
            # Submit to Offers backend with minimal fields; encode extras in desc
            ad_json = request.form.get('ad_json')
            if ad_json:
                try:
                    ad = json.loads(ad_json)
                except Exception:
                    pass
            pm_list = ad.get('payment_methods') or []
            pm_display = pm_list[0] if pm_list else 'Any'
            title = f"{(ad.get('side') or '').capitalize()} {ad.get('crypto', 'XMR')} via {pm_display} ({ad.get('fiat', 'EUR')})"
            desc_payload = {
                'side': ad.get('side'),
                'crypto': ad.get('crypto'),
                'country': ad.get('country'),
                'promo': ad.get('promo_text'),
                'fiat': ad.get('fiat'),
                'payment': ad.get('payment_method') or (pm_list[0] if pm_list else ''),
                'payment_methods': pm_list,
                'limits': {'min': ad.get('min_limit'), 'max': ad.get('max_limit')},
                'escrow_min': ad.get('escrow_minutes'),
                'requirements': {'phone': ad.get('req_phone'), 'id': ad.get('req_id')},
                'conditions': ad.get('trade_conditions'),
                'price_mode': ad.get('price_mode'),
                'margin': ad.get('margin'),
                'fixed_price': ad.get('fixed_price'),
                'equation_enabled': bool(ad.get('pricing_equation')),
                'pricing_equation': ad.get('pricing_equation'),
                'schedule': ad.get('schedule'),
                'seller_name': _get_logged_in_username(),
            }
            # Backend price is handled internally; UI provides a default placeholder value (1.0)
            try:
                price = float(request.form.get('price') or 1.0)
            except Exception:
                price = 1.0
            # Always bind the offer to the logged-in user as owner
            owner_id = _get_logged_in_user_id()
            payload = {
                'title': title,
                'desc': json.dumps(desc_payload),
                'price': price,
                'seller_id': int(owner_id) if owner_id else 0,
            }
            try:
                r = requests.post(f"{OFFERS_SERVICE_URL}/offers", json=payload, timeout=10)
                if r.status_code == 200:
                    flash('Ad created', 'success')
                    return redirect(url_for('my_ads'))
                else:
                    detail = r.text
                    try:
                        detail = r.json().get('detail', detail)
                    except Exception:
                        pass
                    flash(f'Create ad failed: {detail}', 'error')
            except Exception as e:
                flash(f'Create ad failed: {e}', 'error')
        # Preview step
        try:
            preview_price = _compute_price_per_xmr(ad)
        except Exception:
            try:
                preview_price = float(ad.get('fixed_price') or 250.0)
            except Exception:
                preview_price = 250.0
        return render_template('create_ad.html', preview=True, ad=ad, preview_price=preview_price)
    # GET, render blank form
    # Fetch cached market prices for client-side preview (avoid CORS by server-side fetch)
    market_prices = {}
    try:
        r = requests.get(f"{OFFERS_SERVICE_URL}/price", timeout=6)
        if r.status_code == 200:
            data = r.json() or {}
            market_prices = data.get('prices') or {}
    except Exception:
        market_prices = {}
    return render_template('create_ad.html', preview=False, market_prices=market_prices)


@app.route('/ads/mine', methods=['GET'])
def my_ads():
    # Require login to view personal ads
    if not request.cookies.get('access_token'):
        flash('Please log in to view your ads.', 'warning')
        return redirect(url_for('login'))
    offers = []
    uid = _get_logged_in_user_id()
    my_name = _get_logged_in_username()
    try:
        resp = requests.get(f"{OFFERS_SERVICE_URL}/offers", timeout=10)
        if resp.status_code == 200:
            all_offers = resp.json() or []
            # Enrich with seller_name for legacy entries
            all_offers = [_attach_seller_name(o) for o in all_offers]
            # Keep only current user's ads. Prefer seller_id; fallback to seller_name for legacy offers.
            filtered = []
            for o in all_offers:
                try:
                    sid = int(o.get('seller_id') or 0)
                except Exception:
                    sid = 0
                sname = (o.get('seller_name') or '').strip() if isinstance(o.get('seller_name'), str) else ''
                if (uid and sid == uid) or (my_name and sname and my_name == sname):
                    filtered.append(o)
            offers = filtered
    except Exception as e:
        flash(f'Failed to load offers: {e}', 'error')
    # Inform the owner that SELL offers are hidden when balance is insufficient
    try:
        fb = _get_fake_balance(uid)
        if fb is not None and fb <= 0.0:
            flash(
                'Your SELL offers are hidden because you have insufficient XMR. They will reappear when you have enough XMR.',
                'info')
    except Exception:
        pass
    return render_template('my_ads.html', offers=offers, my_name=my_name, my_user_id=uid)


@app.route('/ads/<offer_id>/delete', methods=['POST'])
def delete_ad(offer_id: str):
    if not request.cookies.get('access_token'):
        flash('Please log in to manage your ads.', 'warning')
        return redirect(url_for('login'))
    uid = _get_logged_in_user_id()
    # Verify ownership
    try:
        r = requests.get(f"{OFFERS_SERVICE_URL}/offers/{offer_id}", timeout=10)
        if r.status_code != 200:
            flash('Offer not found', 'error')
            return redirect(url_for('my_ads'))
        offer = r.json() or {}
        owner_id = int(offer.get('seller_id') or 0)
        if not uid or owner_id != uid:
            flash('Not authorized to delete this ad.', 'error')
            return redirect(url_for('my_ads'))
    except Exception as e:
        flash(f'Failed to load offer: {e}', 'error')
        return redirect(url_for('my_ads'))
    # Delete
    try:
        dr = requests.delete(f"{OFFERS_SERVICE_URL}/offers/{offer_id}", timeout=10)
        if dr.status_code in (200, 204):
            flash('Ad deleted', 'success')
        else:
            try:
                detail = dr.json().get('detail', dr.text)
            except Exception:
                detail = dr.text
            flash(f'Delete failed: {detail}', 'error')
    except Exception as e:
        flash(f'Delete failed: {e}', 'error')
    return redirect(url_for('my_ads'))


@app.route('/ads/<offer_id>/edit', methods=['GET', 'POST'])
def edit_ad(offer_id: str):
    if not request.cookies.get('access_token'):
        flash('Please log in to edit your ads.', 'warning')
        return redirect(url_for('login'))
    uid = _get_logged_in_user_id()
    # Load existing offer
    try:
        r = requests.get(f"{OFFERS_SERVICE_URL}/offers/{offer_id}", timeout=10)
        if r.status_code != 200:
            flash('Offer not found', 'error')
            return redirect(url_for('my_ads'))
        offer = r.json() or {}
    except Exception as e:
        flash(f'Failed to load offer: {e}', 'error')
        return redirect(url_for('my_ads'))
    owner_id = int(offer.get('seller_id') or 0)
    if not uid or owner_id != uid:
        flash('Not authorized to edit this ad.', 'error')
        return redirect(url_for('my_ads'))
    ad = _parse_offer_desc(offer.get('desc'))
    if request.method == 'POST':
        # Collect fields
        payment_method = request.form.get('payment_method', ad.get('payment_method') or '')
        price_mode = request.form.get('price_mode', ad.get('price_mode') or 'market')
        # Build schedule (keep simple: 24h or keep existing)
        schedule_mode = request.form.get('schedule_mode', ad.get('schedule', {}).get('mode', '24h'))
        schedule = {'mode': '24h'} if schedule_mode == '24h' else ad.get('schedule') or {'mode': '24h'}
        updated_ad = {
            'side': request.form.get('side', ad.get('side') or 'buy'),
            'crypto': request.form.get('crypto', ad.get('crypto') or 'XMR'),
            'country': request.form.get('country', ad.get('country') or ''),
            'fiat': request.form.get('fiat', ad.get('fiat') or 'EUR'),
            'price_mode': price_mode,
            'margin': request.form.get('margin', ad.get('margin') or '0'),
            'fixed_price': request.form.get('fixed_price', ad.get('fixed_price') or ''),
            'pricing_equation': request.form.get('pricing_equation', ad.get('pricing_equation') or ''),
            'schedule': schedule,
            'payment_method': payment_method,
            'payment_methods': [payment_method] if payment_method else (ad.get('payment_methods') or []),
            'promo_text': request.form.get('promo_text', ad.get('promo_text') or ''),
            'min_limit': request.form.get('min_limit', ad.get('min_limit') or ''),
            'max_limit': request.form.get('max_limit', ad.get('max_limit') or ''),
            'escrow_minutes': request.form.get('escrow_minutes', ad.get('escrow_minutes') or '60'),
            'req_phone': 'req_phone' in request.form if 'req_phone' in request.form else ad.get('req_phone', False),
            'req_id': 'req_id' in request.form if 'req_id' in request.form else ad.get('req_id', False),
            'trade_conditions': request.form.get('trade_conditions', ad.get('trade_conditions') or ''),
        }
        # Build desc payload as in create_ad
        pm_list = updated_ad.get('payment_methods') or []
        pm_display = pm_list[0] if pm_list else 'Any'
        title = request.form.get('title') or offer.get(
            'title') or f"{(updated_ad.get('side') or '').capitalize()} {updated_ad.get('crypto', 'XMR')} via {pm_display} ({updated_ad.get('fiat', 'EUR')})"
        desc_payload = {
            'side': updated_ad.get('side'),
            'crypto': updated_ad.get('crypto'),
            'country': updated_ad.get('country'),
            'promo': updated_ad.get('promo_text'),
            'fiat': updated_ad.get('fiat'),
            'payment': updated_ad.get('payment_method') or (pm_list[0] if pm_list else ''),
            'payment_methods': pm_list,
            'limits': {'min': updated_ad.get('min_limit'), 'max': updated_ad.get('max_limit')},
            'escrow_min': updated_ad.get('escrow_minutes'),
            'requirements': {'phone': updated_ad.get('req_phone'), 'id': updated_ad.get('req_id')},
            'conditions': updated_ad.get('trade_conditions'),
            'price_mode': updated_ad.get('price_mode'),
            'margin': updated_ad.get('margin'),
            'fixed_price': updated_ad.get('fixed_price'),
            'equation_enabled': bool(updated_ad.get('pricing_equation')),
            'pricing_equation': updated_ad.get('pricing_equation'),
            'schedule': updated_ad.get('schedule'),
            'seller_name': _get_logged_in_username(),
        }
        status = request.form.get('status') or offer.get('status')
        payload = {
            'title': title,
            'desc': json.dumps(desc_payload),
            'price': 1.0,
            'status': status,
        }
        try:
            ur = requests.put(f"{OFFERS_SERVICE_URL}/offers/{offer_id}", json=payload, timeout=10)
            if ur.status_code == 200:
                flash('Ad updated', 'success')
                return redirect(url_for('my_ads'))
            else:
                try:
                    detail = ur.json().get('detail', ur.text)
                except Exception:
                    detail = ur.text
                flash(f'Update failed: {detail}', 'error')
        except Exception as e:
            flash(f'Update failed: {e}', 'error')
    # GET mode: render edit form
    # Fetch cached market prices for client-side preview
    market_prices = {}
    try:
        rmp = requests.get(f"{OFFERS_SERVICE_URL}/price", timeout=6)
        if rmp.status_code == 200:
            data = rmp.json() or {}
            market_prices = data.get('prices') or {}
    except Exception:
        market_prices = {}
    return render_template('edit_ad.html', offer=offer, ad=ad, market_prices=market_prices)


@app.route('/ads/<offer_id>/update', methods=['POST'])
def update_ad(offer_id: str):
    # Require login
    if not request.cookies.get('access_token'):
        flash('Please log in to edit your ads.', 'warning')
        return redirect(url_for('login'))
    payload = {
        'title': request.form.get('title'),
        'price': request.form.get('price'),
        'status': request.form.get('status'),
    }
    # Convert price to float if provided
    try:
        if payload.get('price') not in (None, ''):
            payload['price'] = float(payload['price'])
        else:
            payload['price'] = None
    except Exception:
        payload['price'] = None
    try:
        r = requests.put(f"{OFFERS_SERVICE_URL}/offers/{offer_id}", json=payload, timeout=10)
        if r.status_code == 200:
            flash('Ad updated', 'success')
        else:
            try:
                detail = r.json().get('detail', r.text)
            except Exception:
                detail = r.text
            flash(f'Update failed: {detail}', 'error')
    except Exception as e:
        flash(f'Update failed: {e}', 'error')
    return redirect(url_for('my_ads'))


# Balances UI (Transactions service integration)

def _get_logged_in_user_id() -> int:
    try:
        headers = get_auth_headers()
        if not headers:
            return 0
        r = requests.get(f"{BACKEND_URL}/user/profile", headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return int(data.get('id') or 0)
    except Exception:
        return 0
    return 0


@app.route('/balances', methods=['GET'])
def balances():
    # Require login
    if not request.cookies.get('access_token'):
        flash('Please log in to view balances.', 'warning')
        return redirect(url_for('login'))
    user_id = _get_logged_in_user_id()
    if not user_id:
        flash('Could not identify user.', 'error')
        return redirect(url_for('login'))
    bal = None
    monero_address = None
    try:
        r = requests.get(f"{TRANSACTIONS_SERVICE_URL}/balance/{user_id}", timeout=10)
        if r.status_code == 200:
            bal = r.json()
        else:
            try:
                detail = r.json().get('detail', r.text)
            except Exception:
                detail = r.text
            flash(f'Failed to load balance: {detail}', 'error')
    except Exception as e:
        flash(f'Failed to load balance: {e}', 'error')
    # Also fetch user's Monero subaddresses via API Manager (monero service)
    subaddresses = []
    try:
        # OFFERS_SERVICE_URL points to API Manager base (e.g., http://api-manager:8000)
        r2 = requests.get(f"{OFFERS_SERVICE_URL}/monero/addresses", params={"user_id": user_id}, timeout=10)
        if r2.status_code == 200:
            addrs = r2.json() or []
            if isinstance(addrs, list) and addrs:
                try:
                    # Sort all by id desc (newest first)
                    subaddresses = sorted(addrs, key=lambda a: int(a.get('id') or 0), reverse=True)
                    # Prefer the newest non-disabled subaddress
                    active = [a for a in subaddresses if not bool(a.get('is_disabled', False))]
                    candidates = active if active else subaddresses
                    # Sort by id desc (fallback if created_at not comparable across py/JSON)
                    # candidates already sorted by id desc via subaddresses
                    monero_address = (candidates[0].get('address') or None) if candidates else None
                except Exception:
                    # Fallbacks
                    monero_address = addrs[0].get('address') or None
                    subaddresses = addrs
        else:
            # Non-fatal; just log to flash for visibility
            try:
                detail2 = r2.json().get('detail', r2.text)
            except Exception:
                detail2 = r2.text
            flash(f'Could not load Monero address: {detail2}', 'warning')
    except Exception as e:
        # Non-fatal
        flash(f'Could not load Monero address: {e}', 'warning')
    return render_template('balances.html', balance=bal, monero_address=monero_address, subaddresses=subaddresses)


@app.route('/balances/increase', methods=['POST'])
def balances_increase():
    if not request.cookies.get('access_token'):
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user_id = _get_logged_in_user_id()
    if not user_id:
        flash('Could not identify user.', 'error')
        return redirect(url_for('login'))
    kind = request.form.get('kind', 'fake')
    amt_raw = request.form.get('amount_xmr')
    try:
        amt = float(amt_raw)
    except Exception:
        flash('Invalid amount', 'error')
        return redirect(url_for('balances'))
    try:
        r = requests.post(f"{TRANSACTIONS_SERVICE_URL}/balance/{user_id}/increase",
                          json={"amount_xmr": amt, "kind": kind}, timeout=10)
        if r.status_code == 200:
            flash('Balance increased', 'success')
        else:
            try:
                detail = r.json().get('detail', r.text)
            except Exception:
                detail = r.text
            flash(f'Increase failed: {detail}', 'error')
    except Exception as e:
        flash(f'Increase failed: {e}', 'error')
    return redirect(url_for('balances'))


@app.route('/balances/decrease', methods=['POST'])
def balances_decrease():
    if not request.cookies.get('access_token'):
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user_id = _get_logged_in_user_id()
    if not user_id:
        flash('Could not identify user.', 'error')
        return redirect(url_for('login'))
    kind = request.form.get('kind', 'fake')
    amt_raw = request.form.get('amount_xmr')
    try:
        amt = float(amt_raw)
    except Exception:
        flash('Invalid amount', 'error')
        return redirect(url_for('balances'))
    try:
        r = requests.post(f"{TRANSACTIONS_SERVICE_URL}/balance/{user_id}/decrease",
                          json={"amount_xmr": amt, "kind": kind}, timeout=10)
        if r.status_code == 200:
            flash('Balance decreased', 'success')
        else:
            try:
                detail = r.json().get('detail', r.text)
            except Exception:
                detail = r.text
            flash(f'Decrease failed: {detail}', 'error')
    except Exception as e:
        flash(f'Decrease failed: {e}', 'error')
    return redirect(url_for('balances'))


@app.route('/balances/withdraw', methods=['POST'])
def balances_withdraw():
    if not request.cookies.get('access_token'):
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user_id = _get_logged_in_user_id()
    if not user_id:
        flash('Could not identify user.', 'error')
        return redirect(url_for('login'))
    to_address = request.form.get('to_address', '').strip()
    amt_raw = request.form.get('amount_xmr')
    try:
        amt = float(amt_raw)
    except Exception:
        flash('Invalid amount', 'error')
        return redirect(url_for('balances'))
    if not to_address:
        flash('Destination address is required', 'error')
        return redirect(url_for('balances'))
    try:
        # API Manager expects /transactions prefix; TRANSACTIONS_SERVICE_URL already includes it
        r = requests.post(f"{TRANSACTIONS_SERVICE_URL}/withdraw/{user_id}",
                          json={"to_address": to_address, "amount_xmr": amt}, timeout=30)
        if r.status_code == 200:
            try:
                data = r.json()
                txh = data.get('tx_hash') or ''
                flash(f'Withdrawal submitted. tx_hash={txh}', 'success')
            except Exception:
                flash('Withdrawal submitted.', 'success')
        else:
            try:
                detail = r.json().get('detail', r.text)
            except Exception:
                detail = r.text
            flash(f'Withdraw failed: {detail}', 'error')
    except Exception as e:
        flash(f'Withdraw failed: {e}', 'error')
    return redirect(url_for('balances'))


# --- In-memory Trade flow (database-money only) ---
TRADES: dict[str, dict] = {}
# Map user_id -> current active trade_id for quick access
ACTIVE_TRADE_ID_BY_USER: dict[int, str] = {}
# Map username -> current active trade_id (fallback for legacy offers with unknown owner IDs)
ACTIVE_TRADE_ID_BY_USERNAME: dict[str, str] = {}


# --- Matrix chat helpers ---

def _mx_username_for_user(user_id: int, username: str | None = None) -> str:
    """Return Matrix localpart for a user.

    Requirement: The Matrix account must use the USERNAME (not the ID).
    We therefore prefer a sanitized username as the localpart. If no username is
    available, we fall back to a deterministic id-based localpart to avoid failure.
    """
    # Prefer provided username when available
    raw = (username or '').strip().lower()
    if raw:
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._=-")
        local = ''.join(ch if ch in allowed else '_' for ch in raw).strip('_')
        if local:
            return local
    # Fallback to id-based localpart if username is missing/empty after sanitization
    try:
        uid = int(user_id)
        if uid > 0:
            return f"{MATRIX_USER_PREFIX}{uid}"
    except Exception:
        pass
    return f"{MATRIX_USER_PREFIX}0"


def _mx_mxid(username: str) -> str:
    # Build full MXID from localpart and server name
    return f"@{username}:{MATRIX_SERVER_NAME}"


def _mx_password_for_user(user_id: int) -> str:
    return f"pw-{int(user_id)}-{MATRIX_DEFAULT_PASSWORD_SECRET}"


def _matrix_register_if_needed(localpart: str, password: str) -> None:
    if not MATRIX_ENABLED:
        return
    url = f"{MATRIX_HS_URL_BACKEND}/_matrix/client/v3/register"
    payload = {
        "username": localpart,
        "password": password,
        "auth": {"type": "m.login.dummy"},
    }
    try:
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code in (200, 201):
            return
        # If user already exists, Synapse returns 400 with errcode M_USER_IN_USE
        try:
            data = r.json()
            if r.status_code == 400 and (data.get("errcode") == "M_USER_IN_USE"):
                return
        except Exception:
            pass
    except Exception:
        # Best-effort; creation might have already happened
        return


def _matrix_login(localpart: str, password: str) -> str | None:
    if not MATRIX_ENABLED:
        return None
    url = f"{MATRIX_HS_URL_BACKEND}/_matrix/client/v3/login"
    payload = {"type": "m.login.password", "user": localpart, "password": password}
    try:
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code == 200:
            tok = (r.json() or {}).get("access_token")
            return tok
    except Exception:
        return None
    return None


def _matrix_create_trade_room(creator_token: str, invite_mxids: list[str], trade_id: str, seller_name: str | None = None, buyer_name: str | None = None) -> tuple[str | None, str | None]:
    if not MATRIX_ENABLED or not creator_token:
        return None, None
    url = f"{MATRIX_HS_URL_BACKEND}/_matrix/client/v3/createRoom"
    headers = {"Authorization": f"Bearer {creator_token}"}
    alias_local = f"trade_{trade_id}"
    room_name = f"{seller_name or 'seller'}-{buyer_name or 'buyer'}-{trade_id}"
    payload = {
        "preset": "private_chat",
        "is_direct": True,
        "invite": list(dict.fromkeys(invite_mxids)),
        "name": room_name,
        "room_alias_name": alias_local,
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=8)
        if r.status_code in (200, 201):
            data = r.json() or {}
            room_id = data.get("room_id")
            alias = f"#" + alias_local + ":" + MATRIX_SERVER_NAME
            return room_id, alias
        else:
            # Retry without alias if alias conflict
            retry_payload = dict(payload)
            # Omit the alias field entirely to avoid Synapse TypeError on None
            retry_payload.pop("room_alias_name", None)
            r2 = requests.post(url, headers=headers, json=retry_payload, timeout=8)
            if r2.status_code in (200, 201):
                data = r2.json() or {}
                return data.get("room_id"), None
    except Exception:
        return None, None
    return None, None


def _matrix_setup_for_trade(seller_id: int, buyer_id: int, initiator_id: int, trade_id: str, seller_name: str | None = None, buyer_name: str | None = None, initiator_name: str | None = None) -> dict | None:
    if not MATRIX_ENABLED:
        return None
    try:
        # Resolve accurate localparts using backend info
        s_info = _fetch_user_info(seller_id)
        b_info = _fetch_user_info(buyer_id)
        
        # Update names for room naming if fetched
        if s_info and s_info.get('username'):
            seller_name = s_info['username']
        if b_info and b_info.get('username'):
            buyer_name = b_info['username']

        s_local = s_info.get('matrix_localpart') if s_info else None
        if not s_local:
             s_local = _mx_username_for_user(seller_id, s_info.get('username') if s_info else seller_name)

        b_local = b_info.get('matrix_localpart') if b_info else None
        if not b_local:
             b_local = _mx_username_for_user(buyer_id, b_info.get('username') if b_info else buyer_name)

        # Best-effort: ensure accounts exist for legacy flows (won't override existing)
        try:
            _matrix_register_if_needed(s_local, _mx_password_for_user(seller_id))
            _matrix_register_if_needed(b_local, _mx_password_for_user(buyer_id))
        except Exception:
            pass

        # Determine creator localpart from the resolved values
        creator_local = None
        if initiator_id == seller_id:
            creator_local = s_local
        elif initiator_id == buyer_id:
            creator_local = b_local
        else:
            creator_local = _mx_username_for_user(initiator_id, initiator_name)

        other_local = b_local if initiator_id == seller_id else s_local
        other_mxid = _mx_mxid(other_local)
        creator_mxid = _mx_mxid(creator_local)

        # Try to use an existing token (from cookie via APIManager login); fall back to deterministic login
        tok = _matrix_get_token_for_user(int(initiator_id))
        if not tok:
            tok = _matrix_login(creator_local, _mx_password_for_user(initiator_id))
        # Invite only the other participant (creator is joined automatically)
        room_id, alias = _matrix_create_trade_room(tok, [other_mxid], trade_id, seller_name, buyer_name)
        if room_id:
            return {
                "room_id": room_id,
                "alias": alias,
                "seller_mxid": _mx_mxid(s_local),
                "buyer_mxid": _mx_mxid(b_local),
            }
    except Exception:
        return None
    return None


def _gen_trade_id() -> str:
    return secrets.token_urlsafe(8)


def _get_active_trade_id_for_username(username: str) -> str | None:
    if not username:
        return None
    tid = ACTIVE_TRADE_ID_BY_USERNAME.get(username)
    if not tid:
        return None
    t = TRADES.get(tid)
    if not t or t.get('status') == 'completed':
        ACTIVE_TRADE_ID_BY_USERNAME.pop(username, None)
        return None
    return tid


def _get_active_trade_id_for_user(user_id: int) -> str | None:
    if not user_id:
        return None
    tid = ACTIVE_TRADE_ID_BY_USER.get(int(user_id))
    if not tid:
        return None
    t = TRADES.get(tid)
    if not t or t.get('status') == 'completed':
        # Cleanup mapping if stale
        ACTIVE_TRADE_ID_BY_USER.pop(int(user_id), None)
        return None
    return tid


# Inject active_trade_id into templates for navbar convenience
@app.context_processor
def inject_trade_shortcuts():
    tid = None
    is_admin = False
    try:
        # Admin mode comes from a simple cookie for debugging
        raw_admin = request.cookies.get('isadmin') or ''
        is_admin = raw_admin.strip().lower() in {'1', 'true', 'yes', 'on'}
    except Exception:
        is_admin = False
    try:
        if request.cookies.get('access_token'):
            uid = _get_logged_in_user_id()
            uname = _get_logged_in_username()
            # Try quick mappings first
            tid = _get_active_trade_id_for_user(uid)
            if not tid:
                tid = _get_active_trade_id_for_username(uname)
            # Fallback: scan in-memory trades to discover active ones involving this user
            if not tid:
                for t in list(TRADES.values()):
                    try:
                        if t.get('status') == 'completed':
                            continue
                        buyer_id = int(t.get('buyer_id') or 0)
                        seller_id = int(t.get('seller_id') or 0)
                        buyer_name = t.get('buyer_name')
                        seller_name = t.get('seller_name')
                        is_participant = (
                                (uid and uid in (buyer_id, seller_id)) or
                                (uname and uname in {buyer_name, seller_name})
                        )
                        if is_participant:
                            tid = t.get('id')
                            # Backfill quick-access caches so the navbar stays consistent
                            if seller_id:
                                ACTIVE_TRADE_ID_BY_USER[seller_id] = tid
                            if buyer_id:
                                ACTIVE_TRADE_ID_BY_USER[buyer_id] = tid
                            if seller_name:
                                ACTIVE_TRADE_ID_BY_USERNAME[seller_name] = tid
                            if buyer_name:
                                ACTIVE_TRADE_ID_BY_USERNAME[buyer_name] = tid
                            break
                    except Exception:
                        continue
    except Exception:
        tid = None
    return dict(active_trade_id=tid, is_admin=is_admin)


# Quick access to current active trade for the logged-in user
@app.route('/trade/current', methods=['GET'])
def trade_current():
    if not request.cookies.get('access_token'):
        flash('Please log in to view your trade.', 'warning')
        return redirect(url_for('login'))
    uid = _get_logged_in_user_id()
    tid = _get_active_trade_id_for_user(uid)
    if not tid:
        uname = _get_logged_in_username()
        tid = _get_active_trade_id_for_username(uname)
    if tid:
        return redirect(url_for('trade_view', trade_id=tid))
    flash('No active trade found.', 'info')
    return redirect(url_for('offers'))


# List all trades (in this process) involving the current user
@app.route('/trades', methods=['GET'])
def trades_list():
    if not request.cookies.get('access_token'):
        flash('Please log in to view trades.', 'warning')
        return redirect(url_for('login'))
    uid = _get_logged_in_user_id()
    uname = _get_logged_in_username()
    my_trades = []
    # Make a shallow copy to avoid concurrent modification surprises
    for t in list(TRADES.values()):
        try:
            matched = False
            role = None
            # Match by user_id first
            if int(t.get('buyer_id')) == uid:
                matched = True
                role = 'buyer'
            elif int(t.get('seller_id')) == uid:
                matched = True
                role = 'seller'
            # Fallback: match by username if ids are missing/legacy
            if not matched and uname:
                if uname == t.get('buyer_name'):
                    matched = True
                    role = 'buyer'
                elif uname == t.get('seller_name'):
                    matched = True
                    role = 'seller'
            if matched:
                my_trades.append({**t, 'role': role})
        except Exception:
            continue
    # Sort newest first
    my_trades.sort(key=lambda x: x.get('created_at', 0), reverse=True)
    return render_template('trades.html', trades=my_trades, user_id=uid)


def _resolve_roles_for_offer(offer: dict, current_user_id: int) -> tuple[int, int, str]:
    """
    Return (seller_id, buyer_id, side) where side is the offer side ('sell' means offer owner sells XMR).
    If offer side is 'buy', the current user is the seller (providing XMR) and offer owner is the buyer.

    More robustly resolves the offer owner id by falling back to common fields when `seller_id` is missing:
    - seller_id
    - owner_id
    - user_id
    - creator_id
    - seller.id / owner.id / user.id (dict forms)
    """
    # Resolve side safely
    try:
        raw_desc = offer.get('desc')
        ad = _parse_offer_desc(raw_desc)
        side = (ad.get('side') or 'sell').lower()
    except Exception:
        side = 'sell'

    def _to_int(v) -> int:
        try:
            return int(v)
        except Exception:
            return 0

    # Try several common owner fields
    offer_owner_id = _to_int(offer.get('seller_id'))
    if not offer_owner_id:
        offer_owner_id = _to_int(offer.get('owner_id'))
    if not offer_owner_id:
        offer_owner_id = _to_int(offer.get('user_id'))
    if not offer_owner_id:
        offer_owner_id = _to_int(offer.get('creator_id'))
    if not offer_owner_id:
        # Nested dict variants
        for key in ('seller', 'owner', 'user'):
            ent = offer.get(key)
            if isinstance(ent, dict):
                offer_owner_id = _to_int(ent.get('id'))
                if offer_owner_id:
                    break

    # Return roles based on side
    if side == 'sell':
        # Offer owner is providing XMR
        return offer_owner_id, current_user_id, 'sell'
    else:
        # Current user provides XMR to the offer owner
        return current_user_id, offer_owner_id, 'buy'


@app.route('/offers/<offer_id>/trade/start', methods=['POST'])
def trade_start(offer_id: str):
    # Require login
    if not request.cookies.get('access_token'):
        flash('Please log in to start a trade.', 'warning')
        return redirect(url_for('login'))
    user_id = _get_logged_in_user_id()
    if not user_id:
        flash('Could not identify user.', 'error')
        return redirect(url_for('login'))

    # Parse amounts similar to offer_bid
    fiat_amount_raw = request.form.get('fiat_amount')
    xmr_amount_raw = request.form.get('xmr_amount')
    # Optional initial chat message to counterparty
    initial_message = None
    try:
        initial_message = (request.form.get('message') or '').strip()
    except Exception:
        initial_message = None

    def _to_float(val):
        try:
            return float(val)
        except Exception:
            return None

    fiat_amount = _to_float(fiat_amount_raw) if fiat_amount_raw not in (None, '') else None
    xmr_amount = _to_float(xmr_amount_raw) if xmr_amount_raw not in (None, '') else None

    # Fetch offer and compute XMR if needed
    try:
        r_offer = requests.get(f"{OFFERS_SERVICE_URL}/offers/{offer_id}", timeout=10)
        if r_offer.status_code != 200:
            flash('Offer not found', 'error')
            return redirect(url_for('offers'))
        offer = r_offer.json()
        ad = _parse_offer_desc(offer.get('desc'))
        price_per_xmr = _compute_price_per_xmr(ad)
        if (xmr_amount is None or xmr_amount <= 0) and fiat_amount is not None and fiat_amount > 0:
            xmr_amount = fiat_amount / price_per_xmr if price_per_xmr > 0 else 0
        if xmr_amount is None or xmr_amount <= 0:
            flash('Invalid amount', 'error')
            return redirect(url_for('offer_detail', offer_id=offer_id))
        # Enforce fiat min/max limits if provided in the offer description
        try:
            def _as_float(v):
                try:
                    s = (v or '').strip()
                    if s == '':
                        return None
                    return float(s)
                except Exception:
                    return None
            min_limit = _as_float(ad.get('min_limit'))
            max_limit = _as_float(ad.get('max_limit'))
            fiat_total = float(xmr_amount) * float(price_per_xmr)
            if min_limit is not None and fiat_total < min_limit:
                flash(f'Amount below minimum limit: {min_limit} {ad.get("fiat", "").upper()}', 'warning')
                return redirect(url_for('offer_detail', offer_id=offer_id))
            if max_limit is not None and fiat_total > max_limit:
                flash(f'Amount exceeds maximum limit: {max_limit} {ad.get("fiat", "").upper()}', 'warning')
                return redirect(url_for('offer_detail', offer_id=offer_id))
        except Exception:
            pass
    except Exception as e:
        flash(f'Failed to prepare trade: {e}', 'error')
        return redirect(url_for('offer_detail', offer_id=offer_id))

    # Determine roles
    seller_id, buyer_id, side = _resolve_roles_for_offer(offer, user_id)
    # Prevent self-trade
    try:
        if int(seller_id or 0) == int(buyer_id or 0):
            flash('You cannot open a trade with yourself.', 'warning')
            return redirect(url_for('offer_detail', offer_id=offer_id))
    except Exception:
        pass

    # Derive participant usernames for fallback authorization/alerts
    offer_owner_name = ""
    try:
        ad_names = _parse_offer_desc(offer.get('desc'))
        offer_owner_name = ad_names.get('seller_name') or ""
    except Exception:
        offer_owner_name = ""
    current_name = _get_logged_in_username() or ""
    if str(side).lower() == 'sell':
        seller_name = offer_owner_name
        buyer_name = current_name
    else:
        seller_name = current_name
        buyer_name = offer_owner_name

    # Pre-check balances to avoid confusing errors
    try:
        sid_int = int(seller_id or 0)
        if sid_int and float(xmr_amount) > 0:
            fb = _get_fake_balance(sid_int)
            if fb is not None and fb < float(xmr_amount):
                if str(side).lower() == 'sell':
                    flash('Seller has insufficient XMR to escrow the requested amount. Please try later or choose another offer.', 'error')
                else:
                    flash('You do not have enough XMR to sell this amount. Please reduce the amount or deposit more XMR.', 'error')
                return redirect(url_for('offer_detail', offer_id=offer_id))
    except Exception:
        pass

    # Create trade id early to tie reservation context
    trade_id = _gen_trade_id()

    # Reserve seller's XMR immediately (escrow lock)
    try:
        reserve_payload = {
            'seller_id': int(seller_id),
            'amount_xmr': float(xmr_amount),
            'offer_id': str(offer.get('id')) if offer.get('id') is not None else None,
            'trade_id': trade_id,
        }
        r_res = requests.post(f"{TRANSACTIONS_SERVICE_URL}/reserve", json=reserve_payload, timeout=10)

        if r_res.status_code != 200:
            try:
                detail = r_res.json().get('detail', r_res.text)
            except Exception:
                detail = r_res.text
            if isinstance(detail, str) and 'Insufficient fake balance' in detail and str(side).lower() == 'sell':
                detail = 'Seller has insufficient XMR to escrow at the moment. Please try again later or choose another offer.'
            flash(f'Cannot open trade: {detail}', 'error')
            return redirect(url_for('offer_detail', offer_id=offer_id))
        res_body = r_res.json() or {}
        reservation_id = res_body.get('id')
        if not reservation_id:
            flash('Cannot open trade: reservation failed (no id)', 'error')
            return redirect(url_for('offer_detail', offer_id=offer_id))
    except Exception as e:
        flash(f'Cannot open trade: {e}', 'error')
        return redirect(url_for('offer_detail', offer_id=offer_id))

    # Create trade in memory
    TRADES[trade_id] = {
        'id': trade_id,
        'offer_id': offer.get('id'),
        'offer_title': offer.get('title'),
        'seller_id': seller_id,
        'buyer_id': buyer_id,
        'seller_name': seller_name,
        'buyer_name': buyer_name,
        'amount_xmr': float(xmr_amount),
        'status': 'await_buyer',  # buyer must send fiat, then click Money sent
        'side': side,
        'created_at': int(time.time()),
        'buyer_confirmed_at': None,
        'seller_confirmed_at': None,
        'completed_at': None,
        'reservation_id': reservation_id,
        'last_error': None,
    }
    # Set quick-access mapping for both participants
    if int(seller_id):
        ACTIVE_TRADE_ID_BY_USER[int(seller_id)] = trade_id
    if int(buyer_id):
        ACTIVE_TRADE_ID_BY_USER[int(buyer_id)] = trade_id
    if seller_name:
        ACTIVE_TRADE_ID_BY_USERNAME[seller_name] = trade_id
    if buyer_name:
        ACTIVE_TRADE_ID_BY_USERNAME[buyer_name] = trade_id
    # Setup Matrix chat room for this trade (best-effort)
    try:
        mx = _matrix_setup_for_trade(seller_id, buyer_id, user_id, trade_id, seller_name=seller_name, buyer_name=buyer_name, initiator_name=current_name)
        if mx:
            TRADES[trade_id]['matrix'] = mx
        else:
            TRADES[trade_id]['matrix'] = None
    except Exception as e:
        TRADES[trade_id]['matrix'] = None
        TRADES[trade_id]['last_error'] = f"matrix_setup_failed: {e}"

    # If an initial message was provided, send it as the very first chat message (best-effort)
    try:
        if initial_message and TRADES[trade_id].get('matrix'):
            tok = _matrix_get_token_for_user(int(user_id))
            rid = _matrix_resolve_room_id_for_trade(TRADES[trade_id])
            if tok and rid:
                _matrix_ensure_join(tok, rid)
                _matrix_send_message(tok, rid, str(initial_message))
    except Exception:
        # Ignore failures; chat UI will still work
        pass

    return redirect(url_for('trade_view', trade_id=trade_id))


@app.route('/trade/<trade_id>', methods=['GET'])
def trade_view(trade_id: str):
    if not request.cookies.get('access_token'):
        flash('Please log in to view trade.', 'warning')
        return redirect(url_for('login'))
    user_id = _get_logged_in_user_id()
    t = TRADES.get(trade_id)
    if not t:
        flash('Trade not found', 'error')
        return redirect(url_for('offers'))
    if user_id not in (t['buyer_id'], t['seller_id']):
        uname = _get_logged_in_username()
        if not uname or uname not in {t.get('buyer_name'), t.get('seller_name')}:
            flash('Not authorized for this trade', 'error')
            return redirect(url_for('offers'))
    # Resolve role (user_id first, then username fallback)
    if user_id == t['buyer_id']:
        role = 'buyer'
    elif user_id == t['seller_id']:
        role = 'seller'
    else:
        uname = _get_logged_in_username()
        if uname == t.get('buyer_name'):
            role = 'buyer'
        else:
            role = 'seller'
    # Build Matrix embed URL if available
    matrix_embed_url = None
    try:
        mx = t.get('matrix') or {}
        target = mx.get('alias') or mx.get('room_id')
        if target and MATRIX_ELEMENT_URL:
            matrix_embed_url = f"{MATRIX_ELEMENT_URL}/#/room/{target}"
    except Exception:
        matrix_embed_url = None
    
    # Fetch reviews if completed
    reviews = []
    can_review = False
    if t.get('status') == 'completed':
        try:
             headers = get_auth_headers()
             if headers:
                 rr = requests.get(f"{BACKEND_URL}/reviews/by-trade/{trade_id}", headers=headers, timeout=5)
                 if rr.status_code == 200:
                     reviews = rr.json()
        except Exception:
             pass
        
        # Check if I reviewed
        my_review = next((r for r in reviews if r.get('reviewer_user_id') == user_id), None)
        can_review = (my_review is None)

    is_admin = False
    try:
        headers = get_auth_headers()
        if headers:
            resp = requests.get(f'{BACKEND_URL}/user/profile', headers=headers, timeout=5)
            if resp.status_code == 200:
                u = resp.json() or {}
                if u.get('role') in ('admin', 'superadmin'):
                    is_admin = True
    except Exception:
        pass

    return render_template('trade.html', trade=t, role=role, matrix_embed_url=matrix_embed_url, reviews=reviews, can_review=can_review, is_admin=is_admin)


@app.route('/trade/<trade_id>/money_sent', methods=['POST'])
def trade_money_sent(trade_id: str):
    if not request.cookies.get('access_token'):
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user_id = _get_logged_in_user_id()
    t = TRADES.get(trade_id)
    if not t:
        flash('Trade not found', 'error')
        return redirect(url_for('offers'))
    if user_id != t['buyer_id']:
        flash('Only the buyer can mark money as sent.', 'error')
        return redirect(url_for('trade_view', trade_id=trade_id))
    if t['status'] != 'await_buyer':
        flash('Invalid trade state.', 'warning')
        return redirect(url_for('trade_view', trade_id=trade_id))
    t['status'] = 'await_seller'
    t['buyer_confirmed_at'] = int(time.time())
    TRADES[trade_id] = t
    flash('Marked as money sent. Waiting for seller confirmation.', 'info')
    return redirect(url_for('trade_view', trade_id=trade_id))


@app.route('/trade/<trade_id>/payment_received', methods=['POST'])
def trade_payment_received(trade_id: str):
    if not request.cookies.get('access_token'):
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user_id = _get_logged_in_user_id()
    t = TRADES.get(trade_id)
    if not t:
        flash('Trade not found', 'error')
        return redirect(url_for('offers'))
    if user_id != t['seller_id']:
        flash('Only the seller can confirm payment received.', 'error')
        return redirect(url_for('trade_view', trade_id=trade_id))
    if t['status'] != 'await_seller':
        flash('Buyer has not marked money sent yet.', 'warning')
        return redirect(url_for('trade_view', trade_id=trade_id))

    # Commit escrow reservation to transfer from seller -> buyer
    reservation_id = t.get('reservation_id')
    if not reservation_id:
        t['last_error'] = 'Reservation not found for this trade.'
        TRADES[trade_id] = t
        flash('Transfer failed: reservation missing', 'error')
        return redirect(url_for('trade_view', trade_id=trade_id))
    payload = {
        'to_user_id': int(t['buyer_id']),
    }
    try:
        r = requests.post(f"{TRANSACTIONS_SERVICE_URL}/reserve/{reservation_id}/commit", json=payload, timeout=15)
        if r.status_code == 200:
            try:
                res = r.json()
            except Exception:
                res = {}
            t['status'] = 'completed'
            t['seller_confirmed_at'] = int(time.time())
            t['completed_at'] = t['seller_confirmed_at']
            t['ledger_tx'] = res
            t['last_error'] = None
            TRADES[trade_id] = t
            # Clear quick-access entries if they point to this completed trade
            sid = int(t['seller_id'])
            bid = int(t['buyer_id'])
            if ACTIVE_TRADE_ID_BY_USER.get(sid) == trade_id:
                ACTIVE_TRADE_ID_BY_USER.pop(sid, None)
            if ACTIVE_TRADE_ID_BY_USER.get(bid) == trade_id:
                ACTIVE_TRADE_ID_BY_USER.pop(bid, None)
            # Also clear username-based quick-access mappings
            sname = t.get('seller_name')
            bname = t.get('buyer_name')
            if sname and ACTIVE_TRADE_ID_BY_USERNAME.get(sname) == trade_id:
                ACTIVE_TRADE_ID_BY_USERNAME.pop(sname, None)
            if bname and ACTIVE_TRADE_ID_BY_USERNAME.get(bname) == trade_id:
                ACTIVE_TRADE_ID_BY_USERNAME.pop(bname, None)
            
            # Increment successful trades count for both parties
            try:
                requests.post(f"{BACKEND_URL}/users/{int(t['buyer_id'])}/increment_trades", timeout=5)
                requests.post(f"{BACKEND_URL}/users/{int(t['seller_id'])}/increment_trades", timeout=5)
            except Exception as e:
                logging.error(f"Failed to increment trade count: {e}")

            flash('Trade completed. XMR transferred (escrow committed).', 'success')
        else:
            try:
                detail = r.json().get('detail', r.text)
            except Exception:
                detail = r.text
            t['last_error'] = str(detail)
            TRADES[trade_id] = t
            flash(f'Transfer failed: {detail}', 'error')
    except Exception as e:
        t['last_error'] = str(e)
        TRADES[trade_id] = t
        flash(f'Transfer failed: {e}', 'error')
    return redirect(url_for('trade_view', trade_id=trade_id))


@app.route('/trade/<trade_id>/review', methods=['POST'])
def submit_review(trade_id: str):
    headers = get_auth_headers()
    if not headers:
        return redirect(url_for('login'))
    
    rating = request.form.get('rating')
    comment = request.form.get('comment')
    
    t = TRADES.get(trade_id)
    if not t:
        flash('Trade not found', 'error')
        return redirect(url_for('offers'))
    
    user_id = _get_logged_in_user_id()
    if user_id == t['buyer_id']:
        reviewee_id = t['seller_id']
    elif user_id == t['seller_id']:
        reviewee_id = t['buyer_id']
    else:
        flash('Not authorized', 'error')
        return redirect(url_for('trade_view', trade_id=trade_id))
        
    payload = {
        "trade_id": trade_id,
        "reviewee_user_id": int(reviewee_id),
        "rating": int(rating),
        "comment": comment
    }
    
    try:
        r = requests.post(f"{BACKEND_URL}/reviews", json=payload, headers=headers, timeout=10)
        if r.status_code == 200:
             flash('Review submitted!', 'success')
        else:
             try:
                 err = r.json().get('detail', r.text)
             except:
                 err = r.text
             flash(f'Review failed: {err}', 'error')
    except Exception as e:
        flash(f'Review failed: {e}', 'error')
        
    return redirect(url_for('trade_view', trade_id=trade_id))


@app.route('/admin/reviews/<int:review_id>/delete', methods=['POST'])
def delete_review(review_id: int):
    headers = get_auth_headers()
    if not headers:
        return redirect(url_for('login'))
    
    try:
        r = requests.delete(f"{BACKEND_URL}/admin/reviews/{review_id}", headers=headers, timeout=5)
        if r.status_code == 200:
            flash('Review deleted.', 'success')
        else:
             try:
                 err = r.json().get('detail', r.text)
             except:
                 err = r.text
             flash(f'Delete failed: {err}', 'error')
    except Exception as e:
        flash(f'Delete failed: {e}', 'error')
    
    return redirect(request.referrer or url_for('profile'))


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

# Matrix Client-Server API reverse proxy at /matrix → Synapse /_matrix
@app.route('/matrix', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
@app.route('/matrix/<path:subpath>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
def matrix_proxy(subpath: str):
    base = MATRIX_HS_URL_BACKEND.rstrip('/')
    target = f"{base}/{subpath}" if subpath else base
    # Forward method, headers (without Host/Content-Length), and body
    hop = {'host', 'content-length', 'connection', 'upgrade', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding'}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in hop}
    try:
        resp_up = requests.request(
            method=request.method,
            url=target,
            params=request.args,
            data=(request.get_data() if request.method not in ('GET', 'HEAD') else None),
            headers=headers,
            stream=True,
            timeout=30,
        )
    except Exception as e:
        return make_response(f"Matrix backend unavailable: {e}", 502)
    # Build downstream response
    out = Response(
        resp_up.iter_content(chunk_size=4096),
        status=resp_up.status_code,
        content_type=resp_up.headers.get('Content-Type')
    )
    # Copy common headers
    for h in ['Cache-Control', 'ETag', 'Last-Modified', 'Expires']:
        if h in resp_up.headers:
            out.headers[h] = resp_up.headers[h]
    return out


# --- Reverse proxy for Matrix Element to avoid localhost:8080 dependency ---
ELEMENT_BACKEND_BASE = os.getenv("ELEMENT_BACKEND_BASE", "http://pupero-matrix-element").strip()
# --- Reverse proxy for Monero Explorer to make it available under /explorer even without K8s ---
EXPLORER_BACKEND_BASE = os.getenv("EXPLORER_BACKEND_BASE", "http://explore:8081").strip()

@app.route('/chat', defaults={'path': ''})
@app.route('/chat/<path:path>')
def element_proxy(path):
    target = f"{ELEMENT_BACKEND_BASE}/{path}"
    if request.query_string:
        target += '?' + request.query_string.decode()

    upstream = requests.get(target, stream=True)
    resp = Response(
        upstream.iter_content(chunk_size=4096),
        status=upstream.status_code,
        content_type=upstream.headers.get('Content-Type'),
    )

    # Adjust HTML base for SPA routing
    if 'text/html' in upstream.headers.get('Content-Type', ''):
        html = upstream.text
        if '<base ' not in html:
            html = html.replace('<head>', '<head><base href="/element/">', 1)
        resp.set_data(html.encode('utf-8'))

    return resp

@app.route('/element', defaults={'path': ''}, methods=['GET', 'HEAD'])
@app.route('/element/', defaults={'path': ''}, methods=['GET', 'HEAD'])
@app.route('/element/<path:path>', methods=['GET', 'HEAD'])
def element_proxy_webui(path: str):
    # Build upstream URL
    base = ELEMENT_BACKEND_BASE.rstrip('/')
    target = f"{base}/"
    if path:
        target = f"{base}/{path}"
    qs = request.query_string.decode('utf-8') if request.query_string else ''
    if qs:
        target = target + ("&" if "?" in target else "?") + qs
    try:
        # Proxy using the same method (GET/HEAD)
        method = request.method
        upstream = requests.request(method, target, stream=True, timeout=15)
        status = upstream.status_code
        content = upstream.content
        headers = dict(upstream.headers)

        # If HTML, inject <base href="/element/"> only. Avoid additional rewriting
        # to prevent double /element/ prefixes like /element/element/... in assets.
        ct = headers.get('Content-Type', '')
        if isinstance(content, (bytes, bytearray)) and 'text/html' in ct.lower():
            try:
                html = content.decode('utf-8', errors='ignore')
                # Inject base into <head> if not present
                if '<base ' not in html:
                    html = html.replace('<head>', '<head><base href="/element/">', 1)
                content = html.encode('utf-8')
            except Exception:
                pass

        resp = make_response(content, status)
        # Copy essential headers
        for h in ['Content-Type', 'Cache-Control', 'ETag', 'Last-Modified', 'Expires']:
            if h in headers:
                resp.headers[h] = headers[h]
        return resp
    except Exception as e:
        return make_response(f"Element backend unavailable: {e}", 502)


# Fallback proxies for common Element root-relative paths when embedded under /element
@app.route('/config.json', methods=['GET', 'HEAD'])
def element_config_proxy():
    try:
        upstream = requests.request(request.method, f"{ELEMENT_BACKEND_BASE.rstrip('/')}/config.json", timeout=15)
        resp = make_response(upstream.content, upstream.status_code)
        for h in ['Content-Type', 'Cache-Control', 'ETag', 'Last-Modified', 'Expires']:
            if h in upstream.headers:
                resp.headers[h] = upstream.headers[h]
        return resp
    except Exception as e:
        return make_response(f"Element config unavailable: {e}", 502)


@app.route('/bundles/<path:path>', methods=['GET', 'HEAD'])
def element_bundles_proxy(path: str):
    try:
        upstream = requests.request(request.method, f"{ELEMENT_BACKEND_BASE.rstrip('/')}/bundles/{path}", timeout=15)
        resp = make_response(upstream.content, upstream.status_code)
        for h in ['Content-Type', 'Cache-Control', 'ETag', 'Last-Modified', 'Expires']:
            if h in upstream.headers:
                resp.headers[h] = upstream.headers[h]
        return resp
    except Exception as e:
        return make_response(f"Element asset unavailable: {e}", 502)


@app.route('/olm.wasm', methods=['GET', 'HEAD'])
@app.route('/version', methods=['GET', 'HEAD'])
@app.route('/favicon.ico', methods=['GET', 'HEAD'])
def element_misc_proxy():
    try:
        # Map the request path directly to Element backend root
        req_path = request.path.lstrip('/')
        upstream = requests.request(request.method, f"{ELEMENT_BACKEND_BASE.rstrip('/')}/{req_path}", timeout=15)
        resp = make_response(upstream.content, upstream.status_code)
        for h in ['Content-Type', 'Cache-Control', 'ETag', 'Last-Modified', 'Expires']:
            if h in upstream.headers:
                resp.headers[h] = upstream.headers[h]
        return resp
    except Exception as e:
        return make_response(f"Element resource unavailable: {e}", 502)


# --- Reverse proxy for Monero Explorer under /explorer ---
@app.route('/explorer', defaults={'path': ''}, methods=['GET', 'HEAD'])
@app.route('/explorer/', defaults={'path': ''}, methods=['GET', 'HEAD'])
@app.route('/explorer/<path:path>', methods=['GET', 'HEAD'])
def explorer_proxy(path: str):
    base = EXPLORER_BACKEND_BASE.rstrip('/')
    target = f"{base}/"
    if path:
        target = f"{base}/{path}"
    qs = request.query_string.decode('utf-8') if request.query_string else ''
    if qs:
        target = target + ("&" if "?" in target else "?") + qs
    try:
        upstream = requests.request(request.method, target, stream=True, timeout=20)
        status = upstream.status_code
        content = upstream.content
        headers = dict(upstream.headers)
        ct = headers.get('Content-Type', '')
        if isinstance(content, (bytes, bytearray)) and 'text/html' in ct.lower():
            try:
                html = content.decode('utf-8', errors='ignore')
                if '<base ' not in html:
                    html = html.replace('<head>', '<head><base href="/explorer/">', 1)
                for attr in ['href', 'src', 'action']:
                    html = html.replace(f'{attr}="/', f'{attr}="/explorer/')
                html = html.replace('url(/', 'url(/explorer/')
                html = html.replace('/explorer//explorer/', '/explorer/')
                content = html.encode('utf-8')
            except Exception:
                pass
        resp = make_response(content, status)
        for h in ['Content-Type', 'Cache-Control', 'ETag', 'Last-Modified', 'Expires']:
            if h in headers:
                resp.headers[h] = headers[h]
        return resp
    except Exception as e:
        return make_response(f"Explorer backend unavailable: {e}", 502)


# --- Native Matrix chat API (no iframe) ---

def _json_response(obj, status: int = 200):
    try:
        resp = make_response(json.dumps(obj), status)
        resp.headers['Content-Type'] = 'application/json'
        return resp
    except Exception:
        return make_response('{"detail":"serialization_error"}', 500)


def _is_trade_participant(t: dict, user_id: int, username: str | None) -> bool:
    """Return True if the requester is one of the two participants of the trade.
    Accept either numeric user_id match, username match, or quick-access mapping match.
    Robust to type mismatches and missing fields.
    """
    try:
        # Normalize ids
        uid = 0
        try:
            uid = int(user_id or 0)
        except Exception:
            uid = 0
        buyer_id = 0
        seller_id = 0
        try:
            buyer_id = int(t.get('buyer_id') or 0)
        except Exception:
            buyer_id = 0
        try:
            seller_id = int(t.get('seller_id') or 0)
        except Exception:
            seller_id = 0
        if uid and uid in {buyer_id, seller_id}:
            return True
        # Username fallback
        if username:
            if username == t.get('buyer_name') or username == t.get('seller_name'):
                return True
        # Quick-access mapping fallback (helps when names are missing or ids desync)
        tid = (t or {}).get('id')
        if uid and ACTIVE_TRADE_ID_BY_USER.get(uid) == tid:
            return True
        if username and ACTIVE_TRADE_ID_BY_USERNAME.get(username) == tid:
            return True
    except Exception:
        return False
    return False


# Simple token cache and helpers for native chat
MATRIX_TOKENS: dict[int, str] = {}


def _matrix_get_token_for_user(user_id: int) -> str | None:
    if not MATRIX_ENABLED:
        return None
    # Prefer a token delivered by the backend on login (cookie)
    try:
        cookie_tok = request.cookies.get('matrix_access_token')
        if cookie_tok:
            return cookie_tok
    except Exception:
        pass
    # Do not auto-register/login on the frontend; rely on backend-provided token
    # to ensure consistency with the requirement that Matrix password equals site password.
    return None


def _matrix_resolve_room_id_for_trade(trade: dict) -> str | None:
    mx = (trade or {}).get('matrix') or {}
    rid = mx.get('room_id')
    if rid:
        return rid
    alias = mx.get('alias')
    if not alias:
        return None
    try:
        r = requests.get(f"{MATRIX_HS_URL_BACKEND}/_matrix/client/v3/directory/room/{alias}", timeout=5)
        if r.status_code == 200:
            return (r.json() or {}).get('room_id')
    except Exception:
        return None
    return None


def _matrix_ensure_join(token: str, room_id_or_alias: str) -> None:
    if not token or not room_id_or_alias:
        return
    try:
        requests.post(
            f"{MATRIX_HS_URL_BACKEND}/_matrix/client/v3/rooms/{room_id_or_alias}/join",
            headers={"Authorization": f"Bearer {token}"}, json={}, timeout=8
        )
    except Exception:
        pass


def _matrix_fetch_last_messages(token: str, room_id: str, limit: int = 50) -> dict:
    try:
        r = requests.get(
            f"{MATRIX_HS_URL_BACKEND}/_matrix/client/v3/rooms/{room_id}/messages",
            headers={"Authorization": f"Bearer {token}"}, params={"dir": "b", "limit": int(limit)}, timeout=10
        )
        if r.status_code != 200:
            return {"chunk": [], "start": None, "end": None}
        return r.json() or {"chunk": []}
    except Exception:
        return {"chunk": [], "start": None, "end": None}


def _matrix_send_message(token: str, room_id: str, body: str) -> str | None:
    try:
        r = requests.post(
            f"{MATRIX_HS_URL_BACKEND}/_matrix/client/v3/rooms/{room_id}/send/m.room.message",
            headers={"Authorization": f"Bearer {token}"}, json={"msgtype": "m.text", "body": body}, timeout=10
        )
        if r.status_code in (200, 201):
            return (r.json() or {}).get('event_id')
    except Exception:
        return None
    return None


@app.get('/api/chat/<trade_id>/messages')
def api_chat_messages(trade_id: str):
    if not request.cookies.get('access_token'):
        return _json_response({"detail": "unauthorized"}, 401)
    t = TRADES.get(trade_id)
    if not t:
        return _json_response({"detail": "trade_not_found"}, 404)
    uid = _get_logged_in_user_id()
    uname = _get_logged_in_username()
    if not _is_trade_participant(t, uid, uname):
        return _json_response({"detail": "forbidden"}, 403)
    tok = _matrix_get_token_for_user(uid)
    if not tok:
        return _json_response({"detail": "matrix_unavailable"}, 502)
    rid = _matrix_resolve_room_id_for_trade(t)
    if not rid:
        return _json_response({"detail": "room_unavailable"}, 503)
    _matrix_ensure_join(tok, rid)
    data = _matrix_fetch_last_messages(tok, rid, limit=50)
    chunk = data.get('chunk') or []
    # Keep only text messages and normalize
    msgs = []
    for ev in reversed(chunk):  # chronological
        try:
            if ev.get('type') != 'm.room.message':
                continue
            content = ev.get('content') or {}
            body = content.get('body')
            if not body:
                continue
            msgs.append({
                'sender': ev.get('sender'),
                'body': str(body),
                'ts': ev.get('origin_server_ts'),
                'event_id': ev.get('event_id')
            })
        except Exception:
            continue
    return _json_response({"messages": msgs})


@app.post('/api/chat/<trade_id>/send')
def api_chat_send(trade_id: str):
    if not request.cookies.get('access_token'):
        return _json_response({"detail": "unauthorized"}, 401)
    t = TRADES.get(trade_id)
    if not t:
        return _json_response({"detail": "trade_not_found"}, 404)
    uid = _get_logged_in_user_id()
    uname = _get_logged_in_username()
    if not _is_trade_participant(t, uid, uname):
        return _json_response({"detail": "forbidden"}, 403)
    text = None
    try:
        if request.is_json:
            text = (request.get_json(silent=True) or {}).get('text')
        if not text:
            text = request.form.get('text')
    except Exception:
        text = None
    if not text or not str(text).strip():
        return _json_response({"detail": "empty"}, 400)
    tok = _matrix_get_token_for_user(uid)
    rid = _matrix_resolve_room_id_for_trade(t)
    if not tok or not rid:
        return _json_response({"detail": "matrix_unavailable"}, 502)
    _matrix_ensure_join(tok, rid)
    eid = _matrix_send_message(tok, rid, str(text))
    if not eid:
        return _json_response({"detail": "send_failed"}, 502)
    return _json_response({"event_id": eid}, 200)


@app.route('/addresses/rotate', methods=['POST'])
def rotate_address():
    if not request.cookies.get('access_token'):
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user_id = _get_logged_in_user_id()
    if not user_id:
        flash('Could not identify user.', 'error')
        return redirect(url_for('balances'))
    # Generate a friendly label
    try:
        label = f"user_{int(user_id)}_{int(time.time())}"
        r = requests.post(f"{OFFERS_SERVICE_URL}/monero/addresses/rotate",
                          json={"user_id": int(user_id), "label": label}, timeout=20)
        if r.status_code == 200:
            data = {}
            try:
                data = r.json() or {}
            except Exception:
                data = {}
            disabled_prior = data.get('disabled_prior')
            flash(f'New subaddress created. Disabled {disabled_prior} previous address(es).', 'success')
        else:
            try:
                detail = r.json().get('detail', r.text)
            except Exception:
                detail = r.text
            flash(f'Could not create new subaddress: {detail}', 'error')
    except Exception as e:
        flash(f'Could not create new subaddress: {e}', 'error')
    return redirect(url_for('balances'))


# Overriding compute function to use internal market price

def _compute_price_per_xmr(ad: dict, market_base: float = 250.0) -> float:
    """Compute price per XMR for an ad.
    - fixed: return fixed_price
    - market: fetch cached internal market price for selected fiat and apply margin
    - equation: placeholder -> fall back to market style
    Fallback to market_base if price unavailable.
    """
    try:
        mode = (ad.get('price_mode') or 'market').lower()
    except Exception:
        mode = 'market'
    if mode == 'fixed' and ad.get('fixed_price') is not None and str(ad.get('fixed_price')) != '':
        try:
            return float(ad.get('fixed_price'))
        except Exception:
            pass
    # Market or unknown: use market price
    fiat = (ad.get('fiat') or 'EUR').upper()
    base = _get_market_price(fiat) or float(market_base)
    try:
        margin = float(ad.get('margin') or 0.0)
    except Exception:
        margin = 0.0
    try:
        return float(base) * (1.0 + float(margin) / 100.0)
    except Exception:
        return float(market_base)


@app.route('/rates', methods=['GET'])
def rates():
    """Public page that shows cached XMR conversion rates and a simple converter."""
    # Fetch cached prices from API Manager
    prices = {}
    updated_at = 0
    next_update_at = 0
    source = "unknown"
    refresh_seconds = 0
    err = None
    try:
        r = requests.get(f"{OFFERS_SERVICE_URL}/price", timeout=6)
        if r.status_code == 200:
            data = r.json() or {}
            prices = data.get('prices') or {}
            updated_at = int(data.get('updated_at') or 0)
            next_update_at = int(data.get('next_update_at') or 0)
            source = data.get('source') or 'unknown'
            refresh_seconds = int(data.get('refresh_seconds') or 0)
        else:
            err = f"Price endpoint returned {r.status_code}: {r.text[:120]}"
    except Exception as e:
        err = str(e)

    # Prepare human times
    def _fmt(ts: int) -> str:
        try:
            if ts:
                return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
        except Exception:
            pass
        return ''

    context = {
        'prices': prices,
        'updated_at': updated_at,
        'updated_human': _fmt(updated_at),
        'next_update_at': next_update_at,
        'next_update_human': _fmt(next_update_at),
        'source': source,
        'refresh_seconds': refresh_seconds,
        'error': err,
    }
    return render_template('rates.html', **context)
