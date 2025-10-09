from flask import Flask, render_template, request, redirect, url_for, make_response, flash, Response
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
from urllib.parse import urlencode


def _get_logged_in_username() -> str:
    """
    Return the username of the current logged-in user by calling Login service /user/profile
    using the access_token cookie. Returns empty string if unavailable.
    """
    try:
        token = request.cookies.get('access_token')
        if not token:
            return ""
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get(f"{BACKEND_URL}/user/profile", headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            # Prefer username; fallback to email local part
            uname = data.get('username') or ''
            if not uname:
                email = data.get('email') or ''
                uname = email.split('@')[0] if '@' in email else email
            return uname or ""
    except Exception:
        pass
    return ""


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
            # Decide cookie security flags from config; fallback to request.is_secure when not enforced
            secure_flag = SECURE_COOKIES or request.is_secure
            samesite = SESSION_COOKIE_SAMESITE
            max_age = REMEMBER_ME_DAYS * 24 * 60 * 60 if remember_flag else 60 * 60
            resp.set_cookie(
                'access_token',
                tokens.get('access_token', ''),
                httponly=True,
                secure=secure_flag,
                samesite=samesite,
                max_age=max_age
            )
            # Persist remember flag to reuse on token refreshes/updates
            resp.set_cookie(
                'remember',
                '1' if remember_flag else '0',
                secure=secure_flag,
                samesite=samesite,
                max_age=max_age
            )
            try:
                logger.info(
                    json.dumps({"event": "login_cookie_set", "remember": remember_flag, "client": request.remote_addr}))
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
        sessions = [{
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'current': True
        }]
        return render_template('profile.html', user=user_data, sessions=sessions, totp_enabled=totp_enabled)
    else:
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))


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
                           self_trade_block=self_trade_block)


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
    Prefer the provided human username (sanitized) over the numeric id.
    Fallback to prefix+id if username is missing or sanitizes to empty.
    """
    # If a username is provided, sanitize to a valid Matrix localpart
    if username:
        try:
            raw = str(username).strip().lower()
            # Matrix localpart allowed chars: a-z 0-9 . _ = -
            allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._=-")
            local = ''.join(ch if ch in allowed else '_' for ch in raw)
            local = local.strip('_')
            if local:
                return local
        except Exception:
            pass
    # Fallback to legacy scheme using numeric id
    try:
        uid = int(user_id)
    except Exception:
        uid = 0
    return f"{MATRIX_USER_PREFIX}{uid}"


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


def _matrix_create_trade_room(creator_token: str, invite_mxid: str, trade_id: str) -> tuple[str | None, str | None]:
    if not MATRIX_ENABLED or not creator_token:
        return None, None
    url = f"{MATRIX_HS_URL_BACKEND}/_matrix/client/v3/createRoom"
    headers = {"Authorization": f"Bearer {creator_token}"}
    alias_local = f"trade_{trade_id}"
    payload = {
        "preset": "private_chat",
        "is_direct": True,
        "invite": [invite_mxid],
        "name": f"Trade {trade_id}",
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
            r2 = requests.post(url, headers=headers, json={**payload, "room_alias_name": None}, timeout=8)
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
        s_local = _mx_username_for_user(seller_id, seller_name)
        b_local = _mx_username_for_user(buyer_id, buyer_name)
        s_pw = _mx_password_for_user(seller_id)
        b_pw = _mx_password_for_user(buyer_id)
        _matrix_register_if_needed(s_local, s_pw)
        _matrix_register_if_needed(b_local, b_pw)
        # Prefer initiator's provided username; otherwise fall back to counterpart's name for localpart derivation
        inferred_initiator_name = initiator_name
        if not inferred_initiator_name:
            inferred_initiator_name = buyer_name if initiator_id == buyer_id else seller_name
        creator_local = _mx_username_for_user(initiator_id, inferred_initiator_name)
        other_mxid = _mx_mxid(b_local if initiator_id == seller_id else s_local)
        tok = _matrix_login(creator_local, _mx_password_for_user(initiator_id))
        room_id, alias = _matrix_create_trade_room(tok, other_mxid, trade_id)
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
    """
    try:
        raw_desc = offer.get('desc')
        ad = _parse_offer_desc(raw_desc)
        side = (ad.get('side') or 'sell').lower()
    except Exception:
        side = 'sell'
    offer_owner_id = int(offer.get('seller_id') or 0)
    if side == 'sell':
        return offer_owner_id, current_user_id, 'sell'
    else:
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
    if side == 'sell':
        seller_name = offer_owner_name
        buyer_name = current_name
    else:
        seller_name = current_name
        buyer_name = offer_owner_name

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
    return render_template('trade.html', trade=t, role=role, matrix_embed_url=matrix_embed_url)


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


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

# --- Reverse proxy for Matrix Element to avoid localhost:8080 dependency ---
ELEMENT_BACKEND_BASE = "http://pupero-matrix-element"


@app.route('/element', defaults={'path': ''}, methods=['GET', 'HEAD'])
@app.route('/element/', defaults={'path': ''}, methods=['GET', 'HEAD'])
@app.route('/element/<path:path>', methods=['GET', 'HEAD'])
def element_proxy(path: str):
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

        # If HTML, inject <base href="/element/"> and rewrite root-relative URLs
        ct = headers.get('Content-Type', '')
        if isinstance(content, (bytes, bytearray)) and 'text/html' in ct.lower():
            try:
                html = content.decode('utf-8', errors='ignore')
                # Inject base into <head> if not present
                if '<base ' not in html:
                    html = html.replace('<head>', '<head><base href="/element/">', 1)
                # Rewrite common root-relative attrs to live under /element/
                for attr in ['href', 'src', 'action']:
                    html = html.replace(f'{attr}="/', f'{attr}="/element/')
                # Rewrite CSS url(/...)
                html = html.replace('url(/', 'url(/element/')
                # De-dupe any accidental double prefixes
                html = html.replace('/element//element/', '/element/')
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


# --- Native Matrix chat API (no iframe) ---

def _json_response(obj, status: int = 200):
    try:
        resp = make_response(json.dumps(obj), status)
        resp.headers['Content-Type'] = 'application/json'
        return resp
    except Exception:
        return make_response('{"detail":"serialization_error"}', 500)


def _is_trade_participant(t: dict, user_id: int, username: str | None) -> bool:
    try:
        if user_id and user_id in {int(t.get('buyer_id') or 0), int(t.get('seller_id') or 0)}:
            return True
        if username and username in {t.get('buyer_name'), t.get('seller_name')}:
            return True
    except Exception:
        return False
    return False


# Simple token cache and helpers for native chat
MATRIX_TOKENS: dict[int, str] = {}


def _matrix_get_token_for_user(user_id: int) -> str | None:
    if not MATRIX_ENABLED:
        return None
    try:
        uid = int(user_id)
    except Exception:
        return None
    tok = MATRIX_TOKENS.get(uid)
    if tok:
        return tok
    # Prefer the current logged-in username when deriving Matrix localpart
    try:
        current_uname = _get_logged_in_username()
    except Exception:
        current_uname = None
    local = _mx_username_for_user(uid, current_uname)
    pw = _mx_password_for_user(uid)
    try:
        _matrix_register_if_needed(local, pw)
    except Exception:
        pass
    tok = _matrix_login(local, pw)
    if tok:
        MATRIX_TOKENS[uid] = tok
    return tok


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
