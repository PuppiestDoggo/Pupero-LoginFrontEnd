from flask import Flask, render_template, request, redirect, url_for, make_response, flash
import requests
from config import BACKEND_URL, OFFERS_SERVICE_URL, SECRET_KEY, REMEMBER_ME_DAYS, SECURE_COOKIES, SESSION_COOKIE_SAMESITE
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
        for d in ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']:
            if d in days:
                ranges = days[d]
                if isinstance(ranges, list) and ranges:
                    parts.append(f"{d} {ranges[0].get('start','00:00')}-{ranges[0].get('end','23:59')}")
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
    logging.getLogger("pupero_frontend").warning("SECRET_KEY not set; using ephemeral dev key (development only). Set SECRET_KEY in environment for production.")

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
            # Decide cookie security flags from config; fallback to request.is_secure when not enforced
            secure_flag = SECURE_COOKIES or request.is_secure
            samesite = SESSION_COOKIE_SAMESITE
            max_age = REMEMBER_ME_DAYS*24*60*60 if remember_flag else 60*60
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
                    secure_flag = SECURE_COOKIES or request.is_secure
                    samesite = SESSION_COOKIE_SAMESITE
                    remember_cookie = request.cookies.get('remember') == '1'
                    max_age = REMEMBER_ME_DAYS*24*60*60 if remember_cookie else 60*60
                    resp.set_cookie(
                        'access_token',
                        data.get('access_token', ''),
                        httponly=True,
                        secure=secure_flag,
                        samesite=samesite,
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
        offers = [_attach_seller_name(o) for o in offers]
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
    except Exception as e:
        flash(f'Failed to load offer: {e}', 'error')
        return redirect(url_for('offers'))
    return render_template('offer_detail.html', offer=offer, ad=ad, price_per_xmr=price_per_xmr)


@app.route('/offers/<offer_id>/bid', methods=['POST'])
def offer_bid(offer_id: str):
    # Require login to start a trade
    if not request.cookies.get('access_token'):
        flash('Please log in to start a trade.', 'warning')
        return redirect(url_for('login'))

    # Prefer new dual-inputs
    fiat_amount_raw = request.form.get('fiat_amount')
    xmr_amount_raw = request.form.get('xmr_amount')

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
    try:
        r = requests.post(f"{OFFERS_SERVICE_URL}/offers/{offer_id}/bid", json={'bid': xmr_amount}, timeout=10)
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
            # Show only offers where counterparty is selling (user wants to buy)
            filtered = []
            for o in raw:
                try:
                    ad = _parse_offer_desc(o.get('desc'))
                    if (ad.get('side') or '').lower() == 'sell':
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
            for d in ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']:
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
            title = f"{(ad.get('side') or '').capitalize()} {ad.get('crypto', 'XMR')} via {pm_display} ({ad.get('fiat','EUR')})"
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
            # Price field required by backend; approximate or default 1.0
            try:
                price = float(request.form.get('price') or 1.0)
            except Exception:
                price = 1.0
            seller_id = request.form.get('seller_id')
            payload = {
                'title': title,
                'desc': json.dumps(desc_payload),
                'price': price,
                'seller_id': int(seller_id) if seller_id else 0,
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
    return render_template('create_ad.html', preview=False)


@app.route('/ads/mine', methods=['GET'])
def my_ads():
    # Require login to view personal ads
    if not request.cookies.get('access_token'):
        flash('Please log in to view your ads.', 'warning')
        return redirect(url_for('login'))
    # In this minimal implementation, we do not have auth binding; show all offers
    offers = []
    my_name = _get_logged_in_username()
    try:
        resp = requests.get(f"{OFFERS_SERVICE_URL}/offers", timeout=10)
        if resp.status_code == 200:
            offers = resp.json()
            offers = [_attach_seller_name(o) for o in offers]
    except Exception as e:
        flash(f'Failed to load offers: {e}', 'error')
    return render_template('my_ads.html', offers=offers, my_name=my_name)


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


if __name__ == '__main__':
    app.run(debug=True)

