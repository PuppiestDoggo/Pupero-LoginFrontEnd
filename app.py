from flask import Flask, render_template, request, redirect, url_for, make_response, flash
import requests
from config import BACKEND_URL, SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY

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
            'password': request.form['password'],
            'phrase': request.form.get('phrase', '')
        }
        response = requests.post(f'{BACKEND_URL}/register', json=data)
        if response.status_code == 200:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash(response.json().get('detail', 'Registration failed'), 'error')
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = {
            'username': request.form['email'],  # FastAPI uses OAuth2 form, so username=email
            'password': request.form['password']
        }
        totp = request.form.get('totp')
        if totp:
            data['totp'] = totp  # If TOTP field is provided
        response = requests.post(f'{BACKEND_URL}/login', data=data)  # Use data= for form-encoded
        if response.status_code == 200:
            tokens = response.json()
            resp = make_response(redirect(url_for('profile')))
            resp.set_cookie('access_token', tokens['access_token'], httponly=True, secure=True)  # Secure=True in prod
            flash('Login successful!', 'success')
            return resp
        else:
            flash('Login failed: ' + str(response.json()), 'error')
    return render_template('login.html')

# Profile
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    headers = get_auth_headers()
    if not headers:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        data = {'phrase': request.form['phrase']}
        response = requests.put(f'{BACKEND_URL}/user/update', json=data, headers=headers)
        if response.status_code == 200:
            flash('Profile updated!', 'success')
        else:
            flash('Update failed: ' + str(response.json()), 'error')
    
    response = requests.get(f'{BACKEND_URL}/user/profile', headers=headers)
    if response.status_code == 200:
        user_data = response.json()
        return render_template('profile.html', user=user_data)
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
        response = requests.post(f'{BACKEND_URL}/totp/enable', headers=headers)
        if response.status_code == 200:
            data = response.json()
            qr_data_url = f"data:image/png;base64,{data['qr_code']}"
            return render_template('totp_enable.html', secret=data['secret'], qr_url=qr_data_url)
        else:
            flash('Failed to enable TOTP: ' + str(response.json()), 'error')
    return render_template('totp_enable.html')

# Password Reset Request
@app.route('/password/reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == 'POST':
        data = {'email': request.form['email']}
        response = requests.post(f'{BACKEND_URL}/password/reset', json=data)
        flash(response.json().get('message', 'Request processed'), 'info')
        return redirect(url_for('login'))
    return render_template('reset.html')

# Logout
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('home')))
    resp.delete_cookie('access_token')
    flash('Logged out', 'info')
    return resp

if __name__ == 'main':
    app.run(debug=True)

