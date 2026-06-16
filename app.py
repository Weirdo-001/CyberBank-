# app.py
# Citadel National Bank — Main Flask Application
# Security features: bcrypt hashing, OTP 2FA, RBAC, CSRF, account lockout,
#                    session timeout, cache control, IDOR prevention, parameterized SQL

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
from functools import wraps
import os

from database import (
    init_db, get_db,
    create_user, get_user_by_id, get_user_by_username, get_user_by_account,
    get_all_users, get_users_by_role, update_user, delete_user,
    increment_failed_attempts, lock_account, unlock_account, reset_failed_attempts,
    get_user_transactions, get_all_transactions, atomic_transfer,
    save_otp, get_otp_by_token, get_pending_otp, mark_otp_used,
    log_audit, get_audit_logs
)
from security import (
    hash_password, check_password,
    generate_otp, generate_token, generate_account_number,
    is_account_locked, get_lockout_time, get_lockout_remaining,
    MAX_FAILED_ATTEMPTS, encrypt_data, decrypt_data
)

# ===================== APP CONFIGURATION (PERSON 1: CSRF Protection) =====================

app = Flask(__name__)
app.secret_key = os.urandom(32)  # Random secret key each run (secure)
app.config['SESSION_COOKIE_HTTPONLY'] = True      # JS cannot access session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'     # CSRF protection at cookie level
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # Session timeout
app.config['WTF_CSRF_TIME_LIMIT'] = 3600          # CSRF token valid for 1 hour

csrf = CSRFProtect(app)


# ===================== PERSON 5: SESSION STATE & BROWSER SECURITY (Middleware) =====================

@app.after_request
def add_security_headers(response):
    """Prevent browser from caching sensitive pages (no back button after logout)."""
    if request.endpoint and request.endpoint not in ('static', 'landing'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


@app.before_request
def check_session_timeout():
    """Auto-logout if session has been idle for too long."""
    session.permanent = True
    if 'user_id' in session:
        last_activity = session.get('last_activity')
        if last_activity:
            last_time = datetime.fromisoformat(last_activity)
            if datetime.now() - last_time > timedelta(minutes=15):
                user = get_user_by_id(session['user_id'])
                if user:
                    log_audit(user['id'], user['username'], 'SESSION_TIMEOUT',
                              'Session expired due to inactivity', request.remote_addr, 'INFO')
                session.clear()
                flash('Your session has expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
        session['last_activity'] = datetime.now().isoformat()


# ===================== PERSON 4: ROLE-BASED ACCESS CONTROL (RBAC) =====================

def login_required(f):
    """Decorator: must be logged in to access this route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """Decorator: user must have one of the specified roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            user = get_user_by_id(session['user_id'])
            if not user or user['role'] not in roles:
                flash('You do not have permission to access this page.', 'danger')
                log_audit(session.get('user_id'), session.get('username'),
                          'UNAUTHORIZED_ACCESS', f'Tried to access {request.path}',
                          request.remote_addr, 'WARNING')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator


# ===================== SEED DATA =====================

def seed_db():
    """Create default admin, banker, and user accounts if they don't exist."""
    users_to_seed = [
        ('admin', 'System Administrator', 'admin@citadel.com', 'Admin@123', 'admin', 50000.0),
        ('banker1', 'Rajesh Kumar', 'rajesh@citadel.com', 'Banker@123', 'banker', 25000.0),
        ('john_doe', 'John Doe', 'john@example.com', 'User@1234', 'user', 15000.0),
        ('jane_smith', 'Jane Smith', 'jane@example.com', 'User@5678', 'user', 22000.0),
    ]
    for username, full_name, email, password, role, balance in users_to_seed:
        if not get_user_by_username(username):
            acc_num = generate_account_number()
            create_user(username, full_name, email, hash_password(password), role, balance, acc_num)


# ===================== PUBLIC ROUTES =====================

@app.route('/')
def landing():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = get_user_by_username(username)

        if not user:
            log_audit(None, username, 'LOGIN_FAILED', 'User not found', request.remote_addr, 'WARNING')
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

        # Check if account is locked
        if is_account_locked(user['locked_until']):
            remaining = get_lockout_remaining(user['locked_until'])
            log_audit(user['id'], username, 'LOGIN_BLOCKED', f'Account locked, {remaining} remaining',
                      request.remote_addr, 'WARNING')
            flash(f'Account is locked due to too many failed attempts. Try again in {remaining}.', 'danger')
            return render_template('login.html')

        if not user['is_active']:
            flash('Your account has been deactivated. Contact admin.', 'danger')
            return render_template('login.html')

        if check_password(password, user['password_hash']):
            # Password correct — generate OTP for 2FA
            reset_failed_attempts(user['id'])
            otp_code = generate_otp()
            token = generate_token()
            expires = (datetime.now() + timedelta(minutes=5)).isoformat()

            # Encrypt OTP before storing
            encrypted_otp = encrypt_data(otp_code)
            save_otp(user['id'], encrypted_otp, token, 'login', expires)

            # Store pending login in session
            session['pending_user_id'] = user['id']
            session['otp_token'] = token
            session['otp_attempts'] = 0  # Reset OTP attempt counter

            log_audit(user['id'], username, 'LOGIN_OTP_SENT', 'OTP generated for 2FA',
                      request.remote_addr, 'INFO')

            flash('Password verified! Please enter the OTP to complete login.', 'info')
            return render_template('verify_otp.html', token=token, purpose='login')
        else:
            # Wrong password
            attempts = increment_failed_attempts(user['id'])
            remaining_attempts = MAX_FAILED_ATTEMPTS - attempts

            if attempts >= MAX_FAILED_ATTEMPTS:
                lock_account(user['id'], get_lockout_time())
                log_audit(user['id'], username, 'ACCOUNT_LOCKED',
                          f'Locked after {MAX_FAILED_ATTEMPTS} failed attempts',
                          request.remote_addr, 'CRITICAL')
                flash('Too many failed attempts. Account locked for 24 hours.', 'danger')
            else:
                log_audit(user['id'], username, 'LOGIN_FAILED',
                          f'Wrong password, {remaining_attempts} attempts left',
                          request.remote_addr, 'WARNING')
                flash(f'Invalid password. {remaining_attempts} attempt(s) remaining before lockout.', 'danger')

            return render_template('login.html')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        # Validate inputs
        errors = []
        if len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if len(full_name) < 2:
            errors.append('Please enter your full name.')
        if '@' not in email:
            errors.append('Please enter a valid email.')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if password != confirm:
            errors.append('Passwords do not match.')

        # Check password strength
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        if not (has_upper and has_lower and has_digit and has_special):
            errors.append('Password must contain uppercase, lowercase, digit, and special character.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html')

        acc_num = generate_account_number()
        success = create_user(username, full_name, email, hash_password(password), 'user', 1000.0, acc_num)

        if success:
            log_audit(None, username, 'USER_REGISTERED', f'New user registered: {full_name}',
                      request.remote_addr, 'INFO')
            flash('Registration successful! You can now log in. Your starting balance is ₹1,000.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username or email already exists.', 'danger')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    pending_id = session.get('pending_user_id')
    token = session.get('otp_token')

    if not pending_id or not token:
        flash('No pending verification. Please log in first.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        otp_record = get_pending_otp(pending_id, 'login')

        if not otp_record:
            flash('OTP expired or not found. Please try logging in again.', 'danger')
            session.pop('pending_user_id', None)
            session.pop('otp_token', None)
            session.pop('otp_attempts', None)
            return redirect(url_for('login'))

        # Check expiry
        if datetime.fromisoformat(otp_record['expires_at']) < datetime.now():
            flash('OTP has expired. Please try logging in again.', 'danger')
            session.pop('pending_user_id', None)
            session.pop('otp_token', None)
            session.pop('otp_attempts', None)
            return redirect(url_for('login'))

        # Decrypt stored OTP and compare
        stored_otp = decrypt_data(otp_record['otp_code'])

        if entered_otp == stored_otp:
            mark_otp_used(otp_record['id'])
            user = get_user_by_id(pending_id)

            # Set up authenticated session
            session.pop('pending_user_id', None)
            session.pop('otp_token', None)
            session.pop('otp_attempts', None)
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['last_activity'] = datetime.now().isoformat()

            log_audit(user['id'], user['username'], 'LOGIN_SUCCESS',
                      'User logged in successfully via OTP',
                      request.remote_addr, 'INFO')
            flash(f'Welcome back, {user["full_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Track failed OTP attempts — max 3 allowed
            otp_attempts = session.get('otp_attempts', 0) + 1
            session['otp_attempts'] = otp_attempts
            remaining = 3 - otp_attempts

            log_audit(pending_id, '', 'OTP_FAILED',
                      f'Invalid OTP entered ({otp_attempts}/3 attempts)',
                      request.remote_addr, 'WARNING')

            if otp_attempts >= 3:
                mark_otp_used(otp_record['id'])
                session.pop('pending_user_id', None)
                session.pop('otp_token', None)
                session.pop('otp_attempts', None)
                log_audit(pending_id, '', 'OTP_LOCKED',
                          'OTP invalidated after 3 failed attempts',
                          request.remote_addr, 'CRITICAL')
                flash('Too many wrong OTP attempts. Please log in again.', 'danger')
                return redirect(url_for('login'))

            flash(f'Invalid OTP. {remaining} attempt(s) remaining.', 'danger')
            return render_template('verify_otp.html', token=token, purpose='login')

    return render_template('verify_otp.html', token=token, purpose='login')


@app.route('/show-otp/<token>')
def show_otp(token):
    """Simulated OTP delivery — opens in a new tab to show the OTP."""
    otp_record = get_otp_by_token(token)
    if not otp_record:
        return render_template('show_otp.html', otp=None, error='OTP not found or already used.')

    if datetime.fromisoformat(otp_record['expires_at']) < datetime.now():
        return render_template('show_otp.html', otp=None, error='OTP has expired.')

    decrypted_otp = decrypt_data(otp_record['otp_code'])
    user = get_user_by_id(otp_record['user_id'])
    return render_template('show_otp.html', otp=decrypted_otp,
                           purpose=otp_record['purpose'],
                           username=user['username'] if user else 'Unknown')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit(session['user_id'], session.get('username', ''), 'LOGOUT',
                  'User logged out', request.remote_addr, 'INFO')
    session.clear()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('login'))


# ===================== DASHBOARD =====================

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    role = user['role']
    recent_txns = get_user_transactions(user['id'], limit=5)

    if role == 'admin':
        all_users = get_all_users()
        all_logs = get_audit_logs(limit=10)
        return render_template('dashboard_admin.html', user=user, users=all_users,
                               logs=all_logs, transactions=recent_txns)
    elif role == 'banker':
        customers = get_users_by_role('user')
        return render_template('dashboard_banker.html', user=user, customers=customers,
                               transactions=recent_txns)
    else:
        return render_template('dashboard_user.html', user=user, transactions=recent_txns)


# ===================== PERSON 3: IDOR PREVENTION (Fund Transfer Core) =====================

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
@role_required('user', 'admin', 'banker')
def transfer():
    user = get_user_by_id(session['user_id'])

    if request.method == 'POST':
        to_account = request.form.get('to_account', '').strip()
        amount_str = request.form.get('amount', '0')
        description = request.form.get('description', 'Fund Transfer').strip()

        try:
            amount = float(amount_str)
        except ValueError:
            flash('Please enter a valid amount.', 'danger')
            return render_template('transfer.html', user=user)

        if amount <= 0:
            flash('Amount must be greater than zero.', 'danger')
            return render_template('transfer.html', user=user)

        if amount > user['balance']:
            flash('Insufficient balance.', 'danger')
            return render_template('transfer.html', user=user)

        # IDOR prevention: from_account is ALWAYS the logged-in user's account
        from_account = user['account_number']

        if to_account == from_account:
            flash('Cannot transfer to your own account.', 'danger')
            return render_template('transfer.html', user=user)

        recipient = get_user_by_account(to_account)
        if not recipient:
            flash('Recipient account not found.', 'danger')
            return render_template('transfer.html', user=user)

        # Generate OTP for transfer signing
        otp_code = generate_otp()
        token = generate_token()
        expires = (datetime.now() + timedelta(minutes=5)).isoformat()
        encrypted_otp = encrypt_data(otp_code)
        save_otp(user['id'], encrypted_otp, token, 'transfer', expires)

        # Store transfer details in session
        session['pending_transfer'] = {
            'to_account': to_account,
            'to_user_id': recipient['id'],
            'to_name': recipient['full_name'],
            'amount': amount,
            'description': description
        }
        session['transfer_otp_token'] = token
        session['transfer_otp_attempts'] = 0  # Reset transfer OTP attempt counter

        log_audit(user['id'], user['username'], 'TRANSFER_INITIATED',
                  f'Transfer of ₹{amount:.2f} to {to_account} initiated',
                  request.remote_addr, 'INFO')

        flash('Please verify the OTP to complete this transaction.', 'info')
        return render_template('verify_transfer.html', token=token, transfer=session['pending_transfer'])

    return render_template('transfer.html', user=user)


@app.route('/verify-transfer', methods=['GET', 'POST'])
@login_required
def verify_transfer():
    user = get_user_by_id(session['user_id'])
    transfer_data = session.get('pending_transfer')
    token = session.get('transfer_otp_token')

    if not transfer_data or not token:
        flash('No pending transfer found.', 'warning')
        return redirect(url_for('transfer'))

    if request.method == 'POST':
        action = request.form.get('action', '')

        # Handle cancel
        if action == 'cancel':
            session.pop('pending_transfer', None)
            session.pop('transfer_otp_token', None)
            log_audit(user['id'], user['username'], 'TRANSFER_CANCELLED',
                      'User cancelled pending transfer', request.remote_addr, 'INFO')
            flash('Transaction cancelled. No money was transferred.', 'warning')
            return redirect(url_for('dashboard'))

        entered_otp = request.form.get('otp', '').strip()
        otp_record = get_pending_otp(user['id'], 'transfer')

        if not otp_record:
            flash('OTP expired. Please initiate the transfer again.', 'danger')
            session.pop('pending_transfer', None)
            session.pop('transfer_otp_token', None)
            return redirect(url_for('transfer'))

        if datetime.fromisoformat(otp_record['expires_at']) < datetime.now():
            flash('OTP expired. Please initiate the transfer again.', 'danger')
            session.pop('pending_transfer', None)
            session.pop('transfer_otp_token', None)
            return redirect(url_for('transfer'))

        stored_otp = decrypt_data(otp_record['otp_code'])

        if entered_otp == stored_otp:
            mark_otp_used(otp_record['id'])

            amount = transfer_data['amount']

            # --- TOCTOU FIX: Atomic transfer with BEGIN EXCLUSIVE lock ---
            # Balance re-read, debit, credit, and transaction record all happen
            # inside a single exclusive DB transaction — no race window possible.
            success, msg = atomic_transfer(
                user['id'], transfer_data['to_user_id'],
                amount,
                user['account_number'], transfer_data['to_account'],
                transfer_data['description']
            )

            if not success:
                session.pop('pending_transfer', None)
                session.pop('transfer_otp_token', None)
                log_audit(user['id'], user['username'], 'TRANSFER_FAILED',
                          f'Atomic transfer failed: {msg}',
                          request.remote_addr, 'WARNING')
                flash(f'Transfer failed: {msg}', 'danger')
                return redirect(url_for('dashboard'))

            log_audit(user['id'], user['username'], 'TRANSFER_SUCCESS',
                      f'₹{amount:.2f} transferred to {transfer_data["to_account"]} (atomic)',
                      request.remote_addr, 'INFO')

            session.pop('pending_transfer', None)
            session.pop('transfer_otp_token', None)
            flash(f'₹{amount:,.2f} transferred successfully to {transfer_data["to_name"]}!', 'success')
            return redirect(url_for('transactions'))
        else:
            # Track failed transfer OTP attempts — max 3 allowed
            t_otp_attempts = session.get('transfer_otp_attempts', 0) + 1
            session['transfer_otp_attempts'] = t_otp_attempts
            remaining = 3 - t_otp_attempts

            log_audit(user['id'], user['username'], 'TRANSFER_OTP_FAILED',
                      f'Invalid OTP for transfer ({t_otp_attempts}/3 attempts)',
                      request.remote_addr, 'WARNING')

            if t_otp_attempts >= 3:
                mark_otp_used(otp_record['id'])
                session.pop('pending_transfer', None)
                session.pop('transfer_otp_token', None)
                session.pop('transfer_otp_attempts', None)
                log_audit(user['id'], user['username'], 'TRANSFER_OTP_LOCKED',
                          'Transfer cancelled after 3 failed OTP attempts',
                          request.remote_addr, 'CRITICAL')
                flash('Too many wrong OTP attempts. Transfer cancelled for security.', 'danger')
                return redirect(url_for('dashboard'))

            flash(f'Invalid OTP. {remaining} attempt(s) remaining.', 'danger')
            return render_template('verify_transfer.html', token=token, transfer=transfer_data)

    return render_template('verify_transfer.html', token=token, transfer=transfer_data)


# ===================== TRANSACTIONS =====================

@app.route('/transactions')
@login_required
def transactions():
    user = get_user_by_id(session['user_id'])
    # IDOR prevention: user can ONLY see their own transactions
    txns = get_user_transactions(user['id'])
    return render_template('transactions.html', user=user, transactions=txns)


# ===================== PROFILE =====================

@app.route('/profile')
@login_required
def profile():
    user = get_user_by_id(session['user_id'])
    return render_template('profile.html', user=user)


# ===================== PERSON 2: SECURITY AUDITING & ADMIN PANEL =====================

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    users = get_all_users()
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/<int:uid>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_edit_user(uid):
    target_user = get_user_by_id(uid)
    if not target_user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        role = request.form.get('role', 'user')
        balance = request.form.get('balance', '0')
        is_active = request.form.get('is_active', '1')

        try:
            balance = float(balance)
        except ValueError:
            balance = target_user['balance']

        update_user(uid, full_name=full_name, email=email, role=role,
                    balance=balance, is_active=int(is_active))

        log_audit(session['user_id'], session['username'], 'ADMIN_EDIT_USER',
                  f'Edited user {target_user["username"]} (id={uid})',
                  request.remote_addr, 'INFO')
        flash(f'User {target_user["username"]} updated successfully.', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin_edit_user.html', target_user=target_user)


@app.route('/admin/users/<int:uid>/delete', methods=['POST'])
@login_required
@role_required('admin')
def admin_delete_user(uid):
    target_user = get_user_by_id(uid)
    if not target_user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))

    if uid == session['user_id']:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))

    username = target_user['username']
    delete_user(uid)
    log_audit(session['user_id'], session['username'], 'ADMIN_DELETE_USER',
              f'Deleted user {username} (id={uid})', request.remote_addr, 'CRITICAL')
    flash(f'User {username} has been deleted.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:uid>/unlock', methods=['POST'])
@login_required
@role_required('admin')
def admin_unlock_user(uid):
    target_user = get_user_by_id(uid)
    if not target_user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))

    unlock_account(uid)
    log_audit(session['user_id'], session['username'], 'ADMIN_UNLOCK_USER',
              f'Unlocked user {target_user["username"]} (id={uid})',
              request.remote_addr, 'INFO')
    flash(f'Account {target_user["username"]} unlocked.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/logs')
@login_required
@role_required('admin')
def admin_logs():
    logs = get_audit_logs(limit=200)
    return render_template('admin_logs.html', logs=logs)


# ===================== BANKER ROUTES =====================

@app.route('/banker/customers')
@login_required
@role_required('banker', 'admin')
def banker_customers():
    customers = get_users_by_role('user')
    return render_template('banker_customers.html', customers=customers)


# ===================== ERROR HANDLERS =====================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', code=404, message='Page not found.'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500, message='Internal server error.'), 500


# ===================== RUN =====================

if __name__ == '__main__':
    init_db()
    seed_db()
    print("\n  Citadel National Bank is running!")
    print("  http://127.0.0.1:5000\n")
    print("  Default accounts:")
    print("  Admin:   admin / Admin@123")
    print("  Banker:  banker1 / Banker@123")
    print("  User:    john_doe / User@1234")
    print("  User:    jane_smith / User@5678\n")
    app.run(debug=True, port=5000)
