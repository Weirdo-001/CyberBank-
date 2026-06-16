# database.py
# Handles: SQLite database setup, table creation, and all CRUD operations

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'citadel.db')


def get_db():
    """Get a database connection with Row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user' CHECK(role IN ('admin','user','banker')),
        balance REAL DEFAULT 0.0,
        account_number TEXT UNIQUE NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_account TEXT NOT NULL,
        to_account TEXT NOT NULL,
        from_user_id INTEGER,
        to_user_id INTEGER,
        amount REAL NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'completed',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS otp_store (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        otp_code TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        purpose TEXT DEFAULT 'login',
        is_used INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        severity TEXT DEFAULT 'INFO',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()
    conn.close()


# ============ PERSON 3: SQL INJECTION PREVENTION (PARAMETERIZED QUERIES FOR USERS) ============

def create_user(username, full_name, email, password_hash, role='user', balance=0.0, account_number=''):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, full_name, email, password_hash, role, balance, account_number) VALUES (?,?,?,?,?,?,?)",
            (username, full_name, email, password_hash, role, balance, account_number)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user


def get_user_by_username(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user


def get_user_by_account(account_number):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE account_number = ?", (account_number,)).fetchone()
    conn.close()
    return user


def get_all_users():
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return users


def get_users_by_role(role):
    conn = get_db()
    users = conn.execute("SELECT * FROM users WHERE role = ? ORDER BY created_at DESC", (role,)).fetchall()
    conn.close()
    return users


# Whitelist of fields that may be updated — prevents f-string SQL injection.
_ALLOWED_UPDATE_FIELDS = frozenset({
    'full_name', 'email', 'role', 'balance', 'is_active',
    'locked_until', 'failed_attempts', 'password_hash'
})


def update_user(user_id, **kwargs):
    conn = get_db()
    for key, value in kwargs.items():
        if key not in _ALLOWED_UPDATE_FIELDS:
            conn.close()
            raise ValueError(f"update_user: disallowed field '{key}'")
        # Column name is safe — validated against whitelist above
        conn.execute(f"UPDATE users SET {key} = ? WHERE id = ?", (value, user_id))
    conn.commit()
    conn.close()


def delete_user(user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def increment_failed_attempts(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?", (user_id,))
    conn.commit()
    user = conn.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user['failed_attempts'] if user else 0


def lock_account(user_id, locked_until):
    conn = get_db()
    conn.execute("UPDATE users SET locked_until = ?, failed_attempts = 0 WHERE id = ?", (locked_until, user_id))
    conn.commit()
    conn.close()


def unlock_account(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def reset_failed_attempts(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def update_balance(user_id, new_balance):
    conn = get_db()
    conn.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user_id))
    conn.commit()
    conn.close()


# ============ PERSON 3: SQL INJECTION PREVENTION (PARAMETERIZED QUERIES FOR TRANSACTIONS) ============

def create_transaction(from_account, to_account, from_user_id, to_user_id, amount, description='Transfer'):
    conn = get_db()
    conn.execute(
        "INSERT INTO transactions (from_account, to_account, from_user_id, to_user_id, amount, description) VALUES (?,?,?,?,?,?)",
        (from_account, to_account, from_user_id, to_user_id, amount, description)
    )
    conn.commit()
    conn.close()


def atomic_transfer(from_user_id, to_user_id, amount, from_account, to_account, description='Transfer'):
    """
    Execute a fund transfer atomically using BEGIN EXCLUSIVE.
    Prevents TOCTOU race conditions by locking the DB for the full
    read-verify-debit-credit-record cycle in a single exclusive transaction.
    Returns (True, 'Success') or (False, reason_string).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.isolation_level = None  # Manual transaction control (autocommit off)
    try:
        conn.execute("BEGIN EXCLUSIVE")  # Exclusive lock: no other writer can proceed

        # Re-read balances INSIDE the lock — guarantees no concurrent mutation
        sender = conn.execute("SELECT balance FROM users WHERE id = ?", (from_user_id,)).fetchone()
        recipient = conn.execute("SELECT balance FROM users WHERE id = ?", (to_user_id,)).fetchone()

        if not sender or not recipient:
            conn.execute("ROLLBACK")
            return False, "User not found"

        if sender['balance'] < amount:
            conn.execute("ROLLBACK")
            return False, "Insufficient balance"

        # Atomic debit + credit
        conn.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_user_id))
        conn.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_user_id))

        # Record transaction inside the same lock
        conn.execute(
            "INSERT INTO transactions (from_account, to_account, from_user_id, to_user_id, amount, description) VALUES (?,?,?,?,?,?)",
            (from_account, to_account, from_user_id, to_user_id, amount, description)
        )
        conn.execute("COMMIT")
        return True, "Success"
    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return False, str(e)
    finally:
        conn.close()


def get_user_transactions(user_id, limit=50):
    conn = get_db()
    txns = conn.execute(
        """SELECT t.*, 
           u1.full_name as from_name, u1.account_number as from_acc_display,
           u2.full_name as to_name, u2.account_number as to_acc_display
           FROM transactions t
           LEFT JOIN users u1 ON t.from_user_id = u1.id
           LEFT JOIN users u2 ON t.to_user_id = u2.id
           WHERE t.from_user_id = ? OR t.to_user_id = ?
           ORDER BY t.created_at DESC LIMIT ?""",
        (user_id, user_id, limit)
    ).fetchall()
    conn.close()
    return txns


def get_all_transactions(limit=100):
    conn = get_db()
    txns = conn.execute(
        """SELECT t.*,
           u1.full_name as from_name, u2.full_name as to_name
           FROM transactions t
           LEFT JOIN users u1 ON t.from_user_id = u1.id
           LEFT JOIN users u2 ON t.to_user_id = u2.id
           ORDER BY t.created_at DESC LIMIT ?""",
        (limit,)
    ).fetchall()
    conn.close()
    return txns


# ============ PERSON 1: OTP DATABASE STATE MANAGEMENT ============

def save_otp(user_id, otp_code, token, purpose, expires_at):
    conn = get_db()
    conn.execute(
        "INSERT INTO otp_store (user_id, otp_code, token, purpose, expires_at) VALUES (?,?,?,?,?)",
        (user_id, otp_code, token, purpose, expires_at)
    )
    conn.commit()
    conn.close()


def get_otp_by_token(token):
    conn = get_db()
    otp = conn.execute("SELECT * FROM otp_store WHERE token = ? AND is_used = 0", (token,)).fetchone()
    conn.close()
    return otp


def get_pending_otp(user_id, purpose):
    conn = get_db()
    otp = conn.execute(
        "SELECT * FROM otp_store WHERE user_id = ? AND purpose = ? AND is_used = 0 ORDER BY created_at DESC LIMIT 1",
        (user_id, purpose)
    ).fetchone()
    conn.close()
    return otp


def mark_otp_used(otp_id):
    conn = get_db()
    conn.execute("UPDATE otp_store SET is_used = 1 WHERE id = ?", (otp_id,))
    conn.commit()
    conn.close()


# ============ PERSON 2: SECURITY AUDIT LOGGING ============

def log_audit(user_id, username, action, details='', ip_address='', severity='INFO'):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, details, ip_address, severity) VALUES (?,?,?,?,?,?)",
        (user_id, username, action, details, ip_address, severity)
    )
    conn.commit()
    conn.close()


def get_audit_logs(limit=200):
    conn = get_db()
    logs = conn.execute("SELECT id, user_id, username, action, details, ip_address, severity, datetime(created_at, 'localtime') as created_at FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return logs


def get_user_audit_logs(user_id, limit=50):
    conn = get_db()
    logs = conn.execute("SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?", (user_id, limit)).fetchall()
    conn.close()
    return logs
