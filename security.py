# security.py
# Handles: password hashing, OTP generation, account lockout, encryption

import bcrypt
import secrets
import string
import os
from datetime import datetime, timedelta
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------- PERSON 2: PASSWORD CRYPTOGRAPHY (BCRYPT) ---------------

def hash_password(password):
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed):
    """Verify a password against its bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


# --------------- PERSON 1: MULTI-FACTOR AUTHENTICATION (OTP GENERATION & CSPRNG) ---------------

def generate_otp():
    """Generate a 6-digit OTP."""
    return ''.join(secrets.choice(string.digits) for _ in range(6))


def generate_token():
    """Generate a secure URL-safe token for OTP delivery link."""
    return secrets.token_urlsafe(32)


# --------------- Account Number ---------------

def generate_account_number():
    """Generate a unique account number like CNB-XXXXXXXXXX."""
    digits = ''.join(secrets.choice(string.digits) for _ in range(10))
    return f'CNB{digits}'


# --------------- PERSON 2: ACCOUNT LOCKOUT POLICY (BRUTE-FORCE DEFENSE) ---------------

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_HOURS = 24


def is_account_locked(locked_until):
    """Check if an account is currently locked."""
    if not locked_until:
        return False
    try:
        lock_time = datetime.fromisoformat(locked_until)
        return lock_time > datetime.now()
    except (ValueError, TypeError):
        return False


def get_lockout_time():
    """Return the datetime string when lockout expires (24 hours from now)."""
    return (datetime.now() + timedelta(hours=LOCKOUT_HOURS)).isoformat()


def get_lockout_remaining(locked_until):
    """Return human-readable remaining lockout time."""
    if not locked_until:
        return None
    try:
        lock_time = datetime.fromisoformat(locked_until)
        remaining = lock_time - datetime.now()
        if remaining.total_seconds() <= 0:
            return None
        hours = int(remaining.total_seconds() // 3600)
        minutes = int((remaining.total_seconds() % 3600) // 60)
        return f"{hours}h {minutes}m"
    except (ValueError, TypeError):
        return None


# --------------- PERSON 1: DATA AT REST ENCRYPTION (AES-256-GCM) ---------------
# Uses AES-256-GCM: 256-bit key, 96-bit random nonce, authenticated encryption.
# Nonce is prepended to ciphertext before base64 encoding — no nonce reuse possible.

KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.aes256_key')


def _get_encryption_key():
    """Load or create a 32-byte (256-bit) AES key."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
            if len(key) == 32:
                return key
    # Generate new cryptographically secure 256-bit key
    key = os.urandom(32)
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key


def encrypt_data(data):
    """Encrypt a string using AES-256-GCM with a fresh random 96-bit nonce."""
    if not data:
        return data
    key = _get_encryption_key()
    aesgcm = AESGCM(key)              # AES-256-GCM (key is 32 bytes = 256 bits)
    nonce = os.urandom(12)            # 96-bit nonce — NIST recommended for GCM
    ct = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
    # Layout: [12-byte nonce][ciphertext+16-byte auth tag], base64url encoded
    return base64.urlsafe_b64encode(nonce + ct).decode('utf-8')


def decrypt_data(encrypted_data):
    """Decrypt an AES-256-GCM ciphertext. Verifies auth tag automatically."""
    if not encrypted_data:
        return encrypted_data
    try:
        key = _get_encryption_key()
        aesgcm = AESGCM(key)
        raw = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
        nonce, ct = raw[:12], raw[12:]   # Split out the prepended nonce
        return aesgcm.decrypt(nonce, ct, None).decode('utf-8')
    except Exception:
        return '[decryption error]'
