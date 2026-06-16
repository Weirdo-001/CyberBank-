# 🏦 Citadel National Bank — Secure Banking Portal

> A security-hardened Flask banking application demonstrating real-world authentication, authorization, and data protection controls — built as part of the PGDM (FinTech) Cyber Security assignment.

---

## 📖 Project Description

Citadel National Bank is a fully functional banking web portal engineered with a **security-first** mindset. The application simulates real banking operations — user registration, login with Two-Factor Authentication, fund transfers, and role-based dashboards — while hardening each layer against the most critical web vulnerabilities.

The project was inspired by and built to directly address the weaknesses found in the `unsafe_banking` and `secure-login-system` reference projects. Every route, every form, and every database query has been designed to prevent exploitation.

---

## 📚 References Studied

We studied and derived inspiration from the following reference projects in `learning/cyber_security/`:

- **`unsafe_banking`** — Analyzed its intentional vulnerabilities including SQL Injection, IDOR, missing authentication, and no input validation. Our application directly fixes every one of these.
- **`secure-login-system`** — Studied its session management, bcrypt hashing, and login flow patterns to implement a robust authentication pipeline.
- **`minipay`** — Referenced its secure payment token flow to design our OTP-signed fund transfer system.

---

## 🔐 Security Concepts Implemented

### 1. SQL Injection Prevention
**Vulnerable pattern:** Directly formatting user input into SQL strings  
```python
# UNSAFE — vulnerable to ' OR '1'='1' --
f"SELECT * FROM users WHERE username='{username}'"
```
**Our fix:** 100% parameterized queries throughout `database.py`
```python
# SAFE — user input treated as literal data, never executable
conn.execute("SELECT * FROM users WHERE username = ?", (username,))
```

### 2. Plaintext Password Protection
**Vulnerable pattern:** Storing passwords in plaintext or with weak MD5/SHA1  
**Our fix:** All passwords hashed using **bcrypt** with a unique salt per user. Even if the database is leaked, passwords cannot be reversed.

### 3. OTP Two-Factor Authentication (2FA)
Every login and every fund transfer requires a **One-Time Password** valid for 5 minutes. OTPs are generated randomly, **AES-256 encrypted** before being stored in the database, and invalidated after use or 3 failed attempts.

### 4. AES-256 Encryption at Rest
Sensitive OTP codes are encrypted using AES-256 before being written to the database. Even with direct database access, the codes are unreadable without the encryption key.

### 5. CSRF Protection
Every form across the application is protected with a **Flask-WTF CSRF token**. Forged cross-site requests are rejected automatically — no form submission is accepted without a valid, session-bound token.

### 6. Role-Based Access Control (RBAC)
Three distinct roles — **Admin**, **Banker**, **User** — each with strictly enforced permissions:
- Users cannot access admin routes
- Bankers cannot modify user balances
- Unauthorized access attempts are logged as `WARNING` in the audit trail

### 7. IDOR Prevention
The source account in every transfer is **always** pulled from the server-side session — never from client-supplied form data. A user cannot initiate a transfer on behalf of another account by tampering with form fields.

### 8. Account Lockout & Brute Force Protection
After **5 consecutive failed login attempts**, the account is locked for **24 hours**. OTP entry is also limited to 3 attempts before the session is invalidated.

### 9. Session Timeout & Cache Control
Sessions automatically expire after **15 minutes of inactivity**. All authenticated pages send `Cache-Control: no-store` headers, preventing sensitive data from being retrieved via the browser back button after logout.

### 10. Security Audit Logging
Every significant action — logins, failed attempts, lockouts, transfers, admin edits — is recorded in a tamper-visible audit log with timestamp, user, IP address, and severity level (`INFO` / `WARNING` / `CRITICAL`).

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.8 or higher installed
- `py` or `python` available in your terminal

### Step 1 — Create a Virtual Environment *(Recommended)*
```bash
py -m venv venv
venv\Scripts\activate
```

### Step 2 — Install Dependencies
```bash
py -m pip install -r requirements.txt
```

### Step 3 — Run the Application
```bash
py app.py
```

The database (`citadel.db`) is **automatically created and seeded** on the first run.  
Open your browser and go to: **http://127.0.0.1:5000**

---

## 🧪 Test Credentials

The following accounts are seeded automatically on first run:

| Role   | Username     | Password      |
|--------|--------------|---------------|
| Admin  | `admin`      | `Admin@123`   |
| Banker | `banker1`    | `Banker@123`  |
| User   | `john_doe`   | `User@1234`   |
| User   | `jane_smith` | `User@5678`   |

> ⚠️ These credentials are for demonstration only.

---

## 🗂️ Project Structure

```
CyberBank/
├── app.py                  ← All Flask routes and application logic
├── database.py             ← Parameterized DB operations (SQLite)
├── security.py             ← bcrypt, AES-256, OTP, lockout utilities
├── requirements.txt        ← Python dependencies
├── group_info.md           ← Team members and roles
├── README.md               ← This file
│
├── templates/              ← Jinja2 HTML templates
│   ├── base.html
│   ├── landing.html
│   ├── login.html
│   ├── register.html
│   ├── verify_otp.html     ← 2FA OTP entry
│   ├── show_otp.html       ← Simulated OTP delivery
│   ├── dashboard_admin.html
│   ├── dashboard_banker.html
│   ├── dashboard_user.html
│   ├── admin_users.html
│   ├── admin_edit_user.html
│   ├── admin_logs.html     ← Live security audit trail
│   ├── banker_customers.html
│   ├── transfer.html
│   ├── verify_transfer.html
│   ├── transactions.html
│   ├── profile.html
│   └── error.html
│
└── static/                 ← CSS, fonts, and assets
```

---

## 🛠️ Tech Stack

| Layer      | Technology                                |
|------------|-------------------------------------------|
| Backend    | Python 3, Flask                           |
| Database   | SQLite3 (parameterized queries)           |
| Auth       | bcrypt, Flask-WTF (CSRF), OTP (secrets)   |
| Encryption | AES-256 (cryptography library)            |
| Frontend   | HTML5, CSS3, Jinja2                       |

---

## 👥 Group Members

| Roll Number | Full Name          | Person No. | Responsibility                                                                        |
|-------------|--------------------|----|----------------------------------------------------------------------------------------|
| 2310990266  | Aditya Goyal       | 1  | CSRF Protection, OTP 2FA Generation, AES-256 Encryption & OTP DB State Management    |
| 2310990258  | Aarushi Sharma     | 2  | bcrypt Password Hashing, Account Lockout Policy, Security Auditing & Admin Panel (Team Lead) |
| 2310990268  | Adwita Jindal      | 3  | IDOR Prevention & SQL Injection Prevention (Parameterized Queries)                    |
| 2310990210  | Arjit              | 4  | Role-Based Access Control (RBAC)                                                      |
| 2310990192  | Amreen Kaur Sandhu | 5  | Session State & Browser Security (Session Timeout, Cache Control Headers)             |

---

> ⚠️ **Disclaimer:** This project is built for educational purposes as part of a cybersecurity assignment. Test credentials and simulated OTP delivery are intentional demo features. Do not deploy with these defaults in a production environment.
