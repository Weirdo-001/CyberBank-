# streamlit_app.py
# Citadel National Bank — Security Monitoring Dashboard
# Reuses database.py and security.py directly (no Flask required here)
# Flask remains the primary banking app; this is a live monitoring layer.

import streamlit as st
import sys, os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import (
    init_db, create_user,
    get_all_users, get_audit_logs, get_all_transactions,
    unlock_account, log_audit, get_user_by_username
)
from security import (
    hash_password, generate_account_number,
    is_account_locked, MAX_FAILED_ATTEMPTS
)

# ── Page Config ────────────────────────────────────────────────
st.set_page_config(
    page_title="Citadel Bank — Security Dashboard",
    page_icon="🏦",
    layout="wide"
)

# ── Init DB & Seed ─────────────────────────────────────────────
init_db()

SEED_USERS = [
    ('admin',      'System Administrator', 'admin@citadel.com',  'Admin@123',  'admin',  50000.0),
    ('banker1',    'Rajesh Kumar',         'rajesh@citadel.com', 'Banker@123', 'banker', 25000.0),
    ('john_doe',   'John Doe',             'john@example.com',   'User@1234',  'user',   15000.0),
    ('jane_smith', 'Jane Smith',           'jane@example.com',   'User@5678',  'user',   22000.0),
]
for u, fn, em, pw, role, bal in SEED_USERS:
    if not get_user_by_username(u):
        create_user(u, fn, em, hash_password(pw), role, bal, generate_account_number())

# ── Styling ────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
#MainMenu, footer { visibility: hidden; }
.metric-card {
    background: white;
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    box-shadow: 0 2px 8px rgba(0,0,0,0.07);
    border-left: 4px solid #1a3a6b;
}
.metric-card .lbl { color:#6b7280; font-size:0.78rem; text-transform:uppercase; letter-spacing:.05em; }
.metric-card .val { font-size:2rem; font-weight:700; color:#1a3a6b; }
.sev-CRITICAL { color:#dc2626; font-weight:700; }
.sev-WARNING  { color:#d97706; font-weight:600; }
.sev-INFO     { color:#2563eb; }
</style>
""", unsafe_allow_html=True)

# ── Header ─────────────────────────────────────────────────────
st.markdown("""
<div style="background:linear-gradient(135deg,#1a3a6b,#0d2147);
            color:white;padding:1.4rem 2rem;border-radius:12px;margin-bottom:1.5rem;">
    <h2 style="margin:0;font-size:1.5rem">🏦 Citadel National Bank</h2>
    <p style="margin:0;opacity:.7;font-size:.85rem">Security Operations Dashboard — Live Monitoring</p>
</div>
""", unsafe_allow_html=True)

# ── Load data ──────────────────────────────────────────────────
all_users  = get_all_users()
all_logs   = get_audit_logs(limit=200)
all_txns   = get_all_transactions(limit=100)

users_list = [dict(u) for u in all_users]
logs_list  = [dict(l) for l in all_logs]
txns_list  = [dict(t) for t in all_txns]

total_users    = len(users_list)
locked_users   = sum(1 for u in users_list if is_account_locked(u.get('locked_until')))
critical_events= sum(1 for l in logs_list if l.get('severity') == 'CRITICAL')
total_txns     = len(txns_list)
total_volume   = sum(t.get('amount', 0) for t in txns_list)

# ── KPI Row ────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)
def kpi(col, label, value, color="#1a3a6b"):
    col.markdown(f"""
    <div class="metric-card" style="border-left-color:{color}">
        <div class="lbl">{label}</div>
        <div class="val" style="color:{color}">{value}</div>
    </div>""", unsafe_allow_html=True)

kpi(c1, "Total Users",      total_users)
kpi(c2, "Locked Accounts",  locked_users,    "#dc2626")
kpi(c3, "Critical Events",  critical_events, "#d97706")
kpi(c4, "Transactions",     total_txns,      "#059669")
kpi(c5, "Volume (₹)",       f"{total_volume:,.0f}", "#7c3aed")

st.markdown("<br>", unsafe_allow_html=True)

# ── Tabs ───────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["🛡️ Audit Logs", "👥 User Accounts", "💳 Transactions"])

# ── Tab 1: Audit Logs ──────────────────────────────────────────
with tab1:
    col_f1, col_f2 = st.columns([2, 1])
    with col_f1:
        search = st.text_input("Search logs", placeholder="Filter by action, user, or details…")
    with col_f2:
        sev_filter = st.selectbox("Severity", ["All", "CRITICAL", "WARNING", "INFO"])

    filtered = logs_list
    if search:
        q = search.lower()
        filtered = [l for l in filtered if
                    q in str(l.get('action','')).lower() or
                    q in str(l.get('username','')).lower() or
                    q in str(l.get('details','')).lower()]
    if sev_filter != "All":
        filtered = [l for l in filtered if l.get('severity') == sev_filter]

    if not filtered:
        st.info("No logs match your filter.")
    else:
        import pandas as pd
        df = pd.DataFrame(filtered)[['created_at','username','action','severity','details','ip_address']]
        df.columns = ['Timestamp', 'User', 'Action', 'Severity', 'Details', 'IP']
        st.dataframe(df, use_container_width=True, height=420)

# ── Tab 2: Users ───────────────────────────────────────────────
with tab2:
    import pandas as pd
    for u in users_list:
        locked = is_account_locked(u.get('locked_until'))
        status = "🔒 LOCKED" if locked else ("✅ Active" if u.get('is_active') else "❌ Inactive")
        badge  = {"admin":"🟡","banker":"🔵","user":"🟢"}.get(u['role'], "⚪")

        with st.expander(f"{badge} {u['username']} — {u['full_name']}  |  {status}"):
            col_a, col_b, col_c = st.columns(3)
            col_a.metric("Role",    u['role'].upper())
            col_b.metric("Balance", f"₹{u['balance']:,.2f}")
            col_c.metric("Account", u['account_number'])

            if locked:
                if st.button(f"🔓 Unlock {u['username']}", key=f"unlock_{u['id']}"):
                    unlock_account(u['id'])
                    log_audit(None, 'streamlit_admin', 'ADMIN_UNLOCK_USER',
                              f"Unlocked {u['username']} via dashboard", '', 'INFO')
                    st.success(f"Account {u['username']} unlocked.")
                    st.rerun()

# ── Tab 3: Transactions ────────────────────────────────────────
with tab3:
    if not txns_list:
        st.info("No transactions recorded yet.")
    else:
        import pandas as pd
        df = pd.DataFrame(txns_list)[['created_at','from_account','to_account','amount','description','status']]
        df.columns = ['Timestamp', 'From', 'To', 'Amount (₹)', 'Description', 'Status']
        st.dataframe(df, use_container_width=True, height=420)
        st.markdown(f"**Total transacted: ₹{total_volume:,.2f}** across {total_txns} transfers.")

# ── Footer ─────────────────────────────────────────────────────
st.markdown("""
<hr style="border:none;border-top:1px solid #e5e7eb;margin-top:2rem">
<p style="text-align:center;color:#9ca3af;font-size:.78rem">
    Citadel National Bank · AES-256-GCM · bcrypt · RBAC · OTP 2FA · SQLite
    · Flask (primary app) + Streamlit (monitoring)
</p>
""", unsafe_allow_html=True)
