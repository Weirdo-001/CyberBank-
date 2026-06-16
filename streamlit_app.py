# streamlit_app.py
# Citadel National Bank — Security Analytics Dashboard
# Deployed on Streamlit Cloud | Flask app runs separately on AWS EC2
# Reuses database.py + security.py — zero code duplication

import streamlit as st
import sys, os, pandas as pd
from datetime import datetime, timedelta
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import (
    init_db, create_user, get_all_users, get_audit_logs,
    get_all_transactions, unlock_account, log_audit,
    get_user_by_username
)
from security import (
    hash_password, generate_account_number,
    is_account_locked, MAX_FAILED_ATTEMPTS
)

# ── Config ─────────────────────────────────────────────────────
st.set_page_config(
    page_title="Citadel Bank · Security Ops",
    page_icon="🏦", layout="wide",
    initial_sidebar_state="expanded"
)

# ── Seed & Init ────────────────────────────────────────────────
init_db()
SEED = [
    ('admin','System Administrator','admin@citadel.com','Admin@123','admin',50000.0),
    ('banker1','Rajesh Kumar','rajesh@citadel.com','Banker@123','banker',25000.0),
    ('john_doe','John Doe','john@example.com','User@1234','user',15000.0),
    ('jane_smith','Jane Smith','jane@example.com','User@5678','user',22000.0),
]
for u,fn,em,pw,role,bal in SEED:
    if not get_user_by_username(u):
        create_user(u,fn,em,hash_password(pw),role,bal,generate_account_number())

# ── CSS ────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}
#MainMenu,footer,header{visibility:hidden;}

[data-testid="stSidebar"]{
    background:linear-gradient(180deg,#0d2147 0%,#1a3a6b 100%) !important;
}
[data-testid="stSidebar"] *{color:white !important;}

/* Radio nav buttons — make labels clearly visible */
[data-testid="stSidebar"] [data-testid="stRadio"] label {
    color:white !important;
    background:rgba(255,255,255,0.08);
    border:1px solid rgba(255,255,255,0.12);
    border-radius:8px;
    padding:8px 14px !important;
    margin-bottom:5px !important;
    display:flex !important;
    align-items:center !important;
    cursor:pointer;
    transition:all .2s;
    font-weight:500;
    font-size:.88rem;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover{
    background:rgba(255,255,255,0.18) !important;
    transform:translateX(4px);
}
/* Selected item highlight */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked),
[data-testid="stSidebar"] [data-testid="stRadio"] div[aria-checked="true"] label {
    background:rgba(255,255,255,0.25) !important;
    border-color:rgba(255,255,255,0.4) !important;
}
/* Hide the default radio circle — we style the whole label as a button */
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stMarkdownContainer"],
[data-testid="stSidebar"] [data-testid="stRadio"] span[data-baseweb="radio"] > div:first-child{
    display:none !important;
}
[data-testid="stSidebar"] .stButton button{
    background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);
    color:white;border-radius:8px;width:100%;margin-bottom:4px;
    transition:all .2s;
}
[data-testid="stSidebar"] .stButton button:hover{
    background:rgba(255,255,255,0.22);transform:translateX(4px);
}

.kpi{
    background:white;border-radius:14px;padding:1.4rem 1.6rem;
    box-shadow:0 2px 16px rgba(0,0,0,0.06);
    border-top:4px solid var(--c);
    transition:transform .2s;
}
.kpi:hover{transform:translateY(-3px);box-shadow:0 6px 24px rgba(0,0,0,0.1);}
.kpi .lbl{font-size:.72rem;font-weight:600;text-transform:uppercase;
           letter-spacing:.08em;color:#9ca3af;margin-bottom:.4rem;}
.kpi .val{font-size:2.2rem;font-weight:800;color:var(--c);}
.kpi .sub{font-size:.75rem;color:#6b7280;margin-top:.3rem;}

.section-card{
    background:white;border-radius:14px;padding:1.5rem;
    box-shadow:0 2px 12px rgba(0,0,0,0.06);margin-bottom:1.2rem;
}
.section-title{font-size:1rem;font-weight:700;color:#1a3a6b;margin-bottom:1rem;
               padding-bottom:.6rem;border-bottom:2px solid #e5e7eb;}

.threat-row{
    display:flex;justify-content:space-between;align-items:center;
    padding:.6rem .8rem;border-radius:8px;margin-bottom:.4rem;
    background:#fef2f2;border-left:4px solid #ef4444;
}
.threat-row.warn{background:#fffbeb;border-left-color:#f59e0b;}
.threat-row.info{background:#eff6ff;border-left-color:#3b82f6;}

.user-row{
    display:flex;justify-content:space-between;align-items:center;
    padding:.7rem 1rem;background:#f9fafb;border-radius:8px;
    margin-bottom:.5rem;border:1px solid #f3f4f6;
}
.badge{padding:3px 10px;border-radius:20px;font-size:.72rem;font-weight:600;}
.badge-admin{background:#fef3c7;color:#92400e;}
.badge-banker{background:#dbeafe;color:#1d4ed8;}
.badge-user{background:#d1fae5;color:#065f46;}
.badge-locked{background:#fee2e2;color:#991b1b;}
.badge-active{background:#d1fae5;color:#065f46;}
</style>
""", unsafe_allow_html=True)

# ── Load Data ──────────────────────────────────────────────────
@st.cache_data(ttl=10)
def load_data():
    users = [dict(u) for u in get_all_users()]
    logs  = [dict(l) for l in get_audit_logs(limit=500)]
    txns  = [dict(t) for t in get_all_transactions(limit=200)]
    return users, logs, txns

users, logs, txns = load_data()

# ── Header ────────────────────────────────────────────────────
st.markdown("""
<div style="background:linear-gradient(135deg,#0d2147,#1a3a6b);color:white;
            padding:1.2rem 2rem;border-radius:14px;margin-bottom:1rem;
            display:flex;align-items:center;gap:1rem;">
    <span style="font-size:2rem">🏦</span>
    <div>
        <div style="font-size:1.2rem;font-weight:800">Citadel National Bank</div>
        <div style="font-size:.78rem;opacity:.65">Security Operations Center · AES-256-GCM · bcrypt · OTP 2FA · RBAC · Flask (EC2) + Streamlit</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Metrics ────────────────────────────────────────────────────
total_users    = len(users)
locked_users   = sum(1 for u in users if is_account_locked(u.get('locked_until')))
critical_count = sum(1 for l in logs if l.get('severity') == 'CRITICAL')
warning_count  = sum(1 for l in logs if l.get('severity') == 'WARNING')
total_txns     = len(txns)
total_vol      = sum(t.get('amount', 0) for t in txns)
failed_logins  = sum(1 for l in logs if l.get('action') == 'LOGIN_FAILED')
otp_failures   = sum(1 for l in logs if 'OTP_FAILED' in str(l.get('action','')))

# ── Tabs navigation (always visible) ─────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Overview",
    "🛡️ Threat Monitor",
    "👥 User Accounts",
    "💳 Transactions",
    "📋 Audit Trail",
])

# ══════════════════════════════════════════════════════════════
# TAB: OVERVIEW
# ══════════════════════════════════════════════════════════════
with tab1:
    st.markdown("""
    <div style="background:linear-gradient(135deg,#0d2147,#1a3a6b);color:white;
                padding:1.6rem 2rem;border-radius:14px;margin-bottom:1.8rem;">
        <h2 style="margin:0;font-size:1.4rem;font-weight:800">📊 Security Operations Overview</h2>
        <p style="margin:.4rem 0 0;opacity:.65;font-size:.85rem">
            Live metrics · Citadel National Bank · Powered by Streamlit
        </p>
    </div>
    """, unsafe_allow_html=True)

    # KPI Row
    c1,c2,c3,c4 = st.columns(4)
    kpis = [
        (c1, "Total Users",      total_users,  "#1a3a6b", "Registered accounts"),
        (c2, "Locked Accounts",  locked_users, "#dc2626", "Active lockouts"),
        (c3, "Critical Events",  critical_count,"#d97706","Security alerts"),
        (c4, "Transactions",     total_txns,   "#059669", f"₹{total_vol:,.0f} volume"),
    ]
    for col, lbl, val, color, sub in kpis:
        col.markdown(f"""
        <div class="kpi" style="--c:{color}">
            <div class="lbl">{lbl}</div>
            <div class="val">{val}</div>
            <div class="sub">{sub}</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    c_left, c_right = st.columns([3, 2])

    with c_left:
        st.markdown('<div class="section-card"><div class="section-title">📈 Security Events Over Time</div>', unsafe_allow_html=True)
        if logs:
            df_logs = pd.DataFrame(logs)
            df_logs['created_at'] = pd.to_datetime(df_logs['created_at'], errors='coerce')
            df_logs['date'] = df_logs['created_at'].dt.date
            by_sev = df_logs.groupby(['date','severity']).size().reset_index(name='count')
            pivot  = by_sev.pivot(index='date', columns='severity', values='count').fillna(0)
            st.line_chart(pivot, use_container_width=True)
        else:
            st.info("No event data yet.")
        st.markdown('</div>', unsafe_allow_html=True)

    with c_right:
        st.markdown('<div class="section-card"><div class="section-title">🎯 Event Breakdown</div>', unsafe_allow_html=True)
        if logs:
            action_counts = Counter(l['action'] for l in logs)
            top_actions = dict(action_counts.most_common(8))
            df_act = pd.DataFrame({'Action': list(top_actions.keys()),
                                   'Count':  list(top_actions.values())})
            st.bar_chart(df_act.set_index('Action'), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # Second row
    c3a, c3b, c3c = st.columns(3)
    c3a.markdown(f"""
    <div class="kpi" style="--c:#7c3aed">
        <div class="lbl">Failed Logins</div>
        <div class="val">{failed_logins}</div>
        <div class="sub">Brute-force attempts blocked</div>
    </div>""", unsafe_allow_html=True)
    c3b.markdown(f"""
    <div class="kpi" style="--c:#0891b2">
        <div class="lbl">OTP Failures</div>
        <div class="val">{otp_failures}</div>
        <div class="sub">2FA bypass attempts</div>
    </div>""", unsafe_allow_html=True)
    c3c.markdown(f"""
    <div class="kpi" style="--c:#be185d">
        <div class="lbl">Total Volume</div>
        <div class="val">₹{total_vol:,.0f}</div>
        <div class="sub">Across {total_txns} transfers</div>
    </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# PAGE: THREAT MONITOR
# ══════════════════════════════════════════════════════════════
elif "Threat" in page:
    st.markdown("""
    <div style="background:linear-gradient(135deg,#7f1d1d,#991b1b);color:white;
                padding:1.6rem 2rem;border-radius:14px;margin-bottom:1.8rem;">
        <h2 style="margin:0;font-size:1.4rem;font-weight:800">🛡️ Threat Monitor</h2>
        <p style="margin:.4rem 0 0;opacity:.65;font-size:.85rem">
            Real-time security threat detection · CRITICAL & WARNING events
        </p>
    </div>
    """, unsafe_allow_html=True)

    threats = [l for l in logs if l.get('severity') in ('CRITICAL','WARNING')]
    if not threats:
        st.success("✅ No active threats detected.")
    else:
        c_t1, c_t2 = st.columns(2)
        c_t1.metric("Critical Alerts", critical_count, delta=None)
        c_t2.metric("Warnings",        warning_count,  delta=None)
        st.markdown("<br>", unsafe_allow_html=True)

        for t in threats[:30]:
            sev   = t.get('severity','INFO')
            cls   = '' if sev == 'CRITICAL' else 'warn'
            icon  = '🔴' if sev == 'CRITICAL' else '🟡'
            st.markdown(f"""
            <div class="threat-row {cls}">
                <div>
                    <span style="font-weight:700">{icon} {t.get('action','')}</span>
                    <span style="color:#6b7280;font-size:.8rem;margin-left:.8rem">{t.get('details','')}</span>
                </div>
                <div style="font-size:.75rem;color:#9ca3af;text-align:right">
                    {t.get('username','—')}<br>{t.get('created_at','')[:16]}
                </div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-card"><div class="section-title">📊 Threat Severity Distribution</div>', unsafe_allow_html=True)
    if logs:
        sev_counts = Counter(l['severity'] for l in logs)
        df_sev = pd.DataFrame({'Severity': list(sev_counts.keys()),
                               'Count':    list(sev_counts.values())})
        st.bar_chart(df_sev.set_index('Severity'), use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# PAGE: USER ACCOUNTS
# ══════════════════════════════════════════════════════════════
elif "User" in page:
    st.markdown("""
    <div style="background:linear-gradient(135deg,#1a3a6b,#1e40af);color:white;
                padding:1.6rem 2rem;border-radius:14px;margin-bottom:1.8rem;">
        <h2 style="margin:0;font-size:1.4rem;font-weight:800">👥 User Account Management</h2>
        <p style="margin:.4rem 0 0;opacity:.65;font-size:.85rem">
            All registered users · Roles · Balances · Lock status
        </p>
    </div>
    """, unsafe_allow_html=True)

    role_filter = st.selectbox("Filter by Role", ["All","admin","banker","user"])
    filtered_u  = users if role_filter=="All" else [u for u in users if u['role']==role_filter]

    role_counts = Counter(u['role'] for u in users)
    ra,rb,rc,rd = st.columns(4)
    ra.metric("Total",   len(users))
    rb.metric("Admins",  role_counts.get('admin',0))
    rc.metric("Bankers", role_counts.get('banker',0))
    rd.metric("Users",   role_counts.get('user',0))
    st.markdown("<br>", unsafe_allow_html=True)

    for u in filtered_u:
        locked  = is_account_locked(u.get('locked_until'))
        s_badge = '<span class="badge badge-locked">🔒 LOCKED</span>' if locked else '<span class="badge badge-active">✅ Active</span>'
        r_badge = f'<span class="badge badge-{u["role"]}">{u["role"].upper()}</span>'
        st.markdown(f"""
        <div class="user-row">
            <div>
                <b>{u['full_name']}</b>
                <span style="color:#9ca3af;font-size:.8rem;margin-left:.6rem">@{u['username']}</span><br>
                <span style="font-size:.78rem;color:#6b7280">{u['account_number']} · {u['email']}</span>
            </div>
            <div style="text-align:right">
                {r_badge} {s_badge}<br>
                <span style="font-size:.85rem;font-weight:700;color:#1a3a6b">₹{u['balance']:,.2f}</span>
            </div>
        </div>""", unsafe_allow_html=True)
        if locked:
            if st.button(f"🔓 Unlock {u['username']}", key=f"ul_{u['id']}"):
                unlock_account(u['id'])
                log_audit(None,'streamlit_ops','ADMIN_UNLOCK_USER',f"Unlocked {u['username']} via Streamlit dashboard",'','INFO')
                st.cache_data.clear()
                st.success(f"✅ {u['username']} unlocked.")
                st.rerun()

# ══════════════════════════════════════════════════════════════
# PAGE: TRANSACTIONS
# ══════════════════════════════════════════════════════════════
elif "Transaction" in page:
    st.markdown("""
    <div style="background:linear-gradient(135deg,#065f46,#059669);color:white;
                padding:1.6rem 2rem;border-radius:14px;margin-bottom:1.8rem;">
        <h2 style="margin:0;font-size:1.4rem;font-weight:800">💳 Transaction Pipeline</h2>
        <p style="margin:.4rem 0 0;opacity:.65;font-size:.85rem">
            All OTP-verified fund transfers · Atomic DB execution
        </p>
    </div>
    """, unsafe_allow_html=True)

    if txns:
        df_t = pd.DataFrame(txns)
        t1,t2,t3 = st.columns(3)
        t1.metric("Total Transfers", len(txns))
        t2.metric("Total Volume",    f"₹{total_vol:,.2f}")
        t3.metric("Avg Transfer",    f"₹{total_vol/len(txns):,.2f}" if txns else "₹0")
        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown('<div class="section-card"><div class="section-title">📈 Transfer Volume Over Time</div>', unsafe_allow_html=True)
        df_t['created_at'] = pd.to_datetime(df_t['created_at'], errors='coerce')
        df_t['date'] = df_t['created_at'].dt.date
        daily_vol = df_t.groupby('date')['amount'].sum()
        st.area_chart(daily_vol, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="section-card"><div class="section-title">📋 All Transactions</div>', unsafe_allow_html=True)
        display_cols = ['created_at','from_account','to_account','amount','description','status']
        available = [c for c in display_cols if c in df_t.columns]
        st.dataframe(df_t[available].rename(columns={
            'created_at':'Timestamp','from_account':'From',
            'to_account':'To','amount':'Amount (₹)',
            'description':'Description','status':'Status'
        }), use_container_width=True, height=380)
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("No transactions recorded yet. Perform a transfer in the Flask app first.")

# ══════════════════════════════════════════════════════════════
# PAGE: AUDIT TRAIL
# ══════════════════════════════════════════════════════════════
elif "Audit" in page:
    st.markdown("""
    <div style="background:linear-gradient(135deg,#4c1d95,#6d28d9);color:white;
                padding:1.6rem 2rem;border-radius:14px;margin-bottom:1.8rem;">
        <h2 style="margin:0;font-size:1.4rem;font-weight:800">📋 Security Audit Trail</h2>
        <p style="margin:.4rem 0 0;opacity:.65;font-size:.85rem">
            100% traceability · Every login, transfer, and admin action logged
        </p>
    </div>
    """, unsafe_allow_html=True)

    col_s, col_sev, col_act = st.columns([2,1,1])
    search  = col_s.text_input("Search", placeholder="User, action, details, IP…")
    sev_f   = col_sev.selectbox("Severity", ["All","CRITICAL","WARNING","INFO"])
    actions = ["All"] + sorted(set(l.get('action','') for l in logs))
    act_f   = col_act.selectbox("Action", actions)

    filtered = logs
    if search:
        q = search.lower()
        filtered = [l for l in filtered if any(q in str(l.get(k,'')).lower()
                    for k in ('username','action','details','ip_address'))]
    if sev_f != "All":
        filtered = [l for l in filtered if l.get('severity')==sev_f]
    if act_f != "All":
        filtered = [l for l in filtered if l.get('action')==act_f]

    st.markdown(f"**{len(filtered)} records**")
    if filtered:
        df_l = pd.DataFrame(filtered)
        show_cols = ['created_at','username','action','severity','details','ip_address']
        available = [c for c in show_cols if c in df_l.columns]
        st.dataframe(
            df_l[available].rename(columns={
                'created_at':'Timestamp','username':'User',
                'action':'Action','severity':'Severity',
                'details':'Details','ip_address':'IP'
            }),
            use_container_width=True, height=480
        )
    else:
        st.info("No logs match your filters.")
