import streamlit as st
import sys, os, pandas as pd
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import (
    init_db, create_user, get_all_users, get_audit_logs,
    get_all_transactions, unlock_account, log_audit, get_user_by_username
)
from security import (
    hash_password, generate_account_number,
    is_account_locked, MAX_FAILED_ATTEMPTS
)

st.set_page_config(page_title="Citadel Bank · Security Ops", page_icon="🏦", layout="wide")

init_db()
for u,fn,em,pw,role,bal in [
    ('admin','System Administrator','admin@citadel.com','Admin@123','admin',50000.0),
    ('banker1','Rajesh Kumar','rajesh@citadel.com','Banker@123','banker',25000.0),
    ('john_doe','John Doe','john@example.com','User@1234','user',15000.0),
    ('jane_smith','Jane Smith','jane@example.com','User@5678','user',22000.0),
]:
    if not get_user_by_username(u):
        create_user(u,fn,em,hash_password(pw),role,bal,generate_account_number())

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}
#MainMenu,footer,header{visibility:hidden;}
.kpi{background:white;border-radius:12px;padding:1.2rem 1.4rem;
     box-shadow:0 2px 12px rgba(0,0,0,0.06);border-top:4px solid var(--c);}
.kpi .lbl{font-size:.72rem;font-weight:600;text-transform:uppercase;
          letter-spacing:.07em;color:#9ca3af;margin-bottom:.3rem;}
.kpi .val{font-size:2rem;font-weight:800;color:var(--c);}
.kpi .sub{font-size:.72rem;color:#6b7280;margin-top:.2rem;}
.card{background:white;border-radius:12px;padding:1.4rem;
      box-shadow:0 2px 10px rgba(0,0,0,0.06);margin-bottom:1rem;}
.card-title{font-size:.95rem;font-weight:700;color:#1a3a6b;
            border-bottom:2px solid #e5e7eb;padding-bottom:.5rem;margin-bottom:.8rem;}
.urow{display:flex;justify-content:space-between;align-items:center;
      padding:.7rem 1rem;background:#f9fafb;border-radius:8px;
      margin-bottom:.4rem;border:1px solid #f3f4f6;}
.badge{padding:2px 9px;border-radius:20px;font-size:.7rem;font-weight:700;}
.ba{background:#fef3c7;color:#92400e;}
.bb{background:#dbeafe;color:#1d4ed8;}
.bu{background:#d1fae5;color:#065f46;}
.blk{background:#fee2e2;color:#991b1b;}
.bact{background:#d1fae5;color:#065f46;}
.thr{display:flex;justify-content:space-between;align-items:center;
     padding:.55rem .8rem;border-radius:7px;margin-bottom:.35rem;
     background:#fef2f2;border-left:4px solid #ef4444;}
.thr.w{background:#fffbeb;border-left-color:#f59e0b;}
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div style="background:linear-gradient(135deg,#0d2147,#1a3a6b);color:white;
            padding:1.1rem 1.8rem;border-radius:12px;margin-bottom:1rem;
            display:flex;align-items:center;gap:.9rem;">
  <span style="font-size:1.8rem">🏦</span>
  <div>
    <div style="font-size:1.1rem;font-weight:800">Citadel National Bank</div>
    <div style="font-size:.75rem;opacity:.65">
      Security Operations Center · AES-256-GCM · bcrypt · OTP 2FA · RBAC · Flask (EC2) + Streamlit
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

@st.cache_data(ttl=15)
def load():
    return (
        [dict(u) for u in get_all_users()],
        [dict(l) for l in get_audit_logs(limit=500)],
        [dict(t) for t in get_all_transactions(limit=200)],
    )

users, logs, txns = load()

total_users    = len(users)
locked_users   = sum(1 for u in users if is_account_locked(u.get('locked_until')))
critical_count = sum(1 for l in logs if l.get('severity')=='CRITICAL')
warning_count  = sum(1 for l in logs if l.get('severity')=='WARNING')
total_txns     = len(txns)
total_vol      = sum(t.get('amount',0) for t in txns)
failed_logins  = sum(1 for l in logs if l.get('action')=='LOGIN_FAILED')
otp_fails      = sum(1 for l in logs if 'OTP_FAILED' in str(l.get('action','')))

def kpi(col, label, val, color, sub=""):
    col.markdown(f"""<div class="kpi" style="--c:{color}">
      <div class="lbl">{label}</div><div class="val">{val}</div>
      <div class="sub">{sub}</div></div>""", unsafe_allow_html=True)

# ── Tabs ───────────────────────────────────────────────────────
t1,t2,t3,t4,t5 = st.tabs([
    "📊 Overview","🛡️ Threat Monitor","👥 Users","💳 Transactions","📋 Audit Trail"
])

# ══ TAB 1: OVERVIEW ══════════════════════════════════════════
with t1:
    c1,c2,c3,c4,c5 = st.columns(5)
    kpi(c1,"Total Users",     total_users,   "#1a3a6b","Registered accounts")
    kpi(c2,"Locked",          locked_users,  "#dc2626","Active lockouts")
    kpi(c3,"Critical Events", critical_count,"#d97706","Security alerts")
    kpi(c4,"Transactions",    total_txns,    "#059669",f"₹{total_vol:,.0f} volume")
    kpi(c5,"OTP Failures",    otp_fails,     "#7c3aed","2FA bypass attempts")

    st.markdown("<br>", unsafe_allow_html=True)
    left, right = st.columns([3,2])

    with left:
        st.markdown('<div class="card"><div class="card-title">📈 Security Events Over Time</div>', unsafe_allow_html=True)
        if logs:
            df = pd.DataFrame(logs)
            df['created_at'] = pd.to_datetime(df['created_at'], errors='coerce')
            df['date'] = df['created_at'].dt.date
            pivot = df.groupby(['date','severity']).size().reset_index(name='n') \
                      .pivot(index='date', columns='severity', values='n').fillna(0)
            st.line_chart(pivot, use_container_width=True)
        else:
            st.info("No events yet.")
        st.markdown('</div>', unsafe_allow_html=True)

    with right:
        st.markdown('<div class="card"><div class="card-title">🎯 Top Actions</div>', unsafe_allow_html=True)
        if logs:
            top = dict(Counter(l['action'] for l in logs).most_common(7))
            st.bar_chart(pd.DataFrame({'Count': top}), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    a,b,c = st.columns(3)
    kpi(a,"Failed Logins",  failed_logins,         "#be185d","Brute-force blocked")
    kpi(b,"Warning Events", warning_count,          "#0891b2","Needs attention")
    kpi(c,"Total Volume",   f"₹{total_vol:,.0f}",  "#059669",f"Across {total_txns} transfers")

# ══ TAB 2: THREAT MONITOR ════════════════════════════════════
with t2:
    st.markdown("""<div style="background:linear-gradient(135deg,#7f1d1d,#991b1b);
    color:white;padding:1.2rem 1.6rem;border-radius:12px;margin-bottom:1rem;">
    <b style="font-size:1.1rem">🛡️ Threat Monitor</b>
    <p style="margin:.3rem 0 0;opacity:.65;font-size:.8rem">CRITICAL &amp; WARNING events · Live feed</p>
    </div>""", unsafe_allow_html=True)

    threats = [l for l in logs if l.get('severity') in ('CRITICAL','WARNING')]
    ca, cb = st.columns(2)
    ca.metric("Critical Alerts", critical_count)
    cb.metric("Warnings",        warning_count)
    st.markdown("<br>", unsafe_allow_html=True)

    if not threats:
        st.success("✅ No active threats detected.")
    else:
        for th in threats[:30]:
            sev  = th.get('severity','')
            cls  = '' if sev=='CRITICAL' else 'w'
            icon = '🔴' if sev=='CRITICAL' else '🟡'
            st.markdown(f"""<div class="thr {cls}">
              <div><b>{icon} {th.get('action','')}</b>
                   <span style="color:#6b7280;font-size:.78rem;margin-left:.6rem">{th.get('details','')}</span>
              </div>
              <div style="font-size:.72rem;color:#9ca3af;text-align:right">
                {th.get('username','—')}<br>{str(th.get('created_at',''))[:16]}
              </div></div>""", unsafe_allow_html=True)

    st.markdown('<div class="card"><div class="card-title">📊 Severity Distribution</div>', unsafe_allow_html=True)
    if logs:
        sc = Counter(l['severity'] for l in logs)
        st.bar_chart(pd.DataFrame({'Count': sc}), use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ══ TAB 3: USERS ═════════════════════════════════════════════
with t3:
    st.markdown("""<div style="background:linear-gradient(135deg,#1a3a6b,#1e40af);
    color:white;padding:1.2rem 1.6rem;border-radius:12px;margin-bottom:1rem;">
    <b style="font-size:1.1rem">👥 User Accounts</b>
    <p style="margin:.3rem 0 0;opacity:.65;font-size:.8rem">Roles · Balances · Lock status</p>
    </div>""", unsafe_allow_html=True)

    rc = Counter(u['role'] for u in users)
    ua,ub,uc,ud = st.columns(4)
    ua.metric("Total",   total_users)
    ub.metric("Admins",  rc.get('admin',0))
    uc.metric("Bankers", rc.get('banker',0))
    ud.metric("Users",   rc.get('user',0))

    role_f = st.selectbox("Filter by Role", ["All","admin","banker","user"], key="role_filter_t3")
    show   = users if role_f=="All" else [u for u in users if u['role']==role_f]
    st.markdown("<br>", unsafe_allow_html=True)

    rbadge = {'admin':'ba','banker':'bb','user':'bu'}
    for u in show:
        locked  = is_account_locked(u.get('locked_until'))
        sb = f'<span class="badge blk">🔒 LOCKED</span>' if locked else '<span class="badge bact">✅ Active</span>'
        rb = f'<span class="badge {rbadge.get(u["role"],"bu")}">{u["role"].upper()}</span>'
        st.markdown(f"""<div class="urow">
          <div><b>{u['full_name']}</b>
               <span style="color:#9ca3af;font-size:.78rem;margin-left:.5rem">@{u['username']}</span><br>
               <span style="font-size:.73rem;color:#6b7280">{u['account_number']} · {u['email']}</span>
          </div>
          <div style="text-align:right">{rb} {sb}<br>
               <b style="color:#1a3a6b">₹{u['balance']:,.2f}</b>
          </div></div>""", unsafe_allow_html=True)
        if locked:
            if st.button(f"🔓 Unlock {u['username']}", key=f"unlock_u_{u['id']}"):
                unlock_account(u['id'])
                log_audit(None,'streamlit_ops','ADMIN_UNLOCK_USER',
                          f"Unlocked {u['username']} via dashboard",'','INFO')
                st.cache_data.clear()
                st.success(f"✅ {u['username']} unlocked.")
                st.rerun()

# ══ TAB 4: TRANSACTIONS ══════════════════════════════════════
with t4:
    st.markdown("""<div style="background:linear-gradient(135deg,#065f46,#059669);
    color:white;padding:1.2rem 1.6rem;border-radius:12px;margin-bottom:1rem;">
    <b style="font-size:1.1rem">💳 Transaction Pipeline</b>
    <p style="margin:.3rem 0 0;opacity:.65;font-size:.8rem">OTP-verified · Atomic DB execution</p>
    </div>""", unsafe_allow_html=True)

    if not txns:
        st.info("No transactions yet. Perform a transfer in the Flask app first.")
    else:
        ta,tb,tc = st.columns(3)
        ta.metric("Total Transfers", total_txns)
        tb.metric("Total Volume",    f"₹{total_vol:,.2f}")
        tc.metric("Avg Transfer",    f"₹{total_vol/total_txns:,.2f}")
        st.markdown("<br>", unsafe_allow_html=True)

        df_t = pd.DataFrame(txns)
        df_t['created_at'] = pd.to_datetime(df_t['created_at'], errors='coerce')
        df_t['date'] = df_t['created_at'].dt.date

        st.markdown('<div class="card"><div class="card-title">📈 Daily Transfer Volume</div>', unsafe_allow_html=True)
        st.area_chart(df_t.groupby('date')['amount'].sum(), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="card"><div class="card-title">📋 All Transfers</div>', unsafe_allow_html=True)
        cols = [c for c in ['created_at','from_account','to_account','amount','description','status'] if c in df_t.columns]
        st.dataframe(df_t[cols].rename(columns={
            'created_at':'Timestamp','from_account':'From','to_account':'To',
            'amount':'Amount (₹)','description':'Description','status':'Status'
        }), use_container_width=True, height=360)
        st.markdown('</div>', unsafe_allow_html=True)

# ══ TAB 5: AUDIT TRAIL ═══════════════════════════════════════
with t5:
    st.markdown("""<div style="background:linear-gradient(135deg,#4c1d95,#6d28d9);
    color:white;padding:1.2rem 1.6rem;border-radius:12px;margin-bottom:1rem;">
    <b style="font-size:1.1rem">📋 Security Audit Trail</b>
    <p style="margin:.3rem 0 0;opacity:.65;font-size:.8rem">100% traceability · Every login, transfer &amp; admin action</p>
    </div>""", unsafe_allow_html=True)

    cs, csev, cact = st.columns([2,1,1])
    srch  = cs.text_input("Search", placeholder="User, action, details, IP…", key="audit_search")
    sevf  = csev.selectbox("Severity", ["All","CRITICAL","WARNING","INFO"], key="audit_sev")
    acts  = ["All"] + sorted({l.get('action','') for l in logs})
    actf  = cact.selectbox("Action", acts, key="audit_act")

    fil = logs
    if srch:
        q   = srch.lower()
        fil = [l for l in fil if any(q in str(l.get(k,'')).lower()
               for k in ('username','action','details','ip_address'))]
    if sevf != "All":
        fil = [l for l in fil if l.get('severity')==sevf]
    if actf != "All":
        fil = [l for l in fil if l.get('action')==actf]

    st.markdown(f"**{len(fil)} records**")
    if fil:
        df_l = pd.DataFrame(fil)
        vcols = [c for c in ['created_at','username','action','severity','details','ip_address'] if c in df_l.columns]
        st.dataframe(df_l[vcols].rename(columns={
            'created_at':'Timestamp','username':'User','action':'Action',
            'severity':'Severity','details':'Details','ip_address':'IP'
        }), use_container_width=True, height=460)
    else:
        st.info("No logs match your filters.")

st.markdown("""<hr style="border:none;border-top:1px solid #e5e7eb;margin-top:1.5rem">
<p style="text-align:center;color:#9ca3af;font-size:.73rem">
Citadel National Bank · AES-256-GCM · bcrypt · RBAC · OTP 2FA · SQLite ·
Flask (EC2 primary app) + Streamlit (Security Analytics)
</p>""", unsafe_allow_html=True)
