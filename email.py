import streamlit as st
import re
import pandas as pd
from io import BytesIO
from datetime import datetime
import plotly.express as px

# ----------------------------------------------------------------
# PAGE CONFIG
# ----------------------------------------------------------------
st.set_page_config(page_title="CyberSOC Console", page_icon="🧠", layout="wide")

# ----------------------------------------------------------------
# GLOBAL VARIABLES
# ----------------------------------------------------------------
ATTACHMENT_SIZE_LIMIT_MB = 5
ATTACHMENT_SIZE_LIMIT_BYTES = ATTACHMENT_SIZE_LIMIT_MB * 1024 * 1024

# ----------------------------------------------------------------
# CUSTOM STYLES
# ----------------------------------------------------------------
st.markdown("""
<style>
/* Main page styling */
.stApp {
    background: radial-gradient(circle at top left, #0d1117, #010409);
    color: #e5e7eb;
    font-family: 'Segoe UI', sans-serif;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0a0f16;
    border-right: 1px solid #00e5ff30;
}
section[data-testid="stSidebar"] h1 {
    color: #00e5ff;
}

/* Headers */
h1, h2, h3 {
    color: #00e5ff;
    font-weight: 600;
}

/* Buttons */
.stButton button {
    background: linear-gradient(90deg, #00e5ff, #0078ff);
    border: none;
    color: white;
    font-weight: 600;
    border-radius: 10px;
    transition: 0.3s ease;
}
.stButton button:hover {
    box-shadow: 0 0 20px #00e5ff;
}

/* Metric Cards */
.metric-card {
    background: linear-gradient(180deg, #0d1b2a, #0a192f);
    border: 1px solid #00e5ff40;
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    box-shadow: 0 0 15px #00e5ff20;
    transition: 0.4s;
}
.metric-card:hover {
    transform: scale(1.05);
    box-shadow: 0 0 25px #00e5ff50;
}

/* Alert Banner */
@keyframes pulse {
  0% {background-position: 0% 50%;}
  50% {background-position: 100% 50%;}
  100% {background-position: 0% 50%;}
}
.alert-banner {
  background: linear-gradient(270deg, #ff003c, #ff512f);
  background-size: 400% 400%;
  animation: pulse 2s infinite;
  padding: 15px;
  text-align: center;
  color: white;
  font-weight: bold;
  border-radius: 8px;
  margin-bottom: 15px;
  font-size: 18px;
  text-shadow: 1px 1px 2px #000;
}

/* Email cards */
.email-card {
  background: #0e1726;
  border-radius: 10px;
  padding: 15px;
  margin-bottom: 12px;
  border-left: 4px solid #00e5ff80;
  box-shadow: 0 0 10px #00e5ff20;
  transition: 0.3s;
}
.email-card:hover {
  box-shadow: 0 0 25px #00e5ff50;
}

/* Live Feed */
.live-feed {
  background: #001524;
  padding: 12px;
  border-radius: 10px;
  border-left: 5px solid #00e5ff;
  margin-bottom: 10px;
  transition: 0.3s;
}
.live-feed:hover {
  background: #00263b;
}
</style>
""", unsafe_allow_html=True)

# ----------------------------------------------------------------
# FUNCTIONS
# ----------------------------------------------------------------
REGEX_PATTERNS = {
    "Phone Number": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Financial Amount": r"[$€£¥]\s*\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?",
}

def detect_phishing(body_text, from_email):
    flags = []
    if re.search(r"urgent|verify|password|reset|wire|login|account suspended|click here", body_text, re.I):
        flags.append("Phishing Keywords Detected")
    if re.search(r"https?://[^\s]+", body_text):
        flags.append("Suspicious URL Found")
    if any(x in from_email for x in ["billing@", "support@", "helpdesk@"]) and not from_email.endswith("company.com"):
        flags.append("Spoofed Sender")
    return flags

def classify_threat(flags):
    if not flags:
        return ("Safe", "✅", "Low")
    if any("Credit Card" in f or "Financial" in f for f in flags):
        return ("Data Leakage", "💳", "High")
    if any("Phishing" in f or "Spoof" in f or "URL" in f for f in flags):
        return ("Phishing Attempt", "🎯", "High")
    return ("Policy Violation", "⚠️", "Medium")

def monitor_email(from_email, body_text, attachments):
    flags = []
    for name, pattern in REGEX_PATTERNS.items():
        if re.search(pattern, body_text, re.I):
            flags.append(name)
    flags += detect_phishing(body_text, from_email)
    if attachments:
        for att in attachments:
            if att.size > ATTACHMENT_SIZE_LIMIT_BYTES:
                flags.append(f"Oversized Attachment ({att.name})")
            if att.type.startswith("image/"):
                flags.append(f"Image Attached ({att.name})")
    return list(set(flags))

def add_to_log(direction, from_email, to_email, subject, flags):
    if "log" not in st.session_state:
        st.session_state.log = []
    threat, icon, severity = classify_threat(flags)
    st.session_state.log.append({
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Direction": direction,
        "From": from_email,
        "To": to_email,
        "Subject": subject,
        "Threat Type": threat,
        "Severity": severity,
        "Flags": ", ".join(flags) if flags else "None"
    })
    if severity == "High":
        st.session_state.latest_alert = f"{icon} {threat} detected from {from_email} — {subject}"

# ----------------------------------------------------------------
# INITIALIZATION
# ----------------------------------------------------------------
if "log" not in st.session_state:
    st.session_state.log = []
if "latest_alert" not in st.session_state:
    st.session_state.latest_alert = None

# ----------------------------------------------------------------
# SIDEBAR NAVIGATION
# ----------------------------------------------------------------
st.sidebar.title("🧠 CyberSOC Console")
page = st.sidebar.radio("Navigate", ["📤 Compose", "📥 Inbox", "📊 Dashboard", "🚨 Live Threat Feed"])

# ----------------------------------------------------------------
# ALERT BANNER
# ----------------------------------------------------------------
if st.session_state.latest_alert:
    st.markdown(f"<div class='alert-banner'>🚨 {st.session_state.latest_alert}</div>", unsafe_allow_html=True)

# ----------------------------------------------------------------
# PAGES
# ----------------------------------------------------------------
if page == "📤 Compose":
    st.title("📤 Compose & Analyze Email")

    with st.form("compose"):
        from_email = st.text_input("From", "employee@company.com")
        to_email = st.text_input("To", "client@partner.com")
        subject = st.text_input("Subject", "Quarterly Financial Report")
        body = st.text_area("Message Body", "Please find the attached report.")
        attachments = st.file_uploader("Attachments", accept_multiple_files=True)
        send = st.form_submit_button("Send Securely")

    if send:
        flags = monitor_email(from_email, body, attachments)
        if flags:
            threat, icon, severity = classify_threat(flags)
            st.error(f"{icon} {threat} | Severity: {severity}")
            st.warning(f"⚠️ Flags: {', '.join(flags)}")
        else:
            st.success("✅ Message Sent Securely")
        add_to_log("Outgoing", from_email, to_email, subject, flags)

elif page == "📥 Inbox":
    st.title("📥 Simulated Inbox Scanner")
    mock_emails = [
        {"from": "billing@phishbank.net", "subject": "URGENT Account Locked", "body": "Verify details at http://phish-link.com"},
        {"from": "hr@company.com", "subject": "Team Event", "body": "Looking forward to seeing you at our event!"},
        {"from": "support@malicious.net", "subject": "Invoice Attached", "body": "Payment required immediately"}
    ]
    for mail in mock_emails:
        with st.container():
            st.markdown(f"<div class='email-card'><b>📧 {mail['subject']}</b><br>"
                        f"From: {mail['from']}<br></div>", unsafe_allow_html=True)
            flags = monitor_email(mail["from"], mail["body"], [])
            if flags:
                threat, icon, severity = classify_threat(flags)
                st.error(f"{icon} {threat} | Severity: {severity}")
                add_to_log("Incoming", mail["from"], "employee@company.com", mail["subject"], flags)
            else:
                st.success("✅ Safe Email")
            st.text_area("Body", mail["body"], height=80, disabled=True)

elif page == "📊 Dashboard":
    st.title("📊 Threat Analytics Dashboard")
    if not st.session_state.log:
        st.info("No logs yet. Send or receive an email to start monitoring.")
    else:
        df = pd.DataFrame(st.session_state.log)
        total, high, med, low = len(df), len(df[df["Severity"]=="High"]), len(df[df["Severity"]=="Medium"]), len(df[df["Severity"]=="Low"])

        c1, c2, c3, c4 = st.columns(4)
        c1.markdown(f"<div class='metric-card'><h3>Total Emails</h3><h2>{total}</h2></div>", unsafe_allow_html=True)
        c2.markdown(f"<div class='metric-card'><h3>High Severity</h3><h2 style='color:#ff1744'>{high}</h2></div>", unsafe_allow_html=True)
        c3.markdown(f"<div class='metric-card'><h3>Medium</h3><h2 style='color:#ff9800'>{med}</h2></div>", unsafe_allow_html=True)
        c4.markdown(f"<div class='metric-card'><h3>Low</h3><h2 style='color:#4caf50'>{low}</h2></div>", unsafe_allow_html=True)

        st.divider()
        st.dataframe(df, use_container_width=True)

        colA, colB = st.columns(2)
        with colA:
            st.plotly_chart(px.bar(df, x="Severity", color="Severity", title="Threats by Severity", text_auto=True), use_container_width=True)
        with colB:
            st.plotly_chart(px.pie(df, names="Threat Type", title="Threat Type Distribution", hole=0.4), use_container_width=True)

elif page == "🚨 Live Threat Feed":
    st.title("🚨 Real-Time Threat Intelligence Feed")
    if not st.session_state.log:
        st.info("No detected threats yet.")
    else:
        df = pd.DataFrame(st.session_state.log)
        for _, row in df.tail(8).iterrows():
            st.markdown(f"<div class='live-feed'>🕒 <b>{row['Timestamp']}</b> — {row['Threat Type']} "
                        f"({row['Severity']})<br>📤 {row['From']} → {row['To']}<br>"
                        f"🧩 Flags: {row['Flags']}</div>", unsafe_allow_html=True)
