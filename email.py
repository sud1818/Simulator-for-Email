import streamlit as st
import re
import pandas as pd
from io import BytesIO
import random
from datetime import datetime
import plotly.express as px
import time

# ----------------------------- PAGE CONFIG ---------------------------------
st.set_page_config(page_title="Corporate SOC Console", layout="wide", page_icon="🧠")

# ----------------------------- GLOBALS ---------------------------------
ATTACHMENT_SIZE_LIMIT_MB = 5
ATTACHMENT_SIZE_LIMIT_BYTES = ATTACHMENT_SIZE_LIMIT_MB * 1024 * 1024

# ----------------------------- STYLING ---------------------------------
st.markdown("""
<style>
.stApp {
    background-color: #0e1117;
    color: #e5e7eb;
    font-family: 'Segoe UI', sans-serif;
}
[data-testid="stHeader"] {background: rgba(0,0,0,0);}
div[data-testid="stExpander"] {background-color: #161b22; border: 1px solid #30363d; border-radius: 10px;}
.stTextInput > div > div > input, .stTextArea > div > div > textarea {
    background-color: #161b22 !important;
    color: white !important;
}
.stButton button {
    background: linear-gradient(90deg, #00c6ff, #0072ff);
    border: none; color: white; font-weight: 600;
    border-radius: 8px;
}
.stDownloadButton button {
    background: linear-gradient(90deg, #00c853, #009624);
    color: white; border: none; border-radius: 8px;
}
.metric-card {
    background-color: #161b22;
    padding: 20px; border-radius: 12px; text-align: center;
    box-shadow: 0px 0px 10px rgba(0,255,255,0.2);
}
@keyframes flash {
  0% {background-color: #ff1744;}
  50% {background-color: #b71c1c;}
  100% {background-color: #ff1744;}
}
.alert-banner {
  padding: 15px;
  color: white;
  font-weight: bold;
  text-align: center;
  border-radius: 8px;
  animation: flash 1s infinite;
  font-size: 18px;
  margin-bottom: 15px;
}
</style>
""", unsafe_allow_html=True)

# ----------------------------- DETECTION LOGIC ---------------------------------
REGEX_PATTERNS = {
    "Phone Number": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Financial Amount": r"[$€£¥]\s*\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?",
    "Numbers in Words (Financial)": r"\b(?:hundred|thousand|million|billion)\s+(?:dollars|euros|pounds|usd|eur)\b"
}

def detect_phishing(body_text, from_email):
    flags = []
    if re.search(r"urgent|verify|password|reset|wire|login|account suspended|click here", body_text, re.I):
        flags.append("Phishing Keywords Detected")
    if re.search(r"https?://[^\s]+", body_text):
        flags.append("Suspicious URL Found")
    if any(word in from_email for word in ["billing@", "helpdesk@", "support@", "security@"]) and not from_email.endswith("company.com"):
        flags.append("Potential Spoofed Sender")
    return flags

def classify_threat(flags):
    if not flags:
        return ("Safe", "✅", "Low")
    if any("Credit Card" in f or "Financial" in f for f in flags):
        return ("Data Leakage", "🚨", "High")
    if any("Phishing" in f or "Spoof" in f or "URL" in f for f in flags):
        return ("Phishing Attack", "🧨", "High")
    if any("Attachment" in f or "Image" in f for f in flags):
        return ("Suspicious Attachment", "⚠️", "Medium")
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
                flags.append(f"Attachment Too Large ({att.name})")
            if att.type.startswith("image/"):
                flags.append(f"Image Attached ({att.name})")
    return list(set(flags))

def add_to_log(from_email, to_email, subject, flags, direction):
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
        "Flags": ", ".join(flags) if flags else "None",
        "Icon": icon
    })
    # Store latest high severity alert for banner
    if severity == "High":
        st.session_state.latest_alert = f"{icon} {threat} detected from {from_email} — {subject}"

# ----------------------------- MOCK EMAILS ---------------------------------
mock_img = BytesIO(b"fakeimg"); mock_img.name="invoice.png"; mock_img.type="image/png"; mock_img.size=120000
mock_big = BytesIO(b"x"*6000000); mock_big.name="data.zip"; mock_big.type="application/zip"; mock_big.size=6000000

MOCK_INBOX = [
    {"from": "security@fakebank.net", "subject": "URGENT: Account Suspended", "body": "Verify at http://login-fakebank.com", "attachments": []},
    {"from": "billing@suspicious.net", "subject": "Payment Reminder", "body": "Please wire $10,000 immediately.", "attachments": []},
    {"from": "design@partner.com", "subject": "Branding Assets", "body": "New assets attached below.", "attachments": [mock_big]},
    {"from": "hr@company.com", "subject": "Policy Update", "body": "Please review updated HR policy document.", "attachments": []},
]

if "log" not in st.session_state:
    st.session_state.log = []
if "latest_alert" not in st.session_state:
    st.session_state.latest_alert = None

# ----------------------------- SIDEBAR ---------------------------------
st.sidebar.title("🧠 SOC Console Navigation")
page = st.sidebar.radio("Sections", ["📤 Compose", "📥 Inbox", "📊 Dashboard", "🚨 Live Threat Feed"])

# ----------------------------- ALERT BANNER ---------------------------------
if st.session_state.latest_alert:
    st.markdown(f"<div class='alert-banner'>🚨 {st.session_state.latest_alert}</div>", unsafe_allow_html=True)

# ----------------------------- COMPOSE PAGE ---------------------------------
if page == "📤 Compose":
    st.title("📤 Compose Outgoing Email")

    with st.form("compose"):
        from_email = st.text_input("From", "employee@company.com")
        to_email = st.text_input("To", "client@partner.com")
        subject = st.text_input("Subject", "Monthly Report")
        body = st.text_area("Body", "Hello, please find the attached report.")
        attachments = st.file_uploader("Attach Files", accept_multiple_files=True)
        send = st.form_submit_button("Send")

    if send:
        flags = monitor_email(from_email, body, attachments)
        if flags:
            threat, icon, severity = classify_threat(flags)
            st.error(f"{icon} {threat} Detected — Severity: {severity}")
            st.warning(f"Flags: {', '.join(flags)}")
            add_to_log(from_email, to_email, subject, flags, "Outgoing")
        else:
            st.success("✅ Secure Email Sent Successfully")

# ----------------------------- INBOX PAGE ---------------------------------
elif page == "📥 Inbox":
    st.title("📥 Incoming Email Feed")
    search = st.text_input("Search Inbox by Subject or Sender")
    emails = [e for e in MOCK_INBOX if search.lower() in e["subject"].lower() or search.lower() in e["from"].lower()]

    for mail in emails:
        with st.expander(f"📧 {mail['subject']} — {mail['from']}"):
            flags = monitor_email(mail["from"], mail["body"], mail["attachments"])
            if flags:
                threat, icon, severity = classify_threat(flags)
                st.error(f"{icon} {threat} | Severity: {severity}")
                st.caption(f"Flags: {', '.join(flags)}")
                add_to_log(mail["from"], "employee@company.com", mail["subject"], flags, "Incoming")
            else:
                st.success("✅ Safe Email")
            st.text_area("Body", mail["body"], height=100, disabled=True)
            if mail["attachments"]:
                st.info(f"📎 {', '.join([a.name for a in mail['attachments']])}")

# ----------------------------- DASHBOARD PAGE ---------------------------------
elif page == "📊 Dashboard":
    st.title("📊 Security Analytics Dashboard")

    if not st.session_state.log:
        st.info("No activity yet.")
    else:
        df = pd.DataFrame(st.session_state.log)
        total = len(df)
        high = len(df[df["Severity"]=="High"])
        med = len(df[df["Severity"]=="Medium"])
        low = len(df[df["Severity"]=="Low"])

        c1, c2, c3, c4 = st.columns(4)
        c1.markdown(f"<div class='metric-card'><h3>Total Emails</h3><h2>{total}</h2></div>", unsafe_allow_html=True)
        c2.markdown(f"<div class='metric-card'><h3>High</h3><h2 style='color:#ff4b4b'>{high}</h2></div>", unsafe_allow_html=True)
        c3.markdown(f"<div class='metric-card'><h3>Medium</h3><h2 style='color:#ff9800'>{med}</h2></div>", unsafe_allow_html=True)
        c4.markdown(f"<div class='metric-card'><h3>Low</h3><h2 style='color:#4caf50'>{low}</h2></div>", unsafe_allow_html=True)

        st.divider()
        st.dataframe(df, use_container_width=True, hide_index=True)

        colA, colB = st.columns(2)
        with colA:
            fig1 = px.bar(df, x="Severity", color="Severity", title="Threats by Severity", text_auto=True)
            st.plotly_chart(fig1, use_container_width=True)
        with colB:
            fig2 = px.pie(df, names="Threat Type", title="Threat Distribution", hole=0.4)
            st.plotly_chart(fig2, use_container_width=True)

        st.download_button("⬇️ Export Logs", df.to_csv(index=False).encode('utf-8'), "security_log.csv", "text/csv")

# ----------------------------- LIVE THREAT FEED ---------------------------------
elif page == "🚨 Live Threat Feed":
    st.title("🚨 Real-Time Threat Intelligence Feed")

    if not st.session_state.log:
        st.info("No events detected yet.")
    else:
        df = pd.DataFrame(st.session_state.log)
        for _, row in df.tail(10).iterrows():
            color = "#ff4b4b" if row["Severity"]=="High" else "#ff9800" if row["Severity"]=="Medium" else "#4caf50"
            st.markdown(f"<div style='background-color:{color}; padding:10px; border-radius:6px; margin-bottom:5px;'>"
                        f"🕒 {row['Timestamp']} — <b>{row['Threat Type']}</b> ({row['Severity']})<br>"
                        f"📤 {row['From']} → {row['To']}<br>🧩 Flags: {row['Flags']}</div>", unsafe_allow_html=True)

        st.caption("Feed updates whenever a new email is scanned or sent.")
