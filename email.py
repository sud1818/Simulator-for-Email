import streamlit as st
import re
import pandas as pd
from io import BytesIO
import random
from datetime import datetime
import plotly.express as px

# ----------------------------- CONFIG ---------------------------------
st.set_page_config(page_title="Corporate Email Security Console", layout="wide", page_icon="🧠")

ATTACHMENT_SIZE_LIMIT_MB = 5
ATTACHMENT_SIZE_LIMIT_BYTES = ATTACHMENT_SIZE_LIMIT_MB * 1024 * 1024

# ----------------------------- STYLING ---------------------------------
st.markdown("""
<style>
.stApp {
    background-color: #0e1117;
    color: #f5f5f5;
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
    if not flags: return ("Safe", "✅", "Low")
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
    if "log" not in st.session_state: st.session_state.log = []
    threat, icon, severity = classify_threat(flags)
    st.session_state.log.append({
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Direction": direction, "From": from_email, "To": to_email,
        "Subject": subject, "Threat Type": threat,
        "Severity": severity, "Flags": ", ".join(flags) if flags else "None", "Icon": icon
    })

# ----------------------------- MOCK DATA ---------------------------------
mock_img = BytesIO(b"fakeimg"); mock_img.name="invoice.png"; mock_img.type="image/png"; mock_img.size=120000
mock_big = BytesIO(b"x"*6000000); mock_big.name="data.zip"; mock_big.type="application/zip"; mock_big.size=6000000

MOCK_INBOX = [
    {"from": "security@fakebank.net", "subject": "URGENT: Account Suspended", "body": "Verify at http://login-fakebank.com", "attachments": []},
    {"from": "billing@suspicious.net", "subject": "Payment Reminder", "body": "Please wire $10,000 immediately.", "attachments": []},
    {"from": "design@partner.com", "subject": "Branding Assets", "body": "New assets attached below.", "attachments": [mock_big]},
    {"from": "hr@company.com", "subject": "Policy Update", "body": "Please review updated HR policy document.", "attachments": []},
]

if "log" not in st.session_state: st.session_state.log = []

# ----------------------------- SIDEBAR ---------------------------------
st.sidebar.title("🧠 Security Console")
page = st.sidebar.radio("Sections", ["📤 Compose", "📥 Inbox", "📈 Dashboard", "🧩 Threat Insights"])

# ----------------------------- COMPOSE PAGE ---------------------------------
if page == "📤 Compose":
    st.title("📤 Compose Outgoing Email")
    st.caption("Simulate sending corporate emails through the monitoring engine.")

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
elif page == "📈 Dashboard":
    st.title("📊 Threat Monitoring Dashboard")

    if not st.session_state.log:
        st.info("No activity detected. Interact with inbox or compose to generate logs.")
    else:
        df = pd.DataFrame(st.session_state.log)

        total = len(df)
        high = len(df[df["Severity"]=="High"])
        med = len(df[df["Severity"]=="Medium"])
        low = len(df[df["Severity"]=="Low"])

        col1, col2, col3, col4 = st.columns(4)
        col1.markdown(f"<div class='metric-card'><h3>Total Emails</h3><h2>{total}</h2></div>", unsafe_allow_html=True)
        col2.markdown(f"<div class='metric-card'><h3>High Severity</h3><h2 style='color:#ff4b4b'>{high}</h2></div>", unsafe_allow_html=True)
        col3.markdown(f"<div class='metric-card'><h3>Medium</h3><h2 style='color:#ff9800'>{med}</h2></div>", unsafe_allow_html=True)
        col4.markdown(f"<div class='metric-card'><h3>Low</h3><h2 style='color:#4caf50'>{low}</h2></div>", unsafe_allow_html=True)

        st.divider()
        st.dataframe(df, use_container_width=True, hide_index=True)

        col5, col6 = st.columns(2)
        with col5:
            fig1 = px.bar(df, x="Severity", color="Severity", title="Threats by Severity", text_auto=True)
            st.plotly_chart(fig1, use_container_width=True)
        with col6:
            fig2 = px.pie(df, names="Threat Type", title="Threat Type Distribution", hole=0.4)
            st.plotly_chart(fig2, use_container_width=True)

        st.download_button("⬇️ Export CSV", df.to_csv(index=False).encode('utf-8'), "security_log.csv", "text/csv")

# ----------------------------- THREAT INSIGHTS PAGE ---------------------------------
elif page == "🧩 Threat Insights":
    st.title("🧠 Threat Intelligence Feed")
    st.caption("Live analytics of the simulated security environment")

    if not st.session_state.log:
        st.info("No data available. Generate some events first.")
    else:
        df = pd.DataFrame(st.session_state.log)
        recent = df.tail(5)
        st.markdown("### 🔥 Recent Incidents")
        for _, r in recent.iterrows():
            st.markdown(f"**{r['Timestamp']}** | {r['Icon']} **{r['Threat Type']}** from `{r['From']}` → `{r['To']}` | *{r['Severity']}*")

        st.markdown("### ⏱️ Activity Over Time")
        fig3 = px.line(df, x="Timestamp", color="Severity", title="Timeline of Detected Events")
        st.plotly_chart(fig3, use_container_width=True)
