import streamlit as st
import re
import pandas as pd
from io import BytesIO
import random
from datetime import datetime

# ----------------------------- CONFIG ---------------------------------

ATTACHMENT_SIZE_LIMIT_MB = 5
ATTACHMENT_SIZE_LIMIT_BYTES = ATTACHMENT_SIZE_LIMIT_MB * 1024 * 1024

REGEX_PATTERNS = {
    "Phone Number": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Financial Amount": r"[$€£¥]\s*\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?",
    "Numbers in Words (Financial)": r"\b(?:five|ten|twenty|hundred|thousand|million|billion)\s+(?:dollars|euros|pounds|usd|eur)\b"
}

# ----------------------------- DETECTION ENGINE ---------------------------------

def classify_threat(flags):
    """Assign severity and category based on detected flags."""
    if not flags:
        return ("Safe", "✅", "Low")
    if any("Credit Card" in f or "Financial" in f for f in flags):
        return ("Data Leakage", "🚨", "High")
    if any("Image" in f or "Attachment" in f for f in flags):
        return ("Suspicious Attachment", "⚠️", "Medium")
    if "Phone Number" in flags:
        return ("Sensitive Info", "🕵️", "Medium")
    return ("Potential Policy Violation", "⚠️", "Medium")

def monitor_email(body_text, attachments):
    flags = []
    for flag_name, pattern in REGEX_PATTERNS.items():
        if re.search(pattern, body_text, re.IGNORECASE):
            flags.append(flag_name)

    if attachments:
        for att in attachments:
            if att.size > ATTACHMENT_SIZE_LIMIT_BYTES:
                flags.append(f"Attachment Size > {ATTACHMENT_SIZE_LIMIT_MB}MB ({att.name})")
            if att.type.startswith("image/"):
                flags.append(f"Image Attached ({att.name})")

    return list(set(flags))

def add_to_log(from_email, to_email, subject, flags, direction):
    if "log" not in st.session_state:
        st.session_state.log = []
    
    threat_type, icon, severity = classify_threat(flags)
    log_entry = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Direction": direction,
        "From": from_email,
        "To": to_email,
        "Subject": subject,
        "Flags": ", ".join(flags) if flags else "None",
        "Threat Type": threat_type,
        "Severity": severity,
        "Icon": icon
    }
    st.session_state.log.append(log_entry)

# ----------------------------- MOCK EMAILS ---------------------------------

mock_image_file = BytesIO(b"dummy_image_data_bytes")
mock_image_file.name = "invoice.png"
mock_image_file.type = "image/png"
mock_image_file.size = 150000

mock_large_file = BytesIO(b"x" * 6000000)
mock_large_file.name = "presentation.zip"
mock_large_file.type = "application/zip"
mock_large_file.size = 6000000

MOCK_INBOX = [
    {
        "id": 1,
        "from": "accounting@partner.com",
        "subject": "Urgent Invoice Payment",
        "body": "Please see the attached invoice for payment. Call me at (123) 456-7890 if you have questions.",
        "attachments": [mock_image_file]
    },
    {
        "id": 2,
        "from": "safe_sender@company.com",
        "subject": "Meeting Notes",
        "body": "Here are the notes from today's sync. Great job team.",
        "attachments": []
    },
    {
        "id": 3,
        "from": "external.design@graphics.com",
        "subject": "New Branding Assets",
        "body": "Here are the new branding assets. The file is large, let me know if it comes through.",
        "attachments": [mock_large_file]
    },
    {
        "id": 4,
        "from": "billing@suspicious.net",
        "subject": "Action Required: Pay Your Bill",
        "body": "Your payment of $1,450.00 is overdue. Please pay with your card 1234-5678-9012-3456 immediately.",
        "attachments": []
    },
    {
        "id": 5,
        "from": "investor@moneytalk.com",
        "subject": "Wire Transfer Request",
        "body": "Please wire the one hundred thousand dollars as we discussed. This is time sensitive.",
        "attachments": []
    }
]

# ----------------------------- UI SETUP ---------------------------------

st.set_page_config(page_title="Email Security Monitor", layout="wide", page_icon="📧")

st.markdown("""
<style>
    .stApp {background-color: #f8fafc;}
    .flag {background-color: #fde68a; padding: 5px 10px; border-radius: 10px;}
    .critical {background-color: #fecaca; padding: 5px 10px; border-radius: 10px;}
    .ok {background-color: #bbf7d0; padding: 5px 10px; border-radius: 10px;}
</style>
""", unsafe_allow_html=True)

if "log" not in st.session_state:
    st.session_state.log = []

st.sidebar.title("📬 Email Security Simulator")
page = st.sidebar.radio("Navigation", ["📤 Compose Email", "📥 Inbox", "🛡️ Security Dashboard"])

# ----------------------------- COMPOSE PAGE ---------------------------------

if page == "📤 Compose Email":
    st.title("📤 Compose Outgoing Email")
    st.caption("Simulate sending an email. The monitor will intercept and scan for policy violations.")

    with st.form("compose_form"):
        from_email = st.text_input("From", "employee@company.com")
        to_email = st.text_input("To", "customer@external.com")
        subject = st.text_input("Subject", "Project Update")
        body = st.text_area("Body", "Hi,\n\nPlease find the attached report.")
        attachments = st.file_uploader("Attachments", accept_multiple_files=True)
        submitted = st.form_submit_button("Send Email")

    if submitted:
        flags = monitor_email(body, attachments)
        if flags:
            threat, icon, severity = classify_threat(flags)
            st.error(f"{icon} **Policy Violation Detected ({severity})**")
            st.warning(f"Threat Type: {threat}")
            st.info(f"Violations: {', '.join(flags)}")
            add_to_log(from_email, to_email, subject, flags, "Outgoing")
        else:
            st.success("✅ Email Sent Securely — No Violations Found")

# ----------------------------- INBOX PAGE ---------------------------------

elif page == "📥 Inbox":
    st.title("📥 Inbox - Incoming Emails")
    search = st.text_input("🔍 Search Email Subject or Sender")
    st.divider()

    filtered_inbox = [e for e in MOCK_INBOX if search.lower() in e["subject"].lower() or search.lower() in e["from"].lower()]

    for email in filtered_inbox:
        with st.expander(f"📨 {email['subject']} — *{email['from']}*"):
            flags = monitor_email(email["body"], email["attachments"])
            if flags:
                threat, icon, severity = classify_threat(flags)
                st.error(f"{icon} **{threat} Detected** | Severity: {severity}")
                st.warning(f"Flags: {', '.join(flags)}")
                add_to_log(email['from'], "employee@company.com", email['subject'], flags, "Incoming")
            else:
                st.success("✅ Email is Safe")

            st.text_area("Body Preview", email['body'], height=120, disabled=True)
            if email["attachments"]:
                st.info(f"📎 Attachments: {', '.join([a.name for a in email['attachments']])}")
            else:
                st.caption("No Attachments")

# ----------------------------- DASHBOARD PAGE ---------------------------------

elif page == "🛡️ Security Dashboard":
    st.title("🛡️ Security Monitoring Dashboard")

    if not st.session_state.log:
        st.info("No incidents logged yet. Try sending or opening an email with violations.")
    else:
        df = pd.DataFrame(st.session_state.log)
        df = df[["Timestamp", "Direction", "From", "To", "Subject", "Threat Type", "Severity", "Flags"]]

        severity_filter = st.multiselect("Filter by Severity", ["Low", "Medium", "High"], default=["Low", "Medium", "High"])
        df = df[df["Severity"].isin(severity_filter)]

        st.dataframe(df, use_container_width=True, hide_index=True)

        st.download_button(
            label="⬇️ Download Log as CSV",
            data=df.to_csv(index=False).encode('utf-8'),
            file_name=f"security_log_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv"
        )

        if st.button("🧹 Clear Log"):
            st.session_state.log = []
            st.rerun()
