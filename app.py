import streamlit as st
import pandas as pd
import re
from io import BytesIO
from datetime import datetime
import altair as alt

# ---------------------- CONFIG ----------------------
st.set_page_config(
    layout="wide",
    page_title="Email Security Monitoring Simulator",
    page_icon="📧"
)

ATTACHMENT_SIZE_LIMIT_MB = 5
ATTACHMENT_SIZE_LIMIT_BYTES = ATTACHMENT_SIZE_LIMIT_MB * 1024 * 1024

# --- Regex & Phishing Patterns ---
REGEX_PATTERNS = {
    "Phone Number": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Financial Amount": r"[$€£¥]\s*\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?",
    "Numbers in Words (Financial)": r"\b(?:five|ten|hundred|thousand|million|billion)\s+(?:dollars|euros|pounds|usd|eur)\b",
}

PHISHING_KEYWORDS = [
    "urgent", "verify your account", "password", "click here", "update details",
    "wire transfer", "invoice", "payment overdue", "act now", "bank login"
]


# ---------------------- MONITORING LOGIC ----------------------
def detect_phishing(body_text):
    found = [word for word in PHISHING_KEYWORDS if word.lower() in body_text.lower()]
    return found


def monitor_email(body_text, attachments):
    flags = []

    # Regex-based detection
    for flag_name, pattern in REGEX_PATTERNS.items():
        if re.search(pattern, body_text, re.IGNORECASE):
            flags.append(flag_name)

    # Phishing keyword detection
    phishing_flags = detect_phishing(body_text)
    if phishing_flags:
        flags.append(f"Phishing Keywords: {', '.join(phishing_flags)}")

    # Attachment scanning
    if attachments:
        for att in attachments:
            if att.size > ATTACHMENT_SIZE_LIMIT_BYTES:
                flags.append(f"Attachment Size > {ATTACHMENT_SIZE_LIMIT_MB}MB ({att.name})")
            if att.type.startswith("image/"):
                flags.append(f"Image Attached ({att.name})")

    return list(set(flags))


def add_to_log(direction, sender, receiver, subject, flags):
    """Add entry to session log"""
    if "log" not in st.session_state:
        st.session_state.log = []
    st.session_state.log.append({
        "Timestamp": datetime.now(),
        "Direction": direction,
        "From": sender,
        "To": receiver,
        "Subject": subject,
        "Flags": ", ".join(flags)
    })


# ---------------------- MOCK EMAIL DATA ----------------------
mock_image = BytesIO(b"fake_image_data")
mock_image.name = "invoice.png"
mock_image.type = "image/png"
mock_image.size = 180000

mock_zip = BytesIO(b"fake_zip_data" * 1000000)
mock_zip.name = "finance_report.zip"
mock_zip.type = "application/zip"
mock_zip.size = 6200000

MOCK_INBOX = [
    {
        "id": 1,
        "from": "accounting@partner.com",
        "subject": "Urgent Invoice Payment",
        "body": "Please review attached invoice and wire $1,200 immediately. Call (123) 456-7890 for assistance.",
        "attachments": [mock_image]
    },
    {
        "id": 2,
        "from": "updates@company.com",
        "subject": "Weekly Summary",
        "body": "All systems normal. No further actions needed.",
        "attachments": []
    },
    {
        "id": 3,
        "from": "admin@suspicious.net",
        "subject": "Action Required: Verify Your Account",
        "body": "Your account password has expired. Click here to verify your details immediately.",
        "attachments": [mock_zip]
    },
]


# ---------------------- SIDEBAR NAVIGATION ----------------------
st.sidebar.title("📧 Email Security Simulator")
st.sidebar.markdown("### 🧠 Real-Time Email Threat Detection")
st.sidebar.divider()
page = st.sidebar.radio("Navigation", ["📤 Compose Email", "📥 Inbox", "🧩 Reply / Respond", "📊 Dashboard"])

# Initialize log
if "log" not in st.session_state:
    st.session_state.log = []

# ---------------------- PAGE 1: COMPOSE ----------------------
if page == "📤 Compose Email":
    st.title("📤 Compose New Email (Outgoing Monitor)")

    with st.form("compose_form"):
        col1, col2 = st.columns(2)
        with col1:
            sender = st.text_input("From", "employee@company.com")
            subject = st.text_input("Subject", "Follow-up on project update")
        with col2:
            receiver = st.text_input("To", "client@example.com")

        body = st.text_area("Email Body", "Hi team,\nPlease find the attached invoice for review.")
        attachments = st.file_uploader("Attach Files", accept_multiple_files=True)
        send = st.form_submit_button("📨 Send Email")

    if send:
        st.markdown("---")
        flags = monitor_email(body, attachments)
        if flags:
            st.error("🛑 **Email Blocked: Policy Violation Detected!**")
            st.warning(f"Detected Issues: {', '.join(flags)}")
            add_to_log("Outgoing", sender, receiver, subject, flags)
        else:
            st.success("✅ Email Sent Successfully! No violations detected.")

# ---------------------- PAGE 2: INBOX ----------------------
elif page == "📥 Inbox":
    st.title("📥 Incoming Email Monitor")
    st.markdown("Open emails to automatically scan them for threats or sensitive data.")
    st.divider()

    for mail in MOCK_INBOX:
        with st.expander(f"**{mail['subject']}** — From: {mail['from']}"):
            st.info("Scanning this email for security threats...")
            flags = monitor_email(mail["body"], mail["attachments"])

            if flags:
                st.error("⚠️ Suspicious Content Detected!")
                st.warning(f"Issues: {', '.join(flags)}")
                add_to_log("Incoming", mail["from"], "employee@company.com", mail["subject"], flags)
            else:
                st.success("✅ Safe Email")

            st.text_area("Body", mail["body"], height=150)
            if mail["attachments"]:
                st.markdown("📎 Attachments:")
                for att in mail["attachments"]:
                    st.info(f"{att.name} ({att.type}, {att.size / 1024:.1f} KB)")
            else:
                st.caption("No attachments")

# ---------------------- PAGE 3: REPLY ----------------------
elif page == "🧩 Reply / Respond":
    st.title("💬 Simulate Email Reply")
    st.markdown("Compose a response and check if your reply contains risky or phishing-like language.")
    st.divider()

    with st.form("reply_form"):
        reply_to = st.text_input("Replying To", "customer@domain.com")
        subject = st.text_input("Subject", "Re: Invoice Confirmation")
        reply_body = st.text_area("Your Reply", "Hi,\n\nPlease verify your payment credentials immediately.")
        submit_reply = st.form_submit_button("✉️ Send Reply")

    if submit_reply:
        flags = monitor_email(reply_body, [])
        if flags:
            st.error("🚨 Reply Blocked - Potential Violation Detected!")
            st.warning(f"Detected: {', '.join(flags)}")
            add_to_log("Outgoing (Reply)", "employee@company.com", reply_to, subject, flags)
        else:
            st.success("✅ Reply Sent Securely!")

# ---------------------- PAGE 4: DASHBOARD ----------------------
elif page == "📊 Dashboard":
    st.title("📊 Email Security Analytics Dashboard")
    st.markdown("Manager view for monitoring all flagged incidents.")
    st.divider()

    if not st.session_state.log:
        st.info("No incidents recorded yet.")
    else:
        df = pd.DataFrame(st.session_state.log)
        df["Date"] = pd.to_datetime(df["Timestamp"]).dt.date
        st.subheader("Incident Log")
        st.dataframe(df, use_container_width=True)

        col1, col2 = st.columns(2)
        with col1:
            chart1 = alt.Chart(df).mark_bar().encode(
                x="Direction",
                y="count()",
                color="Direction"
            ).properties(title="Incidents by Direction")
            st.altair_chart(chart1, use_container_width=True)

        with col2:
            chart2 = alt.Chart(df).mark_bar().encode(
                x="Flags:N",
                y="count()",
                color="Flags:N"
            ).properties(title="Incident Types Frequency")
            st.altair_chart(chart2, use_container_width=True)

        total = len(df)
        incoming = len(df[df["Direction"].str.contains("Incoming")])
        outgoing = total - incoming

        st.metric("Total Incidents", total)
        st.metric("Incoming Threats", incoming)
        st.metric("Outgoing Violations", outgoing)

        if st.button("🧹 Clear Incident Log"):
            st.session_state.log = []
            st.success("Logs Cleared! Dashboard reset.")
            st.rerun()
