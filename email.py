# email_monitor_full.py
import streamlit as st
import re
import pandas as pd
from io import BytesIO
from datetime import datetime, timedelta
import random
import matplotlib.pyplot as plt

# ----------------------- Configuration -----------------------
ATTACHMENT_SIZE_LIMIT_MB = 5
ATTACHMENT_SIZE_LIMIT_BYTES = ATTACHMENT_SIZE_LIMIT_MB * 1024 * 1024

# Regex patterns for DLP detection
REGEX_PATTERNS = {
    "Phone Number": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Financial Amount": r"[$€£¥]\s*\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?",
    "Numbers in Words (Financial)": r"\b(?:one|two|five|ten|twenty|fifty|hundred|thousand|million|billion)\s+(?:dollars|euros|pounds|usd|eur)\b"
}

# Phishing heuristics
PHISHING_KEYWORDS = [
    "verify", "verification", "login", "suspended", "urgent", "immediately",
    "expire", "update your", "confirm", "verify your", "pay now", "wire", "transfer"
]

SUSPICIOUS_DOMAINS = [
    "secure-payments.net", "unverifiedmail.com", "secure-login.info",
    "acct-update.com", "verify-now.net"
]

DANGEROUS_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".pif", ".msi", ".html"]

# ----------------------- Utilities -----------------------

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_getattr(obj, attr, default=None):
    """Return getattr or dictionary-like access for mock attachments or UploadedFile."""
    try:
        return getattr(obj, attr)
    except Exception:
        try:
            return obj.get(attr, default)
        except Exception:
            return default

def size_kb(att):
    size = safe_getattr(att, "size", 0) or 0
    return size / 1024

# ----------------------- Detection Engine -----------------------

def detect_dlp(body_text: str):
    """Return list of DLP flags found by regex scanning."""
    flags = []
    if not body_text:
        return flags
    for name, pattern in REGEX_PATTERNS.items():
        if re.search(pattern, body_text, re.IGNORECASE):
            flags.append(name)
    return flags

def detect_phishing(body_text: str, subject: str, from_email: str, attachments):
    """
    Heuristic phishing detector:
    - Looks for urgent keywords
    - Looks for suspicious links (http(s) with mismatched display)
    - Checks suspicious sender domain list
    - Dangerous attachment extensions
    Returns list of phishing indicators.
    """
    indicators = []

    txt = f"{subject}\n{body_text}".lower() if subject or body_text else ""
    # keywords
    for kw in PHISHING_KEYWORDS:
        if kw in txt:
            indicators.append(f"Keyword: '{kw}'")

    # suspicious domain in sender
    sender_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
    if sender_domain in SUSPICIOUS_DOMAINS:
        indicators.append(f"Suspicious sender domain: {sender_domain}")

    # links present
    links = re.findall(r"https?://[^\s'\"<>]+", txt)
    if links:
        indicators.append(f"Contains {len(links)} link(s)")

    # attachments with dangerous extensions
    if attachments:
        for att in attachments:
            name = safe_getattr(att, "name", "") or ""
            for ext in DANGEROUS_EXTENSIONS:
                if name.lower().endswith(ext):
                    indicators.append(f"Dangerous attachment ext: {ext} ({name})")
    
    # spoofed-from heuristic (displayed name vs domain) - simulated by presence of keywords like "support" + strange domain
    if "support" in from_email and not from_email.endswith(("company.com", "trusted.com")):
        indicators.append("Possible spoofed sender (support@ with unexpected domain)")

    return list(set(indicators))

def monitor_email(body_text, attachments, subject="", from_email=""):
    """Perform DLP + phishing checks and aggregation into flags + threat info."""
    dlp_flags = detect_dlp(body_text)
    phishing_indicators = detect_phishing(body_text, subject, from_email, attachments)

    attach_flags = []
    if attachments:
        for att in attachments:
            size = safe_getattr(att, "size", 0) or 0
            name = safe_getattr(att, "name", "") or "attachment"
            mtype = safe_getattr(att, "type", "") or ""
            if size > ATTACHMENT_SIZE_LIMIT_BYTES:
                attach_flags.append(f"Attachment Size > {ATTACHMENT_SIZE_LIMIT_MB}MB ({name})")
            # image types might be sensitive too
            if mtype and str(mtype).startswith("image/"):
                attach_flags.append(f"Image Attached ({name})")
    
    flags = list(set(dlp_flags + attach_flags + phishing_indicators))

    # Determine severity & action
    severity = "Low"
    action = "Allowed"
    category = "Safe"
    confidence = 0.0

    # simple scoring
    score = 0
    score += len(dlp_flags) * 2
    score += len(attach_flags) * 1.5
    score += len(phishing_indicators) * 3

    # severity thresholds
    if score == 0:
        severity = "Low"
        category = "Safe"
        action = "Allow"
    elif score < 3:
        severity = "Medium"
        category = "Policy Violation"
        action = "Flag for Review"
    elif score < 6:
        severity = "High"
        category = "Data Leakage / Suspicious"
        action = "Quarantine"
    else:
        severity = "Critical"
        category = "Phishing / Malicious"
        action = "Quarantine & Block Sender"

    # confidence (0-100)
    confidence = min(95, 30 + int(score * 15 + random.uniform(0, 10)))

    return {
        "flags": flags,
        "severity": severity,
        "action": action,
        "category": category,
        "score": score,
        "confidence": confidence
    }

# ----------------------- Logging & Threading -----------------------

def add_to_log(from_email, to_email, subject, flags_summary, direction, details=None, thread_id=None):
    """Append a log entry to session_state.log"""
    if "log" not in st.session_state:
        st.session_state.log = []

    entry = {
        "Timestamp": now(),
        "Direction": direction,
        "From": from_email,
        "To": to_email,
        "Subject": subject,
        "Flags Summary": flags_summary or "None",
        "Details": details or "",
        "Thread ID": thread_id or "",
    }
    st.session_state.log.append(entry)

def ensure_threads_initialized():
    """Initialize session state for threads and mock inbox if missing."""
    if "inbox" not in st.session_state:
        # Create mock attachments
        mock_image_file = BytesIO(b"dummy_image_data_bytes")
        mock_image_file.name = "invoice.png"
        mock_image_file.type = "image/png"
        mock_image_file.size = 150000

        mock_large_file = BytesIO(b"x" * 6000000)
        mock_large_file.name = "presentation.zip"
        mock_large_file.type = "application/zip"
        mock_large_file.size = 6000000

        mock_malicious_file = BytesIO(b"evil")
        mock_malicious_file.name = "payload.exe"
        mock_malicious_file.type = "application/octet-stream"
        mock_malicious_file.size = 500000

        # Seed a realistic mock inbox with thread IDs
        st.session_state.inbox = [
            {
                "id": "T-1001",
                "from": "accounting@partner.com",
                "subject": "FW: Urgent Invoice",
                "body": "Please see the attached invoice for payment. Call me at (123) 456-7890 if you have questions.",
                "attachments": [mock_image_file],
                "timestamp": (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
                "thread": []
            },
            {
                "id": "T-1002",
                "from": "safe_sender@company.com",
                "subject": "Meeting Notes",
                "body": "Here are the notes from today's sync. Great job team.",
                "attachments": [],
                "timestamp": (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),
                "thread": []
            },
            {
                "id": "T-1003",
                "from": "external.design@graphics.com",
                "subject": "New Branding Assets",
                "body": "Here are the new branding assets. The file is large, let me know if it comes through.",
                "attachments": [mock_large_file],
                "timestamp": (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S"),
                "thread": []
            },
            {
                "id": "T-1004",
                "from": "billing@suspicious.net",
                "subject": "Action Required: Pay Your Bill",
                "body": "Your payment of $1,450.00 is overdue. Please pay with your card 1234-5678-9012-3456 immediately.",
                "attachments": [],
                "timestamp": (datetime.now() - timedelta(hours=10)).strftime("%Y-%m-%d %H:%M:%S"),
                "thread": []
            },
            {
                "id": "T-1005",
                "from": "investor@moneytalk.com",
                "subject": "Wire Transfer Request",
                "body": "Please wire the one hundred thousand dollars as we discussed. This is very time sensitive. Use this account: 9876543210.",
                "attachments": [],
                "timestamp": (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S"),
                "thread": []
            },
            {
                "id": "T-1006",
                "from": "support@secure-payments.net",
                "subject": "Verify your account now",
                "body": "Your account is suspended. Please verify at https://secure-payments.net/verify immediately or you will lose access.",
                "attachments": [mock_malicious_file],
                "timestamp": (datetime.now() - timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
                "thread": []
            }
        ]

    if "log" not in st.session_state:
        st.session_state.log = []

ensure_threads_initialized()

# ----------------------- UI -----------------------

st.set_page_config(page_title="Email Security Simulator (Full)", layout="wide", page_icon="🛡️")
st.markdown("""
<style>
    .stApp { background: linear-gradient(180deg,#f8fafc,#ffffff); }
    .header { font-size: 18px; font-weight: 600; }
    .metric { padding: 8px; border-radius: 8px; background: #ffffff; box-shadow: 0 1px 4px rgba(0,0,0,0.04); }
</style>
""", unsafe_allow_html=True)

st.sidebar.title("🔐 Email Security Simulator")
page = st.sidebar.radio("Navigation", ["📥 Inbox", "📤 Compose / Reply", "📊 Analytics Dashboard", "⚙️ Admin"])

# ----------------------- Inbox Page -----------------------

if page == "📥 Inbox":
    st.title("📥 Inbox")
    st.markdown("Open an email to scan, view thread, and reply. Actions are simulated for demo purposes.")
    col1, col2 = st.columns([1, 2])

    with col1:
        search = st.text_input("🔎 Search (sender / subject / body)")
        severity_filter = st.multiselect("Filter by Severity", ["Low", "Medium", "High", "Critical"], default=["Low", "Medium", "High", "Critical"])
        from_filter = st.text_input("Filter by sender domain (e.g., suspicious.net)")

        # List emails
        def email_matches(e):
            txt = f"{e['from']} {e['subject']} {e['body']}".lower()
            if search and search.lower() not in txt:
                return False
            if from_filter and from_filter.lower() not in e['from'].lower():
                return False
            return True

        inbox_list = [e for e in st.session_state.inbox if email_matches(e)]
        for e in inbox_list:
            # Precompute a scan to show badge
            scan = monitor_email(e['body'], e['attachments'], subject=e['subject'], from_email=e['from'])
            sev = scan["severity"]
            # simple filter by severity selection
            if sev not in severity_filter:
                continue
            st.markdown(f"**{e['subject']}**  —  *{e['from']}*   •   {e['timestamp']}")
            badges = f" Severity: **{sev}** | Action: **{scan['action']}** | Confidence: **{scan['confidence']}%**"
            st.caption(badges)
            st.write("---")

    with col2:
        st.subheader("Email Viewer / Thread")
        selected_id = st.selectbox("Select email thread", [e["id"] for e in st.session_state.inbox], index=0)
        email = next((x for x in st.session_state.inbox if x["id"] == selected_id), None)

        if email:
            st.markdown(f"### {email['subject']}")
            st.markdown(f"**From:** {email['from']}   •   **Received:** {email['timestamp']}")
            st.text_area("Message Preview", email['body'], height=160, disabled=True)
            if email['attachments']:
                st.markdown("**Attachments:**")
                for att in email['attachments']:
                    st.info(f"{safe_getattr(att,'name','attachment')} — {safe_getattr(att,'type','')}, {size_kb(att):.1f} KB")

            # show scan results with details
            scan = monitor_email(email['body'], email['attachments'], subject=email['subject'], from_email=email['from'])
            if scan["flags"]:
                st.error(f"⚠️ {scan['category']} detected — Severity: {scan['severity']}")
                st.markdown(f"**Action Suggested:** {scan['action']}")
                st.markdown(f"**Detected Flags:** {', '.join(scan['flags'])}")
                st.markdown(f"**Confidence:** {scan['confidence']}%")
            else:
                st.success("✅ No issues detected")

            st.markdown("---")
            st.subheader("Thread")
            # display thread messages if any
            if email.get("thread"):
                for msg in email["thread"]:
                    st.markdown(f"**{msg['direction']}** — *{msg['from']} → {msg['to']}* • {msg['timestamp']}")
                    st.text_area("Message", msg["body"], height=80, disabled=True)
                    st.caption(f"Flags: {msg['flags'] or 'None'} | Action: {msg['action']} | Confidence: {msg['confidence']}%")
                    st.write("---")
            else:
                st.caption("No replies in this thread yet.")

            # Reply form
            st.subheader("Reply to this email")
            with st.form(f"reply_form_{email['id']}"):
                reply_from = st.text_input("From", "employee@company.com")
                reply_to = st.text_input("To", email['from'])
                reply_body = st.text_area("Reply Body", value=f"Hi,\n\nThanks for your message regarding '{email['subject']}'.\n\n")
                reply_attachments = st.file_uploader("Attachments (optional)", accept_multiple_files=True, key=f"reply_uploader_{email['id']}")
                reply_send = st.form_submit_button("Send Reply (Simulated)")

            if reply_send:
                # scan reply before sending
                reply_scan = monitor_email(reply_body, reply_attachments, subject=f"RE: {email['subject']}", from_email=reply_from)
                # Add reply to thread and log outgoing
                thread_msg = {
                    "timestamp": now(),
                    "direction": "Outgoing",
                    "from": reply_from,
                    "to": reply_to,
                    "body": reply_body,
                    "flags": ", ".join(reply_scan["flags"]) if reply_scan["flags"] else "",
                    "action": reply_scan["action"],
                    "confidence": reply_scan["confidence"]
                }
                email.setdefault("thread", []).append(thread_msg)
                # Log event
                add_to_log(reply_from, reply_to, f"RE: {email['subject']}", thread_msg["flags"], "Outgoing", details=str(reply_scan), thread_id=email["id"])

                if reply_scan["flags"]:
                    st.error(f"Reply flagged: {reply_scan['category']} — Action: {reply_scan['action']}")
                    st.warning(f"Flags: {', '.join(reply_scan['flags'])}")
                    st.info("This reply has been added to the thread and recorded in the security log.")
                else:
                    st.success("Reply sent (simulated) — No violations detected")
                    st.info("Reply has been appended to the thread and recorded in the log.")

# ----------------------- Compose Page -----------------------

elif page == "📤 Compose / Reply":
    st.title("📤 Compose New Outgoing Email")
    st.markdown("Compose and send an outgoing email. All outgoing emails are scanned before being allowed.")
    with st.form("compose_new"):
        from_email = st.text_input("From", "employee@company.com")
        to_email = st.text_input("To", "recipient@external.com")
        subject = st.text_input("Subject", "Project Update")
        body = st.text_area("Body", "Hi,\n\nPlease find attached the requested document.\n\nRegards,")
        attachments = st.file_uploader("Attachments", accept_multiple_files=True)
        submit = st.form_submit_button("Send (Simulated)")

    if submit:
        result = monitor_email(body, attachments, subject=subject, from_email=from_email)
        add_to_log(from_email, to_email, subject, ", ".join(result["flags"]), "Outgoing", details=str(result))
        if result["flags"]:
            st.error(f"⚠️ Email blocked/flagged: {result['category']} (Severity: {result['severity']})")
            st.warning(f"Suggested Action: {result['action']}")
            st.info(f"Detected: {', '.join(result['flags'])}")
        else:
            st.success("✅ Email 'sent' (simulated) — No violations detected")
            st.info("This outgoing message has been recorded in the security log.")

# ----------------------- Analytics Dashboard -----------------------

elif page == "📊 Analytics Dashboard":
    st.title("📊 Security Analytics Dashboard")
    st.markdown("Summary metrics, breakdowns, and the incident log. Use this for demonstrations and training.")

    log_df = pd.DataFrame(st.session_state.log) if st.session_state.log else pd.DataFrame(columns=[
        "Timestamp", "Direction", "From", "To", "Subject", "Flags Summary", "Details", "Thread ID"
    ])

    total_scanned = len(st.session_state.log) + sum(len(e.get("thread", [])) for e in st.session_state.inbox)
    total_flagged = log_df[log_df["Flags Summary"].astype(bool)].shape[0] if not log_df.empty else 0

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Events (approx)", total_scanned)
    col2.metric("Logged Incidents", len(st.session_state.log))
    col3.metric("Flagged Events", total_flagged)

    st.markdown("---")
    st.subheader("Incident Log")
    if log_df.empty:
        st.info("No incidents logged yet (try opening or sending an email with sensitive content).")
    else:
        # Parse details to extract severity/category if possible (details stored as string repr)
        def extract_field(details_str, field):
            # naive extraction from python dict string
            try:
                m = re.search(fr"'{field}':\s*'([^']+)'", details_str)
                if m:
                    return m.group(1)
                m2 = re.search(fr'"{field}":\s*"([^"]+)"', details_str)
                if m2:
                    return m2.group(1)
            except Exception:
                pass
            return ""

        # add columns if possible
        if "Details" in log_df.columns:
            log_df["Category"] = log_df["Details"].apply(lambda d: extract_field(d, "category"))
            log_df["Action"] = log_df["Details"].apply(lambda d: extract_field(d, "action"))
            # confidence
            try:
                log_df["Confidence"] = log_df["Details"].apply(lambda d: re.search(r"'confidence':\s*([0-9]+)", d).group(1) if re.search(r"'confidence':\s*([0-9]+)", d) else "")
            except Exception:
                log_df["Confidence"] = ""

        st.dataframe(log_df.sort_values(by="Timestamp", ascending=False), use_container_width=True)

        csv = log_df.to_csv(index=False).encode("utf-8")
        st.download_button("⬇ Download full incident log (CSV)", csv, file_name=f"incident_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")

    st.markdown("---")
    st.subheader("Threat Breakdown (by Category)")
    # build breakdown from log_df["Details"]
    categories = {}
    for d in st.session_state.log:
        details = d.get("Details", "")
        cat = ""
        # attempt to read 'category' from details which is a dict-str
        m = re.search(r"'category':\s*'([^']+)'", details)
        if m:
            cat = m.group(1)
        else:
            # fallback to 'Flags Summary' presence
            fs = d.get("Flags Summary", "")
            if fs and "Phishing" in fs:
                cat = "Phishing"
            elif fs:
                cat = "Policy Violation"
            else:
                cat = "Safe"
        categories[cat] = categories.get(cat, 0) + 1

    if categories:
        labels = list(categories.keys())
        values = list(categories.values())
        fig, ax = plt.subplots(figsize=(6, 3))
        ax.pie(values, labels=labels, autopct="%1.1f%%", startangle=140)
        ax.axis("equal")
        st.pyplot(fig)
    else:
        st.info("No categorized incidents yet.")

# ----------------------- Admin Page -----------------------

elif page == "⚙️ Admin":
    st.title("⚙️ Admin & Settings")
    st.markdown("Utilities for demo management: seed phishing examples, clear logs, and export data.")

    if st.button("Seed a Phishing Email into Inbox"):
        # Add a synthetic phishing email
        phish_file = BytesIO(b"malicious")
        phish_file.name = "verify.html"
        phish_file.type = "text/html"
        phish_file.size = 2000
        new = {
            "id": f"T-{random.randint(2000,9999)}",
            "from": "alert@verify-now.net",
            "subject": "URGENT: Verify Your Account",
            "body": "Your account will be closed! Click https://verify-now.net/login and enter your details immediately to avoid service interruption.",
            "attachments": [phish_file],
            "timestamp": now(),
            "thread": []
        }
        st.session_state.inbox.insert(0, new)
        st.success("✅ Phishing email seeded into inbox.")

    if st.button("Clear Incident Log"):
        st.session_state.log = []
        st.success("✅ Incident log cleared.")

    if st.button("Reset Demo Inbox"):
        if "inbox" in st.session_state:
            del st.session_state["inbox"]
        ensure_threads_initialized()
        st.success("✅ Demo inbox reset.")

st.markdown("---")
st.caption("Email Security Simulator — Demo-only. Not connected to any real email servers. Use for training and demos.")
