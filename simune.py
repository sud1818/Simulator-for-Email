import streamlit as st
import re
import pandas as pd
from io import BytesIO

# --- Configuration & Monitoring Logic ---

# Set a threshold for attachment size (in bytes). 5MB
ATTACHMENT_SIZE_LIMIT_MB = 5
ATTACHMENT_SIZE_LIMIT_BYTES = ATTACHMENT_SIZE_LIMIT_MB * 1024 * 1024

# Regex patterns for detection
REGEX_PATTERNS = {
    "Phone Number": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "Credit Card": r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b", # More specific
    "Financial Amount": r"[$€£¥]\s*\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?",
    "Numbers in Words (Financial)": r"\b(?:five|ten|twenty|fifty|hundred|thousand|million|billion)\s+(?:dollars|euros|pounds|usd|eur|thousand|million|billion)\b" # More general
}

def monitor_email(body_text, attachments):
    """
    Scans email body and attachments for red flags.
    Returns a list of flags.
    """
    flags = []
    
    # 1. Scan body text with regex
    for flag_name, pattern in REGEX_PATTERNS.items():
        if re.search(pattern, body_text, re.IGNORECASE):
            flags.append(flag_name)
            
    # 2. Scan attachments
    if not attachments:
        return flags

    for att in attachments:
        # Check size
        if att.size > ATTACHMENT_SIZE_LIMIT_BYTES:
            flags.append(f"Attachment Size > {ATTACHMENT_SIZE_LIMIT_MB}MB ({att.name})")
        
        # Check type for image
        if att.type.startswith("image/"):
            flags.append(f"Image Attached ({att.name})")
            
    # Return unique flags
    return list(set(flags))

def add_to_log(from_email, to_email, subject, flags, direction):
    """Adds a flagged event to the session state log."""
    if "log" not in st.session_state:
        st.session_state.log = []
    
    log_entry = {
        "Timestamp": pd.Timestamp.now(),
        "Direction": direction,
        "From": from_email,
        "To": to_email,
        "Subject": subject,
        "Flags": ", ".join(flags)
    }
    st.session_state.log.append(log_entry)

# --- Mock Data for Inbox ---

# Create dummy BytesIO objects for mock attachments
mock_image_file = BytesIO(b"dummy_image_data_bytes")
mock_image_file.name = "invoice.png"
mock_image_file.type = "image/png"
mock_image_file.size = 150000 # 150 KB (safe size)

mock_large_file = BytesIO(b"dummy_large_file_data_bytes" * 1000000) # > 5MB
mock_large_file.name = "presentation.zip"
mock_large_file.type = "application/zip"
mock_large_file.size = 6000000 # 6 MB (too large)


MOCK_INBOX = [
    {
        "id": 1,
        "from": "accounting@partner.com",
        "subject": "FW: Urgent Invoice",
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
        "body": "Your payment of $1,450.00 is overdue. Please pay with your card 4111-1111-1111-1111 immediately.", # Visa
        "attachments": []
    },
    {
        "id": 5,
        "from": "investor@moneytalk.com",
        "subject": "Wire Transfer",
        "body": "Please wire the one hundred thousand dollars as we discussed. This is very time sensitive.",
        "attachments": []
    },
    {
        "id": 6,
        "from": "security@amex.com",
        "subject": "Verify Your Card",
        "body": "Please verify your new Amex card: 3742-000000-12345. Thank you.", # Amex
        "attachments": []
    }
]

# --- Streamlit App UI ---

st.set_page_config(layout="wide", page_title="Email Monitor Simulator")

# Initialize session state for log and inbox state
if "log" not in st.session_state:
    st.session_state.log = []
if "selected_email_id" not in st.session_state:
    st.session_state.selected_email_id = None
if "logged_email_ids" not in st.session_state:
    st.session_state.logged_email_ids = []


st.sidebar.title("📧 Email Simulator")
st.sidebar.markdown("---")
CURRENT_USER = "employee@company.com"
st.sidebar.markdown(f"**Logged in as:**\n`{CURRENT_USER}`")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigation", ["📥 Inbox (Incoming)", "📤 Compose (Outgoing)", "🛡️ Monitor Dashboard (Manager)"])

# --- Page 1: Compose (Email Prepare) ---
if page == "📤 Compose (Outgoing)":
    st.title("📤 Compose Email (Outgoing Simulator)")
    st.markdown("Simulate sending an email. The monitor will scan it *before* it's 'sent'.")

    with st.form("compose_form"):
        from_email = st.text_input("From:", CURRENT_USER, disabled=True)
        to_email = st.text_input("To:", "customer@example.com")
        subject = st.text_input("Subject:", "Following up on your order")
        body = st.text_area("Body:", "Hi,\n\nHere is the information you requested...")
        attachments = st.file_uploader("Attachments (monitoring for size and image type)", accept_multiple_files=True)
        
        submitted = st.form_submit_button("Simulate Send")

    if submitted:
        st.markdown("---")
        st.info("Monitor is scanning email...")
        
        # Process attachments for the monitor
        # In a real app, st.file_uploader gives UploadedFile objects
        # which have .name, .size, and .type attributes.
        
        flags = monitor_email(body, attachments)
        
        if flags:
            st.error(f"**🛑 RED FLAG!** Email sending blocked. (Policy Violation)")
            st.warning(f"**Violations Detected:** {', '.join(flags)}")
            st.warning("This incident has been logged and sent to your manager.")
            
            # Add to log
            add_to_log(from_email, to_email, subject, flags, "Outgoing")
            
        else:
            st.success("✅ **Email 'Sent' Successfully!** (No violations detected)")

# --- Page 2: Inbox (Email Read) ---
elif page == "📥 Inbox (Incoming)":
    st.title("📥 Inbox (Incoming Simulator)")
    st.markdown("Simulate receiving emails. The monitor scans them *as* you open them.")
    st.markdown("---")

    col1, col2 = st.columns([1, 2], gap="medium")

    with col1:
        st.subheader("Your Fake Inbox")
        
        for email in MOCK_INBOX:
            with st.container(border=True):
                st.markdown(f"**From:** {email['from']}\n\n**Subject:** {email['subject']}")
                if st.button("Open", key=f"open_{email['id']}"):
                    st.session_state.selected_email_id = email['id']
                    
    with col2:
        st.subheader("Email Content")
        st.markdown("---")
        
        if st.session_state.selected_email_id is None:
            st.info("Select an email from the list to read it.")
        else:
            # Find the selected email from the mock inbox
            email = next((e for e in MOCK_INBOX if e['id'] == st.session_state.selected_email_id), None)
            
            if email:
                st.info("Monitor is scanning this email as you open it...")
                
                flags = monitor_email(email['body'], email['attachments'])
                
                if flags:
                    st.error(f"**🛑 RED FLAG!** This email contains sensitive or non-compliant content.")
                    st.warning(f"**Violations Detected:** {', '.join(flags)}")
                    
                    # Only log it the first time it's opened
                    if email['id'] not in st.session_state.logged_email_ids:
                        st.warning("This incident has been logged and sent to your manager.")
                        add_to_log(email['from'], CURRENT_USER, email['subject'], flags, "Incoming")
                        st.session_state.logged_email_ids.append(email['id'])
                    else:
                        st.info("This incident has already been logged.")
                
                else:
                    st.success("✅ **Email is Safe!** (No violations detected)")
                
                st.markdown("---")
                st.text_input("From", email['from'], disabled=True)
                st.text_input("Subject", email['subject'], disabled=True)
                st.text_area("Body", email['body'], height=200, disabled=True)
                
                if email['attachments']:
                    st.markdown("**Attachments:**")
                    for att in email['attachments']:
                        st.info(f"📄 {att.name} ({att.type}, {att.size / 1024:.1f} KB)")
                else:
                    st.markdown("**Attachments:** None")

# --- Page 3: Monitor Dashboard (Manager's View) ---
elif page == "🛡️ Monitor Dashboard (Manager)":
    st.title("🛡️ Monitor Dashboard (Manager's View)")
    st.markdown("This view simulates the manager's console, showing *only* the flagged events. **The full email content is not stored or shown here.**")
    st.markdown("---")

    if not st.session_state.log:
        st.info("No flagged events have been logged yet. Try sending or opening a non-compliant email.")
    else:
        log_df = pd.DataFrame(st.session_state.log)
        
        # --- Metrics ---
        total_flags = len(log_df)
        outgoing_flags = len(log_df[log_df["Direction"] == "Outgoing"])
        incoming_flags = len(log_df[log_df["Direction"] == "Incoming"])
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Incidents", total_flags)
        c2.metric("Outgoing Flags", outgoing_flags)
        c3.metric("Incoming Flags", incoming_flags)
        
        st.markdown("---")
        st.subheader("Red Flag Incident Log")
        
        # Convert log list of dicts to a DataFrame for easy viewing
        log_df = pd.DataFrame(st.session_state.log)
        
        # Reorder columns for clarity
        log_df = log_df[["Timestamp", "Direction", "From", "To", "Subject", "Flags"]]
        
        # Sort by timestamp, newest first
        log_df = log_df.sort_values(by="Timestamp", ascending=False)
        
        st.dataframe(log_df, use_container_width=True)

        if st.button("Clear Log"):
            st.session_state.log = []
            st.rerun()

