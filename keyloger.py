import streamlit as st
import pandas as pd
import random
import time
from io import BytesIO

# -------------------------
#       PAGE SETTINGS
# -------------------------
st.set_page_config(page_title="Keylogger Heuristic Scanner (Demo)", layout="wide")

st.title("🛡️ Keylogger Heuristic Scanner – Cloud Safe Demo")
st.write("""
This is a **cloud-friendly simulated scanner**.  
No real system scanning is performed.  
""")

# -------------------------
#     SIDEBAR OPTIONS
# -------------------------
st.sidebar.header("⚙️ Scan Rules")

keyword_rule = st.sidebar.checkbox("Keyword Detection", True)
extension_rule = st.sidebar.checkbox("Extension Check", True)
pattern_rule = st.sidebar.checkbox("Pattern Matching", True)
random_noise_rule = st.sidebar.checkbox("Random Noise Rule", False)

st.sidebar.divider()

history_enabled = st.sidebar.checkbox("Enable Scan History", True)


# -------------------------
#   GENERATOR (SAFE DATA)
# -------------------------
def generate_fake_scan():
    safe_names = [
        "process_alpha.exe", "module_beta.py", "service_update.exe",
        "utility_gamma.dll", "script_runner.ps1", "editor_app.exe",
        "engine_delta.bin", "task_handler.app", "monitor_sigma.out"
    ]

    suspicious_keywords = ["alpha", "gamma", "sigma"]
    suspicious_ext = [".dll", ".bin", ".ps1"]

    data = []

    for name in safe_names:
        reasons = []
        suspicious = False

        # Rule: Keyword detection
        if keyword_rule:
            if any(k in name.lower() for k in suspicious_keywords):
                suspicious = True
                reasons.append("matched keyword rule")

        # Rule: File extension check
        if extension_rule:
            if any(name.lower().endswith(ext) for ext in suspicious_ext):
                suspicious = True
                reasons.append("suspicious extension")

        # Rule: Pattern matching
        if pattern_rule:
            if "_" in name:
                suspicious = True
                reasons.append("pattern detected")

        # Rule: Random noise flag
        if random_noise_rule:
            if random.random() < 0.25:
                suspicious = True
                reasons.append("random noise trigger")

        data.append({
            "Type": random.choice(["Process", "File"]),
            "Name": name,
            "Path": f"/cloud/demo/{name}",
            "Suspicious": suspicious,
            "Reasons": ", ".join(reasons)
        })

    return pd.DataFrame(data)


# -------------------------
#     SCAN HISTORY
# -------------------------
if history_enabled:
    if "scan_history" not in st.session_state:
        st.session_state["scan_history"] = []


# -------------------------
#     START SCAN BUTTON
# -------------------------
if st.button("🚀 Run Scan"):

    with st.spinner("Initializing scan..."):
        time.sleep(1.0)

    # Fake progress animation
    progress = st.progress(0)
    messages = [
        "Loading scan engine...",
        "Checking demo processes...",
        "Applying heuristic models...",
        "Simulating memory pattern checks...",
        "Finalizing results..."
    ]

    for i, msg in enumerate(messages):
        progress.progress(int((i + 1) * 20))
        st.info(msg)
        time.sleep(0.4)

    df = generate_fake_scan()
    suspicious_df = df[df["Suspicious"]]

    # Save history
    if history_enabled:
        st.session_state["scan_history"].append(df)

    st.success(f"Completed! Found {len(suspicious_df)} suspicious items.")
    st.dataframe(df, use_container_width=True)

    # -------------------------
    #     EXPORT EXCEL
    # -------------------------
    buffer = BytesIO()
    df.to_excel(buffer, index=False)
    buffer.seek(0)

    st.download_button(
        "⬇️ Download Report (Excel)",
        buffer,
        file_name="demo_keylogger_report.xlsx"
    )

    st.divider()

    # -------------------------
    #     PIE REPLACEMENT
    # -------------------------
    st.subheader("📊 Suspicious vs Normal (Chart)")

    status_df = pd.DataFrame({
        "Status": ["Suspicious", "Clean"],
        "Count": [len(suspicious_df), len(df) - len(suspicious_df)]
    })

    st.bar_chart(status_df, x="Status", y="Count", use_container_width=True)

    st.divider()

    # -------------------------
    #     BAR CHART REPLACEMENT
    # -------------------------
    st.subheader("📊 File vs Process Distribution")

    type_counts = df["Type"].value_counts()
    type_df = pd.DataFrame({
        "Type": type_counts.index,
        "Count": type_counts.values
    })

    st.bar_chart(type_df, x="Type", y="Count", use_container_width=True)


# -------------------------
#     SHOW HISTORY
# -------------------------
if history_enabled and st.session_state["scan_history"]:
    st.subheader("📚 Scan History")

    for i, scan in enumerate(st.session_state["scan_history"], 1):
        with st.expander(f"Scan #{i}"):
            st.dataframe(scan, use_container_width=True)

st.caption("✔ Cloud-safe demo • No real device scanning performed.")
