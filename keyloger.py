import streamlit as st
import pandas as pd
import random

st.set_page_config(page_title="Keylogger Heuristic Scanner (Cloud Safe)", layout="wide")

st.title("🛡️ Keylogger Heuristic Scanner — Cloud Safe Demo")
st.write("""
This is a **safe simulation** that does NOT scan your real system.  
All results are randomly generated for demonstration.
""")

SAFE_ITEMS = [
    "system32.dll", "chrome.exe", "notepad.exe", "capturekeys.py",
    "clipboard_hook.dll", "mouse_event.dll", "update_service.exe",
    "vpnservice.exe", "taskhostw.exe", "winlogin.bin",
    "secure_loader.ps1", "gamma_record.exe", "alpha_hook.dll"
]

def compute_score(triggered):
    score_map = {
        "Keyword Detection": 40,
        "Suspicious Extension": 30,
        "Pattern Match": 20,
        "Random Noise": 10
    }
    return sum(score_map[r] for r in triggered)

def run_scan(rules):
    data = []
    rule_counts = {
        "Keyword Detection": 0,
        "Suspicious Extension": 0,
        "Pattern Match": 0,
        "Random Noise": 0
    }

    for name in SAFE_ITEMS:
        triggered = []
        reasons = []

        # Keyword rule
        if rules["keyword_detection"]:
            for k in ["alpha", "gamma", "hook", "capture", "key"]:
                if k in name.lower():
                    triggered.append("Keyword Detection")
                    reasons.append(f"keyword:{k}")
                    rule_counts["Keyword Detection"] += 1
                    break

        # Extension rule
        if rules["extension_check"]:
            for ext in [".dll", ".bin", ".ps1"]:
                if name.lower().endswith(ext):
                    triggered.append("Suspicious Extension")
                    reasons.append("extension")
                    rule_counts["Suspicious Extension"] += 1
                    break

        # Pattern rule
        if rules["pattern_matching"]:
            if "_" in name or "-" in name:
                triggered.append("Pattern Match")
                reasons.append("pattern")
                rule_counts["Pattern Match"] += 1

        # Random noise
        if rules["noise"]:
            if random.random() < 0.22:
                triggered.append("Random Noise")
                reasons.append("noise")
                rule_counts["Random Noise"] += 1

        score = compute_score(triggered)
        suspicious = score >= rules["score_threshold"]

        data.append({
            "Type": random.choice(["Process", "File"]),
            "Name": name,
            "Path": f"/cloud/demo/{name}",
            "Triggered Rules": ";".join(triggered),
            "Reasons": ";".join(reasons),
            "Score": score,
            "Suspicious": suspicious
        })

    return pd.DataFrame(data), rule_counts


# Sidebar
st.sidebar.header("🔧 Settings")

rules = {
    "keyword_detection": st.sidebar.checkbox("Keyword Detection", True),
    "extension_check": st.sidebar.checkbox("Extension Checking", True),
    "pattern_matching": st.sidebar.checkbox("Pattern Matching", True),
    "noise": st.sidebar.checkbox("Random Noise", False),
    "score_threshold": st.sidebar.slider("Suspicious Score Threshold", 10, 100, 50)
}

only_suspicious = st.sidebar.checkbox("Show Only Suspicious", False)
min_score = st.sidebar.slider("Minimum Score", 0, 100, 0)


# Run button
if st.button("🚀 Run Scan"):
    df, rule_stats = run_scan(rules)

    st.success("Scan completed successfully!")

    st.subheader("📊 Rule Hits")
    st.write(rule_stats)

    # Filtering (SAFE)
    filtered = df.copy()
    if only_suspicious:
        filtered = filtered[filtered["Suspicious"] == True]
    filtered = filtered[filtered["Score"] >= min_score]
    filtered = filtered.reset_index(drop=True)

    st.subheader("🔍 Scan Results")
    st.dataframe(filtered, use_container_width=True)

    # CSV export (No Excel → No errors)
    filtered.to_csv("keylogger_report.csv", index=False)

    with open("keylogger_report.csv", "rb") as f:
        st.download_button(
            "⬇️ Download CSV Report",
            f,
            file_name="keylogger_report.csv",
            mime="text/csv"
        )

st.caption("✔ 100% Cloud Safe — No system access. No Excel. No openpyxl.")
