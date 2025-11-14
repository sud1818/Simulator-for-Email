import streamlit as st
import pandas as pd
import random

st.set_page_config(page_title="Keylogger Heuristic Scanner (Cloud Safe)", layout="wide")

st.title("🛡️ Keylogger Heuristic Scanner — Cloud-Safe Demo")
st.write("""
This is a **safe simulation** of how heuristic keylogger scanners work.  
It does **not** scan your device — all data is artificially generated.
""")

# -------------------------------------------------------------------
# Fake items to simulate a scan
# -------------------------------------------------------------------
SAFE_ITEMS = [
    "system32.dll", "chrome.exe", "notepad.exe", "update_service.exe",
    "clipboard_hook.dll", "mouse_event.dll", "capturekeys.py",
    "vpnservice.exe", "taskhostw.exe", "winlogin.bin",
    "secure_loader.ps1", "gamma_record.exe", "alpha_hook.dll"
]

# -------------------------------------------------------------------
# Compute suspicious score from triggered rules
# -------------------------------------------------------------------
def compute_score(triggered_rules):
    score_map = {
        "Keyword Detection": 40,
        "Suspicious Extension": 30,
        "Pattern Match": 20,
        "Random Noise": 10
    }
    return sum(score_map[r] for r in triggered_rules)

# -------------------------------------------------------------------
# Simulated scan logic
# -------------------------------------------------------------------
def run_simulated_scan(rules):
    results = []
    rule_counts = {
        "Keyword Detection": 0,
        "Suspicious Extension": 0,
        "Pattern Match": 0,
        "Random Noise": 0
    }

    for name in SAFE_ITEMS:
        rule_hits = []
        reasons = []

        # Keyword rule
        if rules["keyword_detection"]:
            keywords = ["alpha", "gamma", "hook", "capture", "key"]
            for k in keywords:
                if k in name.lower():
                    rule_hits.append("Keyword Detection")
                    rule_counts["Keyword Detection"] += 1
                    reasons.append(f"keyword:{k}")
                    break

        # Extension rule
        if rules["extension_check"]:
            bad_ext = [".dll", ".bin", ".ps1"]
            if any(name.lower().endswith(x) for x in bad_ext):
                rule_hits.append("Suspicious Extension")
                rule_counts["Suspicious Extension"] += 1
                reasons.append("bad_extension")

        # Pattern rule
        if rules["pattern_matching"]:
            if "_" in name or "-" in name:
                rule_hits.append("Pattern Match")
                rule_counts["Pattern Match"] += 1
                reasons.append("pattern_match")

        # Random noise rule
        if rules["noise"]:
            if random.random() < 0.22:
                rule_hits.append("Random Noise")
                rule_counts["Random Noise"] += 1
                reasons.append("random_noise")

        score = compute_score(rule_hits)
        suspicious = score >= rules["score_threshold"]

        results.append({
            "Type": random.choice(["Process", "File"]),
            "Name": name,
            "Path": f"/cloud/demo/{name}",
            "Triggered Rules": ";".join(rule_hits),
            "Reasons": ";".join(reasons),
            "Score": score,
            "Suspicious": suspicious
        })

    return pd.DataFrame(results), rule_counts

# -------------------------------------------------------------------
# Sidebar controls
# -------------------------------------------------------------------
st.sidebar.header("🔧 Scanner Settings")

rules = {
    "keyword_detection": st.sidebar.checkbox("Keyword Detection", True),
    "extension_check": st.sidebar.checkbox("Extension Checking", True),
    "pattern_matching": st.sidebar.checkbox("Pattern Matching", True),
    "noise": st.sidebar.checkbox("Random Noise", False),
    "score_threshold": st.sidebar.slider("Suspicious Score Threshold", 10, 100, 50)
}

show_only_suspicious = st.sidebar.checkbox("Show Only Suspicious Items", False)
min_score = st.sidebar.slider("Minimum Score Filter", 0, 100, 0)

# -------------------------------------------------------------------
# Run scan button
# -------------------------------------------------------------------
if st.button("🚀 Run Simulated Scan"):
    df, rule_counts = run_simulated_scan(rules)

    st.success("Scan completed successfully.")

    # Display rule stats
    st.subheader("📊 Rule Trigger Counts")
    st.write(rule_counts)

    # -------------------------------------------------------------------
    # Filtering (SAFE — FIXED)
    # -------------------------------------------------------------------
    filtered = df.copy()

    if show_only_suspicious:
        filtered = filtered[filtered["Suspicious"] == True]

    filtered = filtered[filtered["Score"] >= min_score]
    filtered = filtered.reset_index(drop=True)

    st.subheader("🔍 Scan Results")
    st.dataframe(filtered, use_container_width=True)

    # Download report
    df.to_excel("keylogger_simulation_report.xlsx", index=False)
    with open("keylogger_simulation_report.xlsx", "rb") as f:
        st.download_button(
            "⬇️ Download Full Report",
            f,
            file_name="keylogger_simulation_report.xlsx"
        )

st.caption("⚙️ 100% Cloud-safe — no system scanning is performed.")
