import streamlit as st
import pandas as pd
import time
import random

# -----------------------------------
# SAFE SIMULATION DATA
# -----------------------------------
modules = [
    "Keyboard Hook Monitor",
    "Process Memory Inspector",
    "System API Usage Tracker",
    "Hidden Window Detector",
    "Key Event Frequency Analyzer",
    "Suspicious Pattern Matcher",
    "Background Task Monitor",
]

# -----------------------------------
# PAGE SETUP
# -----------------------------------
st.set_page_config(page_title="Keylogger Simulation Scanner", layout="centered")

st.title("🔐 Keylogger Detection Simulator (Safe Demo)")
st.write("This is a **safe, simulated** keylogger scanner with real-time animation.")

# Start scan button
start = st.button("▶️ Start Real-Time Scan")

# -----------------------------------
# REAL-TIME SCAN
# -----------------------------------
if start:

    scan_bar = st.progress(0)
    live_log = st.empty()
    threat_indicator = st.empty()
    results_table = st.empty()

    log_messages = []
    result_rows = []

    for i in range(1, 101):

        # RANDOMLY SELECT MODULE
        module = random.choice(modules)

        # SIMULATE STATUS
        status = random.choice(["OK", "OK", "OK", "Suspicious"])  # 25% suspicious
        detail = (
            "Normal behavior"
            if status == "OK"
            else f"Anomaly detected in {module.lower()}."
        )

        log_entry = f"{i}% — Scanning: {module} → {status}"
        log_messages.append(log_entry)

        # LIVE LOG ANIMATION (blinking, scrolling)
        live_log.markdown(
            f"""
            <div style="padding:10px; background:#111; color:#0f0; font-family:monospace; height:200px; overflow:auto;">
            {('<br>'.join(log_messages[-8:]))}
            </div>
            """,
            unsafe_allow_html=True,
        )

        # THREAT PULSE ANIMATION
        if status == "Suspicious":
            threat_indicator.markdown(
                """
                <div style="padding:10px; background:#550000; color:#ff4d4d; 
                text-align:center; border-radius:8px; font-weight:bold;">
                ⚠️ Suspicious Activity Detected
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            threat_indicator.markdown("")

        # SAVE ROW
        result_rows.append({"Module": module, "Status": status, "Detail": detail})

        # PROGRESS BAR
        scan_bar.progress(i)

        time.sleep(0.07)

    # -----------------------------------
    # FINAL RESULTS
    # -----------------------------------
    st.success("✅ Scan Completed")

    df = pd.DataFrame(result_rows)

    results_table.dataframe(df, use_container_width=True)

    # -----------------------------------
    # EXPORT TO EXCEL — NO RED BOX!
    # -----------------------------------
    try:
        df.to_excel("keylogger_simulation_report.xlsx", index=False)
        with open("keylogger_simulation_report.xlsx", "rb") as f:
            st.download_button(
                label="⬇️ Download Full Report (Excel)",
                data=f,
                file_name="keylogger_simulation_report.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
    except Exception:
        st.warning("Report export unavailable (OpenPyXL missing). Still safe to run.")
