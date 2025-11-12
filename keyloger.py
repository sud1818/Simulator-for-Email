import streamlit as st
import pandas as pd
import random

st.set_page_config(page_title="Keylogger Heuristic Scanner (Demo)", layout="wide")

st.title("🛡️ Keylogger Heuristic Scanner (Cloud-Safe Demo)")
st.write("""
This demo simulates how a **heuristic keylogger scanner** works.  
It doesn't access your real system — safe for **Streamlit Cloud**.
""")

# Fake data generator
def generate_fake_scan():
    fake_names = [
        "keylogger.exe", "chrome.exe", "capturekeys.py", "update_service.exe",
        "clipboard_hook.dll", "notepad.exe", "system_monitor.ps1"
    ]
    data = []
    for name in fake_names:
        suspicious = any(k in name.lower() for k in ["keylog", "hook", "capture", "clipboard"])
        data.append({
            "type": random.choice(["process", "file"]),
            "name": name,
            "path": f"C:/Users/User/AppData/Local/{name}",
            "suspicious": suspicious,
            "reasons": "contains suspicious keyword" if suspicious else ""
        })
    return pd.DataFrame(data)

if st.button("🚀 Run Simulated Scan"):
    df = generate_fake_scan()
    suspicious_df = df[df["suspicious"]]
    st.success(f"✅ Scan complete — {len(suspicious_df)} suspicious items found.")
    st.dataframe(df, use_container_width=True)
    df.to_excel("demo_keylogger_report.xlsx", index=False)
    with open("demo_keylogger_report.xlsx", "rb") as f:
        st.download_button("⬇️ Download Demo Report", f, file_name="demo_keylogger_report.xlsx")

st.caption("⚙️ Cloud-safe simulation — does not scan your device.")
