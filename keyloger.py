import os
import psutil
import pandas as pd
import traceback
import streamlit as st
from pathlib import Path

# Try to import Windows-only features
try:
    import winreg
    import subprocess
    import ctypes
    IS_WINDOWS = True
except Exception:
    IS_WINDOWS = False

# ---------------- CONFIG ----------------
HOME = Path.home()
COMMON_DIRS = [
    HOME / "AppData" / "Roaming",
    HOME / "AppData" / "Local" / "Temp",
    HOME / "Downloads",
]
COMMON_DIRS = [p for p in COMMON_DIRS if p.exists()]

KEYWORDS = [
    "keylog", "keylogger", "keystroke", "logger",
    "hook", "capture", "clipboard", "spy", "spyware"
]

MAX_FILES_PER_DIR = 300  # smaller for demo safety

# ---------------- HELPERS ----------------
def lower_contains_any(s, keywords=KEYWORDS):
    if not s:
        return False
    s = s.lower()
    return any(k in s for k in keywords)

def is_in_suspicious_dir(path: Path):
    p = str(path).lower()
    suspects = ['appdata', 'temp', 'downloads']
    return any(x in p for x in suspects)

# ---------------- SCANNERS ----------------
def scan_processes():
    rows = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            info = proc.info
            pid = info.get('pid')
            name = info.get('name', '')
            exe = info.get('exe', '')
            reasons, suspicious = [], False

            if lower_contains_any(name) or lower_contains_any(exe):
                reasons.append("name/exe contains suspicious keyword")
                suspicious = True
            if exe and is_in_suspicious_dir(Path(exe)):
                reasons.append("running from suspicious directory")
                suspicious = True

            rows.append({
                "type": "process", "name": name, "path": exe,
                "pid": pid, "suspicious": suspicious,
                "reasons": "; ".join(reasons)
            })
        except Exception:
            continue
    return rows

def scan_files_in_dir(dirpath: Path):
    rows = []
    count = 0
    for root, _, files in os.walk(dirpath):
        for fname in files:
            if count > MAX_FILES_PER_DIR:
                return rows
            count += 1
            try:
                fpath = Path(root) / fname
                reasons, suspicious = [], False
                if lower_contains_any(fname):
                    reasons.append("filename contains suspicious keyword")
                    suspicious = True
                if is_in_suspicious_dir(fpath):
                    reasons.append("located in suspicious directory")
                    suspicious = True
                rows.append({
                    "type": "file", "name": fname, "path": str(fpath),
                    "pid": "", "suspicious": suspicious,
                    "reasons": "; ".join(reasons)
                })
            except Exception:
                continue
    return rows

def run_scan(safe_mode=True):
    results = []

    with st.spinner("🔍 Scanning running processes..."):
        results.extend(scan_processes())

    with st.spinner("📂 Scanning common directories..."):
        for d in COMMON_DIRS:
            results.extend(scan_files_in_dir(d))

    if IS_WINDOWS and not safe_mode:
        try:
            import subprocess
            with st.spinner("🕓 Checking scheduled tasks..."):
                subprocess.run(['schtasks', '/query'], capture_output=True)
        except Exception:
            st.info("Skipping scheduled tasks scan (restricted).")

    df = pd.DataFrame(results)
    if df.empty:
        st.warning("No data collected.")
        return df
    df['suspicious'] = df['suspicious'].astype(bool)
    return df

# ---------------- STREAMLIT UI ----------------
st.set_page_config(page_title="Keylogger Heuristic Scanner", layout="wide")

st.title("🛡️ Keylogger Heuristic Scanner (Safe Streamlit Version)")
st.write("""
This demo scans your system heuristically for **potential keylogger indicators**.  
> **Safe Mode** avoids deep system access (registry/tasks) to prevent Streamlit data warnings.
""")

safe_mode = st.toggle("🧩 Safe Mode (recommended)", value=True)

if st.button("🚀 Run Scan"):
    try:
        df = run_scan(safe_mode)
        if not df.empty:
            suspicious_df = df[df['suspicious']]
            st.success(f"✅ Scan complete — {len(suspicious_df)} suspicious items found.")
            st.dataframe(suspicious_df, use_container_width=True)
            df.to_excel("keylogger_scan_report.xlsx", index=False)
            with open("keylogger_scan_report.xlsx", "rb") as f:
                st.download_button("⬇️ Download Report", f, file_name="keylogger_scan_report.xlsx")
        else:
            st.info("No suspicious entries found.")
    except Exception as e:
        st.error("⚠️ Scan failed (restricted environment).")
        st.text(traceback.format_exc())

st.caption("© 2025 Educational Demo — Not a replacement for antivirus")
