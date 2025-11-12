"""
Streamlit Keylogger Heuristic Scanner
=====================================
⚠️ Educational demo (not a replacement for antivirus)
- Run as Administrator for full access (on Windows)
- Produces: keylogger_scan_report.xlsx
- Shows suspicious processes, files, registry entries, and scheduled tasks
"""

import os
import psutil
import pandas as pd
import subprocess
import traceback
import ctypes
import streamlit as st
from pathlib import Path

# Try to import Windows registry
try:
    import winreg
    IS_WINDOWS = True
except Exception:
    IS_WINDOWS = False

# ---------------- CONFIG ----------------
HOME = Path.home()
COMMON_DIRS = [
    HOME / "AppData" / "Roaming",
    HOME / "AppData" / "Local" / "Temp",
    HOME / "Downloads",
    Path("C:/ProgramData") if os.name == "nt" else None,
    Path("C:/Program Files") if os.name == "nt" else None,
    Path("C:/Program Files (x86)") if os.name == "nt" else None,
    Path("C:/Windows") if os.name == "nt" else None,
]
COMMON_DIRS = [p for p in COMMON_DIRS if p and p.exists()]

KEYWORDS = [
    "keylog", "keylogger", "key_log", "key-log", "keyboard", "keyhook", "keystroke",
    "keystrokes", "logger", "log_", "log-", "hook", "capture", "clipboard",
    "spy", "spyware", "ransomware"
]

MAX_FILES_PER_DIR = 1000  # reduce for Streamlit responsiveness

# ---------------- HELPERS ----------------
def lower_contains_any(s, keywords=KEYWORDS):
    if not s:
        return False
    s = s.lower()
    return any(k in s for k in keywords)

def is_in_suspicious_dir(path: Path):
    p = str(path).lower()
    suspects = ['appdata', 'temp', 'downloads', 'programdata']
    return any(x in p for x in suspects)

# ---------------- SCAN FUNCTIONS ----------------
def scan_processes():
    rows = []
    for proc in psutil.process_iter(['pid','name','exe','cmdline','username']):
        try:
            info = proc.info
            pid = info.get('pid')
            name = info.get('name') or ""
            exe = info.get('exe') or ""
            cmdline = " ".join(info.get('cmdline') or [])
            username = info.get('username') or ""
            reasons, suspicious = [], False

            if lower_contains_any(name) or lower_contains_any(exe) or lower_contains_any(cmdline):
                reasons.append("name/cmdline contains suspicious keyword")
                suspicious = True

            if exe and is_in_suspicious_dir(Path(exe)):
                reasons.append("executable in suspicious dir (AppData/Temp/Downloads)")
                suspicious = True

            rows.append({
                "type": "process", "path_or_name": exe or name,
                "process_name": name, "pid": pid, "username": username,
                "suspicious": suspicious, "reasons": "; ".join(reasons)
            })
        except Exception:
            continue
    return rows

def scan_files_in_dir(dirpath: Path, max_files=MAX_FILES_PER_DIR):
    rows = []
    count = 0
    for root, _, files in os.walk(dirpath):
        for fname in files:
            if count >= max_files:
                return rows
            count += 1
            try:
                fpath = Path(root) / fname
                reasons, suspicious = [], False
                if lower_contains_any(fname):
                    reasons.append("filename contains suspicious keyword")
                    suspicious = True
                if is_in_suspicious_dir(fpath):
                    reasons.append("file in suspicious dir (AppData/Temp/Downloads)")
                    suspicious = True
                if fpath.suffix.lower() in ('.exe','.dll','.bat','.ps1','.py','.js'):
                    reasons.append(f"executable/script file ({fpath.suffix})")
                    if lower_contains_any(fname) or is_in_suspicious_dir(fpath):
                        suspicious = True
                rows.append({
                    "type": "file",
                    "path_or_name": str(fpath),
                    "process_name": "", "pid": "",
                    "username": str(fpath.owner()) if hasattr(fpath, "owner") else "",
                    "suspicious": suspicious, "reasons": "; ".join(reasons)
                })
            except Exception:
                continue
    return rows

def scan_common_dirs():
    all_rows = []
    for d in COMMON_DIRS:
        try:
            all_rows.extend(scan_files_in_dir(d))
        except Exception as e:
            print("Error scanning", d, ":", e)
            continue
    return all_rows

def scan_windows_startup():
    rows = []
    if not IS_WINDOWS:
        return rows
    RUN_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    ]
    for hive, keypath in RUN_KEYS:
        try:
            with winreg.OpenKey(hive, keypath) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        reasons, suspicious = [], False
                        if lower_contains_any(name) or lower_contains_any(value):
                            reasons.append("startup entry has suspicious keyword")
                            suspicious = True
                        if value and is_in_suspicious_dir(Path(value.split('"')[-1])):
                            reasons.append("startup entry in suspicious dir")
                            suspicious = True
                        rows.append({
                            "type": "registry_startup",
                            "path_or_name": f"{keypath}\\{name}",
                            "process_name": value,
                            "pid": "", "username": "",
                            "suspicious": suspicious,
                            "reasons": "; ".join(reasons)
                        })
                    except OSError:
                        break
        except Exception:
            continue
    return rows

def scan_schtasks():
    rows = []
    if not IS_WINDOWS:
        return rows
    try:
        proc = subprocess.run(['schtasks','/query','/fo','LIST','/v'], capture_output=True, text=True, timeout=30)
        out = proc.stdout
        tasks = out.splitlines()
        current = {}
        for line in tasks:
            if not line.strip():
                if current:
                    name = current.get("TaskName","")
                    run = current.get("Task To Run","")
                    reasons, suspicious = [], False
                    if lower_contains_any(name) or lower_contains_any(run):
                        reasons.append("task contains suspicious keyword")
                        suspicious = True
                    if run and is_in_suspicious_dir(Path(run.strip().strip('"').split()[0])):
                        reasons.append("task runs from suspicious dir")
                        suspicious = True
                    rows.append({
                        "type": "scheduled_task",
                        "path_or_name": name,
                        "process_name": run,
                        "pid": "", "username": "",
                        "suspicious": suspicious,
                        "reasons": "; ".join(reasons)
                    })
                current = {}
                continue
            if ':' in line:
                k, v = line.split(':', 1)
                current[k.strip()] = v.strip()
    except Exception as e:
        print("schtasks scan failed:", e)
    return rows

# ---------------- MAIN SCAN FUNCTION ----------------
def run_scan():
    results = []
    with st.spinner("🔍 Scanning running processes..."):
        results.extend(scan_processes())
    with st.spinner("🗂️ Scanning common directories..."):
        results.extend(scan_common_dirs())
    if IS_WINDOWS:
        with st.spinner("🪟 Checking Windows startup entries..."):
            results.extend(scan_windows_startup())
        with st.spinner("🕓 Checking scheduled tasks..."):
            results.extend(scan_schtasks())

    df = pd.DataFrame(results)
    if df.empty:
        st.warning("No data found during scan.")
        return df
    df['suspicious'] = df['suspicious'].astype(bool)
    return df

# ---------------- STREAMLIT UI ----------------
st.set_page_config(page_title="Keylogger Heuristic Scanner", layout="wide")

st.title("🛡️ Keylogger Heuristic Scanner (Demo)")
st.write("""
This tool heuristically scans your system for **potential keylogger indicators**  
(Process names, file paths, startup entries, and scheduled tasks).  
> ⚠️ For best results, run as Administrator (Windows only)
""")

if IS_WINDOWS:
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_admin = False
    if not is_admin:
        st.warning("⚠️ Not running as Administrator. Some checks may be limited.")

if st.button("🚀 Run Full System Scan"):
    df = run_scan()
    if not df.empty:
        suspicious_df = df[df['suspicious']]
        st.success(f"✅ Scan complete. Found {len(suspicious_df)} suspicious entries out of {len(df)} total.")
        st.dataframe(suspicious_df, use_container_width=True)
        
        # Allow download
        excel_file = "keylogger_scan_report.xlsx"
        df.to_excel(excel_file, index=False)
        with open(excel_file, "rb") as f:
            st.download_button("⬇️ Download Full Report (Excel)", f, file_name=excel_file)
    else:
        st.info("No suspicious entries found.")

st.caption("Developed for educational cybersecurity awareness. © 2025")
