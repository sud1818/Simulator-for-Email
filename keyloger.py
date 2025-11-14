# keyloger.py
import streamlit as st
import pandas as pd
import random
import time
from io import BytesIO
import math
import wave
import struct
import base64
import html

# -------------------------
# Page config
# -------------------------
st.set_page_config(page_title="Keylogger Heuristic Scanner — Fixed Demo", layout="wide")

# -------------------------
# Simple CSS for badges / console / radar
# -------------------------
st.markdown(
    """
    <style>
    .chip {display:inline-block;padding:6px 10px;border-radius:16px;font-weight:600;}
    .chip.green{background:#e6f7ea;color:#0a6b2d}
    .chip.yellow{background:#fff7e0;color:#b86b00}
    .chip.red{background:#ffecec;color:#a70000}
    .radar {font-family:monospace; font-size:18px; line-height:1.0; white-space:pre;}
    .console {background:#0b1220;color:#d6e6ff;padding:8px;border-radius:6px;font-family:monospace}
    .controls {padding:8px}
    .heatcell {padding:6px;border-radius:6px;color:white;font-weight:700; text-align:center}
    table.heat{border-collapse:collapse}
    table.heat td{padding:6px}
    </style>
    """,
    unsafe_allow_html=True
)

# -------------------------
# Session defaults
# -------------------------
if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []

if "last_report" not in st.session_state:
    st.session_state["last_report"] = None

if "theme" not in st.session_state:
    st.session_state["theme"] = "light"

def set_theme(t):
    st.session_state["theme"] = t

# -------------------------
# Safe demo names
# -------------------------
SAFE_NAMES = [
    "process_alpha.exe", "module_beta.py", "service_update.exe",
    "utility_gamma.dll", "script_runner.ps1", "editor_app.exe",
    "engine_delta.bin", "task_handler.app", "monitor_sigma.out",
    "worker_theta.exe", "agent_phi.py", "daemon_kappa.bin"
]

# -------------------------
# Beep generator (WAV) for completion sound
# -------------------------
def generate_beep(duration_seconds=0.18, freq=880.0, volume=0.5, samplerate=22050):
    n_samples = int(samplerate * duration_seconds)
    buf = BytesIO()
    with wave.open(buf, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(samplerate)
        for i in range(n_samples):
            t = float(i) / samplerate
            amplitude = volume * (1.0 - (t / duration_seconds))
            sample = int(amplitude * 32767 * math.sin(2 * math.pi * freq * t))
            wf.writeframes(struct.pack('<h', sample))
    return buf.getvalue()

BEEP_BYTES = generate_beep()

# -------------------------
# Score computation
# -------------------------
def compute_score(name, rules_triggered):
    base = random.randint(5, 25)
    triggers = len(rules_triggered)
    score = base + triggers * random.randint(20, 30)
    nudges = {"alpha": 8, "gamma": 10, "sigma": 6, "delta": 4, "theta": 5}
    for k, v in nudges.items():
        if k in name:
            score += v
    return min(100, score)

# -------------------------
# Heatmap HTML builder (safe for empty)
# -------------------------
def build_heatmap_html(rule_counts):
    if not rule_counts:
        return "<div>No rule data</div>"
    maxc = max(rule_counts.values()) if any(rule_counts.values()) else 1
    rows = []
    rows.append('<table class="heat">')
    for rule, cnt in rule_counts.items():
        intensity = int(200 * (cnt / maxc)) if maxc else 0
        # gentle color ramp
        r = max(50, 255 - intensity)
        g = max(30, 80 + int(intensity / 2))
        b = max(30, 80)
        color = f"rgb({r},{g},{b})"
        rows.append(
            f"<tr><td style='font-weight:700;padding-right:10px'>{html.escape(rule)}</td>"
            f"<td><div class='heatcell' style='background:{color}'>{cnt}</div></td></tr>"
        )
    rows.append('</table>')
    return "".join(rows)

# -------------------------
# Fixed generator: consistent rule_counts keys and safe .get usage
# -------------------------
def generate_scan_dataframe(rules):
    """
    rules: dict with keys (may be missing) -
      "keyword_detection", "extension_check", "pattern_matching", "random_noise", "score_threshold"
    Returns: (df, rule_counts) where rule_counts uses human-readable names
    """
    data = []
    # Use human-readable keys that match the rest of the app
    rule_counts = {
        "Keyword Detection": 0,
        "Extension Check": 0,
        "Pattern Matching": 0,
        "Random Noise Rule": 0
    }

    for name in SAFE_NAMES:
        reasons = []
        triggered = []
        # Keyword detection
        if rules.get("keyword_detection", False):
            keywords = ["alpha", "gamma", "sigma", "theta"]
            for k in keywords:
                if k in name.lower():
                    reasons.append(f"keyword:{k}")
                    triggered.append("Keyword Detection")
                    rule_counts["Keyword Detection"] += 1
                    break
        # Extension check
        if rules.get("extension_check", False):
            bad_exts = [".dll", ".bin", ".ps1"]
            if any(name.lower().endswith(e) for e in bad_exts):
                reasons.append("suspicious_ext")
                triggered.append("Extension Check")
                rule_counts["Extension Check"] += 1
        # Pattern matching
        if rules.get("pattern_matching", False):
            # underscore pattern and no digits (demo rule)
            if "_" in name and not any(ch.isdigit() for ch in name):
                reasons.append("underscore_pattern")
                triggered.append("Pattern Matching")
                rule_counts["Pattern Matching"] += 1
        # Random noise
        if rules.get("random_noise", False):
            if random.random() < 0.18:
                reasons.append("random_noise")
                triggered.append("Random Noise Rule")
                rule_counts["Random Noise Rule"] += 1
        # score and suspicious flag
        score = compute_score(name, triggered)
        suspicious = score >= rules.get("score_threshold", 50)
        data.append({
            "Type": random.choice(["Process", "File"]),
            "Name": name,
            "Path": f"/demo/cloud/{name}",
            "Suspicious": suspicious,
            "Score": score,
            "Reasons": ", ".join(reasons),
            "Triggered": ";".join(triggered)
        })
    df = pd.DataFrame(data)
    return df, rule_counts

# -------------------------
# UI: sidebar navigation
# -------------------------
st.sidebar.title("🔧 Scanner Menu")
page = st.sidebar.selectbox("Choose page", ["Scanner", "Dashboard", "History", "Settings"])

# -------------------------
# Settings page
# -------------------------
if page == "Settings":
    st.header("⚙️ Settings")
    c1, c2 = st.columns(2)
    with c1:
        theme_choice = st.radio("Theme", ["light", "dark"], index=0 if st.session_state["theme"]=="light" else 1)
        if st.button("Apply Theme"):
            set_theme(theme_choice)
        st.write("---")
        st.subheader("Scan rule defaults")
        st.checkbox("Keyword Detection (default)", True, key="ui_keyword")
        st.checkbox("Extension Check (default)", True, key="ui_ext")
        st.checkbox("Pattern Matching (default)", True, key="ui_pattern")
        st.checkbox("Random Noise Rule (default)", False, key="ui_noise")
    with c2:
        st.subheader("Advanced")
        st.slider("Suspicious Score Threshold (default)", 0, 100, 50, key="ui_threshold")
        st.checkbox("Enable Scan History (default)", True, key="ui_history")
    st.write("Settings are stored in-session for this demo.")

# -------------------------
# Scanner page
# -------------------------
if page == "Scanner":
    st.header("🚀 Scanner (Fixed)")
    # Controls
    col1, col2, col3 = st.columns([2,2,1])
    with col1:
        st.subheader("Scan Rules")
        keyword_detection = st.checkbox("Keyword Detection", True, key="r_keyword")
        extension_check = st.checkbox("Extension Check", True, key="r_ext")
        pattern_matching = st.checkbox("Pattern Matching", True, key="r_pattern")
        random_noise = st.checkbox("Random Noise Rule", False, key="r_noise")
    with col2:
        st.subheader("Behavior")
        score_threshold = st.slider("Suspicious Score Threshold", 0, 100, 50, key="r_threshold")
        show_console = st.checkbox("Show real-time console", True)
        radar_enabled = st.checkbox("Enable radar animation", True)
    with col3:
        st.subheader("History")
        history_enabled = st.checkbox("Enable scan history", True, key="r_history")

    rules = {
        "keyword_detection": keyword_detection,
        "extension_check": extension_check,
        "pattern_matching": pattern_matching,
        "random_noise": random_noise,
        "score_threshold": score_threshold
    }

    if st.button("🔍 Run Scan Now"):
        init = st.empty()
        init.info("Initializing scan engine...")
        time.sleep(0.8)
        init.empty()

        radar_area = st.empty()
        console_area = st.empty() if show_console else None
        progress = st.progress(0)

        steps = 10
        console_lines = []
        for i in range(steps):
            progress.progress(int((i+1)/steps*100))
            if radar_enabled:
                sweep_pos = i % 8
                radar_rows = []
                for r in range(7):
                    row_chars = []
                    for c in range(15):
                        if (r + c) % 8 == sweep_pos:
                            row_chars.append("🔴")
                        else:
                            row_chars.append("·")
                    radar_rows.append("".join(row_chars))
                radar_area.markdown(f'<div class="radar">{"<br>".join(radar_rows)}</div>', unsafe_allow_html=True)
            if console_area:
                msgs = [
                    "[✓] Loading heuristic models...",
                    "[✓] Scanning process table...",
                    "[✓] Inspecting file patterns...",
                    "[⚠] Pattern mismatch detected in module...",
                    "[i] Evaluating risk score...",
                    "[✓] Gathering final results..."
                ]
                console_lines.append(random.choice(msgs))
                console_html = "<div class='console'>" + "<br>".join(html.escape(l) for l in console_lines[-6:]) + "</div>"
                console_area.markdown(console_html, unsafe_allow_html=True)
            time.sleep(0.22)

        # Generate results (using fixed function)
        df, rule_counts = generate_scan_dataframe(rules)
        df["Suspicious"] = df["Score"] >= rules.get("score_threshold", 50)

        # store history
        if history_enabled:
            st.session_state["scan_history"].append({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "df": df.copy(),
                "rules": rules.copy()
            })

        st.audio(BEEP_BYTES, format="audio/wav")
        st.success("Scan complete!")

        suspicious_count = int(df["Suspicious"].sum())
        total = len(df)
        cA, cB, cC = st.columns(3)
        cA.metric("Total items scanned", total)
        cB.metric("Suspicious items", suspicious_count)
        cC.metric("Average risk score", f"{int(df['Score'].mean())} / 100")

        st.markdown("---")
        with st.expander("🔎 Filters & Interactive Dashboard"):
            f1, f2, f3 = st.columns([2,2,1])
            with f1:
                only_suspicious = st.checkbox("Show only suspicious", value=False, key="filter_susp")
                min_score = st.slider("Min score", 0, 100, 0, key="filter_min")
            with f2:
                sel_type = st.selectbox("Type", ["All"] + sorted(df["Type"].unique().tolist()), key="filter_type")
                name_search = st.text_input("Name contains", value="", key="filter_name")
            with f3:
                st.write("Quick actions")
                if st.button("Download last scan CSV"):
                    csv = df.to_csv(index=False).encode()
                    st.download_button("⬇️ Download CSV", csv, file_name="demo_scan.csv")

        # Apply filters
        filtered = df.copy()
        if only_suspicious:
            filtered = filtered[filtered["Suspicious"]]
        filtered = filtered[filtered][filtered["Score"] >= min_score]
        if sel_type != "All":
            filtered = filtered[filtered["Type"] == sel_type]
        if name_search.strip():
            filtered = filtered[filtered["Name"].str.contains(name_search.strip(), case=False, na=False)]

        # Render results table with chips
        def status_chip_html(s, score):
            if s:
                cls = "green" if score < 60 else ("yellow" if score < 80 else "red")
                label = "Suspicious"
                return f'<span class="chip {cls}">{label} ({int(score)})</span>'
            else:
                return '<span class="chip green">Clean</span>'

        table_rows = []
        table_rows.append("<table style='width:100%;border-collapse:collapse'>")
        table_rows.append("<tr><th style='text-align:left;padding:6px'>Type</th><th style='padding:6px'>Name</th><th style='padding:6px'>Score</th><th style='padding:6px'>Status</th><th style='padding:6px'>Reasons</th></tr>")
        for _, r in filtered.iterrows():
            chip = status_chip_html(r["Suspicious"], r["Score"])
            table_rows.append("<tr>")
            table_rows.append(f"<td style='padding:6px'>{html.escape(str(r['Type']))}</td>")
            table_rows.append(f"<td style='padding:6px;font-weight:700'>{html.escape(r['Name'])}</td>")
            table_rows.append(f"<td style='padding:6px'>{int(r['Score'])}</td>")
            table_rows.append(f"<td style='padding:6px'>{chip}</td>")
            table_rows.append(f"<td style='padding:6px'>{html.escape(r['Reasons'])}</td>")
            table_rows.append("</tr>")
        table_rows.append("</table>")
        st.markdown("".join(table_rows), unsafe_allow_html=True)

        st.markdown("---")
        st.subheader("🔥 Rule Trigger Frequency")
        heat_html = build_heatmap_html(rule_counts)
        st.markdown(heat_html, unsafe_allow_html=True)

        # Report HTML and downloads
        report_html = "<h2>Scan Summary Report</h2>"
        report_html += f"<p>Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>"
        report_html += f"<p>Total scanned: {total}</p>"
        report_html += f"<p>Suspicious: {suspicious_count}</p>"
        report_html += "<h3>Rule counts</h3>"
        report_html += heat_html
        report_html += "<h3>Items</h3><ul>"
        for _, r in df.iterrows():
            report_html += f"<li>{html.escape(r['Name'])} — Score: {int(r['Score'])} — {'Suspicious' if r['Suspicious'] else 'Clean'} — {html.escape(r['Reasons'])}</li>"
        report_html += "</ul>"

        st.markdown("### 📄 Summary Report")
        st.markdown(report_html, unsafe_allow_html=True)
        st.download_button("⬇️ Download HTML Report", report_html.encode("utf-8"), file_name="scan_report.html", mime="text/html")
        excel_buffer = BytesIO()
        df.to_excel(excel_buffer, index=False)
        excel_buffer.seek(0)
        st.download_button("⬇️ Download Excel Report", excel_buffer, file_name="scan_report.xlsx")

# -------------------------
# Dashboard page
# -------------------------
if page == "Dashboard":
    st.header("📊 Dashboard")
    hist = st.session_state.get("scan_history", [])
    if not hist:
        st.info("No scan history yet. Run a scan first.")
    else:
        last = hist[-1]
        lasth_df = last["df"]
        st.subheader("Last Scan Snapshot")
        st.write(f"Timestamp: {last['timestamp']}")
        top = lasth_df.sort_values("Score", ascending=False).head(5)
        st.table(top[["Name", "Type", "Score", "Reasons"]].reset_index(drop=True))
        counts = lasth_df["Type"].value_counts()
        chart_df = pd.DataFrame({"Type": counts.index, "Count": counts.values})
        st.markdown("**Type distribution**")
        st.bar_chart(chart_df.set_index("Type"))
        st.markdown("**Score distribution**")
        st.bar_chart(lasth_df["Score"])

# -------------------------
# History page
# -------------------------
if page == "History":
    st.header("📚 Scan History")
    hist = st.session_state.get("scan_history", [])
    if not hist:
        st.info("No saved scans in this session.")
    else:
        for i, item in enumerate(reversed(hist), 1):
            ts = item["timestamp"]
            df = item["df"]
            rules = item["rules"]
            with st.expander(f"Scan #{len(hist)-i+1} — {ts} (items: {len(df)})"):
                st.write("Rules used:", rules)
                st.dataframe(df[["Type", "Name", "Score", "Suspicious", "Reasons"]], use_container_width=True)
                csv = df.to_csv(index=False).encode()
                st.download_button(f"⬇️ Download scan #{len(hist)-i+1} CSV", csv, file_name=f"scan_{ts.replace(' ','_').replace(':','-')}.csv")

st.markdown("---")
st.caption("Demo scanner • Cloud-safe • No real device scanning performed.")
# --- Filtering ---
filtered = df.copy()

# Only suspicious items
if only_suspicious:
    filtered = filtered[filtered["Suspicious"] == True]

# Score threshold
filtered = filtered[filtered["Score"] >= min_score]

# Reset index for clean table
filtered = filtered.reset_index(drop=True)

# --- Display ---
st.subheader("🔍 Filtered Scan Results")
st.dataframe(filtered, use_container_width=True)

