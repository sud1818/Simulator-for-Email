# app.py
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
st.set_page_config(page_title="Keylogger Heuristic Scanner — Full Demo", layout="wide")
# -------------------------
# Theme toggle (simulated via CSS)
# -------------------------
if "theme" not in st.session_state:
    st.session_state["theme"] = "light"

def set_theme(t):
    st.session_state["theme"] = t

# Small CSS to make badges look nicer (respects theme)
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
    .heatcell {padding:6px;border-radius:6px;color:white;font-weight:700}
    </style>
    """,
    unsafe_allow_html=True
)

# -------------------------
# Sidebar: global navigation
# -------------------------
st.sidebar.title("🔧 Scanner Menu")
page = st.sidebar.selectbox("Choose page", ["Scanner", "Dashboard", "History", "Settings"])

# Settings stored
if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []  # list of dicts (df + meta)

if "last_report" not in st.session_state:
    st.session_state["last_report"] = None

# -------------------------
# Helper: safe fake names (no malware terms)
# -------------------------
SAFE_NAMES = [
    "process_alpha.exe", "module_beta.py", "service_update.exe",
    "utility_gamma.dll", "script_runner.ps1", "editor_app.exe",
    "engine_delta.bin", "task_handler.app", "monitor_sigma.out",
    "worker_theta.exe", "agent_phi.py", "daemon_kappa.bin"
]

# -------------------------
# Helper: generate beep WAV bytes (stdlib)
# -------------------------
def generate_beep(duration_seconds=0.18, freq=880.0, volume=0.5, samplerate=22050):
    n_samples = int(samplerate * duration_seconds)
    buf = BytesIO()
    with wave.open(buf, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)  # 2 bytes
        wf.setframerate(samplerate)
        for i in range(n_samples):
            t = float(i) / samplerate
            # simple decaying sinewave
            amplitude = volume * (1.0 - (t / duration_seconds))  # linear decay
            sample = int(amplitude * 32767 * math.sin(2 * math.pi * freq * t))
            wf.writeframes(struct.pack('<h', sample))
    return buf.getvalue()

BEEP_BYTES = generate_beep()

# -------------------------
# Helper: compute suspicious score (0-100)
# -------------------------
def compute_score(name, rules_triggered):
    base = random.randint(5, 25)
    triggers = len(rules_triggered)
    score = base + triggers * random.randint(20, 30)
    # small name-based nudge (demo safe keywords)
    nudges = {"alpha": 8, "gamma": 10, "sigma": 6, "delta": 4}
    for k, v in nudges.items():
        if k in name:
            score += v
    return min(100, score)

# -------------------------
# Helper: build heatmap-like HTML table
# -------------------------
def build_heatmap_html(rule_counts):
    # rule_counts: dict rule->count
    maxc = max(rule_counts.values()) if rule_counts else 1
    html_rows = []
    for rule, cnt in rule_counts.items():
        # intensity 0..255
        intensity = int(200 * (cnt / maxc))  # 0..200
        color = f"rgb({255-intensity},{80},{80+int(intensity/2)})"
        html_rows.append(
            f'<tr><td style="padding:6px;font-weight:700">{html.escape(rule)}</td>'
            f'<td><div class="heatcell" style="background:{color}">{cnt}</div></td></tr>'
        )
    return "<table>" + "".join(html_rows) + "</table>"

# -------------------------
# Core generator using sidebar rules (shared)
# -------------------------
def generate_scan_dataframe(rules):
    data = []
    rule_counts = {r: 0 for r in rules}
    for name in SAFE_NAMES:
        reasons = []
        triggered = []
        # Keyword detection
        if rules["keyword_detection"]:
            keywords = ["alpha", "gamma", "sigma", "theta"]
            for k in keywords:
                if k in name.lower():
                    reasons.append(f"keyword:{k}")
                    triggered.append("Keyword Detection")
                    rule_counts["Keyword Detection"] += 1
                    break
        # Extension check
        if rules["extension_check"]:
            bad_exts = [".dll", ".bin", ".ps1"]
            if any(name.lower().endswith(e) for e in bad_exts):
                reasons.append("suspicious_ext")
                triggered.append("Extension Check")
                rule_counts["Extension Check"] += 1
        # Pattern matching
        if rules["pattern_matching"]:
            if "_" in name and any(ch.isdigit() for ch in name) == False:
                reasons.append("underscore_pattern")
                triggered.append("Pattern Matching")
                rule_counts["Pattern Matching"] += 1
        # Random noise
        if rules["random_noise"]:
            if random.random() < 0.18:
                reasons.append("random_noise")
                triggered.append("Random Noise Rule")
                rule_counts["Random Noise Rule"] += 1
        # Suspicious score
        score = compute_score(name, triggered)
        suspicious = score >= rules["score_threshold"]
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
# Settings page (user can toggle these persistently)
# -------------------------
if page == "Settings":
    st.header("⚙️ Settings")
    col1, col2 = st.columns(2)
    with col1:
        theme_choice = st.radio("Theme", ["light", "dark"], index=0 if st.session_state["theme"]=="light" else 1)
        st.button("Apply Theme", on_click=set_theme, args=(theme_choice,))
        st.write("Theme toggles some visual styling elements (demo).")
        st.write("---")
        st.subheader("Scan rules (defaults for demo)")
        keyword_detection = st.checkbox("Keyword Detection", True, key="ui_keyword")
        extension_check = st.checkbox("Extension Check", True, key="ui_ext")
        pattern_matching = st.checkbox("Pattern Matching", True, key="ui_pattern")
        random_noise = st.checkbox("Random Noise Rule", False, key="ui_noise")
    with col2:
        st.subheader("Advanced")
        score_threshold = st.slider("Suspicious Score Threshold (0-100)", 0, 100, 50, key="ui_threshold")
        st.write("Lower threshold = more items flagged suspicious.")
        history_enabled = st.checkbox("Enable Scan History", True, key="ui_history")
        st.write("Scan history stored in session only.")
    st.markdown("---")
    st.write("JS/CSS theme changes are cosmetic in this demo.")
    st.caption("Settings are stored in the session only.")

# -------------------------
# Scanner page
# -------------------------
if page == "Scanner":
    st.header("🚀 Scanner")
    # sidebar-like controls inside page for convenience
    with st.container():
        col1, col2, col3 = st.columns([2,2,1])
        with col1:
            st.subheader("Scan Rules")
            keyword_detection = st.checkbox("Keyword Detection", True, key="r_keyword")
            extension_check = st.checkbox("Extension Check", True, key="r_ext")
            pattern_matching = st.checkbox("Pattern Matching", True, key="r_pattern")
            random_noise = st.checkbox("Random Noise Rule", False, key="r_noise")
        with col2:
            st.subheader("Behavior")
            score_threshold = st.slider("Suspend threshold", 0, 100, 50, key="r_threshold")
            show_console = st.checkbox("Show real-time console", True)
            radar_enabled = st.checkbox("Enable radar animation", True)
        with col3:
            st.subheader("History")
            history_enabled = st.checkbox("Enable scan history", True, key="r_history")
            st.write("Saved in this browser session.")

    rules = {
        "keyword_detection": keyword_detection,
        "extension_check": extension_check,
        "pattern_matching": pattern_matching,
        "random_noise": random_noise,
        "score_threshold": score_threshold
    }

    # Interactive controls for dashboard filters (applies to post-scan)
    st.markdown("---")
    run_btn = st.button("🔍 Run Scan Now")

    if run_btn:
        # fake initialization
        init = st.empty()
        init.info("Initializing scan engine...")
        time.sleep(0.9)
        init.empty()

        # animated radar placeholder area
        radar_area = st.empty()
        console_area = st.empty() if show_console else None
        progress = st.progress(0)

        # simulate radar sweep + console + progress
        steps = 10
        console_lines = []
        for i in range(steps):
            progress.progress(int((i+1)/steps*100))
            # radar ASCII sweep
            if radar_enabled:
                sweep_pos = i % 8
                radar_rows = []
                for r in range(7):
                    row_chars = []
                    for c in range(15):
                        # simple moving dot pattern
                        if (r + c) % 8 == sweep_pos:
                            row_chars.append("🔴")
                        else:
                            row_chars.append("·")
                    radar_rows.append("".join(row_chars))
                radar_area.markdown(f'<div class="radar">{"<br>".join(radar_rows)}</div>', unsafe_allow_html=True)
            # update console
            if console_area:
                # add a simulated message
                msgs = [
                    "[✓] Loading heuristic models...",
                    "[✓] Scanning process table...",
                    "[✓] Inspecting file patterns...",
                    "[⚠] Pattern mismatch detected in module...",
                    "[i] Evaluating risk score...",
                    "[✓] Gathering final results..."
                ]
                console_lines.append(random.choice(msgs))
                # keep last 6 lines
                console_html = "<div class='console'>" + "<br>".join(html.escape(l) for l in console_lines[-6:]) + "</div>"
                console_area.markdown(console_html, unsafe_allow_html=True)
            time.sleep(0.25)

        # generate results
        df, rule_counts = generate_scan_dataframe(rules)
        # assign Suspicious computed by threshold in dataframe (score already present)
        df["Suspicious"] = df["Score"] >= rules["score_threshold"]

        # store history
        if history_enabled:
            st.session_state["scan_history"].append({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "df": df.copy(),
                "rules": rules.copy()
            })
        # play beep
        st.audio(BEEP_BYTES, format="audio/wav")
        st.success("Scan complete!")

        # display a summary metrics row
        suspicious_count = int(df["Suspicious"].sum())
        total = len(df)
        colA, colB, colC = st.columns(3)
        colA.metric("Total items scanned", total)
        colB.metric("Suspicious items", suspicious_count)
        avg_score = int(df["Score"].mean())
        colC.metric("Average risk score", f"{avg_score} / 100")

        st.markdown("---")
        # Filters
        with st.expander("🔎 Filters & Interactive Dashboard"):
            fl1, fl2, fl3 = st.columns([2,2,1])
            with fl1:
                only_suspicious = st.checkbox("Show only suspicious", value=False, key="filter_susp")
                min_score = st.slider("Min score", 0, 100, 0, key="filter_min")
            with fl2:
                sel_type = st.selectbox("Type", ["All"] + sorted(df["Type"].unique().tolist()), key="filter_type")
                name_search = st.text_input("Name contains", value="", key="filter_name")
            with fl3:
                st.write("Quick actions")
                if st.button("Download last scan CSV"):
                    csv = df.to_csv(index=False).encode()
                    st.download_button("⬇️ Download CSV", csv, file_name="demo_scan.csv")
        # apply filters and show table with colored badges
        filtered = df.copy()
        if only_suspicious:
            filtered = filtered[filtered["Suspicious"]]
        filtered = filtered[filtered][filtered["Score"] >= min_score]
        if sel_type != "All":
            filtered = filtered[filtered["Type"] == sel_type]
        if name_search.strip():
            filtered = filtered[filtered["Name"].str.contains(name_search.strip(), case=False, na=False)]

        # create display with colored status chips via html
        def status_chip(s, score):
            if s:
                cls = "green" if score < 60 else ("yellow" if score < 80 else "red")
                label = "Suspicious" if s else "Clean"
                return f'<span class="chip {cls}">{label} ({score})</span>'
        # build HTML table rows
        rows = []
        rows.append("<table style='width:100%;border-collapse:collapse'>")
        rows.append("<tr><th style='text-align:left'>Type</th><th>Name</th><th>Score</th><th>Status</th><th>Reasons</th></tr>")
        for _, r in filtered.iterrows():
            st_status = "Yes" if r["Suspicious"] else "No"
            chip = status_chip(r["Suspicious"], r["Score"])
            rows.append("<tr>")
            rows.append(f"<td style='padding:6px'>{html.escape(str(r['Type']))}</td>")
            rows.append(f"<td style='padding:6px;font-weight:700'>{html.escape(r['Name'])}</td>")
            rows.append(f"<td style='padding:6px'>{int(r['Score'])}</td>")
            rows.append(f"<td style='padding:6px'>{chip}</td>")
            rows.append(f"<td style='padding:6px'>{html.escape(r['Reasons'])}</td>")
            rows.append("</tr>")
        rows.append("</table>")
        st.markdown("".join(rows), unsafe_allow_html=True)

        st.markdown("---")
        # Heatmap-like rules summary
        st.subheader("🔥 Rule Trigger Frequency")
        heat_html = build_heatmap_html(rule_counts)
        st.markdown(heat_html, unsafe_allow_html=True)

        # Build summary report (simple HTML)
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
        # offer download as HTML
        b = report_html.encode("utf-8")
        st.download_button("⬇️ Download HTML Report", b, file_name="scan_report.html", mime="text/html")
        # also offer excel
        excel_buffer = BytesIO()
        df.to_excel(excel_buffer, index=False)
        excel_buffer.seek(0)
        st.download_button("⬇️ Download Excel Report", excel_buffer, file_name="scan_report.xlsx")

# -------------------------
# Dashboard page
# -------------------------
if page == "Dashboard":
    st.header("📊 Dashboard")
    # summary from history
    hist = st.session_state.get("scan_history", [])
    if not hist:
        st.info("No scan history yet. Run a scan first.")
    else:
        # show last run summary
        last = hist[-1]
        lasth_df = last["df"]
        st.subheader("Last Scan Snapshot")
        st.write(f"Timestamp: {last['timestamp']}")
        # top suspicious
        top = lasth_df.sort_values("Score", ascending=False).head(5)
        st.table(top[["Name", "Type", "Score", "Reasons"]].reset_index(drop=True))
        # small aggregate charts using st.bar_chart
        counts = lasth_df["Type"].value_counts()
        chart_df = pd.DataFrame({"Type": counts.index, "Count": counts.values})
        st.markdown("**Type distribution**")
        st.bar_chart(chart_df.set_index("Type"))
        # suspicious distribution
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
                # simple table
                st.dataframe(df[["Type", "Name", "Score", "Suspicious", "Reasons"]], use_container_width=True)
                # download CSV for this scan
                csv = df.to_csv(index=False).encode()
                st.download_button(f"⬇️ Download scan #{len(hist)-i+1} CSV", csv, file_name=f"scan_{ts.replace(' ','_').replace(':','-')}.csv")

# -------------------------
# Footer
# -------------------------
st.markdown("---")
st.caption("Demo scanner • Cloud-safe • No real device scanning performed.")
