# SQL-Injection-Detector-Flask-App.py
"""
Simple Flask web app that demonstrates detecting basic SQL Injection attempts
and shows safe parameterized query usage.

Run:
  pip install flask
  python SQL-Injection-Detector-Flask-App.py

Open http://127.0.0.1:5000/ in your browser to test the simple form.

Notes:
- This is a demonstration/learning tool, not a production WAF.
- Detection uses heuristic/regex rules and scoring; it will never be perfect.
- Use parameterized queries and least privilege for real protections.
"""

from flask import Flask, request, render_template_string, jsonify
import re
import sqlite3
import datetime

app = Flask(__name__)

# Simple logging function
def log_event(message):
    with open('detector.log', 'a') as f:
        f.write(f"{datetime.datetime.utcnow().isoformat()} - {message}\n")

# Heuristic rules (regex) for common SQL injection indicators
SQLI_PATTERNS = [
    r"(--|#|\/\*)",                      # SQL comments (--, #, /*)
    r"\b(or|and)\b\s+\d+\s*=\s*\d+", # tautologies like OR 1=1
    r"\b(or|and)\b\s+\'[^\']*\'\s*=\s*\'[^\']*\'", # ' or 'a'='a'
    r"\bunion\b\s+select\b",           # UNION SELECT
    r"\bselect\b.*\bfrom\b",          # SELECT ... FROM
    r"\binformation_schema\b",           # information_schema
    r"\bbenchmark\b\s*\(|\bsleep\b\s*\(", # time-based
    r";\s*drop\b|;\s*insert\b|;\s*update\b|;\s*delete\b", # stacked queries
    r"\bexec\b\s+\w+",                 # exec cmd
    r"0x[0-9a-f]{4,}",                     # hex encoded payloads
    r"\bconcat\b\s*\(",                # concat(
]

# Compile regexes
COMPILED = [re.compile(p, flags=re.IGNORECASE) for p in SQLI_PATTERNS]

# Detector returns score and matched patterns
def detect_sql_injection(user_input: str):
    if not user_input:
        return {'score': 0, 'matches': []}

    score = 0
    matches = []
    # quick sanity: check for a quote followed by space and keyword (common attempt)
    if re.search(r"['\"]\s*(or|and)\b", user_input, flags=re.IGNORECASE):
        score += 30
        matches.append("quote-boolean-operator")

    # apply regex rules and add weights
    for regex in COMPILED:
        m = regex.search(user_input)
        if m:
            matches.append(regex.pattern)
            # basic weighting scheme: more serious-looking things = higher weight
            if 'union' in regex.pattern or 'select' in regex.pattern:
                score += 30
            elif 'sleep' in regex.pattern or 'benchmark' in regex.pattern:
                score += 40
            elif 'drop' in regex.pattern or 'insert' in regex.pattern:
                score += 50
            else:
                score += 15

    # short tautology patterns like "' or '1'='1'"
    if re.search(r"(\b1\b=\b1\b)|('\s*or\s*'1'='1')", user_input, flags=re.IGNORECASE):
        score += 40
        matches.append('tautology')

    # suspicious characters like semicolon combined with quotes
    if re.search(r"['\"];\s*", user_input):
        score += 20
        matches.append('quote-then-semicolon')

    # clamp score
    score = min(score, 100)
    return {'score': score, 'matches': matches}

# A tiny example of a safe DB operation using parameterized queries
def safe_query_example(name_value: str):
    # create an in-memory sqlite DB and simple table for demo purposes
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)')
    # parameterized insertion (safe)
    c.execute('INSERT INTO users (name) VALUES (?)', (name_value,))
    conn.commit()
    c.execute('SELECT id, name FROM users WHERE name = ?', (name_value,))
    rows = c.fetchall()
    conn.close()
    return rows

# Basic web page for demo
INDEX_HTML = '''
<!doctype html>
<title>SQLi Detector Demo</title>
<h2>SQL Injection Detector — Demo</h2>
<form method="post" action="/submit">
  <label>Enter a search name or input:</label><br>
  <input type="text" name="user_input" size="80" autofocus>
  <button type="submit">Submit</button>
</form>
<p>Try payloads like: <code>' OR '1'='1</code>, <code>admin'--</code>, <code>1; DROP TABLE users;</code></p>
'''

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/submit', methods=['POST'])
def submit():
    user_input = request.form.get('user_input', '')
    result = detect_sql_injection(user_input)

    # threshold: treat score >= 50 as suspicious/malicious
    if result['score'] >= 50:
        message = {
            'status': 'blocked',
            'reason': 'input detected as potential SQL injection',
            'score': result['score'],
            'matches': result['matches']
        }
        log_event(f"BLOCKED: {user_input} | {message}")
        return jsonify(message), 400

    # otherwise show a safe parameterized DB example
    rows = safe_query_example(user_input)
    message = {
        'status': 'accepted',
        'score': result['score'],
        'matches': result['matches'],
        'db_rows': rows
    }
    log_event(f"ACCEPTED: {user_input} | {message}")
    return jsonify(message)

# Provide a JSON API for automated testing
@app.route('/api/submit', methods=['POST'])
def api_submit():
    data = request.get_json(force=True) or {}
    user_input = data.get('user_input', '')
    result = detect_sql_injection(user_input)
    if result['score'] >= 50:
        log_event(f"API BLOCKED: {user_input} | {result}")
        return jsonify({'status':'blocked','score':result['score'],'matches':result['matches']}), 400
    log_event(f"API ACCEPTED: {user_input} | {result}")
    rows = safe_query_example(user_input)
    return jsonify({'status':'accepted','score':result['score'],'matches':result['matches'],'db_rows':rows})

if __name__ == '__main__':
    app.run(debug=True)
