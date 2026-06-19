import os

# Define workspace tree structure
STRUCTURE = {
    "requirements.txt": """Flask==3.0.2
Werkzeug==3.0.1
pandas==2.2.1
scikit-learn==1.4.1.post1
numpy==1.26.4
fpdf2==2.7.8""",

    "app.py": """import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pandas as pd

from log_parser import LogParser
from threat_detector import ThreatDetector
from report_generator import ReportGenerator

app = Flask(__name__)
app.secret_key = 'star_shield_secure_secret_key_2026'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'txt', 'csv', 'log'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('models', exist_ok=True)

DB_PATH = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            status TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score REAL NOT NULL,
            recommendation TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id INTEGER,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (threat_id) REFERENCES threats (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_sample_logs():
    return \"\"\"2026-06-18 10:30:01 LOGIN_FAILED 192.168.1.5 admin FAILED
2026-06-18 10:30:05 LOGIN_FAILED 192.168.1.5 admin FAILED
2026-06-18 10:30:08 LOGIN_FAILED 192.168.1.5 admin FAILED
2026-06-18 10:30:10 LOGIN_FAILED 192.168.1.5 admin FAILED
2026-06-18 10:30:15 LOGIN_FAILED 192.168.1.5 admin FAILED
2026-06-18 10:32:00 PORT_SCAN 10.0.0.45 system FAILED
2026-06-18 10:35:12 LOGIN_SUCCESS 192.168.1.12 user1 SUCCESS
2026-06-18 10:40:22 UNAUTHORIZED_ACCESS 172.16.5.99 guest FAILED
2026-06-18 10:45:00 DATA_EXFILTRATION 192.168.1.200 admin SUCCESS
2026-06-18 10:50:11 LOGIN_SUCCESS 192.168.1.15 user2 SUCCESS\"\"\"

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', (username, email, hashed_pw))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or Email already exists.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Welcome to STAR Shield AI Command Center.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Access Denied.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out securely.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    total_logs = conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    total_threats = conn.execute('SELECT COUNT(*) FROM threats WHERE severity != "Safe"').fetchone()[0]
    high_severity = conn.execute('SELECT COUNT(*) FROM threats WHERE severity IN ("High", "Critical")').fetchone()[0]
    safe_logs = conn.execute('SELECT COUNT(*) FROM threats WHERE severity = "Safe"').fetchone()[0]
    alerts = conn.execute('''
        SELECT a.id, a.created_at, a.status, t.threat_type, t.severity, t.risk_score
        FROM alerts a JOIN threats t ON a.threat_id = t.id
        ORDER BY a.id DESC LIMIT 5
    ''').fetchall()
    conn.close()
    return render_template('dashboard.html', total_logs=total_logs, total_threats=total_threats, high_severity=high_severity, safe_logs=safe_logs, alerts=alerts)

@app.route('/api/chart-data')
def chart_data():
    if 'user_id' not in session:
        return {"error": "Unauthorized"}, 401
    conn = get_db_connection()
    threats_df = pd.read_sql_query('SELECT threat_type FROM threats WHERE threat_type != "None"', conn)
    threat_counts = threats_df['threat_type'].value_counts().to_dict() if not threats_df.empty else {}
    severity_df = pd.read_sql_query('SELECT severity FROM threats', conn)
    severity_counts = severity_df['severity'].value_counts().to_dict() if not severity_df.empty else {}
    timeline_df = pd.read_sql_query('SELECT SUBSTR(created_at, 1, 10) as date, COUNT(*) as count FROM alerts GROUP BY date ORDER BY date DESC LIMIT 7', conn)
    timeline_data = dict(zip(timeline_df['date'], timeline_df['count'])) if not timeline_df.empty else {}
    conn.close()
    return {"threat_distribution": threat_counts, "severity_distribution": severity_counts, "timeline_data": timeline_data}

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'log_file' not in request.files:
            flash('No file parameter standard supplied.', 'danger')
            return redirect(url_for('upload'))
        file = request.files['log_file']
        if file.filename == '':
            log_content = generate_sample_logs()
            filename = "generated_fallback_security.log"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(filepath, 'w') as f:
                f.write(log_content)
        else:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
            else:
                flash('Unsupported format. Allowed extensions: .txt, .csv, .log', 'danger')
                return redirect(url_for('upload'))
        parsed_logs = LogParser.parse(filepath)
        if not parsed_logs:
            flash('No structurally readable raw logs identified.', 'warning')
            return redirect(url_for('upload'))
        conn = get_db_connection()
        for log in parsed_logs:
            conn.execute('''
                INSERT INTO logs (timestamp, source_ip, event_type, username, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (log['timestamp'], log['source_ip'], log['event_type'], log['username'], log['status']))
        conn.commit()
        detector = ThreatDetector(parsed_logs)
        evaluated_threats = detector.analyze()
        for record in evaluated_threats:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO threats (threat_type, severity, risk_score, recommendation)
                VALUES (?, ?, ?, ?)
            ''', (record['threat_type'], record['severity'], record['risk_score'], record['recommendation']))
            threat_id = cursor.lastrowid
            conn.execute('''
                INSERT INTO alerts (threat_id, created_at, status)
                VALUES (?, ?, ?)
            ''', (threat_id, record['timestamp'], 'Open'))
        conn.commit()
        conn.close()
        flash(f'Log extraction finalized. Registered {len(parsed_logs)} events.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('upload.html')

@app.route('/alerts', methods=['GET', 'POST'])
def alerts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    if request.method == 'POST':
        alert_id = request.form.get('alert_id')
        new_status = request.form.get('status')
        conn.execute('UPDATE alerts SET status = ? WHERE id = ?', (new_status, alert_id))
        conn.commit()
        flash(f'Alert Engine ID #{alert_id} reassigned to status: {new_status}', 'success')
    alerts_data = conn.execute('''
        SELECT a.id, a.created_at, a.status, t.threat_type, t.severity, t.risk_score, t.recommendation
        FROM alerts a JOIN threats t ON a.threat_id = t.id
        ORDER BY a.id DESC
    ''').fetchall()
    conn.close()
    return render_template('alerts.html', alerts=alerts_data)

@app.route('/reports', methods=['GET', 'POST'])
def reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        report_format = request.form.get('format')
        conn = get_db_connection()
        records = conn.execute('''
            SELECT a.id, a.created_at, a.status, t.threat_type, t.severity, t.risk_score
            FROM alerts a JOIN threats t ON a.threat_id = t.id
            ORDER BY a.id DESC
        ''').fetchall()
        conn.close()
        data_list = [{"Alert ID": r['id'], "Timestamp": r['created_at'], "Threat Type": r['threat_type'], "Severity": r['severity'], "Risk Score": r['risk_score'], "Status": r['status']} for r in records]
        df = pd.DataFrame(data_list)
        if report_format == 'csv':
            csv_path = os.path.join(app.config['UPLOAD_FOLDER'], 'Security_Report.csv')
            df.to_csv(csv_path, index=False)
            return send_file(csv_path, as_attachment=True, download_name='STAR_Shield_Incident_Report.csv')
        elif report_format == 'pdf':
            pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], 'Security_Report.pdf')
            ReportGenerator.build_pdf(data_list, pdf_path)
            return send_file(pdf_path, as_attachment=True, download_name='STAR_Shield_Incident_Report.pdf')
    return render_template('reports.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)""",

    "ml_model.py": """import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

class MLAnomalyDetector:
    def __init__(self):
        self.model_path = os.path.join('models', 'isolation_forest.pkl')
        self.clf = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self._bootstrap_model_if_absent()

    def _bootstrap_model_if_absent(self):
        if not os.path.exists(self.model_path):
            X_train = np.array([[1,0,1], [1,0,2], [2,0,1], [1,0,1], [1,1,5], [3,1,12], [4,1,20], [1,0,2]])
            self.clf.fit(X_train)
            joblib.dump(self.clf, self.model_path)
        else:
            self.clf = joblib.load(self.model_path)

    def predict_anomaly(self, event_type_id, failed_flag, continuous_frequency):
        features = np.array([[event_type_id, failed_flag, continuous_frequency]])
        prediction = self.clf.predict(features)
        score = self.clf.score_samples(features)
        return int(prediction[0]), float(abs(score[0]))""",

    "log_parser.py": """import re
import csv
from datetime import datetime

class LogParser:
    @staticmethod
    def parse(filepath):
        parsed_records = []
        if filepath.endswith('.csv'):
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    parsed_records.append({
                        'timestamp': row.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                        'event_type': row.get('event_type', 'UNKNOWN'),
                        'source_ip': row.get('source_ip', '0.0.0.0'),
                        'username': row.get('username', 'system'),
                        'status': row.get('status', 'SUCCESS')
                    })
            return parsed_records

        log_pattern = re.compile(
            r'(?P<timestamp>\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2})\\s(?P<event_type>[A-Z_]+)\\s(?P<source_ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\s(?P<username>\\w+)\\s(?P<status>[A-Z]+)'
        )
        with open(filepath, 'r') as f:
            for line in f:
                match = log_pattern.search(line)
                if match:
                    parsed_records.append(match.groupdict())
        return parsed_records""",

    "threat_detector.py": """from collections import Counter
from ml_model import MLAnomalyDetector

class ThreatDetector:
    def __init__(self, parsed_logs):
        self.logs = parsed_logs
        self.detector = MLAnomalyDetector()
        
    def analyze(self):
        analyzed_threat_results = []
        ip_failed_counts = Counter([log['source_ip'] for log in self.logs if log['status'] == 'FAILED'])
        event_types_map = {'LOGIN_SUCCESS': 1, 'LOGIN_FAILED': 1, 'PORT_SCAN': 2, 'UNAUTHORIZED_ACCESS': 3, 'DATA_EXFILTRATION': 4}

        for log in self.logs:
            ip = log['source_ip']
            event_type = log['event_type']
            status = log['status']
            threat_type = "None"
            severity = "Safe"
            risk_score = 10.0
            recommendation = "No intervention necessary. Maintain baseline auditing protocols."
            
            event_id = event_types_map.get(event_type, 5)
            failed_binary = 1 if status == 'FAILED' else 0
            freq = ip_failed_counts.get(ip, 1)
            
            if event_type == 'LOGIN_FAILED' and freq >= 5:
                threat_type = "Brute Force Attack"
                severity = "High"
                risk_score = 85.0
                recommendation = "Block source IP address immediately via firewall perimeter rules. Force reset credentials and enable MFA."
            elif event_type == 'UNAUTHORIZED_ACCESS':
                threat_type = "Unauthorized Access Attempt"
                severity = "High"
                risk_score = 80.0
                recommendation = "Audit account token structures. Validate identity against directory parameters."
            elif event_type == 'DATA_EXFILTRATION':
                threat_type = "Data Exfiltration Signature"
                severity = "Critical"
                risk_score = 98.0
                recommendation = "Isolate target system asset endpoints immediately. Terminate connections and notify response admins."
            elif event_type == 'PORT_SCAN':
                threat_type = "Suspicious Reconnaissance Scan"
                severity = "Medium"
                risk_score = 55.0
                recommendation = "Blacklist external IP coordinates across perimeter boundary firewalls."
                
            if threat_type == "None":
                ml_pred, ml_score = self.detector.predict_anomaly(event_id, failed_binary, freq)
                if ml_pred == -1:
                    threat_type = f"Anomalous Behavior ({event_type})"
                    risk_score = round(ml_score * 100, 1)
                    severity = "High" if risk_score > 75 else "Low"
                    recommendation = "Review system metrics immediately. Execute context log tracing protocols."
            
            analyzed_threat_results.append({
                'timestamp': log['timestamp'], 'threat_type': threat_type, 'severity': severity, 'risk_score': risk_score, 'recommendation': recommendation
            })
        return analyzed_threat_results""",

    "report_generator.py": """from fpdf import FPDF

class ReportGenerator:
    @staticmethod
    def build_pdf(data_list, output_path):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 15, "STAR SHIELD AI INCIDENT REPORT", ln=True, align="C")
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 10, "Generated via STAR Shield SIEM Compliance Processing", ln=True, align="C")
        pdf.ln(10)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(15, 8, "ID", border=1, align="C")
        pdf.cell(45, 8, "Timestamp", border=1, align="C")
        pdf.cell(50, 8, "Threat Type", border=1, align="C")
        pdf.cell(25, 8, "Severity", border=1, align="C")
        pdf.cell(25, 8, "Risk Score", border=1, align="C")
        pdf.cell(30, 8, "Status", border=1, align="C")
        pdf.ln()
        pdf.set_font("Helvetica", "", 9)
        for row in data_list:
            pdf.cell(15, 8, str(row["Alert ID"]), border=1, align="C")
            pdf.cell(45, 8, str(row["Timestamp"]), border=1, align="C")
            pdf.cell(50, 8, str(row["Threat Type"]), border=1)
            pdf.cell(25, 8, str(row["Severity"]), border=1, align="C")
            pdf.cell(25, 8, str(row["Risk Score"]), border=1, align="C")
            pdf.cell(30, 8, str(row["Status"]), border=1, align="C")
            pdf.ln()
        pdf.output(output_path)""",

    "static/css/style.css": """:root {
    --bg-main: #0B1220; --sidebar-bg: #111827; --card-bg: #1F2937;
    --accent-blue: #3B82F6; --success-green: #10B981; --warning-yellow: #F59E0B;
    --danger-red: #EF4444; --text-main: #F3F4F6; --text-muted: #9CA3AF;
}
body { background-color: var(--bg-main); color: var(--text-main); font-family: sans-serif; }
.auth-card { background-color: var(--card-bg); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 8px; }
.sidebar { background-color: var(--sidebar-bg); min-height: 100vh; border-right: 1px solid rgba(255,255,255,0.05); }
.sidebar .nav-link { color: var(--text-muted); padding: 12px 20px; border-radius: 4px; display: block; text-decoration: none; }
.sidebar .nav-link.active, .sidebar .nav-link:hover { background-color: rgba(59, 130, 246, 0.15); color: var(--accent-blue); }
.soc-card { background-color: var(--card-bg); border-radius: 6px; border: none; }
.border-left-blue { border-left: 4px solid var(--accent-blue); }
.border-left-red { border-left: 4px solid var(--danger-red); }
.border-left-yellow { border-left: 4px solid var(--warning-yellow); }
.border-left-green { border-left: 4px solid var(--success-green); }
.badge-critical { background-color: var(--danger-red); }
.badge-high { background-color: #C2410C; }
.badge-medium { background-color: var(--warning-yellow); color: black; }
.badge-low { background-color: var(--accent-blue); }
.badge-safe { background-color: var(--success-green); }
.table-dark-custom { background-color: var(--card-bg); color: var(--text-main); }""",

    "static/js/dashboard.js": """document.addEventListener("DOMContentLoaded", function () {
    fetch('/api/chart-data')
        .then(response => response.json())
        .then(data => {
            if (data.error) return;
            const pieCtx = document.getElementById('threatPieChart').getContext('2d');
            const pieLabels = Object.keys(data.threat_distribution);
            const pieValues = Object.values(data.threat_distribution);
            new Chart(pieCtx, {
                type: 'pie',
                data: {
                    labels: pieLabels.length ? pieLabels : ["No Incursions Found"],
                    datasets: [{ data: pieValues.length ? pieValues : [1], backgroundColor: ['#EF4444', '#F59E0B', '#3B82F6', '#10B981'] }]
                },
                options: { plugins: { legend: { labels: { color: '#9CA3AF' } } } }
            });

            const barCtx = document.getElementById('severityBarChart').getContext('2d');
            const sevLabels = ['Safe', 'Low', 'Medium', 'High', 'Critical'];
            const sevValues = sevLabels.map(label => data.severity_distribution[label] || 0);
            new Chart(barCtx, {
                type: 'bar',
                data: {
                    labels: sevLabels,
                    datasets: [{ data: sevValues, backgroundColor: ['#10B981', '#3B82F6', '#F59E0B', '#C2410C', '#EF4444'] }]
                },
                options: { scales: { x: { ticks: { color: '#9CA3AF' } }, y: { ticks: { color: '#9CA3AF' } } }, plugins: { legend: { display: false } } }
            });

            const lineCtx = document.getElementById('timelineLineChart').getContext('2d');
            const lineLabels = Object.keys(data.timeline_data).reverse();
            const lineValues = Object.values(data.timeline_data).reverse();
            new Chart(lineCtx, {
                type: 'line',
                data: {
                    labels: lineLabels.length ? lineLabels : ["Baseline"],
                    datasets: [{ label: 'Incursions', data: lineValues.length ? lineValues : [0], borderColor: '#3B82F6', fill: true, tension: 0.3 }]
                },
                options: { scales: { x: { ticks: { color: '#9CA3AF' } }, y: { ticks: { color: '#9CA3AF' } } }, plugins: { legend: { display: false } } }
            });
        });
});""",

    "templates/login.html": """<!DOCTYPE html>
<html lang="en">
<head>
    <title>STAR Shield AI - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body class="d-flex align-items-center justify-content-center" style="min-height: 100vh;">
    <div class="container col-md-4">
        <div class="auth-card p-4">
            <h3 class="text-center text-primary mb-3">STAR SHIELD AI</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}{% for c, m in messages %}<div class="alert alert-{{ c }} py-2 small">{{ m }}</div>{% endfor %}{% endif %}
            {% endwith %}
            <form method="POST">
                <div class="mb-3"><label class="form-label small text-muted">Operator Handle</label><input type="text" name="username" class="form-control bg-dark text-white border-secondary" required></div>
                <div class="mb-4"><label class="form-label small text-muted">Passphrase</label><input type="password" name="password" class="form-control bg-dark text-white border-secondary" required></div>
                <button type="submit" class="btn btn-primary w-100 fw-semibold mb-3">Authenticate Identity</button>
            </form>
            <div class="text-center"><a href="{{ url_for('register') }}" class="text-decoration-none small text-muted">Request New Handle Account</a></div>
        </div>
    </div>
</body>
</html>""",

    "templates/register.html": """<!DOCTYPE html>
<html lang="en">
<head>
    <title>STAR Shield AI - Register</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body class="d-flex align-items-center justify-content-center" style="min-height: 100vh;">
    <div class="container col-md-4">
        <div class="auth-card p-4">
            <h3 class="text-center text-primary mb-3">PROVISION ACCESS</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}{% for c, m in messages %}<div class="alert alert-{{ c }} py-2 small">{{ m }}</div>{% endfor %}{% endif %}
            {% endwith %}
            <form method="POST">
                <div class="mb-3"><label class="form-label small text-muted">Username</label><input type="text" name="username" class="form-control bg-dark text-white border-secondary" required></div>
                <div class="mb-3"><label class="form-label small text-muted">Corporate Email</label><input type="email" name="email" class="form-control bg-dark text-white border-secondary" required></div>
                <div class="mb-4"><label class="form-label small text-muted">Passphrase</label><input type="password" name="password" class="form-control bg-dark text-white border-secondary" required></div>
                <button type="submit" class="btn btn-success w-100 fw-semibold mb-3">Provision Profile</button>
            </form>
            <div class="text-center"><a href="{{ url_for('login') }}" class="text-decoration-none small text-muted">Return to Login Gateway</a></div>
        </div>
    </div>
</body>
</html>""",

    "templates/dashboard.html": """<!DOCTYPE html>
<html lang="en">
<head>
    <title>STAR Shield AI - Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container-fluid"><div class="row">
        <div class="col-md-2 sidebar p-0">
            <div class="p-4 text-center border-bottom border-secondary">
                <h5 class="text-primary fw-bold mb-0">STAR SHIELD AI</h5>
            </div>
            <nav class="nav flex-column mt-3">
                <a class="nav-link active" href="{{ url_for('dashboard') }}">Dashboard</a>
                <a class="nav-link" href="{{ url_for('upload') }}">Ingest Logs</a>
                <a class="nav-link" href="{{ url_for('alerts') }}">Alert Matrix</a>
                <a class="nav-link" href="{{ url_for('reports') }}">Compliance Reports</a>
                <a class="nav-link text-danger mt-5" href="{{ url_for('logout') }}">Logout</a>
            </nav>
        </div>
        <div class="col-md-10 p-4" style="height: 100vh; overflow-y: auto;">
            <h4 class="mb-4">SIEM Telemetry Core Center</h4>
            <div class="row g-3 mb-4">
                <div class="col-md-3"><div class="card soc-card border-left-blue p-3"><div class="text-muted small">Total Processed Signals</div><h3>{{ total_logs }}</h3></div></div>
                <div class="col-md-3"><div class="card soc-card border-left-yellow p-3"><div class="text-muted small">Identified Threats</div><h3 class="text-warning">{{ total_threats }}</h3></div></div>
                <div class="col-md-3"><div class="card soc-card border-left-red p-3"><div class="text-muted small">High/Critical Incursions</div><h3 class="text-danger">{{ high_severity }}</h3></div></div>
                <div class="col-md-3"><div class="card soc-card border-left-green p-3"><div class="text-muted small">Safe Verified Baselines</div><h3 class="text-success">{{ safe_logs }}</h3></div></div>
            </div>
            <div class="row g-3 mb-4">
                <div class="col-md-4"><div class="card soc-card p-3"><h6>Threat Types Matrix</h6><canvas id="threatPieChart" height="200"></canvas></div></div>
                <div class="col-md-4"><div class="card soc-card p-3"><h6>Severity Distribution Matrix</h6><canvas id="severityBarChart" height="200"></canvas></div></div>
                <div class="col-md-4"><div class="card soc-card p-3"><h6>Timeline Density Flow</h6><canvas id="timelineLineChart" height="200"></canvas></div></div>
            </div>
            <div class="card soc-card p-4">
                <h5 class="mb-3 text-muted">Recent Anomalous Streams</h5>
                <table class="table table-dark table-striped mb-0 table-dark-custom">
                    <thead><tr><th>ID</th><th>Timestamp</th><th>Threat Pattern</th><th>Risk Score</th><th>Severity</th><th>Status</th></tr></thead>
                    <tbody>
                        {% for alert in alerts %}
                        <tr><td>#{{ alert.id }}</td><td>{{ alert.created_at }}</td><td class="text-info">{{ alert.threat_type }}</td><td>{{ alert.risk_score }}%</td><td><span class="badge badge-{{ alert.severity|lower }}">{{ alert.severity }}</span></td><td>{{ alert.status }}</td></tr>
                        {% else %}<tr><td colspan="6" class="text-center text-muted">No active security log anomalies found in the registry.</td></tr>{% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div></div>
    <script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>
</body>
</html>""",

    "templates/upload.html": """<!DOCTYPE html>
<html lang="en">
<head>
    <title>STAR Shield AI - Ingest</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="container-fluid"><div class="row">
        <div class="col-md-2 sidebar p-0">
            <div class="p-4 text-center border-bottom border-secondary"><h5 class="text-primary fw-bold mb-0">STAR SHIELD AI</h5></div>
            <nav class="nav flex-column mt-3">
                <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
                <a class="nav-link active" href="{{ url_for('upload') }}">Ingest Logs</a>
                <a class="nav-link" href="{{ url_for('alerts') }}">Alert Matrix</a>
                <a class="nav-link" href="{{ url_for('reports') }}">Compliance Reports</a>
            </nav>
        </div>
        <div class="col-md-10 p-4">
            <h4>Log Telemetry Aggregator</h4>
            <div class="card soc-card p-4 col-md-6 mt-3">
                <form method="POST" enctype="multipart/form-data">
                    <div class="mb-4">
                        <label class="form-label text-muted small fw-bold">Select Dataset Target Source Path</label>
                        <input type="file" name="log_file" class="form-control bg-dark text-white border-secondary">
                        <div class="form-text text-info small mt-2">Notice: Leaving input parameters empty forces configuration parsing metrics against fallback security test templates.</div>
                    </div>
                    <button type="submit" class="btn btn-primary px-4">Execute Ingestion Pipeline</button>
                </form>
            </div>
        </div>
    </div></div>
</body>
</html>""",

    "templates/alerts.html": """<!DOCTYPE html>
<html lang="en">
<head>
    <title>STAR Shield AI - Alerts</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="container-fluid"><div class="row">
        <div class="col-md-2 sidebar p-0">
            <div class="p-4 text-center border-bottom border-secondary"><h5 class="text-primary fw-bold mb-0">STAR SHIELD AI</h5></div>
            <nav class="nav flex-column mt-3">
                <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
                <a class="nav-link" href="{{ url_for('upload') }}">Ingest Logs</a>
                <a class="nav-link active" href="{{ url_for('alerts') }}">Alert Matrix</a>
                <a class="nav-link" href="{{ url_for('reports') }}">Compliance Reports</a>
            </nav>
        </div>
        <div class="col-md-10 p-4" style="height: 100vh; overflow-y: auto;">
            <h4>Central Security Incident Registry</h4>
            <div class="card soc-card p-4 mt-3">
                <table class="table table-dark table-hover table-dark-custom align-middle">
                    <thead><tr><th>ID</th><th>Timestamp</th><th>Threat Pattern</th><th>Severity</th><th>Score</th><th>Action Mitigation Countermeasures</th><th>Status State</th></tr></thead>
                    <tbody>
                        {% for alert in alerts %}
                        <tr>
                            <td>#{{ alert.id }}</td><td>{{ alert.created_at }}</td><td class="text-info fw-bold">{{ alert.threat_type }}</td>
                            <td><span class="badge badge-{{ alert.severity|lower }}">{{ alert.severity }}</span></td><td>{{ alert.risk_score }}%</td>
                            <td class="small text-muted" style="max-width: 250px;">{{ alert.recommendation }}</td>
                            <td>
                                <form method="POST" class="d-flex gap-1">
                                    <input type="hidden" name="alert_id" value="{{ alert.id }}">
                                    <select name="status" class="form-select form-select-sm bg-dark text-white border-secondary" onchange="this.form.submit()">
                                        <option value="Open" {% if alert.status == 'Open' %}selected{% endif %}>Open</option>
                                        <option value="Investigating" {% if alert.status == 'Investigating' %}selected{% endif %}>Investigating</option>
                                        <option value="Resolved" {% if alert.status == 'Resolved' %}selected{% endif %}>Resolved</option>
                                    </select>
                                </form>
                            </td>
                        </tr>
                        {% else %}<tr><td colspan="7" class="text-center text-muted">No operational logged events registry lines recorded.</td></tr>{% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div></div>
</body>
</html>""",

    "templates/reports.html": """<!DOCTYPE html>
<html lang="en">
<head>
    <title>STAR Shield AI - Reports</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="container-fluid"><div class="row">
        <div class="col-md-2 sidebar p-0">
            <div class="p-4 text-center border-bottom border-secondary"><h5 class="text-primary fw-bold mb-0">STAR SHIELD AI</h5></div>
            <nav class="nav flex-column mt-3">
                <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
                <a class="nav-link" href="{{ url_for('upload') }}">Ingest Logs</a>
                <a class="nav-link" href="{{ url_for('alerts') }}">Alert Matrix</a>
                <a class="nav-link active" href="{{ url_for('reports') }}">Compliance Reports</a>
            </nav>
        </div>
        <div class="col-md-10 p-4">
            <h4>Compliance Engine Export Module</h4>
            <div class="card soc-card p-4 col-md-6 mt-3">
                <form method="POST">
                    <div class="mb-4">
                        <label class="form-label text-muted small fw-bold">Target Structural Architecture Matrix Format</label>
                        <select name="format" class="form-select bg-dark text-white border-secondary">
                            <option value="csv">Structured Spreadsheet Data Object Sheet (.csv)</option>
                            <option value="pdf">Document Regulatory Executive Summary Compliance Summary (.pdf)</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary px-4">Generate and Download File</button>
                </form>
            </div>
        </div>
    </div></div>
</body>
</html>"""
}

def construct_system():
    print("[*] Launching automatic extraction workspace setup architecture...")
    for route_path, code_body in STRUCTURE.items():
        base_dir = os.path.dirname(route_path)
        if base_dir:
            os.makedirs(base_dir, exist_ok=True)
        with open(route_path, "w", encoding="utf-8") as file_payload:
            file_payload.write(code_body.strip())
        print(f"[+] Verified and written structural node layout target file: {route_path}")
    
    # Guarantee runtime media uploads path folder configurations exist
    os.makedirs(os.path.join("static", "uploads"), exist_ok=True)
    os.makedirs("models", exist_ok=True)
    print("[*] Target system setup initialization successful.")

if __name__ == "__main__":
    construct_system()