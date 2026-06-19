import os
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
    return """2026-06-18 10:30:01 LOGIN_FAILED 192.168.1.5 admin FAILED
2026-06-18 10:30:05 LOGIN_FAILED 192.168.1.5 admin FAILED
2026-06-18 10:30:08 LOGIN_FAILED 192.168.1.5 admin FAILED
2026-06-18 10:30:10 LOGIN_FAILED 192.168.1.5 admin FAILED
2026-06-18 10:30:15 LOGIN_FAILED 192.168.1.5 admin FAILED
2026-06-18 10:32:00 PORT_SCAN 10.0.0.45 system FAILED
2026-06-18 10:35:12 LOGIN_SUCCESS 192.168.1.12 user1 SUCCESS
2026-06-18 10:40:22 UNAUTHORIZED_ACCESS 172.16.5.99 guest FAILED
2026-06-18 10:45:00 DATA_EXFILTRATION 192.168.1.200 admin SUCCESS
2026-06-18 10:50:11 LOGIN_SUCCESS 192.168.1.15 user2 SUCCESS"""

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
        
    # 1. Get metric counts from SQLite database
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

    # 2. Read live text file rows from access.log
    try:
        with open('access.log', 'r') as file:
            log_lines = file.readlines()
    except FileNotFoundError:
        log_lines = ["access.log file not found. Please create one in the root folder."]

    # 3. Return a single response handling all frontend variables
    return render_template(
        'dashboard.html', 
        total_logs=total_logs, 
        total_threats=total_threats, 
        high_severity=high_severity, 
        safe_logs=safe_logs, 
        alerts=alerts,
        logs=log_lines
    )

@app.route('/api/chart-data')
def chart_data():
    if 'user_id' not in session:
        return {"error": "Unauthorized"}, 401
    conn = get_db_connection()
    threat_counts = {}
    severity_counts = {}
    timeline_data = {}
    
    try:
        threats_df = pd.read_sql_query('SELECT threat_type FROM threats WHERE threat_type != "None"', conn)
        if not threats_df.empty:
            threat_counts = threats_df['threat_type'].value_counts().to_dict()
            
        severity_df = pd.read_sql_query('SELECT severity FROM threats', conn)
        if not severity_df.empty:
            severity_counts = severity_df['severity'].value_counts().to_dict()
            
        timeline_df = pd.read_sql_query('SELECT SUBSTR(created_at, 1, 10) as date, COUNT(*) as count FROM alerts GROUP BY date ORDER BY date DESC LIMIT 7', conn)
        if not timeline_df.empty:
            timeline_data = dict(zip(timeline_df['date'], timeline_df['count']))
    except Exception as e:
        print(f"Chart data error: {e}")
    finally:
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
            df.to_csv(pdf_path, index=False) # Fallback baseline matrix conversion
            return send_file(pdf_path, as_attachment=True, download_name='STAR_Shield_Incident_Report.pdf')
    return render_template('reports.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
