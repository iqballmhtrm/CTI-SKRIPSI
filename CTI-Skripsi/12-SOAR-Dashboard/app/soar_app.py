import os
import sqlite3
import datetime
import ipaddress
import subprocess
import logging
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
app.secret_key = "soar-secret-key"

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = app.logger

DB_PATH = os.path.join(os.path.dirname(__file__), 'incidents.db')
FORENSICS_DIR = os.path.join(os.path.dirname(__file__), 'forensics')

os.makedirs(FORENSICS_DIR, exist_ok=True)

# Konfigurasi SSH ke Victim VM untuk active response
VICTIM_USER = 'korban'
VICTIM_HOST = '192.168.56.106'
SSH_KEY_PATH = os.path.expanduser(os.environ.get('SSH_KEY_PATH', '~/.ssh/id_ed25519'))

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                timestamp_detected TEXT,
                timestamp_responded TEXT,
                src_ip TEXT,
                attack_type TEXT,
                mitre_tactic TEXT,
                severity INTEGER,
                pipeline_source TEXT,
                status TEXT DEFAULT 'New',
                action_taken TEXT,
                mttd_seconds INTEGER DEFAULT 0,
                mttr_seconds INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                action_type TEXT,
                timestamp TEXT,
                result TEXT,
                ssh_output TEXT,
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            )
        ''')
        conn.commit()

init_db()

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def run_remote_command(command_list):
    if VICTIM_HOST == '100.x.x.x':
        return False, "Error: VICTIM_VPN_IP belum dikonfigurasi!"

    # Password automation removed for security. Relying on NOPASSWD in sudoers.

    ssh_base = ["/usr/bin/ssh", "-i", SSH_KEY_PATH, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", f"{VICTIM_USER}@{VICTIM_HOST}"]
    try:
        # We must use shell=False for subprocess, but pipes won't work if passed as a list of arguments over SSH directly.
        # Instead, we join the command_list into a single string so it's evaluated by the remote bash shell.
        remote_cmd_string = " ".join(command_list)
        result = subprocess.run(ssh_base + [remote_cmd_string], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/incidents')
def api_incidents():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY id DESC")
        rows = cursor.fetchall()
        incidents = [dict(row) for row in rows]
        
        total_new = sum(1 for i in incidents if i.get('status') == 'New')
        total_in_progress = sum(1 for i in incidents if i.get('status') == 'In Progress')
        total_resolved = sum(1 for i in incidents if i.get('status') == 'Resolved')
        
        mttds = [i.get('mttd_seconds') for i in incidents if i.get('mttd_seconds') is not None]
        avg_mttd = sum(mttds) / len(mttds) if mttds else 0
        
        mttrs = [i.get('mttr_seconds') for i in incidents if i.get('status') == 'Resolved' and i.get('mttr_seconds') is not None]
        avg_mttr = sum(mttrs) / len(mttrs) if mttrs else 0
        
        return jsonify({
            "incidents": incidents,
            "stats": {
                "avg_mttd": round(avg_mttd, 2),
                "avg_mttr": round(avg_mttr, 2),
                "total_new": total_new,
                "total_in_progress": total_in_progress,
                "total_resolved": total_resolved
            }
        })

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json or {}
    
    timestamp_alert = data.get('timestamp_alert') or data.get('@timestamp')
    if not timestamp_alert:
        timestamp_alert = datetime.datetime.utcnow().isoformat()
        
    timestamp_detected = datetime.datetime.utcnow().isoformat()
    
    mttd_seconds = 0
    try:
        # Normalisasi ke format Naive UTC dengan menghapus timezone dan microseconds
        clean_alert = timestamp_alert.replace('Z', '').split('+')[0].split('.')[0]
        ts_alert = datetime.datetime.fromisoformat(clean_alert)
        
        clean_det = timestamp_detected.replace('Z', '').split('+')[0].split('.')[0]
        ts_det = datetime.datetime.fromisoformat(clean_det)
        
        """
        DEFINISI MTTD PENELITIAN INI:
        MTTD (Mean Time to Detect) didefinisikan sebagai selisih waktu antara
        timestamp kejadian yang diterima sistem (timestamp_alert dari webhook)
        dan waktu insiden terdeteksi oleh SOAR (timestamp_detected = waktu
        record dibuat di database SOAR).
        CATATAN: Ini BUKAN waktu serangan nyata terjadi di jaringan,
        melainkan waktu sejak alert diterima pipeline hingga tercatat di SOAR.
        """
        raw_mttd = int((ts_det - ts_alert).total_seconds())
        # Proteksi clock drift dan timezone mismatch
        mttd_seconds = max(0, raw_mttd)
    except Exception as e:
        logger.warning(f"Error parsing datetime for MTTD: {e}")

    src_ip = data.get('src_ip', data.get('source', {}).get('ip', 'Unknown'))
    attack_type = data.get('attack_type', data.get('alert', {}).get('signature', 'Unknown Attack'))
    mitre_technique = data.get('mitre_technique', data.get('mitre_tactic', 'Unmapped'))
    mitre_status = data.get('mitre_status', 'Unmapped')

    logger.info(f"Incoming Webhook | Src: {src_ip} | Attack: {attack_type} | MITRE: {mitre_technique} | Status: {mitre_status} | Alert TS: {timestamp_alert}, Detected TS: {timestamp_detected}, MTTD: {mttd_seconds}s")

    severity = data.get('severity', data.get('alert', {}).get('severity', 0))
    pipeline_source = data.get('pipeline_source', 'logstash_http')

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        # Selalu set status = "New" secara eksplisit
        cursor.execute(
            """INSERT INTO incidents 
               (timestamp, timestamp_detected, src_ip, attack_type, mitre_technique, mitre_status, severity, pipeline_source, status, mttd_seconds) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'New', ?)""",
            (timestamp_alert, timestamp_detected, src_ip, attack_type, mitre_technique, mitre_status, severity, pipeline_source, mttd_seconds)
        )
        incident_id = cursor.lastrowid
        conn.commit()

    return jsonify({
        "message": "Incident logged successfully",
        "incident_id": incident_id,
        "mttd_seconds": mttd_seconds,
        "status": "New"
    }), 201

@app.route('/action/<action_type>', methods=['POST'])
def perform_action(action_type):
    data = request.json or {}
    incident_id = data.get('incident_id')
    src_ip = data.get('src_ip')
    
    if not incident_id:
        return jsonify({"error": "incident_id required"}), 400

    success = False
    ssh_output = ""
    new_status = "In Progress"

    if action_type == 'false-positive':
        success = True
        ssh_output = "Marked as False Positive manually"
        new_status = "False Positive"
        
    elif action_type == 'block-ip':
        if not is_valid_ip(src_ip):
            return jsonify({"error": "Invalid IP"}), 400
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"]
        success, ssh_output = run_remote_command(cmd)
        if success: new_status = "Resolved"
        
    elif action_type == 'lock-root':
        cmd = ["sudo", "passwd", "-l", "root"]
        success, ssh_output = run_remote_command(cmd)
        if success: new_status = "Resolved"
        
    elif action_type == 'forensics':
        ts_str = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        s1, o1 = run_remote_command(["sudo", "ps", "aux"])
        s2, o2 = run_remote_command(["sudo", "ss", "-tulnp"])
        success = s1 and s2
        ssh_output = f"Forensics captured at {ts_str}" if success else f"Error. PS: {o1}, SS: {o2}"
        if success:
            with open(os.path.join(FORENSICS_DIR, f"ps_{ts_str}.txt"), "w") as f: f.write(o1)
            with open(os.path.join(FORENSICS_DIR, f"ss_{ts_str}.txt"), "w") as f: f.write(o2)
        if not success:
            return jsonify({"error": ssh_output}), 500
    else:
        return jsonify({"error": "Unknown action"}), 400

    timestamp_responded = datetime.datetime.utcnow()
    mttr_seconds = 0
    action_id = None

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp_detected FROM incidents WHERE id=?", (incident_id,))
        row = cursor.fetchone()
        if row and row[0]:
            try:
                clean_det = row[0].replace('Z', '').split('+')[0].split('.')[0]
                ts_det = datetime.datetime.fromisoformat(clean_det)
                mttr_seconds = max(0, int((timestamp_responded - ts_det).total_seconds()))
            except Exception as e:
                logger.warning(f"Error parsing MTTR: {e}")
                
        cursor.execute("""
            UPDATE incidents 
            SET timestamp_responded=?, status=?, action_taken=?, mttr_seconds=? 
            WHERE id=?
        """, (timestamp_responded.isoformat(), new_status, action_type, mttr_seconds, incident_id))
        
        cursor.execute("""
            INSERT INTO actions (incident_id, action_type, timestamp, result, ssh_output)
            VALUES (?, ?, ?, ?, ?)
        """, (incident_id, action_type, timestamp_responded.isoformat(), "Success" if success else "Failed", ssh_output))
        action_id = cursor.lastrowid
        conn.commit()
        
    return jsonify({
        "success": success,
        "mttr_seconds": mttr_seconds,
        "new_status": new_status,
        "action_id": action_id,
        "message": ssh_output
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
