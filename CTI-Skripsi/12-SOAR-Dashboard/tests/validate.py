import sqlite3
import urllib.request
import json
import time
from datetime import datetime, timedelta
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def post_json(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, context=ctx) as response:
        return json.loads(response.read().decode())

DB_PATH = "/home/iqbal/soar-dashboard/app/incidents.db"

print("\n========================================")
print("1. VALIDASI SCHEMA")
print("========================================")
try:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name IN ('incidents', 'actions', 'schema_version');")
        rows = cursor.fetchall()
        for row in rows:
            print(f"--- Schema {row[0]} ---")
            print(row[1])
        
        cursor.execute("SELECT * FROM schema_version;")
        print("--- Schema Version ---")
        print(cursor.fetchall())
except Exception as e:
    print(f"Error reading DB: {e}")

print("\n========================================")
print("2. VALIDASI MTTD NORMAL")
print("========================================")
try:
    past_time = (datetime.utcnow() - timedelta(minutes=10)).isoformat() + "Z"
    resp = post_json("http://127.0.0.1:5000/webhook", {
        "timestamp_alert": past_time,
        "src_ip": "1.1.1.1",
        "attack_type": "Test Normal"
    })
    print(f"Payload (past time): {past_time}")
    print("Response JSON:", resp)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, status, mttd_seconds FROM incidents ORDER BY id DESC LIMIT 1;")
        row = cursor.fetchone()
        print("Database Record (id, status, mttd_seconds):", row)
        if row and row[2] > 0:
            print(">> PASS: MTTD > 0")
        else:
            print(">> FAIL: MTTD <= 0")
except Exception as e:
    print(f"Error: {e}")

print("\n========================================")
print("3. VALIDASI CLOCK DRIFT PROTECTION")
print("========================================")
try:
    future_time = (datetime.utcnow() + timedelta(minutes=10)).isoformat() + "Z"
    resp = post_json("http://127.0.0.1:5000/webhook", {
        "timestamp_alert": future_time,
        "src_ip": "2.2.2.2",
        "attack_type": "Test Future"
    })
    print(f"Payload (future time): {future_time}")
    print("Response JSON:", resp)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, status, mttd_seconds FROM incidents ORDER BY id DESC LIMIT 1;")
        row = cursor.fetchone()
        print("Database Record (id, status, mttd_seconds):", row)
        if row and row[2] == 0:
            print(">> PASS: MTTD di-set ke 0 (proteksi drift)")
        else:
            print(">> FAIL: MTTD bernilai negatif atau salah")
except Exception as e:
    print(f"Error: {e}")

print("\n========================================")
print("4. VALIDASI MTTR")
print("========================================")
try:
    print("Melakukan aksi 'block-ip' pada incident ID 1...")
    # Delay sedikit untuk menghasilkan MTTR > 0
    time.sleep(2)
    resp = post_json("http://127.0.0.1:5000/action/block-ip", {
        "incident_id": 1,
        "src_ip": "1.1.1.1"
    })
    print("Response JSON:", resp)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, status, mttr_seconds, timestamp_responded FROM incidents WHERE id=1;")
        row = cursor.fetchone()
        print("Database Record (id, status, mttr_seconds, timestamp_responded):", row)
        if row and row[1] in ('Resolved', 'In Progress') and row[2] >= 0 and row[3]:
            print(">> PASS: MTTR tercatat dan waktu respons tersimpan")
        else:
            print(">> FAIL: MTTR gagal tercatat")
except Exception as e:
    print(f"Error: {e}")

print("\n========================================")
print("5. VALIDASI STATUS WORKFLOW")
print("========================================")
try:
    print("Melakukan aksi 'false-positive' pada incident ID 2...")
    resp = post_json("http://127.0.0.1:5000/action/false-positive", {
        "incident_id": 2,
        "src_ip": "2.2.2.2"
    })
    print("Response JSON:", resp)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, status, action_taken FROM incidents WHERE id=2;")
        row = cursor.fetchone()
        print("Database Record (id, status, action_taken):", row)
        if row and row[1] == 'False Positive':
            print(">> PASS: Status berubah dari New menjadi False Positive")
        else:
            print(">> FAIL: Perubahan status gagal")
except Exception as e:
    print(f"Error: {e}")
