import sqlite3
import os

DB_PATH = "/home/iqbal/soar-dashboard/app/incidents.db"

queries = [
    "ALTER TABLE incidents ADD COLUMN timestamp_detected TEXT;",
    "ALTER TABLE incidents ADD COLUMN timestamp_responded TEXT;",
    "ALTER TABLE incidents ADD COLUMN pipeline_source TEXT;",
    "ALTER TABLE incidents ADD COLUMN status TEXT DEFAULT 'New';",
    "ALTER TABLE incidents ADD COLUMN action_taken TEXT;",
    "ALTER TABLE incidents ADD COLUMN mttd_seconds INTEGER DEFAULT 0;",
    "ALTER TABLE incidents ADD COLUMN mttr_seconds INTEGER DEFAULT 0;",
    """CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER,
        action_type TEXT,
        timestamp TEXT,
        result TEXT,
        ssh_output TEXT,
        FOREIGN KEY(incident_id) REFERENCES incidents(id)
    );""",
    """CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TEXT
    );""",
    "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (1, CURRENT_TIMESTAMP);"
]

try:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        for q in queries:
            try:
                cursor.execute(q)
                print("Berhasil eksekusi:", q.replace('\n', ' ')[:50])
            except Exception as e:
                pass # Abaikan error duplicate column
        conn.commit()
    print("MIGRASI SELESAI")
except Exception as e:
    print("GAGAL:", e)
