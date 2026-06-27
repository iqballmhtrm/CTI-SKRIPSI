-- SCHEMA V2: CTI SOAR Dashboard
-- Mendefinisikan struktur database final setelah revisi TASK-C3

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- Waktu dari source (Logstash/Suricata)
    timestamp TEXT,
    
    -- Waktu SOAR menerima webhook (Untuk kalkulasi MTTD)
    timestamp_detected TEXT,
    
    -- Waktu SOAR menjalankan aksi (Untuk kalkulasi MTTR)
    timestamp_responded TEXT,
    
    src_ip TEXT,
    attack_type TEXT,
    mitre_tactic TEXT,
    severity INTEGER,
    
    -- Asal pipeline (kibana_alert, logstash_http, manual_test)
    pipeline_source TEXT,
    
    -- Status default secara eksplisit
    status TEXT DEFAULT 'New',
    action_taken TEXT,
    
    -- Metrik penelitian
    mttd_seconds INTEGER DEFAULT 0,
    mttr_seconds INTEGER DEFAULT 0
);

-- Tabel baru untuk tracking setiap aksi mitigasi
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    action_type TEXT,
    timestamp TEXT,
    result TEXT,
    ssh_output TEXT,
    FOREIGN KEY(incident_id) REFERENCES incidents(id)
);

-- Indeks untuk meningkatkan performa query dashboard
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
