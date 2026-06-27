-- Script ini memodifikasi tabel incidents yang sudah ada
-- Karena SQLite tidak mendukung IF NOT EXISTS pada ADD COLUMN,
-- Abaikan error 'duplicate column name' jika script ini dijalankan berulang kali.

ALTER TABLE incidents ADD COLUMN timestamp_detected TEXT;
ALTER TABLE incidents ADD COLUMN timestamp_responded TEXT;
ALTER TABLE incidents ADD COLUMN pipeline_source TEXT;
ALTER TABLE incidents ADD COLUMN status TEXT DEFAULT 'New';
ALTER TABLE incidents ADD COLUMN action_taken TEXT;
ALTER TABLE incidents ADD COLUMN mttd_seconds INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN mttr_seconds INTEGER DEFAULT 0;

-- Membuat tabel actions untuk audit log aksi mitigasi
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    action_type TEXT,
    timestamp TEXT,
    result TEXT,
    ssh_output TEXT,
    FOREIGN KEY(incident_id) REFERENCES incidents(id)
);

-- Membuat tabel schema_version untuk tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT
);

-- Mencatat penerapan migrasi ini
INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (1, CURRENT_TIMESTAMP);
