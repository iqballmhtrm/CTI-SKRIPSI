-- Rollback Plan untuk Migrasi 001_task_c3_revision.sql
-- Karena SQLite tidak mendukung DROP COLUMN, rollback mengharuskan kita 
-- membuat ulang tabel incidents ke versi awalnya.

-- Instruksi Manual Sebelum Migrasi (DIJALANKAN OLEH ADMIN):
-- cp ~/soar-dashboard/app/incidents.db ~/soar-dashboard/app/incidents.db.backup.$(date +%Y%m%d)
-- Jika terjadi error pada soar_app.py:
-- git checkout -- CTI-Skripsi/12-SOAR-Dashboard/app/soar_app.py

-- ==========================================
-- SCRIPT ROLLBACK (Jalankan di sqlite3)
-- ==========================================

-- 1. Buat ulang tabel incidents versi original
CREATE TABLE IF NOT EXISTS incidents_old (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    attack_type TEXT,
    mitre_tactic TEXT,
    severity INTEGER
);

-- 2. Kembalikan data lama
INSERT INTO incidents_old (id, timestamp, src_ip, attack_type, mitre_tactic, severity)
SELECT id, timestamp, src_ip, attack_type, mitre_tactic, severity FROM incidents;

-- 3. Hapus tabel baru
DROP TABLE incidents;
DROP TABLE actions;
DROP TABLE schema_version;

-- 4. Ubah nama tabel original kembali
ALTER TABLE incidents_old RENAME TO incidents;
