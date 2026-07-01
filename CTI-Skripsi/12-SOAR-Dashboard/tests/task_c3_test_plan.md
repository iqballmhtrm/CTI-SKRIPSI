# Testing Plan: TASK-C3 Revision

## Test Case 1: Webhook Normal (Valid Payload)
**Tujuan:** Memastikan SOAR menerima webhook, mencatat MTTD >= 0, status "New".
**Eksekusi:**
```bash
curl -X POST http://192.168.56.10:5000/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp_alert": "2025-06-15T10:00:00Z",
    "src_ip": "192.168.56.105",
    "attack_type": "SSH Brute Force",
    "mitre_technique": "T1110",
    "mitre_tactic": "Credential Access",
    "severity": 2,
    "pipeline_source": "manual_test"
  }'
```
**Expected Output JSON:** `{"status": "New", "mttd_seconds": <angka_positif>}`
**Verifikasi DB:** `sqlite3 incidents.db "SELECT status, mttd_seconds FROM incidents ORDER BY id DESC LIMIT 1;"`

## Test Case 2: Clock Drift Simulation (Future Timestamp)
**Tujuan:** Memastikan jika alert timestamp lebih besar dari waktu sistem SOAR, `mttd_seconds` tidak menjadi negatif (maksimal 0).
**Eksekusi:**
```bash
# Ubah tahun ke 2099 untuk simulasi masa depan
curl -X POST http://192.168.56.10:5000/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp_alert": "2099-06-15T10:00:00Z",
    "src_ip": "192.168.56.106",
    "attack_type": "Future Attack",
    "severity": 1,
    "pipeline_source": "manual_test"
  }'
```
**Expected Output JSON:** `{"mttd_seconds": 0}` (Tidak boleh minus).

## Test Case 3: Missing Timestamp (Fallback ke utcnow)
**Tujuan:** Memastikan aplikasi aman jika Logstash tidak mengirimkan `@timestamp`.
**Eksekusi:**
```bash
curl -X POST http://192.168.56.10:5000/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "192.168.56.107",
    "attack_type": "No Timestamp Attack",
    "pipeline_source": "manual_test"
  }'
```
**Expected Output JSON:** Berhasil tanpa error HTTP 500. `mttd_seconds` bernilai `0`.

## Test Case 4: Action Execution (Block IP)
**Tujuan:** Memastikan eksekusi mitigasi menghitung MTTR dan memperbarui status ke "Resolved".
**Eksekusi:**
1. Klik tombol 🚫 pada antarmuka web.
2. Konfirmasi pop-up javascript.
**Verifikasi DB:** `sqlite3 incidents.db "SELECT status, mttr_seconds FROM incidents ORDER BY id DESC LIMIT 1;"` (Harus "Resolved" dan angka > 0).

## Test Case 5: False Positive
**Tujuan:** Memastikan penandaan "False Positive" mengubah status tanpa mengeksekusi SSH.
**Eksekusi:**
1. Klik tombol `FP` (Mark False Positive) pada salah satu insiden `New`.
**Verifikasi DB:** `sqlite3 incidents.db "SELECT status, action_taken FROM incidents WHERE status='False Positive';"`
