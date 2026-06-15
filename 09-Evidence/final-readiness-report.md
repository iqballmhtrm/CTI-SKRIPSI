# Audit Kesiapan Sidang Skripsi

## Status Komponen Penelitian

| Komponen | Status |
| -------- | ------ |
| ELK | **100% READY** (Service Running, Integrasi Sukses) |
| Suricata | **100% READY** (Custom Rules berjalan, Interface enp0s8 termonitor) |
| Wazuh | **100% READY** (Meneruskan Suricata Alert ke Elasticsearch) |
| MITRE Mapping | **100% READY** (Dictionary Logstash terpasang dan berhasil mapping data riil) |
| Nmap Validation | **100% READY** (T1046 terbukti terekam) |
| Hydra Validation | **100% READY** (T1110 terbukti terekam) |
| Nikto Validation | **100% READY** (T1595 terbukti terekam) |
| Dashboard | **100% READY** (Seluruh visualisasi komplit dan tersedia) |
| Bab 3 | **100% READY** (Telah disusun pada `10-Bab3/perancangan.md`) |
| Bab 4 | **100% READY** (Laporan akhir pada `11-Bab4/`) |
| Evidence | **95% READY** (Membutuhkan Screenshot Asli) |
| Repository | **100% READY** (Commit akhir telah dilakukan) |

## Ringkasan Penilaian
1. **Persentase kesiapan sidang:** **98%**
2. **Daftar kekurangan yang tersisa:** 
   - Tangkapan layar (*screenshot*) antarmuka grafis (GUI) belum diambil secara manual. Mahasiswa wajib melengkapi direktori `08-Screenshots` dengan gambar layar Kibana dan Wazuh asli untuk dimasukkan ke naskah skripsi final.
3. **Daftar file yang wajib diperiksa sebelum presentasi:**
   - `06-Dashboard/dashboard-final.ndjson` (Pastikan dashboard masih merender visualisasi dengan baik).
   - `03-Suricata/custom.rules` (Jika dosen penguji menanyakan bentuk signature).
   - `05-MITRE/mitre-mapping.yml` (Untuk memperlihatkan pemetaan Logstash riil).
4. **Status akhir:**
   **READY FOR SIDANG**
