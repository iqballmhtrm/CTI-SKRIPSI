# Kesesuaian Konsep vs Implementasi Sistem CTI-ELK (Bahan Bab 4 — Pembahasan)

> Dokumen ini membandingkan **konsep awal penelitian** (MASTER_PROMPT_CTI_ELK, 6 fase;
> serta diagram pipeline Logstash v3.3) dengan **implementasi aktual** yang telah
> diverifikasi pada lab. Tujuannya memastikan sistem sesuai konsep, mencatat
> perubahan secara jujur, dan menjadi rujukan bab pembahasan/penutup skripsi.

Tanggal: 2026-06-24 · Lingkungan: Lab VirtualBox host-only `192.168.56.0/24`
Node: SOC `192.168.56.10` (iqbal) · Victim `192.168.56.106` (korban) · Attacker/Kali `192.168.56.110` (kali)
Status sistem: **29/29 cek kesiapan OK — SIAP DIOPERASIKAN**

---

## 1. Empat Pilar Penelitian — Status Pembuktian

| # | Pilar (konsep) | Implementasi aktual | Status |
|---|----------------|---------------------|--------|
| 1 | Visualisasi dashboard CTI | Index `cti-logs-iqbal-*` terisi & ter-enrich; Kibana aktif (panel detail = pekerjaan lanjutan) | ✅ Fondasi siap |
| 2 | Pemetaan pola ancaman ke MITRE ATT&CK | Enrichment Logstash `translate`: 1000010→T1046, 1000020→T1110, 1000030→T1595.002 | ✅ Terbukti |
| 3 | Deteksi anomali hybrid NIDS+HIDS | Suricata (jaringan) + Wazuh (host) berjalan & saling melengkapi | ✅ Terbukti |
| 4 | Monitoring MTTD & MTTR | 30 iterasi terkontrol → `iterations.csv` (T0/T1/T2 per iterasi) | ✅ Terbukti |

---

## 2. Alur Sistem Menyeluruh (Aktual)

```
[ATTACKER .110] nmap / hydra / nikto
      │
      ▼
[VICTIM .106]  — sensor hybrid —
   ├─ Suricata (NIDS)     → eve.json            : sid 1000010/1000020/1000030
   └─ Wazuh-agent (HIDS)  → Wazuh manager        : rule 5763 (SSH brute), 31151 (banjir 400 web)
                    │
   Filebeat victim → eve.json + active-responses.log → Logstash :5044
                    │
[SOC .10] LOGSTASH (pipeline soc-pipeline.conf):
   (0) Time parser
   (1) Wazuh & Suricata JSON parser
   (2) Ensure source.ip
   (3) GeoIP enrichment                 ← Filter 2 (diagram v3.3)
   (4) DROP noise STREAM                 ← tambahan remediasi
   (5) NORMALIZE alert.* → data.alert.*  ← tambahan remediasi
   (6) Extract signature_id
   (7) MITRE Enricher (translate)        ← Filter 3 (diagram v3.3)
   (8) Pyramid of Pain Classifier        ← Filter 4 (diagram v3.3)
   (9) SOAR normalization
   (10) Tag active-response firewall-drop ← tambahan remediasi (untuk MTTR/T2)
       │                                     │
       ▼                                     ▼
   Elasticsearch `cti-logs-iqbal-*`     Webhook → SOAR Flask :5000 → incidents.db
       │
       ▼
   Kibana (visualisasi)   +   RESPONS OTOMATIS: Wazuh active-response → iptables DROP di victim
```

Catatan: "Drop Stats" (Filter 1 di diagram v3.3) = blok **DROP SURICATA STATS** di pipeline aktual.
Kelima tahap inti diagram v3.3 (**Drop Stats → GeoIP → MITRE → Pyramid → Elasticsearch**) seluruhnya
ADA dan berurutan benar; tiga tahap remediasi ditambahkan agar query metrik cocok dan noise teredam.

### Logika tiap lapisan
- **Sensor ganda (defense-in-depth):** Suricata membaca paket jaringan; Wazuh membaca log host (auth.log, akses Apache). Saling melengkapi: Nmap hanya terlihat Suricata; Hydra/Nikto terlihat keduanya.
- **Penyatuan jalur:** semua event diarahkan lewat Logstash agar ter-enrich MITRE dan masuk satu index.
- **Pengayaan intelijen:** `signature_id` → `technique_id` via kamus `mitre-mapping.yml`.
- **Respons otomatis:** Wazuh active-response (`firewall-drop`) memblok IP penyerang saat rule host yakin ada serangan (5763 brute SSH, 31151 banjir web). Nmap tidak memicu blokir (tak ada rule host) — perilaku benar.
- **Pengukuran:** T0=peluncuran, T1=alert pertama di ES (MTTD), T2=event firewall-drop ter-index (MTTR). Blokir di-reset tiap awal iterasi (`cti-unblock.sh`) demi independensi percobaan.

---

## 3. Hasil Pengukuran (Tabel 4.8 — 30 iterasi, deteksi 100%)

| Skenario (iter) | MITRE | MTTD rata² (rentang) | MTTR rata² (rentang) | Mitigasi otomatis |
|---|---|---|---|---|
| Nmap (1–10)   | T1046     | 2,5 s (1–6) | — (NO_MITIG) | tidak (recon jaringan) |
| Hydra (11–20) | T1110     | 1,6 s (1–4) | 5,3 s (2–9) | ya — Wazuh 5763 → firewall-drop |
| Nikto (21–30) | T1595.002 | 2,2 s (1–4) | 3,1 s (2–4) | ya — Wazuh 31151 → firewall-drop |

Sumber: `~/research-archive/2026-06-21_controlled-run/iterations.csv`.

---

## 4. Kesesuaian dengan Konsep Awal

| Komponen | Konsep awal | Aktual | Status |
|---|---|---|---|
| Hybrid NIDS+HIDS | Suricata + Wazuh | Suricata + Wazuh | ✅ Sesuai |
| Log aggregation | Filebeat→Logstash→ES | idem | ✅ Sesuai |
| Pipeline 5 tahap (v3.3) | Drop Stats→GeoIP→MITRE→Pyramid→ES | ada semua, berurutan | ✅ Sesuai |
| MITRE enrichment | filter `translate` | `translate` + kamus | ✅ Sesuai |
| Visualisasi Kibana | dashboard CTI | index siap & ter-enrich | ✅ Fondasi sesuai |
| MTTD/MTTR | diukur per serangan | 30-run terkontrol | ✅ Sesuai |

---

## 5. PERUBAHAN dari Konsep Awal (wajib ditulis di naskah agar jujur & konsisten)

1. **Model respons: OTOMATIS (Wazuh active-response), bukan one-click manual SOAR.**
   - Konsep (Fase 4A): analis menekan tombol **[Block IP]** → SSH `iptables` (semi-otomatis).
   - Aktual: Wazuh active-response memblok otomatis tanpa intervensi manusia. Tombol SOAR tetap tersedia sebagai opsi manual.
   - Implikasi: respons lebih cepat & otonom; MTTR mencerminkan mitigasi otomatis.

2. **Sumber webhook SOAR: Logstash langsung, bukan Kibana Alerting.**
   - Konsep (Fase 4A) eksplisit: dari Kibana Alerting rule, "BUKAN dari Logstash langsung".
   - Aktual: Logstash `http output` → `/webhook`. Lebih real-time & sederhana.

3. **Definisi MTTR.**
   - Konsep: `MTTR = timestamp_responded − timestamp_detected` (T2 − T1).
   - Aktual (orchestrator): **MTTR = T2 − T0** (peluncuran → mitigasi).
   - Catatan: T0/T1/T2 semuanya tersimpan, jadi MTTR T2−T1 dapat dihitung ulang bila naskah menghendaki definisi konsep.

4. **Deteksi Nikto: behavioral (laju permintaan HTTP), bukan signature User-Agent.**
   - Alasan: Nikto versi ini menyamar User-Agent sebagai browser; rule `content:"Nikto"` tidak match. Rule diubah ke `threshold count 20/10s` (mendeteksi perilaku pemindaian = T1595.002).

5. **Cakupan skenario diciutkan ke 3 (Nmap, Hydra, Nikto).**
   - Konsep (Fase 2A) juga menyebut **Lateral Movement (T1021)** dan **Exfiltration (T1041)**.
   - Aktual: belum diimplementasikan → tulis sebagai **batasan penelitian / saran pengembangan**.

6. **MTTD/MTTR dihitung via skrip orchestrator (curl + bash), bukan ES|QL Kibana** (konsep Fase 3B). Hasil setara; ES|QL dapat ditambah untuk dashboard.

7. **MITRE enrichment via Logstash `translate`, bukan Elasticsearch Ingest Pipeline** (konsep Fase 1B). Pendekatan berbeda, hasil setara.

8. **Penamaan index:** aktual `cti-logs-iqbal-*` (konsep `soc-alerts-*`, diagram `logstash-v3.3-*`). Konsisten dipakai di seluruh sistem.

9. **Pemetaan MITRE Nikto:** product.md = **T1595.002**; MASTER_PROMPT = T1190. Perlu disamakan di naskah (rekomendasi: T1595.002, sesuai sifat pemindaian recon).

---

## 6. Item Konsep yang Belum/ Perlu Diverifikasi

- **ILM policy + snapshot + Stack Monitoring** (Fase 5): skrip tersedia di repo (`02-ELK/rotate_elastic.sh`, `02-ELK/cleanup_snapshots.sh`); status aktif belum diverifikasi pada sesi ini.
- **Dashboard Kibana detail, Vega MITRE matrix, Canvas** (Fase 3): data & index siap; pembuatan panel = pekerjaan tersendiri.
- **Aksi SOAR lanjutan** (Lock Root, Forensics): tersedia di `soar_app.py` (konsep Fase 4A); belum diuji terukur sesi ini.

---

## 7. Kesimpulan

Arsitektur inti sistem **sesuai konsep**: deteksi hybrid → pipeline Logstash 5 tahap (Drop Stats,
GeoIP, MITRE Enricher, Pyramid Classifier, output Elasticsearch) → pengayaan MITRE → penyimpanan &
visualisasi → pengukuran MTTD/MTTR. Terdapat **tiga perubahan substantif** yang perlu dinyatakan
eksplisit di naskah: (1) respons otomatis Wazuh menggantikan one-click SOAR sebagai mekanisme utama,
(2) webhook dikirim dari Logstash bukan Kibana Alerting, dan (3) definisi MTTR memakai T2−T0.
Perubahan lain bersifat penyesuaian teknis yang wajar dan dapat dipertanggungjawabkan. Sistem telah
lolos seluruh cek kesiapan (29/29) dan menghasilkan data terukur untuk Tabel 4.8.
