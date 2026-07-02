# CTI-Skripsi — SOC ELK Stack untuk Cyber Threat Intelligence

Repositori penelitian skripsi:
**"Optimisasi Visualisasi Data Log dan Alert Siber Melalui Dashboard ELK Stack
untuk Mendukung Pengambilan Keputusan Operasional Cyber Threat Intelligence"**

**Muhammad Iqbal Muhtaram** — NIM 2241720265 — Teknik Informatika, Politeknik Negeri Malang

---

## Isi Repositori

Seluruh artefak penelitian berada di **[`CTI-Skripsi/`](CTI-Skripsi/README.md)** —
lihat README di dalamnya untuk struktur lengkap, komponen sistem, skenario
serangan, dan metrik hasil.

## Catatan Penting

- **File VM VirtualBox tidak disertakan.** Folder `SOC-SERVER/`, `ATTACKER-NODE/`,
  file `*.vdi`/`*.vbox`, snapshot, dan log VirtualBox di-*exclude* via `.gitignore`
  karena berukuran puluhan GB. Repositori ini hanya berisi konfigurasi, kode,
  bukti, dan dokumentasi.
- **Kredensial & token disensor.** Password, token bot Telegram, dan API key tidak
  disimpan di repositori (hanya di server lab).

## Topologi Lab (host-only 192.168.56.0/24)

```
ATTACKER (.110)  ──serangan──▶  VICTIM (.106)
   Kali Linux                    Ubuntu + Apache
                                       │ traffic dimonitor
                                       ▼
                                 SOC (.10)
                    Suricata · Wazuh · ELK · SOAR · Telegram
```
