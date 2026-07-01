# Arsitektur CTI Honeypot (Open Environment)

Dokumen ini menjelaskan transisi arsitektur penelitian dari simulasi lab tertutup (VirtualBox lokal) menuju lingkungan nyata (Open Environment Honeypot) yang di-hosting di Cloud/VPS.

## 1. Topologi Jaringan

```text
      [INTERNET BEBAS] (Botnet, Scanner, Real Attackers)
             │
             ▼ (Port 22, 80 terekspos)
 ┌───────────────────────────────────────────┐
 │               VPS A (Honeypot)            │
 │  Peran: Victim Node / Sensor              │
 │  Service: Suricata NIDS, Filebeat         │
 │  IP Publik: <VPS_A_PUBLIC_IP>             │
 │  IP Privat VPN: <HONEYPOT_VPN_IP>         │
 └─────────────────────┬─────────────────────┘
                       │
             [PRIVATE VPN TUNNEL] (Tailscale / ZeroTier)
                       │ (Hanya trafik Filebeat yang melintas)
                       ▼
 ┌───────────────────────────────────────────┐
 │               VPS B (SOC Server)          │
 │  Peran: Otak Analisis & Respons           │
 │  Service: Elasticsearch, Logstash, Kibana,│
 │           Flask SOAR Dashboard            │
 │  IP Publik: <VPS_B_PUBLIC_IP>             │
 │  IP Privat VPN: <SOC_SERVER_VPN_IP>       │
 │  Port Terbuka: HANYA Port VPN & SSH       │
 └─────────────────────┬─────────────────────┘
                       │ (Akses aman via SSH Tunneling)
             [LAPTOP PENELITI]
             Akses Kibana: localhost:5601
             Akses SOAR  : localhost:5000
```

## 2. Deskripsi Arsitektur
- **VPS A (Honeypot):** Merupakan server umpan yang sengaja dibiarkan terekspos ke internet. Port 22 (SSH) dan Port 80 (Web) dibuka lebar agar *bot* dan peretas dari seluruh dunia bisa menyerangnya. Suricata akan memantau trafik ini dan Filebeat akan mengirimkan log (*eve.json*) ke VPS B.
- **VPS B (SOC Server):** Merupakan ruang komando. Server ini **tertutup total** dari internet. Tidak ada port yang di-expose ke publik. Data dari VPS A dikirim melalui *tunnel* VPN yang terenkripsi. 
- **Keamanan Akses:** Peneliti mengakses Kibana (port 5601) dan SOAR Dashboard (port 5000) yang berada di VPS B dengan menggunakan metode *SSH Local Port Forwarding* dari laptop pribadi.

## 3. Narasi Revisi Bab 3
Penelitian ini telah diadaptasi untuk memenuhi tingkat realisme ancaman siber modern. Metodologi simulasi lab (berbasis serangan *Nmap/Hydra* manual) telah diekspansi menjadi metodologi pengumpulan data berbasis *Honeypot* di lingkungan Cloud (Open Environment). 

Pendekatan ini sejalan dengan konsep yang dikemukakan oleh Kosheliuk et al. (2024), di mana *honeypot* yang terintegrasi dengan arsitektur pemantauan (seperti ELK) mampu menarik vektor serangan organik secara *real-time*, memberikan keandalan data ancaman yang jauh melampaui dataset sintetis. Selain itu, pemanfaatan dasbor analitik berbasis honeypot juga memperkuat validitas sistem dalam mengkategorisasikan ancaman sesuai dengan kerangka kerja CTI (mengacu pada Adnyana et al., 2024). Pengumpulan data ini dilakukan secara pasif dan aman, karena *sensor node* diisolasi secara logikal dari *SOC Server* menggunakan jaringan *Virtual Private Network* (VPN), memastikan bahwa kompromi pada honeypot tidak merambat ke infrastruktur komando.

## 4. Rencana Eksekusi dan Pembersihan
- **Durasi Pengumpulan Data:** Sistem akan dibiarkan hidup selama **7 hari berturut-turut** (misal: 1 Juli - 7 Juli 2026).
- **Prosedur Penutupan:**
  1. Setelah 7 hari, Filebeat di VPS A dimatikan agar pengiriman log berhenti.
  2. Data di VPS B di-backup (snapshot/ekspor CSV).
  3. **VPS A (Honeypot) akan dihancurkan (Destroy/Delete)** dari penyedia Cloud agar tidak menjadi inang *botnet* yang berbahaya.
  4. VPS B dapat dipertahankan atau di-backup lokal untuk penyusunan laporan Bab 4.
