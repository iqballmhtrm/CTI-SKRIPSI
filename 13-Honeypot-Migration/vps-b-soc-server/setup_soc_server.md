# Panduan Setup VPS B (SOC Server)

Dokumen ini menjelaskan langkah-langkah setup *Security Operations Center* (SOC) di VPS B yang bertindak sebagai otak dari penelitian ini. VPS ini ditutup rapat dari internet luar.

## 1. Konfigurasi Firewall (UFW)
Untuk memastikan VPS B tertutup dari internet (kecuali port SSH standar dan Tailscale VPN):
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp          # Buka port SSH publik agar Anda bisa login
sudo ufw allow in on tailscale0 # Buka SEMUA port yang berasal dari VPN
sudo ufw enable
```
Dengan ini, port Elasticsearch (9200), Logstash (5044), Kibana (5601), dan SOAR (5000) hanya bisa diakses oleh *devices* yang terhubung ke jaringan Tailscale VPN Anda.

## 2. Instalasi ELK Stack
Langkah-langkah instalasi sama persis dengan yang Anda lakukan di Lab VirtualBox:
1. **Elasticsearch:** Install Elasticsearch 8.x, catat password `elastic`.
2. **Kibana:** Install Kibana, jalankan `elasticsearch-create-enrollment-token` dan konfigurasikan.
3. **Logstash:** Install Logstash dan *copy-paste* semua file kamus `mitre-mapping.yml`, `mitre-name.yml`, dan `mitre-tactic.yml` dari lab lama Anda ke `/etc/logstash/dictionaries/` di VPS B.

## 3. Adaptasi Logstash Pipeline
Buat `/etc/logstash/conf.d/soc-pipeline.conf`. Bagian `input` harus diganti agar mendengarkan koneksi masuk. Karena VPS B sudah diproteksi firewall, Logstash bisa mendengarkan `0.0.0.0`:
```logstash
input {
  beats {
    port => 5044
    host => "0.0.0.0"
  }
}
# ... (Sisanya sama persis dengan soc-pipeline.conf lama Anda) ...
```

## 4. Mengakses Kibana dari Laptop Anda (Secure SSH Tunnel)
Karena Kibana port 5601 diblokir oleh UFW untuk IP Publik, Anda TIDAK bisa membuka `http://<VPS_B_PUBLIC_IP>:5601`. Anda harus membukanya secara aman menggunakan **SSH Local Port Forwarding**.

Buka terminal/PowerShell di laptop Windows Anda, lalu jalankan:
```bash
ssh -L 5601:localhost:5601 -L 5000:localhost:5000 user_vps_b@<VPS_B_PUBLIC_IP>
```
Biarkan terminal tersebut terbuka.
Sekarang, Anda bisa membuka browser di laptop Windows Anda dan mengetik:
- Kibana: `http://localhost:5601`
- SOAR Dashboard: `http://localhost:5000`
Semuanya akan terhubung dengan aman melalui enkripsi SSH langsung ke VPS B Anda!
