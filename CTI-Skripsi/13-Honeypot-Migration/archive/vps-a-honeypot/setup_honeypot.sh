#!/bin/bash
# ==============================================================================
# Setup Script - VPS A (Honeypot / Victim Node)
# Proyek   : CTI Skripsi - Honeypot Migration
# Deskripsi: Skrip ini menginstal dan mengonfigurasi seluruh komponen keamanan
#            pada VPS A yang terekspos ke internet sebagai honeypot.
# Komponen : fail2ban, Nginx (web decoy), Suricata NIDS, Wazuh Agent, Filebeat
# ==============================================================================

set -euo pipefail

# ==============================================================================
# BAGIAN KONFIGURASI — Isi variabel di bawah sebelum menjalankan skrip
# ==============================================================================

# Alamat IP VPN dari SOC Server (VPS B) tempat Wazuh Manager & Logstash berjalan.
# Contoh: "10.8.0.1"
SOC_SERVER_VPN_IP="GANTI_DENGAN_IP_VPN_SOC_SERVER"

# (Opsional) Nama interface jaringan publik. Jika dikosongkan, skrip akan
# mendeteksi otomatis berdasarkan default route.
PUBLIC_IFACE_OVERRIDE=""

# ==============================================================================
# FUNGSI UTILITAS
# ==============================================================================

# Fungsi untuk mencetak pesan langkah dengan format yang jelas
print_step() {
    echo ""
    echo "=================================================================="
    echo "[*] $1"
    echo "=================================================================="
}

# Fungsi untuk mencetak pesan sukses
print_ok() {
    echo "[✔] $1"
}

# Fungsi untuk mencetak pesan error dan keluar
print_error() {
    echo "[✘] ERROR: $1" >&2
    exit 1
}

# ==============================================================================
# VALIDASI PRA-SYARAT
# ==============================================================================

print_step "Memvalidasi pra-syarat..."

# Pastikan skrip dijalankan sebagai root
if [[ "$EUID" -ne 0 ]]; then
    print_error "Skrip ini harus dijalankan sebagai root. Gunakan: sudo bash $0"
fi

# Pastikan SOC_SERVER_VPN_IP sudah diisi, bukan masih placeholder
if [[ "$SOC_SERVER_VPN_IP" == "GANTI_DENGAN_IP_VPN_SOC_SERVER" || -z "$SOC_SERVER_VPN_IP" ]]; then
    print_error "Variabel SOC_SERVER_VPN_IP belum diatur! Silakan edit skrip ini dan isi alamat IP VPN SOC Server."
fi

print_ok "SOC Server VPN IP: $SOC_SERVER_VPN_IP"

# Deteksi interface jaringan publik secara otomatis atau gunakan override
if [[ -n "$PUBLIC_IFACE_OVERRIDE" ]]; then
    PUBLIC_IFACE="$PUBLIC_IFACE_OVERRIDE"
    print_ok "Interface publik (override manual): $PUBLIC_IFACE"
else
    PUBLIC_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
    if [[ -z "$PUBLIC_IFACE" ]]; then
        print_error "Gagal mendeteksi interface jaringan publik. Isi PUBLIC_IFACE_OVERRIDE secara manual."
    fi
    print_ok "Interface publik (auto-detect): $PUBLIC_IFACE"
fi

# ==============================================================================
# LANGKAH 1: Update Sistem & Instal Dependensi Dasar
# ==============================================================================

print_step "Langkah 1: Memperbarui sistem dan menginstal dependensi dasar..."

apt-get update -y
apt-get upgrade -y
apt-get install -y curl gnupg apt-transport-https lsb-release ca-certificates \
    software-properties-common wget jq

print_ok "Sistem berhasil diperbarui dan dependensi dasar terinstal."

# ==============================================================================
# LANGKAH 2: Instal dan Konfigurasi fail2ban
# Tujuan: Melindungi layanan SSH dan Nginx, tetapi dengan threshold tinggi
#         agar serangan sempat terekam oleh Suricata dan Wazuh sebelum diblokir.
# ==============================================================================

print_step "Langkah 2: Menginstal dan mengonfigurasi fail2ban..."

apt-get install -y fail2ban

# Salin konfigurasi jail khusus honeypot ke direktori jail.d
# File ini memiliki maxretry tinggi agar data serangan tetap terekam
cat > /etc/fail2ban/jail.d/honeypot.conf <<'JAIL_EOF'
# =============================================================================
# Konfigurasi Fail2Ban - CTI Honeypot
# =============================================================================
# Threshold sengaja ditinggikan (maxretry=10) karena ini adalah honeypot.
# Tujuannya agar serangan brute-force sempat tercatat oleh Suricata & Wazuh
# sebelum IP penyerang diblokir oleh fail2ban.
# =============================================================================

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
# Maksimal 10 percobaan gagal sebelum ban — sengaja tinggi untuk honeypot
maxretry = 10
# Durasi ban: 600 detik (10 menit) — cukup singkat agar penyerang kembali
bantime  = 600
findtime = 600

[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 10
bantime  = 600
findtime = 600
JAIL_EOF

# Aktifkan dan mulai fail2ban
systemctl enable fail2ban
systemctl restart fail2ban

print_ok "fail2ban berhasil diinstal dan dikonfigurasi (mode honeypot)."

# ==============================================================================
# LANGKAH 3: Instal dan Konfigurasi Nginx sebagai Web Decoy
# Tujuan: Menyediakan layanan HTTP palsu di port 80 sebagai umpan
#         untuk menarik dan merekam aktivitas pemindaian web.
# ==============================================================================

print_step "Langkah 3: Menginstal Nginx sebagai web decoy di port 80..."

apt-get install -y nginx

# Buat halaman web decoy sederhana yang terlihat seperti server sungguhan
cat > /var/www/html/index.html <<'HTML_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
</head>
<body>
    <h1>It works!</h1>
    <p>This server is running.</p>
</body>
</html>
HTML_EOF

# Pastikan konfigurasi default Nginx aktif dan mendengarkan port 80
systemctl enable nginx
systemctl restart nginx

print_ok "Nginx web decoy berhasil aktif di port 80."

# ==============================================================================
# LANGKAH 4: Instal dan Konfigurasi Suricata NIDS
# Tujuan: Mendeteksi lalu lintas jaringan berbahaya menggunakan rule berbasis
#         MITRE ATT&CK. Log eve.json akan dikirim ke SOC Server via Filebeat.
# ==============================================================================

print_step "Langkah 4: Menginstal dan mengonfigurasi Suricata NIDS..."

# Tambahkan repositori resmi Suricata (PPA OISF)
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -y
apt-get install -y suricata

# Buat direktori untuk custom rules jika belum ada
mkdir -p /etc/suricata/rules

# Tulis custom rules dengan pemetaan MITRE ATT&CK
cat > /etc/suricata/rules/local.rules <<'RULES_EOF'
# Custom Rules - CTI Skripsi Honeypot
# =====================================================================
# Rule-rule di bawah dirancang untuk mendeteksi teknik serangan umum
# yang dipetakan ke framework MITRE ATT&CK.
# =====================================================================

# SID 1000010 — Deteksi Nmap Port Scan (MITRE T1046: Network Service Discovery)
# Mendeteksi SYN scan dengan threshold 20 paket SYN dalam 5 detik dari IP yang sama
alert tcp any any -> $HOME_NET any (msg:"CTI Nmap Port Scan Detected [T1046]"; flags:S; threshold:type both, track by_src, count 20, seconds 5; sid:1000010; rev:2; metadata:mitre_technique_id T1046, mitre_technique_name Network Service Discovery, mitre_tactic_name Discovery;)

# SID 1000020 — Deteksi SSH Brute Force (MITRE T1110.001: Password Guessing)
# Mendeteksi 5 koneksi SSH established dalam 60 detik dari IP yang sama
alert tcp any any -> $HOME_NET 22 (msg:"CTI SSH Brute Force Attempt [T1110.001]"; flow:to_server,established; threshold:type both, track by_src, count 5, seconds 60; sid:1000020; rev:2; metadata:mitre_technique_id T1110.001, mitre_technique_name Password Guessing, mitre_tactic_name Credential Access;)

# SID 1000030 — Deteksi Nikto Web Vulnerability Scan (MITRE T1595.002: Vulnerability Scanning)
# Mendeteksi User-Agent mengandung string "Nikto" (scanner web populer)
alert tcp any any -> $HOME_NET any (msg:"CTI Nikto Web Vulnerability Scan [T1595.002]"; flow:to_server,established; content:"Nikto"; nocase; http_user_agent; sid:1000030; rev:2; metadata:mitre_technique_id T1595.002, mitre_technique_name Vulnerability Scanning, mitre_tactic_name Reconnaissance;)
RULES_EOF

print_ok "Custom Suricata rules berhasil ditulis ke /etc/suricata/rules/local.rules"

# Konfigurasi suricata.yaml — set interface dan tambahkan path rule lokal
SURICATA_YAML="/etc/suricata/suricata.yaml"

# Backup konfigurasi asli sebelum modifikasi
if [[ ! -f "${SURICATA_YAML}.bak" ]]; then
    cp "$SURICATA_YAML" "${SURICATA_YAML}.bak"
    print_ok "Backup konfigurasi Suricata asli disimpan di ${SURICATA_YAML}.bak"
fi

# Ganti interface default (biasanya eth0) dengan interface publik yang terdeteksi
# Ini memastikan Suricata memantau lalu lintas di interface yang benar
sed -i "s/- interface: .*/- interface: ${PUBLIC_IFACE}/" "$SURICATA_YAML"
print_ok "Interface Suricata diatur ke: $PUBLIC_IFACE"

# Pastikan rule-files memuat local.rules
# Cek apakah local.rules sudah ada di konfigurasi, jika belum tambahkan
if ! grep -q "local.rules" "$SURICATA_YAML"; then
    # Tambahkan local.rules di bawah baris "rule-files:" yang pertama ditemukan
    sed -i '/rule-files:/a\  - local.rules' "$SURICATA_YAML"
    print_ok "local.rules ditambahkan ke daftar rule-files di suricata.yaml"
else
    print_ok "local.rules sudah terdaftar di suricata.yaml"
fi

# Pastikan default-rule-path mengarah ke /etc/suricata/rules
sed -i 's|default-rule-path:.*|default-rule-path: /etc/suricata/rules|' "$SURICATA_YAML"

# Aktifkan dan mulai Suricata
systemctl enable suricata
systemctl restart suricata

print_ok "Suricata NIDS berhasil diinstal dan dikonfigurasi."

# ==============================================================================
# LANGKAH 5: Instal dan Konfigurasi Wazuh Agent
# Tujuan: Mengirim log keamanan lokal (syslog, auth.log, dll.) ke Wazuh
#         Manager di SOC Server melalui koneksi VPN.
# ==============================================================================

print_step "Langkah 5: Menginstal dan mengonfigurasi Wazuh Agent..."

# Tambahkan repository dan GPG key Wazuh 4.x
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list

apt-get update -y

# Instal wazuh-agent dengan variabel environment untuk mengarahkan ke manajer
WAZUH_MANAGER="$SOC_SERVER_VPN_IP" apt-get install -y wazuh-agent

# Konfigurasi ossec.conf — pastikan alamat manajer benar
# Ini penting karena agent harus terhubung ke Wazuh Manager via tunnel VPN
OSSEC_CONF="/var/ossec/etc/ossec.conf"

if [[ -f "$OSSEC_CONF" ]]; then
    # Ganti tag <address> di dalam blok <client><server> dengan IP VPN SOC Server
    sed -i "s|<address>.*</address>|<address>${SOC_SERVER_VPN_IP}</address>|" "$OSSEC_CONF"
    print_ok "Wazuh Agent diarahkan ke manajer: $SOC_SERVER_VPN_IP"
else
    print_error "File konfigurasi Wazuh ($OSSEC_CONF) tidak ditemukan. Instalasi mungkin gagal."
fi

# Aktifkan dan mulai Wazuh Agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

print_ok "Wazuh Agent berhasil diinstal dan terhubung ke $SOC_SERVER_VPN_IP."

# ==============================================================================
# LANGKAH 6: Instal dan Konfigurasi Filebeat 8.x
# Tujuan: Membaca log eve.json dari Suricata dan mengirimkannya ke
#         Logstash di SOC Server (port 5044) melalui koneksi VPN.
# ==============================================================================

print_step "Langkah 6: Menginstal dan mengonfigurasi Filebeat 8.x..."

# Tambahkan repository Elastic 8.x
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
    > /etc/apt/sources.list.d/elastic-8.x.list

apt-get update -y
apt-get install -y filebeat

# Tulis konfigurasi Filebeat untuk membaca log Suricata
# keys_under_root:true memastikan field JSON dari eve.json diletakkan
# di level root dokumen, sehingga mudah diproses oleh Logstash/Elasticsearch
cat > /etc/filebeat/filebeat.yml <<FILEBEAT_EOF
# =============================================================================
# Konfigurasi Filebeat - CTI Honeypot (VPS A)
# Membaca log Suricata eve.json dan mengirim ke Logstash di SOC Server
# =============================================================================

filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/suricata/eve.json
    # Parsing JSON: letakkan semua key di level root dokumen
    json.keys_under_root: true
    json.overwrite_keys: true
    # Tambahkan field untuk identifikasi sumber log
    fields:
      source_type: suricata
      node_role: honeypot
    fields_under_root: true

# Output ke Logstash di SOC Server melalui VPN
output.logstash:
  hosts: ["${SOC_SERVER_VPN_IP}:5044"]

# Matikan output Elasticsearch langsung (kita pakai Logstash pipeline)
# output.elasticsearch:
#   hosts: ["localhost:9200"]

# Konfigurasi logging Filebeat sendiri
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat.log
  keepfiles: 7
  permissions: 0644
FILEBEAT_EOF

# Aktifkan dan mulai Filebeat
systemctl enable filebeat
systemctl restart filebeat

print_ok "Filebeat 8.x berhasil diinstal dan dikonfigurasi untuk mengirim log ke ${SOC_SERVER_VPN_IP}:5044."

# ==============================================================================
# LANGKAH 7: Hardening SSH
# Tujuan: Meningkatkan keamanan SSH namun tetap memungkinkan akses
#         melalui kunci publik (key-based authentication).
# ==============================================================================

print_step "Langkah 7: Melakukan hardening konfigurasi SSH..."

SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup konfigurasi SSH asli
if [[ ! -f "${SSHD_CONFIG}.bak" ]]; then
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
    print_ok "Backup konfigurasi SSH disimpan di ${SSHD_CONFIG}.bak"
fi

# Nonaktifkan autentikasi password — hanya izinkan key-based login
# Ini mencegah brute-force password berhasil, namun percobaan tetap terekam
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"

# Izinkan root login hanya melalui kunci publik (tanpa password)
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "$SSHD_CONFIG"

# Validasi konfigurasi SSH sebelum restart
if sshd -t; then
    systemctl restart sshd
    print_ok "SSH hardening berhasil diterapkan."
else
    # Jika konfigurasi tidak valid, kembalikan backup
    cp "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
    print_error "Konfigurasi SSH tidak valid! File dikembalikan dari backup."
fi

# ==============================================================================
# RINGKASAN INSTALASI
# ==============================================================================

print_step "Setup VPS A (Honeypot) Selesai!"

echo ""
echo "  Komponen yang terinstal:"
echo "  ─────────────────────────────────────────────────────────────────"
echo "  [1] fail2ban         : Aktif (mode honeypot, maxretry=10)"
echo "  [2] Nginx            : Web decoy di port 80"
echo "  [3] Suricata NIDS    : Memantau interface '$PUBLIC_IFACE'"
echo "  [4] Wazuh Agent      : Terhubung ke manajer $SOC_SERVER_VPN_IP"
echo "  [5] Filebeat 8.x     : Mengirim eve.json ke $SOC_SERVER_VPN_IP:5044"
echo "  [6] SSH Hardening    : PasswordAuth=no, RootLogin=prohibit-password"
echo "  ─────────────────────────────────────────────────────────────────"
echo ""
echo "  Langkah selanjutnya:"
echo "  1. Pastikan tunnel VPN ke SOC Server ($SOC_SERVER_VPN_IP) aktif"
echo "  2. Daftarkan agent di Wazuh Manager (jika belum otomatis)"
echo "  3. Periksa log Suricata   : tail -f /var/log/suricata/eve.json"
echo "  4. Periksa log Filebeat   : tail -f /var/log/filebeat/filebeat.log"
echo "  5. Periksa status Wazuh   : systemctl status wazuh-agent"
echo ""
