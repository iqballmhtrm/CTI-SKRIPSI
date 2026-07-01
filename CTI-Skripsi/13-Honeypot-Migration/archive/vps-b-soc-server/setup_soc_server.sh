#!/bin/bash
# =============================================================================
# Setup SOC Server (VPS B) - CTI Honeypot Skripsi Iqbal
# =============================================================================
# Deskripsi : Script untuk menginstal dan mengkonfigurasi komponen SOC Server
#             pada VPS B. Server ini menerima log dari VPS A (honeypot) melalui
#             VPN Tailscale, lalu menganalisis dan memvisualisasikan data.
#
# Komponen  : Elasticsearch 8.x, Logstash, Kibana, Wazuh Manager,
#             Python3/Flask (SOAR Dashboard)
#
# PENTING   : Script ini TIDAK menjalankan service secara otomatis.
#             Review konfigurasi terlebih dahulu sebelum memulai service.
# =============================================================================

set -euo pipefail

# =============================================================================
# BAGIAN KONFIGURASI - ISI SEBELUM MENJALANKAN SCRIPT
# =============================================================================
# IP VPN Tailscale dari VPS A (honeypot) - untuk whitelist firewall
HONEYPOT_VPN_IP="GANTI_DENGAN_IP_VPN_HONEYPOT"

# Password untuk Elasticsearch built-in user 'elastic'
# Gunakan password yang kuat minimal 16 karakter
ES_PASSWORD="GANTI_DENGAN_PASSWORD_ELASTICSEARCH"

# Direktori kerja untuk file konfigurasi pipeline dan dictionary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# FUNGSI UTILITAS
# =============================================================================

# Warna untuk output terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[i] $1${NC}"
}

# =============================================================================
# VALIDASI AWAL
# =============================================================================

print_header "VALIDASI PRA-INSTALASI"

# Pastikan script dijalankan sebagai root
if [[ $EUID -ne 0 ]]; then
    print_error "Script ini harus dijalankan sebagai root (gunakan sudo)"
    exit 1
fi

# Validasi placeholder sudah diganti
if [[ "$HONEYPOT_VPN_IP" == "GANTI_DENGAN_IP_VPN_HONEYPOT" ]]; then
    print_error "HONEYPOT_VPN_IP belum dikonfigurasi!"
    print_warning "Edit script ini dan ganti nilai HONEYPOT_VPN_IP dengan IP VPN Tailscale VPS A"
    exit 1
fi

if [[ "$ES_PASSWORD" == "GANTI_DENGAN_PASSWORD_ELASTICSEARCH" ]]; then
    print_error "ES_PASSWORD belum dikonfigurasi!"
    print_warning "Edit script ini dan ganti nilai ES_PASSWORD dengan password yang kuat"
    exit 1
fi

print_success "Validasi konfigurasi berhasil"
print_info "HONEYPOT_VPN_IP : $HONEYPOT_VPN_IP"
print_info "ES_PASSWORD     : ********** (tersembunyi)"

# =============================================================================
# LANGKAH 1: UPDATE SISTEM DAN INSTAL DEPENDENSI DASAR
# =============================================================================

print_header "LANGKAH 1: Update Sistem & Dependensi Dasar"

echo "[*] Memperbarui daftar paket dan mengupgrade sistem..."
apt-get update -y
apt-get upgrade -y

echo "[*] Menginstal dependensi dasar..."
apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
    wget \
    unzip \
    jq \
    ufw

print_success "Dependensi dasar berhasil diinstal"

# =============================================================================
# LANGKAH 2: INSTAL JAVA (DIBUTUHKAN ELASTICSEARCH & LOGSTASH)
# =============================================================================

print_header "LANGKAH 2: Instal OpenJDK 17"

echo "[*] Menginstal OpenJDK 17..."
apt-get install -y openjdk-17-jdk

# Verifikasi instalasi Java
java -version 2>&1 | head -1
print_success "OpenJDK 17 berhasil diinstal"

# =============================================================================
# LANGKAH 3: INSTAL ELASTICSEARCH 8.x
# =============================================================================

print_header "LANGKAH 3: Instal Elasticsearch 8.x"

# Tambahkan GPG key dan repository Elastic
echo "[*] Menambahkan repository Elastic APT..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg 2>/dev/null || true

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list

apt-get update -y

echo "[*] Menginstal Elasticsearch..."
apt-get install -y elasticsearch

print_success "Elasticsearch 8.x berhasil diinstal"

# =============================================================================
# LANGKAH 4: KONFIGURASI ELASTICSEARCH
# =============================================================================

print_header "LANGKAH 4: Konfigurasi Elasticsearch"

# --- Konfigurasi JVM Heap Size ---
# Sesuaikan heap size berdasarkan RAM VPS (rekomendasi: 50% RAM, maks 2GB untuk VPS kecil)
echo "[*] Mengatur JVM heap size Elasticsearch ke 2GB..."
cat > /etc/elasticsearch/jvm.options.d/heap.options << 'EOF'
# =============================================================================
# Konfigurasi JVM Heap Elasticsearch - CTI SOC Server
# =============================================================================
# Heap dialokasikan 2GB (sesuaikan dengan kapasitas RAM VPS)
# Aturan: jangan melebihi 50% dari total RAM
# =============================================================================
-Xms2g
-Xmx2g
EOF

print_success "JVM heap size diatur ke 2GB"

# --- Konfigurasi elasticsearch.yml ---
# Mengaktifkan fitur keamanan dan binding ke localhost
echo "[*] Mengkonfigurasi elasticsearch.yml..."
cat > /etc/elasticsearch/elasticsearch.yml << EOF
# =============================================================================
# Konfigurasi Elasticsearch - CTI SOC Server (VPS B)
# =============================================================================
# Dihasilkan oleh setup_soc_server.sh
# Tanggal: $(date '+%Y-%m-%d %H:%M:%S')
# =============================================================================

# --- Pengaturan Cluster ---
cluster.name: cti-soc-cluster
node.name: soc-node-1

# --- Pengaturan Path ---
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# --- Pengaturan Jaringan ---
# Bind ke localhost saja - akses dari luar melalui VPN/SSH tunnel
network.host: 127.0.0.1
http.port: 9200

# --- Pengaturan Discovery ---
# Single-node deployment (tidak perlu cluster discovery)
discovery.type: single-node

# --- Pengaturan Keamanan ---
# Mengaktifkan fitur keamanan bawaan Elasticsearch 8.x
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# Komunikasi antar-node (nonaktifkan SSL untuk single-node)
xpack.security.transport.ssl.enabled: false

# HTTPS untuk API (opsional, bisa diaktifkan jika diperlukan)
xpack.security.http.ssl.enabled: false

# --- Pengaturan Monitoring ---
xpack.monitoring.collection.enabled: true
EOF

print_success "Konfigurasi elasticsearch.yml berhasil ditulis"

# --- Set password untuk user elastic ---
echo "[*] Menyiapkan script untuk set password Elasticsearch..."
cat > /root/set_es_password.sh << EOFSCRIPT
#!/bin/bash
# Jalankan script ini SETELAH Elasticsearch berjalan untuk pertama kali
# Elasticsearch harus sudah running sebelum menjalankan script ini

echo "[*] Mengatur password user 'elastic'..."
echo "y" | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i -b <<< "$ES_PASSWORD
$ES_PASSWORD"

echo "[✓] Password user elastic berhasil diatur"
echo "[i] Gunakan password ini untuk login ke Kibana dan konfigurasi lainnya"
EOFSCRIPT
chmod +x /root/set_es_password.sh

print_warning "Jalankan /root/set_es_password.sh SETELAH Elasticsearch pertama kali distart"

# =============================================================================
# LANGKAH 5: INSTAL LOGSTASH
# =============================================================================

print_header "LANGKAH 5: Instal Logstash"

echo "[*] Menginstal Logstash..."
apt-get install -y logstash

print_success "Logstash berhasil diinstal"

# --- Salin file konfigurasi pipeline ---
echo "[*] Menyalin file pipeline Logstash..."
if [[ -f "${SCRIPT_DIR}/soc-pipeline.conf" ]]; then
    cp "${SCRIPT_DIR}/soc-pipeline.conf" /etc/logstash/conf.d/soc-pipeline.conf
    chown logstash:logstash /etc/logstash/conf.d/soc-pipeline.conf
    print_success "Pipeline soc-pipeline.conf berhasil disalin ke /etc/logstash/conf.d/"
else
    print_warning "File soc-pipeline.conf tidak ditemukan di ${SCRIPT_DIR}"
    print_warning "Salin file pipeline secara manual ke /etc/logstash/conf.d/"
fi

# --- Salin file dictionary MITRE ATT&CK ---
echo "[*] Menyalin file dictionary MITRE ATT&CK..."
mkdir -p /etc/logstash/dictionaries

if [[ -f "${SCRIPT_DIR}/mitre-name.yml" ]]; then
    cp "${SCRIPT_DIR}/mitre-name.yml" /etc/logstash/dictionaries/mitre-name.yml
    print_success "mitre-name.yml berhasil disalin"
else
    print_warning "File mitre-name.yml tidak ditemukan di ${SCRIPT_DIR}"
fi

if [[ -f "${SCRIPT_DIR}/mitre-tactic.yml" ]]; then
    cp "${SCRIPT_DIR}/mitre-tactic.yml" /etc/logstash/dictionaries/mitre-tactic.yml
    print_success "mitre-tactic.yml berhasil disalin"
else
    print_warning "File mitre-tactic.yml tidak ditemukan di ${SCRIPT_DIR}"
fi

# Set permission dictionary files
chown -R logstash:logstash /etc/logstash/dictionaries/
chmod 644 /etc/logstash/dictionaries/*.yml 2>/dev/null || true

print_success "File dictionary MITRE berhasil dikonfigurasi"

# =============================================================================
# LANGKAH 6: INSTAL KIBANA
# =============================================================================

print_header "LANGKAH 6: Instal Kibana"

echo "[*] Menginstal Kibana..."
apt-get install -y kibana

print_success "Kibana berhasil diinstal"

# --- Konfigurasi Kibana ---
echo "[*] Mengkonfigurasi kibana.yml..."

# Generate encryption key untuk encryptedSavedObjects
KIBANA_ENCRYPTION_KEY=$(openssl rand -hex 16)

cat > /etc/kibana/kibana.yml << EOF
# =============================================================================
# Konfigurasi Kibana - CTI SOC Server (VPS B)
# =============================================================================
# Dihasilkan oleh setup_soc_server.sh
# Tanggal: $(date '+%Y-%m-%d %H:%M:%S')
# =============================================================================

# --- Pengaturan Server ---
# Bind ke localhost saja - akses dari luar melalui SSH tunnel atau reverse proxy
server.host: "localhost"
server.port: 5601
server.name: "cti-soc-kibana"

# --- Koneksi ke Elasticsearch ---
elasticsearch.hosts: ["http://127.0.0.1:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "${ES_PASSWORD}"

# --- Pengaturan Keamanan ---
# Encryption key untuk saved objects (alerts, actions, connectors)
xpack.encryptedSavedObjects.encryptionKey: "${KIBANA_ENCRYPTION_KEY}"

# --- Pengaturan Logging ---
logging.appenders.default:
  type: console
  layout:
    type: pattern
    highlight: true

# --- Pengaturan Lainnya ---
# Bahasa antarmuka (opsional)
# i18n.locale: "en"
EOF

print_success "Konfigurasi kibana.yml berhasil ditulis"
print_info "Encryption Key Kibana: ${KIBANA_ENCRYPTION_KEY} (simpan dengan aman!)"

# =============================================================================
# LANGKAH 7: INSTAL WAZUH MANAGER
# =============================================================================

print_header "LANGKAH 7: Instal Wazuh Manager"

# Tambahkan GPG key dan repository Wazuh
echo "[*] Menambahkan repository Wazuh..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh-keyring.gpg 2>/dev/null || true

echo "deb [signed-by=/usr/share/keyrings/wazuh-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

apt-get update -y

echo "[*] Menginstal Wazuh Manager..."
apt-get install -y wazuh-manager

print_success "Wazuh Manager berhasil diinstal"

# --- Konfigurasi dasar Wazuh Manager ---
echo "[*] Mengkonfigurasi Wazuh Manager untuk menerima koneksi dari VPS A..."

# Pastikan Wazuh Manager mendengarkan koneksi agent
# Port default: 1514 (UDP) untuk komunikasi agent, 1515 (TCP) untuk registrasi
print_info "Wazuh Manager akan mendengarkan pada:"
print_info "  - Port 1514 (agent communication)"
print_info "  - Port 1515 (agent registration)"
print_info "  - Port 55000 (Wazuh API)"

print_warning "Setelah Wazuh Manager distart, daftarkan agent VPS A dengan:"
print_warning "  /var/ossec/bin/manage_agents (di VPS B)"
print_warning "  Atau gunakan Wazuh API untuk registrasi otomatis"

# =============================================================================
# LANGKAH 8: KONFIGURASI FIREWALL (UFW)
# =============================================================================

print_header "LANGKAH 8: Konfigurasi Firewall (UFW)"

echo "[*] Mengkonfigurasi aturan UFW..."

# Reset UFW ke default (opsional, hati-hati jika sudah ada rules)
# ufw --force reset

# Kebijakan default: tolak semua koneksi masuk, izinkan semua keluar
ufw default deny incoming
ufw default allow outgoing
print_success "Default policy: deny incoming, allow outgoing"

# Izinkan SSH (port 22) - PENTING: jangan sampai terkunci!
ufw allow 22/tcp comment 'SSH Access'
print_success "SSH (port 22/tcp) diizinkan"

# Izinkan semua traffic pada interface Tailscale VPN (tailscale0)
# Ini memungkinkan komunikasi internal antara VPS A dan VPS B melalui VPN
ufw allow in on tailscale0 comment 'Tailscale VPN - semua traffic internal'
print_success "Semua traffic pada interface tailscale0 diizinkan"

# Tolak akses publik ke Kibana (port 5601) - hanya bisa diakses via SSH tunnel/VPN
ufw deny 5601 comment 'Kibana - blokir akses publik, gunakan SSH tunnel'
print_success "Kibana (port 5601) diblokir dari publik"

# Tolak akses publik ke SOAR webhook (port 5000) - hanya bisa diakses lokal
ufw deny 5000 comment 'SOAR Webhook - blokir akses publik, hanya lokal'
print_success "SOAR Webhook (port 5000) diblokir dari publik"

# Aktifkan UFW (non-interaktif)
echo "[*] Mengaktifkan UFW..."
echo "y" | ufw enable
print_success "UFW berhasil diaktifkan"

# Tampilkan status firewall
echo ""
echo "[*] Status UFW saat ini:"
ufw status verbose
echo ""

# =============================================================================
# LANGKAH 9: INSTAL PYTHON3, PIP, DAN FLASK (UNTUK SOAR DASHBOARD)
# =============================================================================

print_header "LANGKAH 9: Instal Python3, pip, dan Flask (SOAR Dashboard)"

echo "[*] Menginstal Python3 dan pip..."
apt-get install -y python3 python3-pip python3-venv

# Buat virtual environment untuk SOAR Dashboard
echo "[*] Membuat virtual environment untuk SOAR Dashboard..."
mkdir -p /opt/soar-dashboard
python3 -m venv /opt/soar-dashboard/venv

# Instal Flask dan dependensi di dalam virtual environment
echo "[*] Menginstal Flask dan dependensi..."
/opt/soar-dashboard/venv/bin/pip install --upgrade pip
/opt/soar-dashboard/venv/bin/pip install \
    flask \
    flask-cors \
    requests \
    gunicorn

print_success "Python3, pip, dan Flask berhasil diinstal"
print_info "Virtual environment SOAR: /opt/soar-dashboard/venv"
print_info "Aktivasi: source /opt/soar-dashboard/venv/bin/activate"

# =============================================================================
# LANGKAH 10: SALIN ILM POLICY
# =============================================================================

print_header "LANGKAH 10: Persiapan ILM Policy"

if [[ -f "${SCRIPT_DIR}/ilm-policy.json" ]]; then
    cp "${SCRIPT_DIR}/ilm-policy.json" /root/ilm-policy.json
    print_success "File ilm-policy.json berhasil disalin ke /root/"
    print_warning "Terapkan ILM policy SETELAH Elasticsearch berjalan dengan perintah:"
    echo ""
    echo "  curl -X PUT 'http://127.0.0.1:9200/_ilm/policy/cti-logs-policy' \\"
    echo "    -u elastic:${ES_PASSWORD} \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d @/root/ilm-policy.json"
    echo ""
else
    print_warning "File ilm-policy.json tidak ditemukan di ${SCRIPT_DIR}"
fi

# =============================================================================
# LANGKAH 11: ENABLE SERVICES (TANPA START)
# =============================================================================

print_header "LANGKAH 11: Enable Services (Boot Otomatis)"

echo "[*] Mengaktifkan service untuk start otomatis saat boot..."

systemctl daemon-reload
systemctl enable elasticsearch
systemctl enable logstash
systemctl enable kibana
systemctl enable wazuh-manager

print_success "Semua service di-enable untuk start saat boot"
print_warning "Service BELUM dijalankan - review konfigurasi terlebih dahulu!"

# =============================================================================
# RINGKASAN INSTALASI
# =============================================================================

print_header "INSTALASI SELESAI - RINGKASAN"

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              SOC SERVER (VPS B) - SIAP DIKONFIGURASI        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Komponen yang terinstal:"
echo "  ✓ Elasticsearch 8.x    (port 9200, localhost only)"
echo "  ✓ Logstash              (pipeline: soc-pipeline.conf)"
echo "  ✓ Kibana                (port 5601, localhost only)"
echo "  ✓ Wazuh Manager         (port 1514/1515/55000)"
echo "  ✓ Python3 + Flask       (/opt/soar-dashboard/venv)"
echo "  ✓ UFW Firewall          (aktif, SSH + Tailscale diizinkan)"
echo ""
echo "File konfigurasi:"
echo "  • /etc/elasticsearch/elasticsearch.yml"
echo "  • /etc/elasticsearch/jvm.options.d/heap.options"
echo "  • /etc/kibana/kibana.yml"
echo "  • /etc/logstash/conf.d/soc-pipeline.conf"
echo "  • /etc/logstash/dictionaries/mitre-name.yml"
echo "  • /etc/logstash/dictionaries/mitre-tactic.yml"
echo ""
echo -e "${YELLOW}LANGKAH SELANJUTNYA (URUTAN PENTING):${NC}"
echo ""
echo "  1. Review semua file konfigurasi di atas"
echo ""
echo "  2. Start Elasticsearch terlebih dahulu:"
echo "     sudo systemctl start elasticsearch"
echo ""
echo "  3. Set password Elasticsearch:"
echo "     sudo /root/set_es_password.sh"
echo ""
echo "  4. Terapkan ILM policy:"
echo "     curl -X PUT 'http://127.0.0.1:9200/_ilm/policy/cti-logs-policy' \\"
echo "       -u elastic:YOUR_PASSWORD \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d @/root/ilm-policy.json"
echo ""
echo "  5. Set password kibana_system user:"
echo "     /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -i"
echo ""
echo "  6. Start Kibana:"
echo "     sudo systemctl start kibana"
echo ""
echo "  7. Start Logstash:"
echo "     sudo systemctl start logstash"
echo ""
echo "  8. Start Wazuh Manager:"
echo "     sudo systemctl start wazuh-manager"
echo ""
echo "  9. Akses Kibana via SSH tunnel:"
echo "     ssh -L 5601:localhost:5601 user@VPS_B_IP"
echo "     Lalu buka: http://localhost:5601"
echo ""
echo -e "${BLUE}Encryption Key Kibana: ${KIBANA_ENCRYPTION_KEY}${NC}"
echo -e "${YELLOW}(Simpan encryption key ini dengan aman!)${NC}"
echo ""
print_success "Script selesai. Tidak ada service yang dijalankan secara otomatis."
