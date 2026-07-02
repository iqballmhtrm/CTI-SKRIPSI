#!/var/ossec/framework/python/bin/python3
import sys, json, requests
from datetime import datetime, timedelta

def main(args):
    alert_file = args[1]
    hook_url = "https://api.telegram.org/bot<TOKEN_RAHASIA_DI_SERVER>/sendMessage"
    chat_id = "<CHAT_ID>"

    with open(alert_file) as f:
        alert = json.load(f)

    rule = alert.get("rule", {})
    rule_desc = rule.get("description", "Aktivitas mencurigakan")
    severity = int(rule.get("level", 0))
    groups = [g.lower() for g in rule.get("groups", [])]
    timestamp = alert.get("timestamp", "")
    src_ip = alert.get("data", {}).get("srcip", "Tidak diketahui")
    agent_name = alert.get("agent", {}).get("name", "server")

    # --- Tingkat bahaya (bahasa awam) ---
    if severity >= 12:
        bahaya = "SANGAT TINGGI \U0001F534"
    elif severity >= 10:
        bahaya = "TINGGI \U0001F534"
    elif severity >= 7:
        bahaya = "SEDANG \U0001F7E0"
    else:
        bahaya = "RENDAH \U0001F7E1"

    # --- Terjemahkan jenis serangan ke bahasa mudah ---
    desc_l = rule_desc.lower()
    if any(g in groups for g in ("authentication_failures", "authentication_failed")) or "brute force" in desc_l:
        jenis = "Upaya Pembobolan Kata Sandi"
        penjelasan = ("Ada pihak yang mencoba menebak kata sandi untuk masuk "
                      "ke sistem secara paksa dan berulang kali.")
    elif "sql_injection" in groups or "sql injection" in desc_l:
        jenis = "Upaya Pencurian Data"
        penjelasan = ("Ada pihak yang mencoba mencuri data melalui celah "
                      "pada database server.")
    elif "web_attack" in groups or "web" in desc_l:
        jenis = "Upaya Serangan ke Situs Web"
        penjelasan = ("Ada pihak yang mencoba menyerang atau merusak "
                      "situs web pada server.")
    elif "command_injection" in groups:
        jenis = "Upaya Penyusupan Perintah"
        penjelasan = ("Ada pihak yang mencoba menjalankan perintah "
                      "berbahaya pada server.")
    elif "privilege_escalation" in groups:
        jenis = "Upaya Mengambil Alih Hak Akses"
        penjelasan = ("Ada pihak yang mencoba mendapatkan hak akses "
                      "administrator secara ilegal.")
    else:
        jenis = "Aktivitas Serangan Terdeteksi"
        penjelasan = "Terdeteksi aktivitas mencurigakan yang berpotensi membahayakan sistem."

    # --- Waktu ke WIB (UTC+7), format Indonesia ---
    waktu_str = timestamp
    try:
        ts = timestamp.replace("Z", "+0000")
        dt = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S") + timedelta(hours=7)
        bulan = ["Januari","Februari","Maret","April","Mei","Juni","Juli",
                 "Agustus","September","Oktober","November","Desember"]
        waktu_str = f"{dt.day:02d} {bulan[dt.month-1]} {dt.year}, {dt.hour:02d}:{dt.minute:02d} WIB"
    except Exception:
        pass

    # --- Susun pesan sederhana ---
    m  = "\U0001F6A8 *PERINGATAN KEAMANAN*\n"
    m += "────────────────────\n\n"
    m += f"*{jenis}*\n\n"
    m += f"\U0001F534 Tingkat Bahaya : *{bahaya}*\n"
    m += f"\U0001F4CD Asal Serangan  : `{src_ip}`\n"
    m += f"\U0001F3AF Server Sasaran : `{agent_name}`\n"
    m += f"\U0001F550 Waktu          : {waktu_str}\n\n"
    m += f"\U0001F4AC *Penjelasan:*\n{penjelasan}\n\n"
    m += "✅ *Tindakan Sistem:*\nAlamat penyerang sudah otomatis diblokir.\n\n"
    m += "\U0001F449 Mohon segera diperiksa oleh tim keamanan."

    payload = {"chat_id": chat_id, "text": m, "parse_mode": "Markdown"}
    try:
        requests.post(hook_url, json=payload, timeout=10)
    except Exception:
        pass

if __name__ == "__main__":
    main(sys.argv)
