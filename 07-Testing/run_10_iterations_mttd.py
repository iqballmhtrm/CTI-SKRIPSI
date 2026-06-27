#!/usr/bin/env python3
import time
import datetime
import subprocess
import json
import urllib.request
import urllib.error
import uuid
import csv
import os

# Konfigurasi
ES_URL = "http://192.168.56.10:9200/*/_search" # Cari di semua index lokal
LOG_FILE = "/var/log/suricata/eve.json"
TOTAL_ITERASI = 10
DELAY_ANTAR_ITERASI = 2 # detik

results = []

print("======================================================")
print(f"🚀 Memulai Pengujian {TOTAL_ITERASI} Iterasi MTTD Otomatis")
print("======================================================")

# Memastikan log file bisa diakses (butuh sudo jika permission denied)
# Kita pakai sudo tee -a agar aman

for i in range(1, TOTAL_ITERASI + 1):
    # 1. Buat UUID unik untuk melacak log ini sampai masuk ke Elasticsearch
    attack_uuid = str(uuid.uuid4())
    timestamp_iso = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    
    # 2. Catat Waktu Awal (T0)
    t0_wallclock = time.time()
    
    # 3. Inject log palsu ke Suricata eve.json
    payload = {
        "timestamp": timestamp_iso,
        "event_type": "alert",
        "src_ip": "10.10.10.99",
        "dest_ip": "192.168.56.10",
        "alert": {
            "signature_id": 9000002, 
            "signature": f"CTI-LAB SSH Bruteforce Iteration {i} [{attack_uuid}]",
            "severity": 1
        }
    }
    payload_str = json.dumps(payload)
    cmd = f"echo '{payload_str}' | sudo tee -a {LOG_FILE} > /dev/null"
    
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError:
        print(f"❌ [Error] Gagal menulis ke {LOG_FILE}. Pastikan script dijalankan dengan sudo atau user punya akses.")
        break
        
    print(f"⏳ Iterasi {i}/{TOTAL_ITERASI} - Log diinjeksi (T0). Menunggu Logstash & Elasticsearch...")
    
    # 4. Loop melakukan query ke Elasticsearch mencari UUID tersebut
    t1_wallclock = None
    query_payload = json.dumps({
        "query": {
            "match_phrase": {
                "alert.signature": attack_uuid
            }
        }
    }).encode('utf-8')
    
    req = urllib.request.Request(ES_URL, data=query_payload, headers={'Content-Type': 'application/json'})
    
    while True:
        try:
            resp = urllib.request.urlopen(req)
            data = json.loads(resp.read().decode('utf-8'))
            if data['hits']['total']['value'] > 0:
                t1_wallclock = time.time() # T1: Log berhasil terindeks & terbaca
                break
        except Exception as e:
            pass # Abaikan error jika ES belum merespons
            
        time.sleep(0.1) # Cek setiap 100ms
        
        if time.time() - t0_wallclock > 15: # Timeout jika >15 detik
            print(f"⚠️ Iterasi {i} Timeout! (Log tidak muncul di ES dalam 15 detik)")
            break
            
    # 5. Kalkulasi MTTD
    if t1_wallclock:
        mttd = t1_wallclock - t0_wallclock
        print(f"✅ Iterasi {i} Selesai! MTTD: {mttd:.4f} detik")
        results.append((i, mttd))
    else:
        results.append((i, None))
        
    time.sleep(DELAY_ANTAR_ITERASI)

# 6. Kalkulasi Statistik & Simpan
print("\n======================================================")
print("📊 HASIL PENGUJIAN 10 ITERASI MTTD (VirtualBox Lokal)")
print("======================================================")

valid_mttds = [x[1] for x in results if x[1] is not None]
if valid_mttds:
    avg_mttd = sum(valid_mttds) / len(valid_mttds)
    min_mttd = min(valid_mttds)
    max_mttd = max(valid_mttds)
    
    print(f"Rata-rata MTTD (Average) : {avg_mttd:.4f} detik")
    print(f"MTTD Tercepat (Min)      : {min_mttd:.4f} detik")
    print(f"MTTD Terlama (Max)       : {max_mttd:.4f} detik")
else:
    print("Tidak ada data valid yang tertangkap.")

csv_filename = os.path.join(os.path.dirname(__file__), 'hasil_uji_mttd_10_iterasi.csv')
with open(csv_filename, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Iterasi', 'MTTD_Detik'])
    for r in results:
        writer.writerow([r[0], f"{r[1]:.4f}" if r[1] else "Timeout"])

print(f"\n💾 Data mentah CSV berhasil disimpan ke: {csv_filename}")
print("Data CSV ini siap dimasukkan ke dalam Tabel Bab 4 Skripsi Anda!")
