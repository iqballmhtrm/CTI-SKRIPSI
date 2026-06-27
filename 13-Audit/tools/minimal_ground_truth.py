#!/usr/bin/env python3
"""
DATASET COMPOSITION FORENSIC AUDIT
Minimal Ground Truth Query - READ ONLY

Tujuan: Menentukan komposisi dataset aktual tanpa modifikasi apapun.
"""

import sqlite3
import json
from collections import Counter

DB_PATH = '/home/iqbal/soar-dashboard/app/incidents.db'

print("=" * 60)
print("DATASET COMPOSITION REPORT")
print("=" * 60)
print()

try:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # A. TOTAL EVENTS
        print("[A] TOTAL EVENTS")
        cursor.execute("SELECT COUNT(*) as total FROM incidents")
        total_events = cursor.fetchone()['total']
        print(f"Total Incident: {total_events:,}")
        print()
        
        # B. DISTRIBUSI STATUS
        print("[B] DISTRIBUSI STATUS")
        cursor.execute("SELECT status, COUNT(*) as count FROM incidents GROUP BY status ORDER BY count DESC")
        status_rows = cursor.fetchall()
        for row in status_rows:
            percentage = (row['count'] / total_events * 100) if total_events > 0 else 0
            print(f"  {row['status']:20s}: {row['count']:8,} ({percentage:5.2f}%)")
        print()
        
        # C. DISTRIBUSI MITRE
        print("[C] DISTRIBUSI MITRE")
        cursor.execute("SELECT mitre_status, COUNT(*) as count FROM incidents GROUP BY mitre_status ORDER BY count DESC")
        mitre_rows = cursor.fetchall()
        for row in mitre_rows:
            percentage = (row['count'] / total_events * 100) if total_events > 0 else 0
            status = row['mitre_status'] if row['mitre_status'] else 'NULL'
            print(f"  {status:20s}: {row['count']:8,} ({percentage:5.2f}%)")
        print()
        
        # D. TOP 20 ATTACK TYPE
        print("[D] TOP 20 ATTACK TYPE")
        cursor.execute("SELECT attack_type, COUNT(*) as count FROM incidents GROUP BY attack_type ORDER BY count DESC LIMIT 20")
        attack_rows = cursor.fetchall()
        for idx, row in enumerate(attack_rows, 1):
            percentage = (row['count'] / total_events * 100) if total_events > 0 else 0
            print(f"  {idx:2d}. {row['attack_type'][:50]:50s}: {row['count']:8,} ({percentage:5.2f}%)")
        print()
        
        # E. TOP 20 SOURCE IP
        print("[E] TOP 20 SOURCE IP")
        cursor.execute("SELECT src_ip, COUNT(*) as count FROM incidents GROUP BY src_ip ORDER BY count DESC LIMIT 20")
        ip_rows = cursor.fetchall()
        for idx, row in enumerate(ip_rows, 1):
            percentage = (row['count'] / total_events * 100) if total_events > 0 else 0
            print(f"  {idx:2d}. {row['src_ip']:20s}: {row['count']:8,} ({percentage:5.2f}%)")
        print()
        
        # F. RENTANG WAKTU DATA
        print("[F] RENTANG WAKTU DATA")
        cursor.execute("SELECT MIN(timestamp) as earliest, MAX(timestamp) as latest FROM incidents")
        time_row = cursor.fetchone()
        print(f"  Earliest: {time_row['earliest']}")
        print(f"  Latest  : {time_row['latest']}")
        print()
        
        # G. SAMPLE 100 ACAK - KLASIFIKASI
        print("[G] KLASIFIKASI 100 SAMPLE ACAK")
        cursor.execute("SELECT attack_type FROM incidents ORDER BY RANDOM() LIMIT 100")
        samples = [row['attack_type'].lower() for row in cursor.fetchall()]
        
        research_count = 0
        noise_count = 0
        system_count = 0
        duplicate_count = 0
        unknown_count = 0
        
        for attack in samples:
            # Research events: Nmap, Hydra, Nikto, brute force, scan
            if any(keyword in attack for keyword in ['nmap', 'hydra', 'nikto', 'brute', 'scan', 'web vulnerability', 'reconnaissance']):
                research_count += 1
            # Operational noise: Suricata stream events, wazuh, ossec
            elif any(keyword in attack for keyword in ['suricata stream', 'packet out of window', 'invalid ack', 'wazuh', 'ossec']):
                noise_count += 1
            # System events: PAM, session, login, sshd
            elif any(keyword in attack for keyword in ['pam', 'session', 'login', 'sshd']):
                system_count += 1
            else:
                unknown_count += 1
        
        print(f"  Research Event      : {research_count:3d} / 100 ({research_count}%)")
        print(f"  Operational Noise   : {noise_count:3d} / 100 ({noise_count}%)")
        print(f"  System Event        : {system_count:3d} / 100 ({system_count}%)")
        print(f"  Unknown             : {unknown_count:3d} / 100 ({unknown_count}%)")
        print()
        
        # H. KESIMPULAN DATASET
        print("=" * 60)
        print("[H] KESIMPULAN DATASET")
        print("=" * 60)
        
        # Hitung persentase MITRE Mapped
        cursor.execute("SELECT COUNT(*) as count FROM incidents WHERE mitre_status = 'Mapped'")
        mapped_count = cursor.fetchone()['count']
        mapped_percentage = (mapped_count / total_events * 100) if total_events > 0 else 0
        
        print(f"Total Event             : {total_events:,}")
        print(f"Research Event (est.)   : ~{research_count}% dari sample")
        print(f"Operational Noise (est.): ~{noise_count}% dari sample")
        print(f"MITRE Mapped            : {mapped_count:,} ({mapped_percentage:.2f}%)")
        print()
        
        # Kriteria kelayakan dataset penelitian
        print("[PENILAIAN KELAYAKAN DATASET]")
        print()
        
        is_research_dominant = research_count >= 80  # Minimal 80% research event
        is_mitre_mapped = mapped_percentage >= 80     # Minimal 80% mapped ke MITRE
        is_noise_low = noise_count <= 20              # Maksimal 20% noise
        
        print(f"✓ Research Event Dominant (≥80%)  : {'PASS' if is_research_dominant else 'FAIL'} ({research_count}%)")
        print(f"✓ MITRE Mapping Complete (≥80%)   : {'PASS' if is_mitre_mapped else 'FAIL'} ({mapped_percentage:.2f}%)")
        print(f"✓ Operational Noise Low (≤20%)    : {'PASS' if is_noise_low else 'FAIL'} ({noise_count}%)")
        print()
        
        if is_research_dominant and is_mitre_mapped and is_noise_low:
            verdict = "LAYAK - Dataset memenuhi standar penelitian"
        elif mapped_percentage < 50:
            verdict = "TIDAK LAYAK - MITRE mapping tidak memadai"
        elif noise_count > 50:
            verdict = "TIDAK LAYAK - Terlalu banyak operational noise"
        else:
            verdict = "MEMERLUKAN PEMBERSIHAN - Dataset perlu filtering"
        
        print(f"VERDICT: {verdict}")
        print()

except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()

print("=" * 60)
print("END OF REPORT")
print("=" * 60)
