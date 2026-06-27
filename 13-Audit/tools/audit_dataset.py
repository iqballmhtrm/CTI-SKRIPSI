import sqlite3
import json

DB_PATH = '/home/iqbal/soar-dashboard/app/incidents.db'

print("=== AUDIT INCIDENTS.DB ===")
try:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # 1. Total incident
        cursor.execute("SELECT COUNT(*) as count FROM incidents")
        total = cursor.fetchone()['count']
        print(f"Total Incident: {total}")
        
        # 2. Distribusi status
        cursor.execute("SELECT status, COUNT(*) as count FROM incidents GROUP BY status")
        print("\nDistribusi Status:")
        for row in cursor.fetchall():
            print(f" - {row['status']}: {row['count']}")
            
        # 3. Distribusi attack type
        cursor.execute("SELECT attack_type, COUNT(*) as count FROM incidents GROUP BY attack_type ORDER BY count DESC")
        print("\nDistribusi Attack Type (Top 10):")
        for row in cursor.fetchall()[:10]:
            print(f" - {row['attack_type']}: {row['count']}")
            
        # 4. Ambil 100 sample acak & kelompokkan
        cursor.execute("SELECT attack_type FROM incidents ORDER BY RANDOM() LIMIT 100")
        samples = cursor.fetchall()
        
        valid_data = 0
        ops_noise = 0
        sys_event = 0
        unknown = 0
        
        for s in samples:
            at = s['attack_type'].lower()
            if 'nmap' in at or 'hydra' in at or 'nikto' in at or 'brute' in at or 'scan' in at or 'web' in at:
                valid_data += 1
            elif 'pam' in at or 'session' in at or 'login' in at or 'sshd' in at:
                sys_event += 1
            elif 'wazuh' in at or 'ossec' in at or 'rule' in at or 'integrity' in at:
                ops_noise += 1
            else:
                unknown += 1
                
        print(f"\nKlasifikasi dari 100 Sample Acak:")
        print(f" - Valid Research Data: {valid_data}%")
        print(f" - System Event: {sys_event}%")
        print(f" - Operational Noise: {ops_noise}%")
        print(f" - Unknown: {unknown}%")

except Exception as e:
    print(f"DB Error: {e}")
