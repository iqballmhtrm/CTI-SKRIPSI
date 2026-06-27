import sqlite3

try:
    conn = sqlite3.connect('/home/iqbal/soar-dashboard/app/incidents.db')
    c = conn.cursor()
    for row in c.execute('SELECT id, timestamp, src_ip, attack_type, mitre_technique, mitre_status FROM incidents ORDER BY id DESC LIMIT 5;'):
        print(row)
except Exception as e:
    print(e)
