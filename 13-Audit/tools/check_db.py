import sqlite3
import json

db_path = '/home/iqbal/soar-dashboard/app/incidents.db'
try:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT mitre_technique, count(*) as count FROM incidents GROUP BY mitre_technique")
        mitre_data = [dict(r) for r in cursor.fetchall()]
        
        print(json.dumps({
            "mitre_stats": mitre_data
        }))
except Exception as e:
    print(str(e))
