import sqlite3
import json

db_path = '/home/iqbal/soar-dashboard/app/incidents.db'
try:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT count(*) as count, avg(mttd_seconds) as avg_mttd, min(mttd_seconds) as min_mttd, max(mttd_seconds) as max_mttd FROM incidents WHERE mttd_seconds IS NOT NULL")
        mttd_stats = dict(cursor.fetchone())
        
        cursor.execute("SELECT count(*) as count, avg(mttr_seconds) as avg_mttr, min(mttr_seconds) as min_mttr, max(mttr_seconds) as max_mttr FROM incidents WHERE status='Resolved' AND mttr_seconds IS NOT NULL")
        mttr_stats = dict(cursor.fetchone())
        
        print(json.dumps({
            "mttd": mttd_stats,
            "mttr": mttr_stats
        }, indent=2))
except Exception as e:
    print("Error:", str(e))
