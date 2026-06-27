import sqlite3

db_path = '/home/iqbal/soar-dashboard/app/incidents.db'
try:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM incidents;")
        cursor.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'incidents';")
        conn.commit()
        print("DB RESET SUCCESSFUL")
except Exception as e:
    print("Error:", str(e))
