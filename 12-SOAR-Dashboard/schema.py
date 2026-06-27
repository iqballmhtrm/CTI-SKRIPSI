import sqlite3

try:
    conn = sqlite3.connect('/home/iqbal/soar-dashboard/app/incidents.db')
    c = conn.cursor()
    c.execute('PRAGMA table_info(incidents);')
    for row in c.fetchall():
        print(row)
except Exception as e:
    print(e)
