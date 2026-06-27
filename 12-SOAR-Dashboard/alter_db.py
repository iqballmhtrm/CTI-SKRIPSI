import sqlite3

try:
    conn = sqlite3.connect('/home/iqbal/soar-dashboard/app/incidents.db')
    c = conn.cursor()
    c.execute('ALTER TABLE incidents RENAME COLUMN mitre_tactic TO mitre_technique;')
    c.execute('ALTER TABLE incidents ADD COLUMN mitre_status TEXT DEFAULT "Unmapped";')
    conn.commit()
    print("Database altered successfully")
except Exception as e:
    print(e)
