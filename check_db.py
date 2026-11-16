import sqlite3

conn = sqlite3.connect("honeypot.db")
cursor = conn.cursor()

cursor.execute("""
SELECT date, time, event_timestamp
FROM attacks
ORDER BY id DESC
LIMIT 5
""")

rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()
