import sqlite3

connection = sqlite3.connect("honeypot.db")
cursor = connection.cursor()

cursor.execute("""

INSERT INTO attacks(

ip_address,

username,

password,

country,

date,

time,

status

)

VALUES(?,?,?,?,?,?,?)

""",

("8.8.8.8","guest","guest123","Canada","12-Jul-2026","10:15 AM","FAILED"))

connection.commit()
connection.close()

print("New Attack Added")