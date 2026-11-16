import sqlite3

connection = sqlite3.connect("honeypot.db")
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS attacks(

id INTEGER PRIMARY KEY AUTOINCREMENT,

ip_address TEXT,

username TEXT,

password TEXT,

country TEXT,

date TEXT,

time TEXT,

status TEXT

)
""")

connection.commit()
connection.close()

print("Database Created Successfully")