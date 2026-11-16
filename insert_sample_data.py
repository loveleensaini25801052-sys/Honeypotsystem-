import sqlite3

connection = sqlite3.connect("honeypot.db")
cursor = connection.cursor()

sample_data = [

    ("192.168.10.15", "admin", "123456", "India", "10-Jul-2026", "08:30 PM", "FAILED"),

    ("10.10.10.2", "root", "toor", "USA", "10-Jul-2026", "08:45 PM", "FAILED"),

    ("172.16.0.5", "ubuntu", "ubuntu", "Germany", "10-Jul-2026", "09:10 PM", "SUCCESS")

]

cursor.executemany("""
INSERT INTO attacks (
    ip_address,
    username,
    password,
    country,
    date,
    time,
    status
)
VALUES (?, ?, ?, ?, ?, ?, ?)
""", sample_data)

connection.commit()
connection.close()

print("Sample Data Inserted Successfully")