import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), "honeypot.db")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Get existing columns in attacks table
cursor.execute("PRAGMA table_info(attacks)")
existing_cols = [row[1] for row in cursor.fetchall()]
print("Current columns:", existing_cols)

new_columns = [
    ("command", "TEXT DEFAULT ''"),
    ("ssh_version", "TEXT DEFAULT ''"),
    ("threat_level", "TEXT DEFAULT 'MEDIUM'"),
    ("city", "TEXT DEFAULT ''")
]

for col_name, col_type in new_columns:
    if col_name not in existing_cols:
        print(f"Adding column '{col_name}'...")
        cursor.execute(f"ALTER TABLE attacks ADD COLUMN {col_name} {col_type}")

conn.commit()

cursor.execute("PRAGMA table_info(attacks)")
updated_cols = [row[1] for row in cursor.fetchall()]
print("Updated columns:", updated_cols)

conn.close()
print("Migration finished successfully.")
