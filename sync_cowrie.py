import sqlite3
import json
import os
from datetime import datetime
from country_lookup import get_country, get_ip_details

DB_PATH = "/media/sf_honeypot_project/honeypot.db"
# Fallback local path if running on Windows host for testing
if not os.path.exists(DB_PATH):
    DB_PATH = os.path.join(os.path.dirname(__file__), "honeypot.db")

LOG_PATH = "/home/kali/my-honeypot/var/log/cowrie/cowrie.json"
# Fallback local sample log path if running on Windows host for testing
if not os.path.exists(LOG_PATH):
    LOG_PATH = os.path.join(os.path.dirname(__file__), "cowrie.json")

print(f"[*] Syncing Cowrie logs from: {LOG_PATH}")
print(f"[*] Database target: {DB_PATH}")

if not os.path.exists(LOG_PATH):
    print(f"[!] Warning: Log file not found at {LOG_PATH}. Exiting sync.")
    exit(0)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Ensure missing columns exist in database automatically
cursor.execute("PRAGMA table_info(attacks)")
existing_cols = [row[1] for row in cursor.fetchall()]
new_cols = [
    ("command", "TEXT DEFAULT ''"),
    ("ssh_version", "TEXT DEFAULT ''"),
    ("threat_level", "TEXT DEFAULT 'MEDIUM'"),
    ("city", "TEXT DEFAULT ''")
]
for col_name, col_type in new_cols:
    if col_name not in existing_cols:
        cursor.execute(f"ALTER TABLE attacks ADD COLUMN {col_name} {col_type}")
conn.commit()

session_versions = {}
imported_count = 0

with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as logfile:
    for line in logfile:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue

        eventid = event.get("eventid")
        session = event.get("session")

        # Track SSH Client Version from connect events
        if eventid == "cowrie.session.connect":
            version = event.get("version", "")
            if session and version:
                session_versions[session] = version
            continue

        # We care about login attempts and shell command inputs
        if eventid not in ["cowrie.login.failed", "cowrie.login.success", "cowrie.command.input"]:
            continue

        timestamp = event.get("timestamp")
        if not timestamp:
            continue

        # Skip duplicate events already stored
        cursor.execute(
            "SELECT 1 FROM attacks WHERE event_timestamp = ?",
            (timestamp,)
        )
        if cursor.fetchone():
            continue

        ip = event.get("src_ip", "Unknown")
        username = event.get("username", "")
        password = event.get("password", "")
        command = ""
        ssh_version = session_versions.get(session, "")

        country, city, _ = get_ip_details(ip)

        try:
            event_time = datetime.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S")
            date = event_time.strftime("%Y-%m-%d")
            time = event_time.strftime("%H:%M:%S")
        except Exception:
            date = datetime.now().strftime("%Y-%m-%d")
            time = datetime.now().strftime("%H:%M:%S")

        if eventid == "cowrie.login.success":
            status = "SUCCESS"
            threat_level = "CRITICAL"
        elif eventid == "cowrie.command.input":
            status = "SUCCESS"
            command = event.get("input", "")
            threat_level = "CRITICAL"
            if not username:
                username = "interactive_shell"
            if not password:
                password = "[EXEC CMD]"
        else:
            status = "FAILED"
            if username in ["root", "admin", "administrator", "guest", "oracle", "postgres"]:
                threat_level = "HIGH"
            else:
                threat_level = "MEDIUM"

        cursor.execute("""
            INSERT INTO attacks
            (ip_address, username, password, country, date, time, status, event_timestamp, command, ssh_version, threat_level, city)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip,
            username,
            password,
            country,
            date,
            time,
            status,
            timestamp,
            command,
            ssh_version,
            threat_level,
            city
        ))
        imported_count += 1

conn.commit()
conn.close()

print(f"[+] Sync completed. New events imported: {imported_count}")