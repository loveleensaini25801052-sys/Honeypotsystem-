from flask import Flask, render_template, request, redirect, url_for, send_file, session, jsonify
import sqlite3
import csv
import os
from datetime import datetime, date

app = Flask(__name__)
app.secret_key = "honeypot_cyber_soc_secret_key"

DATABASE = os.path.join(os.path.dirname(__file__), "honeypot.db")

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Ensure tables and columns exist on startup."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Create users table if missing
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    # Create attacks table if missing
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            username TEXT,
            password TEXT,
            country TEXT,
            date TEXT,
            time TEXT,
            status TEXT,
            event_timestamp TEXT,
            command TEXT DEFAULT '',
            ssh_version TEXT DEFAULT '',
            threat_level TEXT DEFAULT 'MEDIUM',
            city TEXT DEFAULT ''
        )
    """)
    conn.commit()

    # Migrate columns if existing table lacked new fields
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
    conn.close()

# Run initialization on startup
init_db()

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            session["username"] = username
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid Username or Password!")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            return render_template("register.html", error="Please fill in all fields.")

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="Username already exists!")

    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    # Total attacks
    cursor.execute("SELECT COUNT(*) FROM attacks")
    total_attacks = cursor.fetchone()[0]

    # Today's attacks
    today_str = datetime.now().strftime("%Y-%m-%d")
    cursor.execute("SELECT COUNT(*) FROM attacks WHERE date = ?", (today_str,))
    today_attacks = cursor.fetchone()[0]

    # Unique IPs
    cursor.execute("SELECT COUNT(DISTINCT ip_address) FROM attacks")
    unique_ips = cursor.fetchone()[0]

    # Successful Breaches
    cursor.execute("SELECT COUNT(*) FROM attacks WHERE status='SUCCESS'")
    successful_breaches = cursor.fetchone()[0]

    # Captured Shell Commands Count
    cursor.execute("SELECT COUNT(*) FROM attacks WHERE command != '' AND command IS NOT NULL")
    command_count = cursor.fetchone()[0]

    # Latest 8 attacks
    cursor.execute("""
        SELECT id, ip_address, username, password, country, date, time, status, command, threat_level
        FROM attacks
        ORDER BY id DESC
        LIMIT 8
    """)
    recent_attacks = cursor.fetchall()

    # Top targeted username
    cursor.execute("""
        SELECT username, COUNT(*) as cnt 
        FROM attacks 
        WHERE username != '' 
        GROUP BY username 
        ORDER BY cnt DESC 
        LIMIT 1
    """)
    top_user_row = cursor.fetchone()
    top_username = top_user_row["username"] if top_user_row else "None"

    conn.close()

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        total_attacks=total_attacks,
        today_attacks=today_attacks,
        unique_ips=unique_ips,
        successful_breaches=successful_breaches,
        command_count=command_count,
        top_username=top_username,
        recent_attacks=recent_attacks
    )

@app.route("/live_attacks")
def live_attacks():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attacks ORDER BY id DESC LIMIT 100")
    attacks = cursor.fetchall()
    conn.close()

    return render_template("live_attacks.html", attacks=attacks)

@app.route("/commands")
def commands():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, ip_address, username, date, time, command, threat_level, country
        FROM attacks
        WHERE command != '' AND command IS NOT NULL
        ORDER BY id DESC
    """)
    executed_commands = cursor.fetchall()

    cursor.execute("""
        SELECT command, COUNT(*) as frequency
        FROM attacks
        WHERE command != '' AND command IS NOT NULL
        GROUP BY command
        ORDER BY frequency DESC
        LIMIT 10
    """)
    top_commands = cursor.fetchall()

    conn.close()

    return render_template(
        "commands.html",
        commands=executed_commands,
        top_commands=top_commands
    )

@app.route("/credentials")
def credentials():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()
    
    # Top Targeted Usernames
    cursor.execute("""
        SELECT username, COUNT(*) as count 
        FROM attacks 
        WHERE username != '' AND username IS NOT NULL
        GROUP BY username 
        ORDER BY count DESC 
        LIMIT 10
    """)
    top_usernames = cursor.fetchall()

    # Top Attempted Passwords
    cursor.execute("""
        SELECT password, COUNT(*) as count 
        FROM attacks 
        WHERE password != '' AND password IS NOT NULL AND password != '[EXEC CMD]'
        GROUP BY password 
        ORDER BY count DESC 
        LIMIT 10
    """)
    top_passwords = cursor.fetchall()

    conn.close()

    return render_template(
        "credentials.html",
        top_usernames=top_usernames,
        top_passwords=top_passwords
    )

@app.route("/statistics")
def statistics():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM attacks")
    total_attacks = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT ip_address) FROM attacks")
    unique_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM attacks WHERE status='FAILED'")
    failed_attacks = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM attacks WHERE status='SUCCESS'")
    successful_attacks = cursor.fetchone()[0]

    # Threat level counts
    cursor.execute("SELECT COUNT(*) FROM attacks WHERE threat_level='CRITICAL'")
    critical_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM attacks WHERE threat_level='HIGH'")
    high_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM attacks WHERE threat_level='MEDIUM'")
    medium_count = cursor.fetchone()[0]

    # Top 5 Targeted Usernames for bar chart
    cursor.execute("""
        SELECT username, COUNT(*) as cnt 
        FROM attacks 
        WHERE username != '' 
        GROUP BY username 
        ORDER BY cnt DESC 
        LIMIT 5
    """)
    top_users = cursor.fetchall()

    conn.close()

    return render_template(
        "statistics.html",
        total_attacks=total_attacks,
        unique_ips=unique_ips,
        failed_attacks=failed_attacks,
        successful_attacks=successful_attacks,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        top_users=top_users
    )

@app.route("/reports")
def reports():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attacks ORDER BY id DESC")
    attacks = cursor.fetchall()
    conn.close()

    return render_template("reports.html", attacks=attacks)

@app.route("/download_csv")
def download_csv():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attacks ORDER BY id DESC")
    attacks = cursor.fetchall()
    conn.close()

    filename = "attack_report.csv"
    filepath = os.path.join(os.path.dirname(__file__), filename)

    with open(filepath, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "ID",
            "IP Address",
            "Username",
            "Password",
            "Country",
            "Date",
            "Time",
            "Status",
            "Threat Level",
            "Command",
            "SSH Version"
        ])
        for attack in attacks:
            writer.writerow([
                attack["id"],
                attack["ip_address"],
                attack["username"],
                attack["password"],
                attack["country"],
                attack["date"],
                attack["time"],
                attack["status"],
                attack["threat_level"] if "threat_level" in attack.keys() else "MEDIUM",
                attack["command"] if "command" in attack.keys() else "",
                attack["ssh_version"] if "ssh_version" in attack.keys() else ""
            ])

    return send_file(filepath, as_attachment=True)

@app.route("/settings")
def settings():
    if "username" not in session:
        return redirect(url_for("login"))

    db_size = "0 KB"
    if os.path.exists(DATABASE):
        size_bytes = os.path.getsize(DATABASE)
        db_size = f"{size_bytes / 1024:.2f} KB" if size_bytes < 1048576 else f"{size_bytes / (1024*1024):.2f} MB"

    return render_template("settings.html", db_size=db_size, db_path=DATABASE)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ==========================================
# REST API ENDPOINTS FOR REAL-TIME POLLING
# ==========================================

@app.route("/api/stats")
def api_stats():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM attacks")
    total_attacks = cursor.fetchone()[0]

    today_str = datetime.now().strftime("%Y-%m-%d")
    cursor.execute("SELECT COUNT(*) FROM attacks WHERE date = ?", (today_str,))
    today_attacks = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT ip_address) FROM attacks")
    unique_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM attacks WHERE status='SUCCESS'")
    successful_breaches = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM attacks WHERE command != '' AND command IS NOT NULL")
    command_count = cursor.fetchone()[0]

    cursor.execute("SELECT id FROM attacks ORDER BY id DESC LIMIT 1")
    latest_row = cursor.fetchone()
    latest_id = latest_row["id"] if latest_row else 0

    conn.close()

    return jsonify({
        "total_attacks": total_attacks,
        "today_attacks": today_attacks,
        "unique_ips": unique_ips,
        "successful_breaches": successful_breaches,
        "command_count": command_count,
        "latest_id": latest_id,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    })

@app.route("/api/live_attacks")
def api_live_attacks():
    status_filter = request.args.get("status", "ALL").upper()
    search_query = request.args.get("search", "").strip()

    conn = get_db()
    cursor = conn.cursor()

    query = "SELECT * FROM attacks WHERE 1=1"
    params = []

    if status_filter == "SUCCESS":
        query += " AND status='SUCCESS'"
    elif status_filter == "FAILED":
        query += " AND status='FAILED'"
    elif status_filter == "HIGH":
        query += " AND (threat_level='HIGH' OR threat_level='CRITICAL')"

    if search_query:
        query += " AND (ip_address LIKE ? OR username LIKE ? OR password LIKE ? OR country LIKE ? OR command LIKE ?)"
        term = f"%{search_query}%"
        params.extend([term, term, term, term, term])

    query += " ORDER BY id DESC LIMIT 50"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    attacks = []
    for r in rows:
        attacks.append({
            "id": r["id"],
            "ip_address": r["ip_address"],
            "username": r["username"],
            "password": r["password"],
            "country": r["country"],
            "date": r["date"],
            "time": r["time"],
            "status": r["status"],
            "threat_level": r["threat_level"] if "threat_level" in r.keys() else "MEDIUM",
            "command": r["command"] if "command" in r.keys() else "",
            "ssh_version": r["ssh_version"] if "ssh_version" in r.keys() else ""
        })

    return jsonify({"attacks": attacks})

@app.route("/api/clear_logs", methods=["POST"])
def api_clear_logs():
    if "username" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM attacks")
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "All attack logs cleared."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)