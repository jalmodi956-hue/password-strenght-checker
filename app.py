from flask import (
    Flask, render_template, request, send_file, redirect,
    url_for, session, flash
)
import sqlite3
import re
import csv
import math
import random
import string
import os

from io import StringIO, BytesIO
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
app.secret_key = "change_this_secret_key_123"
if os.environ.get("VERCEL"):
    DB_NAME = "/tmp/password_checker.db"
else:
    DB_NAME = "password_checker.db"

COMMON_WEAK_PASSWORDS = {
    "123456", "123456789", "password", "admin", "qwerty",
    "abc123", "letmein", "welcome", "iloveyou", "000000",
    "password123", "admin123", "india123", "test123"
}


# --------------------------------
# Database Connection
# --------------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------------
# Database Setup
# --------------------------------
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Password history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_text TEXT NOT NULL,
            score INTEGER NOT NULL,
            strength TEXT NOT NULL,
            color TEXT NOT NULL,
            entropy REAL DEFAULT 0,
            crack_time TEXT DEFAULT 'Instantly',
            scan_time TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Password policy table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_policy (
            user_id INTEGER PRIMARY KEY,
            min_length INTEGER DEFAULT 8,
            require_uppercase INTEGER DEFAULT 1,
            require_lowercase INTEGER DEFAULT 1,
            require_digit INTEGER DEFAULT 1,
            require_special INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Old DB migration support
    cursor.execute("PRAGMA table_info(password_history)")
    history_columns = [col[1] for col in cursor.fetchall()]

    if "user_id" not in history_columns:
        try:
            cursor.execute("ALTER TABLE password_history ADD COLUMN user_id INTEGER DEFAULT 1")
        except:
            pass

    if "entropy" not in history_columns:
        try:
            cursor.execute("ALTER TABLE password_history ADD COLUMN entropy REAL DEFAULT 0")
        except:
            pass

    if "crack_time" not in history_columns:
        try:
            cursor.execute("ALTER TABLE password_history ADD COLUMN crack_time TEXT DEFAULT 'Instantly'")
        except:
            pass

    conn.commit()
    conn.close()


# --------------------------------
# Session Helpers
# --------------------------------
def is_logged_in():
    return "user_id" in session


def get_current_user_id():
    return session.get("user_id")


# --------------------------------
# Auth Helpers
# --------------------------------
def create_default_user_if_needed():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    user = cursor.fetchone()

    if not user:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", "admin123")
        )
        conn.commit()
        user_id = cursor.lastrowid

        cursor.execute("""
            INSERT OR IGNORE INTO password_policy
            (user_id, min_length, require_uppercase, require_lowercase, require_digit, require_special)
            VALUES (?, 8, 1, 1, 1, 1)
        """, (user_id,))
        conn.commit()

    conn.close()


# --------------------------------
# Policy Helpers
# --------------------------------
def get_user_policy(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM password_policy WHERE user_id = ?", (user_id,))
    policy = cursor.fetchone()

    if not policy:
        cursor.execute("""
            INSERT INTO password_policy
            (user_id, min_length, require_uppercase, require_lowercase, require_digit, require_special)
            VALUES (?, 8, 1, 1, 1, 1)
        """, (user_id,))
        conn.commit()
        cursor.execute("SELECT * FROM password_policy WHERE user_id = ?", (user_id,))
        policy = cursor.fetchone()

    conn.close()
    return policy


def update_user_policy(user_id, min_length, require_uppercase, require_lowercase, require_digit, require_special):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO password_policy
        (user_id, min_length, require_uppercase, require_lowercase, require_digit, require_special)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            min_length=excluded.min_length,
            require_uppercase=excluded.require_uppercase,
            require_lowercase=excluded.require_lowercase,
            require_digit=excluded.require_digit,
            require_special=excluded.require_special
    """, (
        user_id,
        min_length,
        require_uppercase,
        require_lowercase,
        require_digit,
        require_special
    ))

    conn.commit()
    conn.close()


# --------------------------------
# Password Helper Functions
# --------------------------------
def mask_password(password):
    if not password:
        return ""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def has_repeated_chars(password):
    return re.search(r"(.)\1{2,}", password) is not None


def has_sequence(password):
    password_lower = password.lower()
    sequences = [
        "0123456789",
        "1234567890",
        "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]
    for seq in sequences:
        for i in range(len(seq) - 2):
            part = seq[i:i+3]
            if part in password_lower:
                return True
    return False


def has_keyboard_pattern(password):
    password_lower = password.lower()
    patterns = ["qwerty", "asdf", "zxcv", "qaz", "wsx", "edc"]
    return any(pattern in password_lower for pattern in patterns)


def calculate_charset_size(password):
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset += 32
    return charset


def calculate_entropy(password):
    charset = calculate_charset_size(password)
    if not password or charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)


def estimate_crack_time(entropy):
    if entropy <= 0:
        return "Instantly"

    guesses = 2 ** entropy
    guesses_per_second = 1_000_000_000
    seconds = guesses / guesses_per_second

    if seconds < 1:
        return "Less than 1 second"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    elif seconds < 2592000:
        return f"{int(seconds // 86400)} days"
    elif seconds < 31536000:
        return f"{int(seconds // 2592000)} months"
    elif seconds < 3153600000:
        return f"{int(seconds // 31536000)} years"
    else:
        return "Many years"


# --------------------------------
# Password Generator
# --------------------------------
def generate_password(length=14, use_upper=True, use_lower=True, use_digits=True, use_special=True):
    chars = ""
    if use_upper:
        chars += string.ascii_uppercase
    if use_lower:
        chars += string.ascii_lowercase
    if use_digits:
        chars += string.digits
    if use_special:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?/"

    if not chars:
        chars = string.ascii_letters + string.digits

    password = ''.join(random.choice(chars) for _ in range(length))
    return password


# --------------------------------
# Password Strength Logic
# --------------------------------
def check_password_strength(password, policy):
    score = 0
    feedback = []

    min_length = policy["min_length"]
    require_uppercase = policy["require_uppercase"]
    require_lowercase = policy["require_lowercase"]
    require_digit = policy["require_digit"]
    require_special = policy["require_special"]

    if not password:
        return {
            "score": 0,
            "strength": "Weak",
            "color": "red",
            "feedback": ["Please enter a password"],
            "entropy": 0,
            "crack_time": "Instantly"
        }

    # Length scoring
    if len(password) >= max(min_length, 16):
        score += 30
    elif len(password) >= max(min_length, 12):
        score += 25
    elif len(password) >= min_length:
        score += 18
    else:
        feedback.append(f"Use at least {min_length} characters")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 12
    elif require_uppercase:
        feedback.append("Add at least one uppercase letter")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 12
    elif require_lowercase:
        feedback.append("Add at least one lowercase letter")

    # Digit
    if re.search(r"[0-9]", password):
        score += 12
    elif require_digit:
        feedback.append("Add at least one number")

    # Special character
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\];'`~]", password):
        score += 16
    elif require_special:
        feedback.append("Add at least one special character")

    # Bonus
    if len(re.findall(r"[^A-Za-z0-9]", password)) >= 2:
        score += 6
    if len(set(password)) >= 8:
        score += 5

    # Penalties
    if password.lower() in COMMON_WEAK_PASSWORDS:
        score -= 35
        feedback.append("This is a very common password. Avoid common passwords.")

    if has_repeated_chars(password):
        score -= 10
        feedback.append("Avoid repeated characters like aaa or 111")

    if has_sequence(password):
        score -= 10
        feedback.append("Avoid easy sequences like 123, abc, qwe")

    if has_keyboard_pattern(password):
        score -= 8
        feedback.append("Avoid keyboard patterns like qwerty or asdf")

    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    if entropy < 40:
        feedback.append("Password entropy is low. Make it longer and more random.")
    elif entropy >= 60 and score >= 75:
        feedback.append("Good entropy level. This password is relatively strong.")

    score = max(0, min(score, 100))

    if score <= 40:
        strength = "Weak"
        color = "red"
    elif score <= 75:
        strength = "Medium"
        color = "orange"
    else:
        strength = "Strong"
        color = "green"

    return {
        "score": score,
        "strength": strength,
        "color": color,
        "feedback": feedback,
        "entropy": entropy,
        "crack_time": crack_time
    }


# --------------------------------
# History Save
# --------------------------------
def save_to_history(user_id, password, score, strength, color, entropy, crack_time):
    conn = get_db_connection()
    cursor = conn.cursor()

    scan_time = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")
    masked_password = mask_password(password)

    cursor.execute("""
        INSERT INTO password_history
        (user_id, password_text, score, strength, color, entropy, crack_time, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, masked_password, score, strength, color, entropy, crack_time, scan_time))

    conn.commit()
    conn.close()


# --------------------------------
# Auth Routes
# --------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Login successful!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            conn.commit()
            user_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO password_policy
                (user_id, min_length, require_uppercase, require_lowercase, require_digit, require_special)
                VALUES (?, 8, 1, 1, 1, 1)
            """, (user_id,))
            conn.commit()

            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


# --------------------------------
# Main Routes
# --------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if not is_logged_in():
        return redirect(url_for("login"))

    result = None
    user_id = get_current_user_id()
    policy = get_user_policy(user_id)

    if request.method == "POST":
        password = request.form.get("password", "").strip()

        if password:
            result = check_password_strength(password, policy)
            # save_to_history(
            #     user_id,
            #     password,
            #     result["score"],
            #     result["strength"],
            #     result["color"],
            #     result["entropy"],
            #     result["crack_time"]
            # )

    return render_template(
        "index.html",
        result=result,
        policy=policy,
        username=session.get("username")
    )


@app.route("/history")
def history():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, password_text, score, strength, color, entropy, crack_time, scan_time
        FROM password_history
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user_id,))
    records = cursor.fetchall()
    conn.close()

    return render_template("history.html", records=records)


@app.route("/delete_history/<int:record_id>", methods=["POST"])
def delete_history(record_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM password_history WHERE id = ? AND user_id = ?",
        (record_id, user_id)
    )
    conn.commit()
    conn.close()

    return redirect(url_for("history"))


@app.route("/clear_history", methods=["POST"])
def clear_history():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM password_history WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("history"))


@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM password_history WHERE user_id = ?", (user_id,))
    total_scans = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM password_history
        WHERE user_id = ? AND strength = 'Weak'
    """, (user_id,))
    weak_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM password_history
        WHERE user_id = ? AND strength = 'Medium'
    """, (user_id,))
    medium_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM password_history
        WHERE user_id = ? AND strength = 'Strong'
    """, (user_id,))
    strong_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT password_text, score, strength, scan_time
        FROM password_history
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
    """, (user_id,))
    recent_scans = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        weak_count=weak_count,
        medium_count=medium_count,
        strong_count=strong_count,
        recent_scans=recent_scans
    )


# --------------------------------
# Password Generator Route
# --------------------------------
@app.route("/generate_password", methods=["GET", "POST"])
def generate_password_route():
    if not is_logged_in():
        return redirect(url_for("login"))

    generated_password = None

    if request.method == "POST":
        length = int(request.form.get("length", 14))
        use_upper = bool(request.form.get("use_upper"))
        use_lower = bool(request.form.get("use_lower"))
        use_digits = bool(request.form.get("use_digits"))
        use_special = bool(request.form.get("use_special"))

        generated_password = generate_password(
            length=length,
            use_upper=use_upper,
            use_lower=use_lower,
            use_digits=use_digits,
            use_special=use_special
        )

    return render_template("generator.html", generated_password=generated_password)


# --------------------------------
# Policy Settings Route
# --------------------------------
@app.route("/policy", methods=["GET", "POST"])
def policy():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = get_current_user_id()

    if request.method == "POST":
        min_length = int(request.form.get("min_length", 8))
        require_uppercase = 1 if request.form.get("require_uppercase") else 0
        require_lowercase = 1 if request.form.get("require_lowercase") else 0
        require_digit = 1 if request.form.get("require_digit") else 0
        require_special = 1 if request.form.get("require_special") else 0

        update_user_policy(
            user_id,
            min_length,
            require_uppercase,
            require_lowercase,
            require_digit,
            require_special
        )
        flash("Password policy updated successfully.", "success")
        return redirect(url_for("policy"))

    policy_data = get_user_policy(user_id)
    return render_template("policy.html", policy=policy_data)


# --------------------------------
# Export CSV
# --------------------------------
@app.route("/export_csv")
def export_csv():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, password_text, score, strength, color, entropy, crack_time, scan_time
        FROM password_history
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user_id,))
    records = cursor.fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Password", "Score", "Strength", "Color",
        "Entropy", "Estimated Crack Time", "Scan Time"
    ])
    writer.writerows([tuple(row) for row in records])

    mem = BytesIO()
    mem.write(output.getvalue().encode("utf-8"))
    mem.seek(0)

    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name="password_history.csv"
    )


# --------------------------------
# Export PDF
# --------------------------------
@app.route("/export_pdf")
def export_pdf():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT password_text, score, strength, entropy, crack_time, scan_time
        FROM password_history
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user_id,))
    records = cursor.fetchall()
    conn.close()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Cyber Password Security Engine - Password Report", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"User: {session.get('username')}", styles["Normal"]))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%d-%m-%Y %I:%M:%S %p')}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    table_data = [["Password", "Score", "Strength", "Entropy", "Crack Time", "Scan Time"]]
    for row in records:
        table_data.append([
            row["password_text"],
            row["score"],
            row["strength"],
            row["entropy"],
            row["crack_time"],
            row["scan_time"]
        ])

    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.black),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
    ]))

    elements.append(table)
    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="password_report.pdf",
        mimetype="application/pdf"
    )


# --------------------------------
# Main
# --------------------------------

init_db()
create_default_user_if_needed()

if __name__ == "__main__":
    app.run(debug=True)