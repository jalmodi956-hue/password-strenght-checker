from flask import Flask, render_template, request, send_file, redirect, url_for
import sqlite3
import re
import csv
import math
from io import StringIO, BytesIO
from datetime import datetime

app = Flask(__name__)
DB_NAME = "password_checker.db"

# Common weak passwords
COMMON_WEAK_PASSWORDS = {
    "123456", "123456789", "password", "admin", "qwerty",
    "abc123", "letmein", "welcome", "iloveyou", "000000",
    "password123", "admin123", "india123", "test123"
}


# --------------------------------
# Database Setup
# --------------------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Create table if it does not exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_text TEXT NOT NULL,
            score INTEGER NOT NULL,
            strength TEXT NOT NULL,
            color TEXT NOT NULL,
            entropy REAL DEFAULT 0,
            crack_time TEXT DEFAULT 'Instantly',
            scan_time TEXT NOT NULL
        )
    """)

    # Check existing columns
    cursor.execute("PRAGMA table_info(password_history)")
    columns = [col[1] for col in cursor.fetchall()]

    # Add missing columns for old database
    if "entropy" not in columns:
        cursor.execute("ALTER TABLE password_history ADD COLUMN entropy REAL DEFAULT 0")

    if "crack_time" not in columns:
        cursor.execute("ALTER TABLE password_history ADD COLUMN crack_time TEXT DEFAULT 'Instantly'")

    conn.commit()
    conn.close()


# --------------------------------
# Helper Functions
# --------------------------------
def mask_password(password):
    if not password:
        return ""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def has_repeated_chars(password):
    """Detect 3 or more repeated same characters like aaa / 111"""
    return re.search(r"(.)\1{2,}", password) is not None


def has_sequence(password):
    """Detect simple sequences like 123 / abc / qwe"""
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
    """Detect common keyboard patterns"""
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
    """
    Rough estimate based on guesses per second.
    This is for project/demo purpose only.
    """
    if entropy <= 0:
        return "Instantly"

    guesses = 2 ** entropy
    guesses_per_second = 1_000_000_000  # 1 billion guesses/sec
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
# Password Strength Logic
# --------------------------------
def check_password_strength(password):
    score = 0
    feedback = []

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
    if len(password) >= 16:
        score += 30
    elif len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 18
    else:
        feedback.append("Use at least 8 characters")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 12
    else:
        feedback.append("Add at least one uppercase letter")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 12
    else:
        feedback.append("Add at least one lowercase letter")

    # Digit
    if re.search(r"[0-9]", password):
        score += 12
    else:
        feedback.append("Add at least one number")

    # Special character
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\];'`~]", password):
        score += 16
    else:
        feedback.append("Add at least one special character")

    # Bonus
    if len(re.findall(r"[^A-Za-z0-9]", password)) >= 2:
        score += 6

    if len(set(password)) >= 8:
        score += 5

    # Penalty checks
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

    # Entropy and crack time
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    # Entropy feedback
    if entropy < 40:
        feedback.append("Password entropy is low. Make it longer and more random.")
    elif entropy >= 60 and score >= 75:
        feedback.append("Good entropy level. This password is relatively strong.")

    # Clamp score
    score = max(0, min(score, 100))

    # Final strength
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
# Save Scan History
# --------------------------------
def save_to_history(password, score, strength, color, entropy, crack_time):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    scan_time = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")
    masked_password = mask_password(password)

    cursor.execute("""
        INSERT INTO password_history
        (password_text, score, strength, color, entropy, crack_time, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (masked_password, score, strength, color, entropy, crack_time, scan_time))

    conn.commit()
    conn.close()


# --------------------------------
# Routes
# --------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        password = request.form.get("password", "").strip()

        if password:
            result = check_password_strength(password)
            save_to_history(
                password,
                result["score"],
                result["strength"],
                result["color"],
                result["entropy"],
                result["crack_time"]
            )

    return render_template("index.html", result=result)


@app.route("/history")
def history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, password_text, score, strength, color, entropy, crack_time, scan_time
        FROM password_history
        ORDER BY id DESC
    """)
    records = cursor.fetchall()
    conn.close()

    return render_template("history.html", records=records)


@app.route("/delete_history/<int:record_id>", methods=["POST"])
def delete_history(record_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM password_history WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("history"))


@app.route("/clear_history", methods=["POST"])
def clear_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM password_history")
    conn.commit()
    conn.close()

    return redirect(url_for("history"))


@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM password_history")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM password_history WHERE strength = 'Weak'")
    weak_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM password_history WHERE strength = 'Medium'")
    medium_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM password_history WHERE strength = 'Strong'")
    strong_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT password_text, score, strength, scan_time
        FROM password_history
        ORDER BY id DESC
        LIMIT 5
    """)
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


@app.route("/export_csv")
def export_csv():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, password_text, score, strength, color, entropy, crack_time, scan_time
        FROM password_history
        ORDER BY id DESC
    """)
    records = cursor.fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Password", "Score", "Strength", "Color",
        "Entropy", "Estimated Crack Time", "Scan Time"
    ])
    writer.writerows(records)

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
# Main
# --------------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)

