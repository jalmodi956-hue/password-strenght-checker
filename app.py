from flask import (
    Flask, render_template, request, send_file,
    redirect, url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

import re
import csv
import math
import secrets
import string
import os

from io import StringIO, BytesIO
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet


# ==================================================
# APP CONFIG
# ==================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key"
)

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///password_checker.db"
)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 280
}

db = SQLAlchemy(app)


COMMON_WEAK_PASSWORDS = {
    "123456",
    "123456789",
    "password",
    "admin",
    "qwerty",
    "abc123",
    "letmein",
    "welcome",
    "iloveyou",
    "000000",
    "password123",
    "admin123",
    "india123",
    "test123"
}


# ==================================================
# DATABASE MODELS
# ==================================================

class User(db.Model):

    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True
    )

    password = db.Column(
        db.Text,
        nullable=False
    )


class PasswordHistory(db.Model):

    __tablename__ = "password_history"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    password_text = db.Column(
        db.Text,
        nullable=False
    )

    score = db.Column(
        db.Integer,
        nullable=False
    )

    strength = db.Column(
        db.String(50),
        nullable=False
    )

    color = db.Column(
        db.String(50),
        nullable=False
    )

    entropy = db.Column(
        db.Float,
        default=0
    )

    crack_time = db.Column(
        db.Text,
        default="Instantly"
    )

    scan_time = db.Column(
        db.String(100),
        nullable=False
    )


class PasswordPolicy(db.Model):

    __tablename__ = "password_policy"

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        primary_key=True
    )

    min_length = db.Column(
        db.Integer,
        default=8
    )

    require_uppercase = db.Column(
        db.Integer,
        default=1
    )

    require_lowercase = db.Column(
        db.Integer,
        default=1
    )

    require_digit = db.Column(
        db.Integer,
        default=1
    )

    require_special = db.Column(
        db.Integer,
        default=1
    )


# ==================================================
# DATABASE SETUP
# ==================================================

def init_db():

    db.create_all()


def create_default_user_if_needed():

    user = User.query.filter_by(
        username="admin"
    ).first()

    if not user:

        user = User(
            username="admin",
            password=generate_password_hash(
                "admin123"
            )
        )

        db.session.add(user)

        db.session.flush()

        policy = PasswordPolicy(
            user_id=user.id
        )

        db.session.add(policy)

        db.session.commit()


# ==================================================
# SESSION HELPERS
# ==================================================

def is_logged_in():

    return "user_id" in session


def get_current_user_id():

    return session.get("user_id")


# ==================================================
# PASSWORD VERIFY
# ==================================================

def verify_password(
    stored_password,
    entered_password
):

    if stored_password.startswith(
        ("scrypt:", "pbkdf2:")
    ):

        return check_password_hash(
            stored_password,
            entered_password
        )

    return secrets.compare_digest(
        stored_password,
        entered_password
    )


# ==================================================
# POLICY HELPERS
# ==================================================

def get_user_policy(user_id):

    policy = db.session.get(
        PasswordPolicy,
        user_id
    )

    if not policy:

        policy = PasswordPolicy(
            user_id=user_id
        )

        db.session.add(policy)

        db.session.commit()

    return policy


def update_user_policy(
    user_id,
    min_length,
    require_uppercase,
    require_lowercase,
    require_digit,
    require_special
):

    policy = get_user_policy(user_id)

    policy.min_length = min_length

    policy.require_uppercase = (
        require_uppercase
    )

    policy.require_lowercase = (
        require_lowercase
    )

    policy.require_digit = require_digit

    policy.require_special = (
        require_special
    )

    db.session.commit()


# ==================================================
# PASSWORD HELPERS
# ==================================================

def mask_password(password):

    if not password:

        return ""

    if len(password) <= 2:

        return "*" * len(password)

    return (
        password[0]
        + "*" * (len(password) - 2)
        + password[-1]
    )


def has_repeated_chars(password):

    return re.search(
        r"(.)\1{2,}",
        password
    ) is not None


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

        for i in range(
            len(seq) - 2
        ):

            part = seq[i:i + 3]

            if part in password_lower:

                return True

    return False


def has_keyboard_pattern(password):

    password_lower = password.lower()

    patterns = [
        "qwerty",
        "asdf",
        "zxcv",
        "qaz",
        "wsx",
        "edc"
    ]

    return any(
        pattern in password_lower
        for pattern in patterns
    )


def calculate_charset_size(password):

    charset = 0

    if re.search(
        r"[a-z]",
        password
    ):

        charset += 26

    if re.search(
        r"[A-Z]",
        password
    ):

        charset += 26

    if re.search(
        r"[0-9]",
        password
    ):

        charset += 10

    if re.search(
        r"[^A-Za-z0-9]",
        password
    ):

        charset += 32

    return charset


def calculate_entropy(password):

    charset = calculate_charset_size(
        password
    )

    if not password or charset == 0:

        return 0

    return round(
        len(password)
        * math.log2(charset),
        2
    )


def estimate_crack_time(entropy):

    if entropy <= 0:

        return "Instantly"

    guesses = 2 ** entropy

    guesses_per_second = 1_000_000_000

    seconds = (
        guesses / guesses_per_second
    )

    if seconds < 1:

        return "Less than 1 second"

    if seconds < 60:

        return f"{int(seconds)} seconds"

    if seconds < 3600:

        return (
            f"{int(seconds // 60)} minutes"
        )

    if seconds < 86400:

        return (
            f"{int(seconds // 3600)} hours"
        )

    if seconds < 2592000:

        return (
            f"{int(seconds // 86400)} days"
        )

    if seconds < 31536000:

        return (
            f"{int(seconds // 2592000)} months"
        )

    if seconds < 3153600000:

        return (
            f"{int(seconds // 31536000)} years"
        )

    return "Many years"


# ==================================================
# PASSWORD GENERATOR
# ==================================================

def generate_password(
    length=14,
    use_upper=True,
    use_lower=True,
    use_digits=True,
    use_special=True
):

    length = max(
        8,
        min(int(length), 128)
    )

    groups = []

    if use_upper:

        groups.append(
            string.ascii_uppercase
        )

    if use_lower:

        groups.append(
            string.ascii_lowercase
        )

    if use_digits:

        groups.append(
            string.digits
        )

    if use_special:

        groups.append(
            "!@#$%^&*()_+-=[]{}|;:,.<>?/"
        )

    if not groups:

        groups = [
            string.ascii_letters,
            string.digits
        ]

    password_chars = [
        secrets.choice(group)
        for group in groups
    ]

    all_chars = "".join(groups)

    while len(password_chars) < length:

        password_chars.append(
            secrets.choice(all_chars)
        )

    secrets.SystemRandom().shuffle(
        password_chars
    )

    return "".join(
        password_chars[:length]
    )


# ==================================================
# PASSWORD STRENGTH CHECK
# ==================================================

def check_password_strength(
    password,
    policy
):

    score = 0

    feedback = []

    min_length = policy.min_length

    require_uppercase = (
        policy.require_uppercase
    )

    require_lowercase = (
        policy.require_lowercase
    )

    require_digit = (
        policy.require_digit
    )

    require_special = (
        policy.require_special
    )

    if not password:

        return {
            "score": 0,
            "strength": "Weak",
            "color": "red",
            "feedback": [
                "Please enter a password"
            ],
            "entropy": 0,
            "crack_time": "Instantly"
        }


    if len(password) >= max(
        min_length,
        16
    ):

        score += 30

    elif len(password) >= max(
        min_length,
        12
    ):

        score += 25

    elif len(password) >= min_length:

        score += 18

    else:

        feedback.append(
            f"Use at least {min_length} characters"
        )


    if re.search(
        r"[A-Z]",
        password
    ):

        score += 12

    elif require_uppercase:

        feedback.append(
            "Add at least one uppercase letter"
        )


    if re.search(
        r"[a-z]",
        password
    ):

        score += 12

    elif require_lowercase:

        feedback.append(
            "Add at least one lowercase letter"
        )


    if re.search(
        r"[0-9]",
        password
    ):

        score += 12

    elif require_digit:

        feedback.append(
            "Add at least one number"
        )


    if re.search(
        r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\];'`~]",
        password
    ):

        score += 16

    elif require_special:

        feedback.append(
            "Add at least one special character"
        )


    if len(
        re.findall(
            r"[^A-Za-z0-9]",
            password
        )
    ) >= 2:

        score += 6


    if len(set(password)) >= 8:

        score += 5


    if password.lower() in COMMON_WEAK_PASSWORDS:

        score -= 35

        feedback.append(
            "This is a very common password. Avoid common passwords."
        )


    if has_repeated_chars(password):

        score -= 10

        feedback.append(
            "Avoid repeated characters like aaa or 111"
        )


    if has_sequence(password):

        score -= 10

        feedback.append(
            "Avoid easy sequences like 123, abc, qwe"
        )


    if has_keyboard_pattern(password):

        score -= 8

        feedback.append(
            "Avoid keyboard patterns like qwerty or asdf"
        )


    entropy = calculate_entropy(
        password
    )

    crack_time = estimate_crack_time(
        entropy
    )


    if entropy < 40:

        feedback.append(
            "Password entropy is low. Make it longer and more random."
        )

    elif entropy >= 60 and score >= 75:

        feedback.append(
            "Good entropy level. This password is relatively strong."
        )


    score = max(
        0,
        min(score, 100)
    )


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


# ==================================================
# SAVE HISTORY
# ==================================================

def save_to_history(
    user_id,
    password,
    score,
    strength,
    color,
    entropy,
    crack_time
):

    record = PasswordHistory(

        user_id=user_id,

        password_text=mask_password(
            password
        ),

        score=score,

        strength=strength,

        color=color,

        entropy=entropy,

        crack_time=crack_time,

        scan_time=datetime.now().strftime(
            "%d-%m-%Y %I:%M:%S %p"
        )
    )

    db.session.add(record)

    db.session.commit()


# ==================================================
# LOGIN
# ==================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if is_logged_in():

        return redirect(
            url_for("index")
        )


    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )


        user = User.query.filter_by(
            username=username
        ).first()


        if user and verify_password(
            user.password,
            password
        ):

            if not user.password.startswith(
                ("scrypt:", "pbkdf2:")
            ):

                user.password = (
                    generate_password_hash(
                        password
                    )
                )

                db.session.commit()


            session.clear()

            session["user_id"] = user.id

            session["username"] = (
                user.username
            )


            flash(
                "Login successful!",
                "success"
            )

            return redirect(
                url_for("index")
            )


        flash(
            "Invalid username or password.",
            "danger"
        )


    return render_template(
        "login.html"
    )


# ==================================================
# REGISTER
# ==================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )


        if not username or not password:

            flash(
                "Username and password are required.",
                "danger"
            )

            return redirect(
                url_for("register")
            )


        if len(username) > 255:

            flash(
                "Username is too long.",
                "danger"
            )

            return redirect(
                url_for("register")
            )


        user = User(

            username=username,

            password=generate_password_hash(
                password
            )
        )


        try:

            db.session.add(user)

            db.session.flush()


            db.session.add(

                PasswordPolicy(
                    user_id=user.id
                )

            )


            db.session.commit()


            flash(
                "Registration successful. Please login.",
                "success"
            )


            return redirect(
                url_for("login")
            )


        except IntegrityError:

            db.session.rollback()

            flash(
                "Username already exists.",
                "danger"
            )


    return render_template(
        "register.html"
    )


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "Logged out successfully.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ==================================================
# HOME
# ==================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def index():

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    result = None

    user_id = get_current_user_id()

    policy = get_user_policy(
        user_id
    )


    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )


        if password:

            result = check_password_strength(
                password,
                policy
            )


            save_to_history(

                user_id,

                password,

                result["score"],

                result["strength"],

                result["color"],

                result["entropy"],

                result["crack_time"]

            )


    return render_template(

        "index.html",

        result=result,

        policy=policy,

        username=session.get(
            "username"
        )

    )


# ==================================================
# HISTORY
# ==================================================

@app.route("/history")
def history():

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    records = (

        PasswordHistory.query

        .filter_by(
            user_id=get_current_user_id()
        )

        .order_by(
            PasswordHistory.id.desc()
        )

        .all()

    )


    return render_template(

        "history.html",

        records=records

    )


# ==================================================
# DELETE HISTORY
# ==================================================

@app.route(
    "/delete_history/<int:record_id>",
    methods=["POST"]
)
def delete_history(record_id):

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    record = PasswordHistory.query.filter_by(

        id=record_id,

        user_id=get_current_user_id()

    ).first()


    if record:

        db.session.delete(record)

        db.session.commit()


    return redirect(
        url_for("history")
    )


# ==================================================
# CLEAR HISTORY
# ==================================================

@app.route(
    "/clear_history",
    methods=["POST"]
)
def clear_history():

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    PasswordHistory.query.filter_by(

        user_id=get_current_user_id()

    ).delete()


    db.session.commit()


    return redirect(
        url_for("history")
    )


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
def dashboard():

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    user_id = get_current_user_id()


    total_scans = PasswordHistory.query.filter_by(
        user_id=user_id
    ).count()


    weak_count = PasswordHistory.query.filter_by(
        user_id=user_id,
        strength="Weak"
    ).count()


    medium_count = PasswordHistory.query.filter_by(
        user_id=user_id,
        strength="Medium"
    ).count()


    strong_count = PasswordHistory.query.filter_by(
        user_id=user_id,
        strength="Strong"
    ).count()


    recent_scans = (

        PasswordHistory.query

        .filter_by(
            user_id=user_id
        )

        .order_by(
            PasswordHistory.id.desc()
        )

        .limit(5)

        .all()

    )


    return render_template(

        "dashboard.html",

        total_scans=total_scans,

        weak_count=weak_count,

        medium_count=medium_count,

        strong_count=strong_count,

        recent_scans=recent_scans

    )


# ==================================================
# PASSWORD GENERATOR
# ==================================================

@app.route(
    "/generate_password",
    methods=["GET", "POST"]
)
def generate_password_route():

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    generated_password = None


    if request.method == "POST":

        try:

            length = int(
                request.form.get(
                    "length",
                    14
                )
            )

        except ValueError:

            length = 14


        generated_password = generate_password(

            length=length,

            use_upper=bool(
                request.form.get(
                    "use_upper"
                )
            ),

            use_lower=bool(
                request.form.get(
                    "use_lower"
                )
            ),

            use_digits=bool(
                request.form.get(
                    "use_digits"
                )
            ),

            use_special=bool(
                request.form.get(
                    "use_special"
                )
            )

        )


    return render_template(

        "generator.html",

        generated_password=generated_password

    )


# ==================================================
# POLICY
# ==================================================

@app.route(
    "/policy",
    methods=["GET", "POST"]
)
def policy():

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    user_id = get_current_user_id()


    if request.method == "POST":

        try:

            min_length = int(
                request.form.get(
                    "min_length",
                    8
                )
            )

        except ValueError:

            min_length = 8


        min_length = max(
            4,
            min(min_length, 128)
        )


        update_user_policy(

            user_id,

            min_length,

            1 if request.form.get(
                "require_uppercase"
            ) else 0,

            1 if request.form.get(
                "require_lowercase"
            ) else 0,

            1 if request.form.get(
                "require_digit"
            ) else 0,

            1 if request.form.get(
                "require_special"
            ) else 0

        )


        flash(
            "Password policy updated successfully.",
            "success"
        )


        return redirect(
            url_for("policy")
        )


    return render_template(

        "policy.html",

        policy=get_user_policy(
            user_id
        )

    )


# ==================================================
# EXPORT CSV
# ==================================================

@app.route("/export_csv")
def export_csv():

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    records = (

        PasswordHistory.query

        .filter_by(
            user_id=get_current_user_id()
        )

        .order_by(
            PasswordHistory.id.desc()
        )

        .all()

    )


    output = StringIO()

    writer = csv.writer(output)


    writer.writerow([
        "ID",
        "Password",
        "Score",
        "Strength",
        "Color",
        "Entropy",
        "Estimated Crack Time",
        "Scan Time"
    ])


    for row in records:

        writer.writerow([

            row.id,

            row.password_text,

            row.score,

            row.strength,

            row.color,

            row.entropy,

            row.crack_time,

            row.scan_time

        ])


    mem = BytesIO(
        output.getvalue().encode(
            "utf-8"
        )
    )

    mem.seek(0)


    return send_file(

        mem,

        mimetype="text/csv",

        as_attachment=True,

        download_name="password_history.csv"

    )


# ==================================================
# EXPORT PDF
# ==================================================

@app.route("/export_pdf")
def export_pdf():

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    records = (

        PasswordHistory.query

        .filter_by(
            user_id=get_current_user_id()
        )

        .order_by(
            PasswordHistory.id.desc()
        )

        .all()

    )


    buffer = BytesIO()


    doc = SimpleDocTemplate(

        buffer,

        pagesize=A4

    )


    styles = getSampleStyleSheet()


    elements = []


    elements.append(

        Paragraph(

            "Cyber Password Security Engine - Password Report",

            styles["Title"]

        )

    )


    elements.append(
        Spacer(1, 12)
    )


    elements.append(

        Paragraph(

            f"User: {session.get('username')}",

            styles["Normal"]

        )

    )


    elements.append(

        Paragraph(

            "Generated on: "
            + datetime.now().strftime(
                "%d-%m-%Y %I:%M:%S %p"
            ),

            styles["Normal"]

        )

    )


    elements.append(
        Spacer(1, 12)
    )


    table_data = [[

        "Password",

        "Score",

        "Strength",

        "Entropy",

        "Crack Time",

        "Scan Time"

    ]]


    for row in records:

        table_data.append([

            row.password_text,

            row.score,

            row.strength,

            row.entropy,

            row.crack_time,

            row.scan_time

        ])


    table = Table(

        table_data,

        repeatRows=1

    )


    table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.black
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                1,
                colors.grey
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "BACKGROUND",
                (0, 1),
                (-1, -1),
                colors.whitesmoke
            )

        ])

    )


    elements.append(table)


    doc.build(elements)


    buffer.seek(0)


    return send_file(

        buffer,

        as_attachment=True,

        download_name="password_report.pdf",

        mimetype="application/pdf"

    )


# ==================================================
# APP STARTUP
# ==================================================

with app.app_context():

    init_db()

    create_default_user_if_needed()


if __name__ == "__main__":

    app.run(debug=True)