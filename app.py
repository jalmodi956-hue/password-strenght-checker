import os
import re
import math
import hashlib
from datetime import datetime
from functools import wraps
from io import BytesIO

import requests

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file
)

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer


# =========================================================
# APP CONFIG
# =========================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "hexa-shield-secret-key"
)

database_url = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("STORAGE_URL")
    or "sqlite:///password_checker.db"
)

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True
}

db = SQLAlchemy(app)


# =========================================================
# DATE TIME
# =========================================================

def current_time():
    return datetime.now().strftime(
        "%d-%m-%Y %I:%M:%S %p"
    )


# =========================================================
# USER MODEL
# =========================================================

class User(db.Model):

    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default="user"
    )

    theme = db.Column(
        db.String(20),
        default="dark"
    )

    created_at = db.Column(
        db.String(50)
    )


# =========================================================
# PASSWORD SCAN MODEL
# =========================================================

class PasswordScan(db.Model):

    __tablename__ = "scans"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        nullable=False
    )

    password_length = db.Column(
        db.Integer,
        default=0
    )

    score = db.Column(
        db.Integer,
        default=0
    )

    strength = db.Column(
        db.String(50)
    )

    entropy = db.Column(
        db.Float,
        default=0
    )

    crack_time = db.Column(
        db.String(100)
    )

    breached = db.Column(
        db.Boolean,
        default=False
    )

    scan_time = db.Column(
        db.String(50)
    )


# =========================================================
# PASSWORD POLICY MODEL
# =========================================================

class PasswordPolicy(db.Model):

    __tablename__ = "password_policy"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        unique=True,
        nullable=False
    )

    min_length = db.Column(
        db.Integer,
        default=8
    )

    require_uppercase = db.Column(
        db.Boolean,
        default=True
    )

    require_lowercase = db.Column(
        db.Boolean,
        default=True
    )

    require_number = db.Column(
        db.Boolean,
        default=True
    )

    require_special = db.Column(
        db.Boolean,
        default=True
    )


# =========================================================
# DATABASE START
# =========================================================

def update_database():

    try:

        with app.app_context():

            db.create_all()

            print("DATABASE TABLES READY")

    except Exception as error:

        print(
            "DATABASE ERROR:",
            repr(error)
        )


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login first.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return decorated_function


# =========================================================
# ADMIN REQUIRED
# =========================================================

def admin_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if not session.get("is_admin"):

            flash(
                "Admin access required.",
                "danger"
            )

            return redirect(
                url_for("index")
            )

        return function(*args, **kwargs)

    return decorated_function


# =========================================================
# ENTROPY
# =========================================================

def calculate_entropy(password):

    pool_size = 0

    if re.search(r"[a-z]", password):
        pool_size += 26

    if re.search(r"[A-Z]", password):
        pool_size += 26

    if re.search(r"[0-9]", password):
        pool_size += 10

    if re.search(r"[^A-Za-z0-9]", password):
        pool_size += 32

    if pool_size == 0:
        return 0

    entropy = len(password) * math.log2(pool_size)

    return round(entropy, 2)


# =========================================================
# CRACK TIME
# =========================================================

def calculate_crack_time(entropy):

    guesses_per_second = 10_000_000_000

    seconds = (2 ** entropy) / guesses_per_second

    if seconds < 1:
        return "Instantly"

    if seconds < 60:
        return f"{int(seconds)} seconds"

    if seconds < 3600:
        return f"{int(seconds / 60)} minutes"

    if seconds < 86400:
        return f"{int(seconds / 3600)} hours"

    if seconds < 31536000:
        return f"{int(seconds / 86400)} days"

    years = seconds / 31536000

    if years > 1_000_000_000:
        return "Billions of years"

    if years > 1_000_000:
        return "Millions of years"

    if years > 1000:
        return "Thousands of years"

    return f"{int(years)} years"


# =========================================================
# BREACH API
# =========================================================

def check_password_breach(password):

    try:

        password_hash = hashlib.sha1(
            password.encode("utf-8")
        ).hexdigest().upper()

        prefix = password_hash[:5]
        suffix = password_hash[5:]

        response = requests.get(
            "https://api.pwnedpasswords.com/range/" + prefix,
            timeout=5
        )

        if response.status_code != 200:
            return False

        for line in response.text.splitlines():

            hash_suffix = line.split(":")[0]

            if hash_suffix == suffix:
                return True

        return False

    except requests.RequestException:

        return False


# =========================================================
# PASSWORD ANALYZER
# =========================================================

def analyze_password(password):

    score = 0
    recommendations = []

    if len(password) >= 8:
        score += 1
    else:
        recommendations.append(
            "Use at least 8 characters."
        )

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        recommendations.append(
            "Add an uppercase letter."
        )

    if re.search(r"[a-z]", password):
        score += 1
    else:
        recommendations.append(
            "Add a lowercase letter."
        )

    if re.search(r"[0-9]", password):
        score += 1
    else:
        recommendations.append(
            "Add a number."
        )

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        recommendations.append(
            "Add a special character."
        )

    if score <= 2:
        strength = "Weak"

    elif score == 3:
        strength = "Medium"

    elif score == 4:
        strength = "Strong"

    else:
        strength = "Very Strong"

    entropy = calculate_entropy(password)

    crack_time = calculate_crack_time(entropy)

    breached = check_password_breach(password)

    if breached:

        recommendations.insert(
            0,
            "Password appears in known breach data. Do not reuse it."
        )

    if len(password) < 12:

        recommendations.append(
            "For better security use 12-16 characters."
        )

    if not recommendations:

        recommendations.append(
            "Password security looks strong. Keep it unique."
        )

    return {
        "score": score,
        "strength": strength,
        "entropy": entropy,
        "crack_time": crack_time,
        "breached": breached,
        "recommendations": recommendations
    }


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        user = User.query.filter(
            db.func.lower(User.email) == email
        ).first()

        if user is None:

            flash(
                "Email account not found.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        if not check_password_hash(
            user.password,
            password
        ):

            flash(
                "Incorrect password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        session.clear()

        session["user_id"] = user.id
        session["username"] = user.username
        session["is_admin"] = user.role == "admin"
        session["theme"] = user.theme or "dark"

        flash(
            "Login successful.",
            "success"
        )

        return redirect(
            url_for("index")
        )

    return render_template(
        "login.html"
    )


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not username or not email or not password:

            flash(
                "All fields are required.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "warning"
            )

            return redirect(
                url_for("register")
            )

        if User.query.filter_by(
            username=username
        ).first():

            flash(
                "Username already exists.",
                "warning"
            )

            return redirect(
                url_for("register")
            )

        if User.query.filter_by(
            email=email
        ).first():

            flash(
                "Email already registered.",
                "warning"
            )

            return redirect(
                url_for("register")
            )

        try:

            user = User(
                username=username,
                email=email,
                password=generate_password_hash(password),
                role="user",
                theme="dark",
                created_at=current_time()
            )

            db.session.add(user)

            db.session.flush()

            user_policy = PasswordPolicy(
                user_id=user.id,
                min_length=8,
                require_uppercase=True,
                require_lowercase=True,
                require_number=True,
                require_special=True
            )

            db.session.add(user_policy)

            db.session.commit()

            flash(
                "Account created successfully. Please login.",
                "success"
            )

            return redirect(
                url_for("login")
            )

        except Exception as error:

            db.session.rollback()

            print(
                "REGISTER ERROR:",
                repr(error)
            )

            flash(
                "Unable to create account.",
                "danger"
            )

    return render_template(
        "register.html"
    )


# =========================================================
# ANALYZER
# =========================================================

@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    result = None

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        if not password:

            flash(
                "Please enter a password.",
                "warning"
            )

            return redirect(
                url_for("index")
            )

        result = analyze_password(password)

        scan = PasswordScan(
            user_id=session["user_id"],
            password_length=len(password),
            score=result["score"],
            strength=result["strength"],
            entropy=result["entropy"],
            crack_time=result["crack_time"],
            breached=result["breached"],
            scan_time=current_time()
        )

        try:

            db.session.add(scan)

            db.session.commit()

        except Exception as error:

            db.session.rollback()

            print(
                "SCAN SAVE ERROR:",
                repr(error)
            )

            flash(
                "Unable to save scan.",
                "danger"
            )

        session["last_result"] = result

    return render_template(
        "index.html",
        result=result
    )


# =========================================================
# GENERATOR
# =========================================================

@app.route("/generator")
@login_required
def generator():

    return render_template(
        "generator.html"
    )


# =========================================================
# HISTORY
# =========================================================

@app.route("/history")
@login_required
def history():

    scans = (
        PasswordScan.query
        .filter_by(
            user_id=session["user_id"]
        )
        .order_by(
            PasswordScan.id.desc()
        )
        .all()
    )

    return render_template(
        "history.html",
        scans=scans
    )


# =========================================================
# CLEAR HISTORY
# =========================================================

@app.route("/clear-history")
@login_required
def clear_history():

    PasswordScan.query.filter_by(
        user_id=session["user_id"]
    ).delete()

    db.session.commit()

    flash(
        "Scan history cleared.",
        "success"
    )

    return redirect(
        url_for("history")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    scans = PasswordScan.query.filter_by(
        user_id=session["user_id"]
    ).all()

    total_scans = len(scans)

    if total_scans:

        average_score = round(
            sum(
                scan.score or 0
                for scan in scans
            ) / total_scans,
            2
        )

    else:

        average_score = 0

    weak_count = sum(
        scan.strength == "Weak"
        for scan in scans
    )

    medium_count = sum(
        scan.strength == "Medium"
        for scan in scans
    )

    strong_count = sum(
        scan.strength == "Strong"
        for scan in scans
    )

    very_strong_count = sum(
        scan.strength == "Very Strong"
        for scan in scans
    )

    strong_passwords = (
        strong_count + very_strong_count
    )

    if total_scans:

        strong_percentage = round(
            (
                strong_passwords
                / total_scans
            ) * 100,
            2
        )

    else:

        strong_percentage = 0

    last_scan = (
        PasswordScan.query
        .filter_by(
            user_id=session["user_id"]
        )
        .order_by(
            PasswordScan.id.desc()
        )
        .first()
    )

    last_scan_time = (
        last_scan.scan_time
        if last_scan
        else None
    )

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        average_score=average_score,
        strong_passwords=strong_passwords,
        strong_percentage=strong_percentage,
        last_scan_time=last_scan_time,
        weak_count=weak_count,
        medium_count=medium_count,
        strong_count=strong_count,
        very_strong_count=very_strong_count
    )


# =========================================================
# PASSWORD POLICY
# =========================================================

@app.route("/policy", methods=["GET", "POST"])
@login_required
def policy():

    user_policy = PasswordPolicy.query.filter_by(
        user_id=session["user_id"]
    ).first()

    if not user_policy:

        user_policy = PasswordPolicy(
            user_id=session["user_id"],
            min_length=8,
            require_uppercase=True,
            require_lowercase=True,
            require_number=True,
            require_special=True
        )

        db.session.add(user_policy)

        db.session.commit()

    if request.method == "POST":

        try:

            min_length = int(
                request.form.get(
                    "min_length",
                    8
                )
            )

            user_policy.min_length = max(
                6,
                min(min_length, 64)
            )

            user_policy.require_uppercase = (
                "require_uppercase"
                in request.form
            )

            user_policy.require_lowercase = (
                "require_lowercase"
                in request.form
            )

            user_policy.require_number = (
                "require_number"
                in request.form
            )

            user_policy.require_special = (
                "require_special"
                in request.form
            )

            db.session.commit()

            flash(
                "Password policy updated.",
                "success"
            )

            return redirect(
                url_for("policy")
            )

        except Exception as error:

            db.session.rollback()

            print(
                "POLICY ERROR:",
                repr(error)
            )

            flash(
                "Unable to update policy.",
                "danger"
            )

    return render_template(
        "policy.html",
        policy=user_policy
    )


# =========================================================
# PDF EXPORT
# =========================================================

@app.route("/export-pdf")
@login_required
def export_pdf():

    result = session.get(
        "last_result"
    )

    if not result:

        flash(
            "Analyze a password first.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4
    )

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "Hexa Shield Security Report",
            styles["Title"]
        )
    )

    content.append(
        Spacer(1, 20)
    )

    content.append(
        Paragraph(
            f"Security Score: {result['score']}/5",
            styles["Normal"]
        )
    )

    content.append(
        Spacer(1, 10)
    )

    content.append(
        Paragraph(
            f"Password Strength: {result['strength']}",
            styles["Normal"]
        )
    )

    content.append(
        Spacer(1, 10)
    )

    content.append(
        Paragraph(
            f"Entropy: {result['entropy']} bits",
            styles["Normal"]
        )
    )

    content.append(
        Spacer(1, 10)
    )

    content.append(
        Paragraph(
            f"Estimated Crack Time: {result['crack_time']}",
            styles["Normal"]
        )
    )

    breach_status = (
        "Detected"
        if result["breached"]
        else "Not Detected"
    )

    content.append(
        Spacer(1, 10)
    )

    content.append(
        Paragraph(
            f"Known Breach Status: {breach_status}",
            styles["Normal"]
        )
    )

    content.append(
        Spacer(1, 20)
    )

    content.append(
        Paragraph(
            "Security Recommendations",
            styles["Heading2"]
        )
    )

    for recommendation in result["recommendations"]:

        content.append(
            Paragraph(
                f"- {recommendation}",
                styles["Normal"]
            )
        )

        content.append(
            Spacer(1, 5)
        )

    document.build(content)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="hexa_shield_report.pdf",
        mimetype="application/pdf"
    )


# =========================================================
# ADMIN
# =========================================================

@app.route("/admin")
@login_required
@admin_required
def admin():

    users = User.query.order_by(
        User.id.desc()
    ).all()

    total_users = User.query.count()

    total_scans = PasswordScan.query.count()

    return render_template(
        "admin.html",
        users=users,
        total_users=total_users,
        total_scans=total_scans
    )


# =========================================================
# DELETE USER
# =========================================================

@app.route("/admin/delete-user/<int:user_id>")
@login_required
@admin_required
def delete_user(user_id):

    if user_id == session["user_id"]:

        flash(
            "You cannot delete your own account.",
            "warning"
        )

        return redirect(
            url_for("admin")
        )

    user = db.session.get(
        User,
        user_id
    )

    if not user:

        flash(
            "User not found.",
            "danger"
        )

        return redirect(
            url_for("admin")
        )

    PasswordScan.query.filter_by(
        user_id=user.id
    ).delete()

    PasswordPolicy.query.filter_by(
        user_id=user.id
    ).delete()

    db.session.delete(user)

    db.session.commit()

    flash(
        "User deleted successfully.",
        "success"
    )

    return redirect(
        url_for("admin")
    )


# =========================================================
# LOGOUT
# =========================================================

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


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

update_database()


# =========================================================
# RUN APP
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )