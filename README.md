# 🔐 Cyber Password Security Engine

A modern **Flask-based Password Security Analyzer** with a **cyber / hacker style UI** that helps users test password strength, generate secure passwords, manage custom password policies, track scan history, and export reports.

---

# 🚀 Features

## 1) User Authentication

* User **Login**
* User **Register**
* **Logout**
* **Multi-user support** using SQLite database

---

## 2) Password Strength Analysis

The app analyzes passwords using multiple security checks:

* Password **score out of 100**
* Strength level:

  * **Weak**
  * **Medium**
  * **Strong**
* **Entropy calculation**
* **Estimated crack time**
* Uppercase / lowercase / digit / special character checks
* Common weak password detection
* Repeated character detection
* Sequence detection (`123`, `abc`, `qwe`)
* Keyboard pattern detection (`qwerty`, `asdf`)

---

## 3) Live Security Engine

* Live password score preview
* Live strength preview
* Live entropy preview
* Live crack time preview
* Live recommendations while typing
* Show / hide password
* Copy password

---

## 4) Password Generator

Users can generate strong passwords with custom settings:

* Select password length
* Include uppercase letters
* Include lowercase letters
* Include digits
* Include special characters
* Copy generated password

---

## 5) Password Policy Customization

Each user can define their own password policy:

* Minimum password length
* Require uppercase
* Require lowercase
* Require digit
* Require special character

---

## 6) Password Scan History

Every password scan can be stored in SQLite with:

* Masked password
* Score
* Strength
* Entropy
* Estimated crack time
* Scan date and time

History features:

* View all previous scans
* Delete individual records
* Clear all history

---

## 7) Security Dashboard

Dashboard shows a quick overview of password scan data:

* Total scans
* Weak password count
* Medium password count
* Strong password count
* Recent scan records

---

## 8) Report Export

The app supports exporting password scan data as:

* **CSV report**
* **PDF report**

---

# 🛠️ Tech Stack

* **Backend:** Python, Flask
* **Frontend:** HTML, CSS, JavaScript
* **Database:** SQLite
* **PDF Export:** ReportLab

---

# 📂 Project Structure

```bash id="moxc7z"
Cyber_Password_Security_Engine/
│
├── app.py
├── README.md
├── requirements.txt
├── password_checker.db
│
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── generator.html
│   ├── policy.html
│   ├── history.html
│   └── dashboard.html
│
└── static/
    ├── style.css
    └── script.js
```

---

# ⚙️ Installation & Setup

## 1) Clone the repository

```bash id="e12dd6"
git clone https://github.com/jalmodi956-hue/password-strenght-checker.git
cd password-strenght-checker
```

## 2) Install dependencies

```bash id="80c3dx"
pip install -r requirements.txt
```

## 3) Run the application

```bash id="8jsazx"
python app.py
```

## 4) Open in browser

```bash id="mk14t8"
http://127.0.0.1:5000
```

---

# 🔑 Default Login Credentials

A default admin user is automatically created when the app runs for the first time.

* **Username:** `admin`
* **Password:** `admin123`

---

# 🧠 How the Password Scoring Works

The password engine uses:

## Positive checks

* Longer password length
* Uppercase letters
* Lowercase letters
* Numbers
* Special characters
* Multiple unique characters
* More symbol variety

## Penalty checks

* Common weak passwords
* Repeated characters
* Sequential patterns
* Keyboard patterns

The final result includes:

* Score
* Strength level
* Entropy
* Crack time estimate
* Security recommendations

---

# 📄 Pages in the Project

## 1) Login Page

Allows existing users to log in.

## 2) Register Page

Allows new users to create an account.

## 3) Home Page / Password Checker

Main page for password strength analysis.

## 4) History Page

Displays all saved password scan records.

## 5) Dashboard Page

Displays overall password security statistics.

## 6) Generator Page

Creates strong random passwords based on selected settings.

## 7) Policy Page

Allows users to customize password rules.

---

# 🧪 Example Test Passwords

## Weak

```txt id="jz7zpq"
123456
```

## Medium

```txt id="ywdh7x"
jal12345
```

## Strong

```txt id="uwx7jk"
Jal@2026#SecurePass
```

---

# 📤 Export Features

## CSV Export

Exports all password scan history into a CSV file.

## PDF Export

Exports all password scan history into a PDF report with table format.

---

# 🔮 Future Improvements

Possible future upgrades:

* Password breach API integration
* Dashboard charts and graphs
* Password sharing risk analysis
* AI-based password recommendations
* Dark/light theme switch
* Email-based password alerts
* Admin panel for user management

---

# 👨‍💻 Author

**Jal Modi**

---

# 📜 License

This project is made for **educational and learning purposes**.
