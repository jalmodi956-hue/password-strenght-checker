# 🔐 Cyber Password Security Engine

A modern **Flask-based Password Strength Checker** with a **cyber / hacker style UI** that analyzes password security using multiple checks such as strength score, entropy, estimated crack time, weak password detection, sequence detection, and history tracking.

---

## 🚀 Features

### 🔍 Password Security Analysis

* Password strength score out of **100**
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

### 📊 Data & Tracking

* Save password scan history in **SQLite**
* Store **masked passwords** instead of plain text
* View full **scan history**
* **Delete individual records**
* **Clear all history**
* **Dashboard analytics**
* **Export scan history as CSV**

### 🎨 UI / UX

* Cyber / hacker style dark theme
* Live strength preview
* Show / hide password
* Copy password button
* Security recommendations
* Responsive design

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask
* **Frontend:** HTML, CSS, JavaScript
* **Database:** SQLite
* **Other Modules:** `re`, `math`, `csv`, `datetime`

---

## 📂 Project Structure

```bash
Cyber_Password_Security_Engine/
│
├── app.py
├── password_checker.db
│
├── templates/
│   ├── index.html
│   ├── history.html
│   └── dashboard.html
│
└── static/
    ├── style.css
    └── script.js
```

---

## ⚙️ Installation & Setup

### 1) Clone the repository

```bash
git clone <your-repository-link>
cd Cyber_Password_Security_Engine
```

### 2) Install Flask

```bash
pip install flask
```

### 3) Run the application

```bash
python app.py
```

### 4) Open in browser

```bash
http://127.0.0.1:5000
```

---

## 🧠 How It Works

The application checks the password using multiple rules:

* **Length-based scoring**
* Presence of:

  * uppercase letters
  * lowercase letters
  * numbers
  * special characters
* Bonus points for:

  * longer passwords
  * multiple special characters
  * more unique characters
* Penalty points for:

  * common weak passwords
  * repeated characters
  * simple sequences
  * keyboard patterns

It also calculates:

* **Entropy**
* **Estimated crack time**

After analysis, the password scan result is stored in the database with:

* masked password
* score
* strength
* entropy
* crack time
* scan date & time

---

## 📸 Pages in the Project

### 1. Home Page

* Enter password
* Run security analysis
* View score, strength, entropy, crack time
* See suggestions for improvement

### 2. History Page

* View all previous scans
* Delete individual records
* Clear all history

### 3. Dashboard Page

* Total scans
* Weak password count
* Medium password count
* Strong password count
* Recent scans

---

## 🔐 Example Security Checks

The engine can detect risky passwords such as:

* `123456`
* `password`
* `admin123`
* `aaaa111`
* `abc123`
* `qwerty123`

---

## 📤 Export Feature

The app allows users to export scan history in **CSV format** for reporting and analysis.

---

## 📌 Future Improvements

Possible upgrades for the project:

* Password breach API integration
* Password generator
* Login / user authentication
* PDF export report
* Charts on dashboard
* Multi-user support
* Password policy customization

---

## 👨‍💻 Author

**Jal Modi**

---

## 📜 License

This project is for **educational and learning purposes**.
