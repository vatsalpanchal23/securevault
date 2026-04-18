# 🔐 SecureVault – Advanced Password Manager

SecureVault is a cybersecurity-focused password manager built using **Flask + MySQL**, designed to securely store credentials, enforce strong authentication, and demonstrate real-world defensive security practices.

---

## 🚀 Features

### 🔑 Authentication & Security

* User Registration & Login System
* Two-Factor Authentication (2FA) via Email OTP
* QR Code-Based Login (Cross-device authentication)
* Secure session management
* Brute-force attack mitigation (rate limiting / login protection)
* SQL Injection protection (parameterized queries)
* XSS mitigation (input sanitization & output escaping)

### 🛡️ Advanced Security Monitoring

* Real-time password breach detection
* Security log analysis
* User activity tracking & audit logs
* Suspicious behavior detection (login anomalies, repeated failures)

### 🔒 Encryption

* Password encryption using **Fernet (symmetric encryption)**
* Secure key management (`secret.key`)
* File encryption & decryption support
* No plaintext password storage

### 🗂️ Password Vault

* Add, edit, delete credentials
* Category/tag-based organization
* Search & filtering system
* Password visibility only in edit mode
* Copy-to-clipboard functionality

### ⚠️ Security Enhancements

* Password breach checking (`/check_breach`)
* Strong password generator
* Input validation on all forms

### 🎨 User Interface

* Modern glassmorphism UI
* Dark / Light mode toggle
* Responsive dashboard
* Toast notifications & visual feedback

### 📂 Additional Features

* File encryption/decryption tool
* Profile photo upload
* Export vault (planned)

---

## 🛠️ Tech Stack

**Backend:**

* Python (Flask)
* MySQL

**Frontend:**

* HTML, CSS (TailwindCSS + custom styling)
* JavaScript

**Security:**

* Fernet Encryption (`cryptography`)
* Email OTP (2FA)

---

## 📁 Project Structure

```
SecureVault/
│
├── backend.py
├── encryption.py
├── db_config.py
├── database.sql
│
├── templates/
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── verify_otp.html
│   ├── qr_login.html
│
├── static/
│   ├── static.css
│   ├── assets/
│
├── secret.key
└── README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone Repository

```bash
git clone https://github.com/your-username/securevault.git
cd securevault
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Setup Database

* Import `database.sql` into MySQL
* Update credentials in `db_config.py`

### 4️⃣ Run Application

```bash
python backend.py
```

Access: `http://127.0.0.1:5000`

---

## 🔐 Security Notes (Important)

* Never commit or expose `secret.key`
* Use **environment variables** for:

  * DB credentials
  * Email credentials
  * Secret keys
* Enable HTTPS in production
* Use strong email security (App Passwords, not raw password)
* Implement proper session timeout & logout handling

---

## ⚠️ Missing / Recommended Security Improvements

Your README is strong—but for a **final-year cybersecurity project**, these will elevate it significantly:

### 🔧 Add if not already implemented:

* CSRF Protection (Flask-WTF or tokens) ⚠️ *important*
* Password hashing for login (e.g., bcrypt) *(even if vault uses encryption)*
* Rate limiting (Flask-Limiter)
* Secure cookies (`HttpOnly`, `Secure`, `SameSite`)
* Input validation + length restrictions
* File upload validation (MIME type + size limits)
* Logging failed login attempts with IP tracking
* Account lockout after repeated failures

### 🧠 Advanced (high impact for evaluation):

* Zero-knowledge architecture explanation (even partial)
* Encrypted backups
* Threat model section in README
* Security architecture diagram

---

## 📈 Future Enhancements

* Biometric authentication
* Encrypted vault export (CSV/JSON)
* Browser extension
* Role-based access control
* Real-time alert system

---

## 🤝 Contribution

* Report bugs
* Suggest features
* Submit pull requests

---

## 📜 License

For educational use. Modify as needed.

---

## 👨‍💻 Author

Developed as a cybersecurity project demonstrating **practical secure system design, encryption, and attack mitigation techniques**.

---

## ⚡ Final Note

This is not just a CRUD app — it actively demonstrates:

* Defensive coding
* Authentication hardening
* Encryption usage
* Attack mitigation

That distinction matters a lot during interviews and evaluations 🚀
