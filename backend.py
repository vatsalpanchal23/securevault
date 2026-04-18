# =========================
# Standard Library Imports
# =========================
import os
import csv
import io
import json
import base64
import random
import string
import time
from datetime import datetime, timedelta, UTC
from dotenv import load_dotenv
load_dotenv()

# =========================
# Flask Imports
# =========================
from flask import (
    Flask,
    flash,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file,
    send_from_directory,
    Response,
    jsonify
)

from flask_wtf import CSRFProtect

app = Flask(__name__)
app.config["PROPAGATE_EXCEPTIONS"] = False
secret = os.environ.get("SECUREVAULT_SECRET")

if not secret:
    raise RuntimeError("SECUREVAULT_SECRET not set. Refusing to start.")

app.secret_key = secret

csrf = CSRFProtect(app)


import segno
from io import BytesIO
import socket
# =========================
# Database
# =========================
from db_config1 import get_db_connection
import mysql.connector

# =========================
# Security & Auth
# =========================
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =========================
# Cryptography
# =========================
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

# =========================
# Email
# =========================
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# =========================
# Project Files
# =========================
from encryption1 import encrypt_file, decrypt_file, encrypt_password, decrypt_password

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch


# In-memory QR store (token -> {status, user_id, created_at})
qr_store = {}

# -------------------- Rate Limiting --------------------

rate_limits = {}

def rate_limit(key, max_requests, window_seconds):
    now = time.time()
    bucket = rate_limits.get(key, [])

    # Remove expired timestamps
    bucket = [t for t in bucket if now - t < window_seconds]

    if len(bucket) >= max_requests:
        return False  # blocked

    bucket.append(now)
    rate_limits[key] = bucket
    return True


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "secure_uploads")
ENCRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, "encrypted")
DECRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, "decrypted")

os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
PROFILE_FOLDER = os.path.join(BASE_DIR, "static", "profile_photos")

DEFAULT_PHOTO = "default.png"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}


# Email (Gmail App Password)
EMAIL_ADDRESS = os.environ.get("SECUREVAULT_EMAIL")
EMAIL_PASSWORD = os.environ.get("SECUREVAULT_EMAIL_PASSWORD")

if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
    raise RuntimeError("Email environment variables not set")


# Ensure folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROFILE_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# -------------------- Utilities --------------------
import re

def is_strong_password(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def verify_user_password(user_id, password):
    conn = get_db_connection()
    if conn is None:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password_hash FROM users WHERE id = %s",
            (user_id,)
        )
        row = cursor.fetchone()
        if not row:
            return False

        return check_password_hash(row[0], password)

    finally:
        cursor.close()
        conn.close()


# -------------------- Global Session Security --------------------

@app.before_request
def enforce_session_security():
    public_routes = {
        "landing",
        "login",
        "signup",
        "forgot_password",
        "verify_reset_otp",
        "reset_password",
        "verify_otp",
        "static",
        "generate_qr_login",
        "qr_poll",
        "qr_confirm",
        "qr_login",
        "mark_safe"
    }

    if request.endpoint is None:
        return

    if request.endpoint in public_routes:
        return

    if "user_id" not in session:
        return redirect(url_for("landing"))

    now = time.time()

    last_activity = session.get("last_activity")
    session_ip = session.get("ip_address")
    session_ua = session.get("user_agent")

    current_ip = request.remote_addr
    current_ua = request.headers.get("User-Agent")

    # Inactivity timeout (5 minutes)
    if not last_activity or now - float(last_activity) > 300:
        log_security_event(session.get("user_id"), "SESSION_EXPIRED_INACTIVITY")
        session.clear()
        return redirect(url_for("landing"))

    # Session hijack detection
    if session_ip != current_ip or session_ua != current_ua:
        log_security_event(session.get("user_id"), "SESSION_HIJACK_DETECTED")
        session.clear()
        return redirect(url_for("landing"))

    # Refresh activity timestamp
    session["last_activity"] = now


# Cookie & session hardening
is_production = os.environ.get("ENV") == "production"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=is_production,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=5)
)


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def log_audit(action, user_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs (user_id, action, ip_address, user_agent)
            VALUES (%s, %s, %s, %s)
            """,
            (
                user_id,
                action,
                request.remote_addr,
                request.headers.get("User-Agent")
            )
        )
        conn.commit()
    except Exception as e:
        print("Audit log error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass


def send_html_email(receiver_email: str, subject: str, html_content: str):
    print("SMTP CONNECT STARTED")

    if not receiver_email or not receiver_email.strip():
        raise ValueError("Receiver email is empty")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = receiver_email.strip()

    msg.attach(MIMEText(html_content, "html"))

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

        # 🔴 IMPORTANT FIX: DO NOT use send_message
        server.sendmail(
            EMAIL_ADDRESS,
            [receiver_email.strip()],
            msg.as_string()
        )


def send_otp_email(receiver_email: str, otp: str, subject: str = "SecureVault 2FA OTP"):
    html_content = f"""
    <html><body>
      <p>Your SecureVault OTP is:</p>
      <h2>{otp}</h2>
      <p>This OTP will expire in 5 minutes.</p>
    </body></html>
    """
    send_html_email(receiver_email, subject, html_content)


def log_security_event(user_id, event, ip_address=None):
    conn = get_db_connection()
    if conn is None:
        return

    # 🔴 DEFINE RISK LEVEL HERE
    HIGH_RISK_EVENTS = {
        "LOGIN_FAILED",
        "SESSION_HIJACK_DETECTED",
        "ACCOUNT_LOCKED",
        "OTP_VERIFICATION_FAILED",
        "QR_LOGIN_REJECTED"
    }

    risk_level = "HIGH" if event in HIGH_RISK_EVENTS else "LOW"

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO security_logs (user_id, event, ip_address, risk_level)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, event, ip_address, risk_level)
        )
        conn.commit()
        cursor.close()
    finally:
        conn.close()





# -------------------- Routes --------------------

@app.route("/backup")
def backup_page():
    return render_template("backup.html")

@app.route("/restore")
def restore_page():
    return render_template("restore.html")

@app.route("/activity")
def activity():
    user_id = session["user_id"]

    conn = get_db_connection()
    if conn is None:
        return "Database connection failed."

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT action, ip_address, user_agent, created_at
            FROM audit_logs
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 100
            """,
            (user_id,)
        )
        logs = cursor.fetchall() or []
        cursor.close()
    except Exception as e:
        return f"Error fetching activity logs: {str(e)}"
    finally:
        conn.close()

    return render_template("activity.html", logs=logs)


@app.route("/restore_vault_encrypted", methods=["POST"])
def restore_vault_encrypted():
    if "user_id" not in session:
        return redirect(url_for("landing"))

    user_id = session["user_id"]

    # 🔐 Re-authentication
    confirm_password = request.form.get("confirm_password")
    if not confirm_password:
        flash("Password confirmation required", "error")
        return redirect(url_for("restore_page"))

    if not verify_user_password(user_id, confirm_password):
        log_audit("VAULT_RESTORE_REAUTH_FAILED", user_id)
        flash("Wrong account password", "error")
        return redirect(url_for("restore_page"))

    backup_password = request.form.get("backup_password")
    backup_file = request.files.get("backup_file")

    if not backup_password or not backup_file:
        flash("Backup file and password are required", "error")
        return redirect(url_for("restore_page"))

    try:
        # Read & decode file
        file_bytes = backup_file.read()
        decoded = base64.b64decode(file_bytes)

        # Extract salt + encrypted data
        salt = decoded[:16]
        encrypted_data = decoded[16:]

        # Decrypt backup
        key = derive_key(backup_password, salt)
        fernet = Fernet(key)
        decrypted_json = fernet.decrypt(encrypted_data)

        data = json.loads(decrypted_json.decode())

        # Validate structure
        if "vault" not in data or not isinstance(data["vault"], list):
            flash("Invalid backup file", "error")
            return redirect(url_for("restore_page"))

        conn = get_db_connection()
        if conn is None:
            flash("Database connection failed", "error")
            return redirect(url_for("restore_page"))

        cursor = conn.cursor()

        # ⚠️ Clear existing vault
        cursor.execute("DELETE FROM vault WHERE user_id = %s", (user_id,))

        # Restore vault entries
        restored_count = 0
        for item in data["vault"]:
            cursor.execute(
                """
                INSERT INTO vault (user_id, service_name, service_username, service_password)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    user_id,
                    item["service_name"],
                    item["service_username"],
                    item["service_password"],
                )
            )
            restored_count += 1

        conn.commit()

        # 📊 Audit log
        log_audit(f"VAULT_BACKUP_RESTORED | count={restored_count}", user_id)

        # ✅ Post-restore success summary
        return render_template(
            "restore_success.html",
            restored_count=restored_count,
            backup_time=data.get("exported_at")
        )

    except InvalidToken:
        flash("Wrong backup password or corrupted backup file", "error")
        return redirect(url_for("restore_page"))

    except Exception:
        flash("Restore failed due to an unexpected error", "error")
        return redirect(url_for("restore_page"))

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass





@app.route("/export_vault_encrypted", methods=["POST"])
def export_vault_encrypted():
    if "user_id" not in session:
        return redirect(url_for("landing"))

    user_id = session["user_id"]

    # 🔐 RE-AUTHENTICATION
    confirm_password = request.form.get("confirm_password")

    if not confirm_password:
        flash("Password confirmation required", "error")
        return redirect(url_for("backup_page"))

    if not verify_user_password(user_id, confirm_password):
        log_audit("VAULT_ENCRYPTED_EXPORT_REAUTH_FAILED", user_id)
        flash("Wrong account password", "error")
        return redirect(url_for("backup_page"))
    # 🔐 END RE-AUTH

    backup_password = request.form.get("backup_password")

    if not backup_password:
        flash("Backup password is required", "error")
        return redirect(url_for("backup_page"))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed", "error")
        return redirect(url_for("backup_page"))

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT service_name, service_username, service_password
            FROM vault
            WHERE user_id = %s
            """,
            (user_id,)
        )
        rows = cursor.fetchall()

        # Prepare JSON payload
        data = {
            "user_id": user_id,
            "exported_at": datetime.now(UTC).isoformat(),
            "vault": [
                {
                    "service_name": r[0],
                    "service_username": r[1],
                    "service_password": r[2]
                }
                for r in rows
            ]
        }

        json_data = json.dumps(data).encode()

        # Encrypt backup
        salt = os.urandom(16)
        key = derive_key(backup_password, salt)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(json_data)

        # Final payload (salt + encrypted data)
        final_blob = base64.b64encode(salt + encrypted_data)

        # 📊 ACTIVITY LOG — context-rich
        count = len(rows)
        log_audit(f"VAULT_BACKUP_EXPORTED | count={count}", user_id)

        

        return Response(
            final_blob,
            mimetype="application/octet-stream",
            headers={
                "Content-Disposition": "attachment; filename=securevault_backup.svault"
            }
        )

    except Exception:
        flash("Failed to export encrypted backup", "error")
        return redirect(url_for("backup_page"))

    finally:
        cursor.close()
        conn.close()





@app.route("/generate-password", methods=["GET"])
def generate_password():
    length = int(request.args.get("length", 12))
    if length < 4:
        return {"error": "Password length must be at least 4 characters"}, 400
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return {"password": password}

@app.route('/verify-master-password', methods=['POST'])
def verify_master_password():
    if 'user_id' not in session:
        return jsonify({'success': False}), 401

    data = request.get_json() or {}
    entered_password = (data.get('password') or "").strip()

    if not entered_password:
        return jsonify({'success': False}), 400

    user_id = session['user_id']
    ip = request.remote_addr

    # 🔒 Rate limit (critical for brute-force protection)
    if not rate_limit(f"re_auth:{user_id}:{ip}", 5, 60):
        return jsonify({'success': False, 'error': 'Too many attempts'}), 429

    # 🔒 Session binding check (extra protection)
    if (
        session.get("ip_address") != request.remote_addr or
        session.get("user_agent") != request.headers.get("User-Agent")
    ):
        session.clear()
        return jsonify({'success': False}), 403

    conn = get_db_connection()
    if conn is None:
        return jsonify({'success': False}), 500

    try:
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "SELECT password_hash FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], entered_password):
            # ✅ Success → allow sensitive actions
            session['re_auth'] = True
            log_security_event(user_id, "MASTER_PASSWORD_VERIFIED", ip)
            return jsonify({'success': True})

        # ❌ Failed attempt
        log_security_event(user_id, "MASTER_PASSWORD_FAILED", ip)
        return jsonify({'success': False}), 403

    except Exception:
        return jsonify({'success': False}), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        # --------------------
        # 🔒 Basic Validation
        # --------------------
        if not username or not email or not password:
            return render_template("signup.html", error="All fields are required.")

        # Username validation
        if len(username) < 3 or len(username) > 30:
            return render_template("signup.html", error="Username must be 3–30 characters.")

        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            return render_template("signup.html", error="Username can only contain letters, numbers, and underscores.")

        # Email validation
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            return render_template("signup.html", error="Invalid email format.")

        # --------------------
        # 🔐 Password Policy
        # --------------------
        if not is_strong_password(password):
            return render_template(
                "signup.html",
                error="Password must be at least 8 characters and include uppercase, lowercase, number, and symbol."
            )

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        if conn is None:
            return render_template("signup.html", error="Server error. Try again later.")

        cursor = conn.cursor()

        try:
            # Check existing user (avoid enumeration detail)
            cursor.execute(
                "SELECT id FROM users WHERE username = %s OR email = %s",
                (username, email)
            )
            if cursor.fetchone():
                return render_template("signup.html", error="User already exists.")

            # Insert user
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                (username, email, password_hash)
            )
            conn.commit()

        except Exception:
            conn.rollback()
            return render_template("signup.html", error="Something went wrong. Please try again.")

        finally:
            cursor.close()
            conn.close()

        return redirect(url_for("login"))

    return render_template("signup.html")




@app.route("/")
def landing():
    return render_template("landing.html")


# ========== Login + 2FA (using otp_verification table) ==========


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # --------------------
        # 🔒 Basic Validation
        # --------------------
        if not username or not password:
            return render_template("login.html", error="Invalid username or password")

        # 🔒 Rate limit (per IP + username)
        ip = request.remote_addr
        if not rate_limit(f"login:{username}:{ip}", 5, 60):
            return render_template("login.html", error="Too many attempts. Try again later.")

        conn = get_db_connection()
        if conn is None:
            return render_template("login.html", error="Server error. Try again later.")

        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT id, password_hash, email, failed_attempts, locked_until "
                "FROM users WHERE username = %s",
                (username,)
            )
            result = cursor.fetchone()

            now = datetime.now(UTC)

            # --------------------
            # ❌ USER NOT FOUND
            # --------------------
            if not result:
                log_security_event(None, "LOGIN_FAILED", ip)
                return render_template("login.html", error="Invalid username or password")

            user_id, password_hash, email, failed_attempts, locked_until = result

            # --------------------
            # 🔒 ACCOUNT LOCK CHECK
            # --------------------
            if locked_until and locked_until.replace(tzinfo=UTC) > now:
                log_security_event(user_id, "LOGIN_BLOCKED_ACCOUNT_LOCKED", ip)
                return render_template(
                    "login.html",
                    error="Account temporarily locked. Try again later."
                )

            # --------------------
            # ❌ WRONG PASSWORD
            # --------------------
            if not check_password_hash(password_hash, password):
                failed_attempts += 1

                if failed_attempts >= 5:
                    lock_until = now + timedelta(minutes=15)
                    cursor.execute(
                        "UPDATE users SET failed_attempts = %s, locked_until = %s WHERE id = %s",
                        (failed_attempts, lock_until, user_id)
                    )
                    log_security_event(user_id, "ACCOUNT_LOCKED_BRUTE_FORCE", ip)
                else:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = %s WHERE id = %s",
                        (failed_attempts, user_id)
                    )

                conn.commit()
                log_security_event(user_id, "LOGIN_FAILED", ip)

                return render_template("login.html", error="Invalid username or password")

            # --------------------
            # ✅ PASSWORD CORRECT
            # --------------------
            cursor.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s",
                (user_id,)
            )
            conn.commit()

            log_security_event(user_id, "LOGIN_PASSWORD_SUCCESS", ip)
            session["pre_2fa_user_id"] = user_id

            # --------------------
            # 📧 EMAIL VALIDATION
            # --------------------
            email = (email or "").strip()
            if not email:
                return render_template(
                    "login.html",
                    error="Invalid username or password"
                )

            # --------------------
            # 🔐 OTP GENERATION
            # --------------------
            otp = str(random.randint(100000, 999999))
            expires_at = now + timedelta(minutes=5)
            sent_at = now

            send_otp_email(email, otp, subject="SecureVault 2FA OTP")
            log_security_event(user_id, "OTP_SENT", ip)

            cursor.execute("DELETE FROM otp_verification WHERE user_id = %s", (user_id,))
            cursor.execute(
                """
                INSERT INTO otp_verification
                (user_id, otp, expires_at, attempts, locked_until, last_sent_at)
                VALUES (%s, %s, %s, 0, NULL, %s)
                """,
                (user_id, otp, expires_at, sent_at)
            )
            conn.commit()

            return redirect(url_for("verify_otp"))

        except Exception:
            conn.rollback()
            return render_template("login.html", error="Something went wrong. Try again.")

        finally:
            cursor.close()
            conn.close()

    return render_template("login.html")





# -------------------- Security Lab (Breach Simulation) --------------------

@app.route("/api/security_lab_data")
def api_security_lab_data():
    if "user_id" not in session:
        return jsonify({"encrypted": [], "plaintext_demo": []})

    user_id = session["user_id"]

    conn = get_db_connection()
    if conn is None:
        return jsonify({"encrypted": [], "plaintext_demo": []})

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, service_name, service_username, service_password
            FROM vault
            WHERE user_id = %s
            """,
            (user_id,)
        )
        rows = cursor.fetchall() or []

        # What attacker actually gets (raw encrypted values)
        encrypted_view = [
            {
                "id": r["id"],
                "service": r["service_name"],
                "username": r["service_username"],
                "password": r["service_password"]
            }
            for r in rows
        ]

        # Demo-only: how dangerous plaintext storage would look
        plaintext_demo = [
            {
                "id": r["id"],
                "service": r["service_name"],
                "username": r["service_username"],
                "password": f"{r['service_name'].lower()}_password123"
            }
            for r in rows
        ]

        # Audit: user opened the lab
        log_audit("SECURITY_LAB_VIEWED", user_id)

        return jsonify({
            "encrypted": encrypted_view,
            "plaintext_demo": plaintext_demo
        })

    finally:
        cursor.close()
        conn.close()




@app.route("/generate_security_report")
def generate_security_report():
    if "user_id" not in session:
        return redirect(url_for("landing"))

    username = session.get("username", "User")
    now = datetime.now().strftime("%d %B %Y, %H:%M:%S")

    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    title = styles["Title"]
    heading = styles["Heading2"]

    content = []

    # ---- Logo (if exists) ----
    logo_path = os.path.join(app.root_path, "static", "securevault_logo.png")
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=1.6 * inch, height=1.6 * inch)
        content.append(logo)
        content.append(Spacer(1, 0.2 * inch))

    # ---- Title Block ----
    content.append(Paragraph("SecureVault – Security Architecture Report", title))
    content.append(Spacer(1, 0.2 * inch))
    content.append(Paragraph(f"<b>Author:</b> {username}", normal))
    content.append(Paragraph(f"<b>Generated on:</b> {now}", normal))
    content.append(Spacer(1, 0.3 * inch))

    # ---- System Overview ----
    content.append(Paragraph("System Overview", heading))
    content.append(Paragraph(
        "SecureVault is a security-focused password management platform designed to protect sensitive credentials "
        "against real-world threats such as database breaches, account compromise, and session hijacking. "
        "It combines encryption-at-rest, multi-factor authentication, session binding, and audit logging "
        "to create a defense-in-depth architecture.",
        normal
    ))

    content.append(Spacer(1, 0.2 * inch))

    # ---- Threat Model ----
    content.append(Paragraph("Threat Model", heading))
    content.append(Paragraph(
        "The primary threat considered is a full database compromise. In such a scenario, an attacker gains access "
        "to all stored vault records. Secondary threats include credential stuffing, brute-force login attempts, "
        "session hijacking, and unauthorized access from untrusted devices.",
        normal
    ))

    content.append(Spacer(1, 0.2 * inch))

    # ---- Breach Scenario ----
    content.append(Paragraph("Breach Scenario", heading))
    content.append(Paragraph(
        "If an attacker steals the SecureVault database, they obtain only encrypted ciphertext. "
        "Service passwords are never stored in plaintext. Without access to the encryption key, "
        "the stolen data is computationally useless. This prevents mass credential exposure even "
        "after a successful breach.",
        normal
    ))

    content.append(Spacer(1, 0.2 * inch))

    # ---- Controls ----
    content.append(Paragraph("Security Controls Implemented", heading))
    content.append(Paragraph(
        "<b>• Encryption-at-Rest:</b> All stored passwords are encrypted using strong symmetric cryptography.<br/>"
        "<b>• Key Separation:</b> Encryption keys are not stored alongside the database.<br/>"
        "<b>• Two-Factor Authentication:</b> Login requires OTP verification via email.<br/>"
        "<b>• Session Binding:</b> Sessions are locked to IP and device fingerprint.<br/>"
        "<b>• Inactivity Timeout:</b> Sessions expire automatically after inactivity.<br/>"
        "<b>• Audit & Security Logs:</b> All sensitive actions are recorded for traceability.",
        normal
    ))

    content.append(Spacer(1, 0.2 * inch))

    # ---- Recommendations ----
    content.append(Paragraph("Recommended Secure Usage", heading))
    content.append(Paragraph(
        "For maximum protection, users should enable 2FA, avoid weak master passwords, log out from shared devices, "
        "and regularly review audit logs. When used correctly, SecureVault enforces hardened security and resists "
        "common attack vectors used in real-world breaches.",
        normal
    ))

    content.append(Spacer(1, 0.3 * inch))

    # ---- Verdict ----
    content.append(Paragraph(
        "<b>Security Status: PROTECTED</b><br/>"
        "When SecureVault is used as designed, it provides hardened protection against credential theft, "
        "database compromise, and unauthorized access. The system meets professional security expectations "
        "for a modern credential management platform.",
        normal
    ))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    doc.build(content)

    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name="SecureVault_Security_Report.pdf",
        mimetype="application/pdf"
    )



# ================= QR LOGIN =================


@app.route("/qr_login/<token>", methods=["GET", "POST"])
def qr_login(token):
    if token not in qr_store:
        return "QR expired or invalid."

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, password_hash FROM users WHERE username = %s",
            (username,)
        )
        result = cursor.fetchone()

        if not result:
            cursor.close()
            conn.close()
            return render_template(
                "qr_login.html",
                error="Invalid credentials",
                token=token
            )

        user_id, password_hash = result

        if not check_password_hash(password_hash, password):
            cursor.close()
            conn.close()
            return render_template(
                "qr_login.html",
                error="Invalid credentials",
                token=token
            )

        # Approve QR
        qr_store[token]["status"] = "approved"
        qr_store[token]["user_id"] = user_id

        log_security_event(user_id, "QR_LOGIN_APPROVED_FROM_DEVICE")
        log_audit("QR_LOGIN_APPROVED", user_id)

        cursor.close()
        conn.close()

        return render_template(
            "qr_login.html",
            success="Login approved. You may return to your computer.",
            token=token
        )

    # GET request
    return render_template("qr_login.html", token=token)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


@app.route("/generate_qr_login")
def generate_qr_login():
    ip = request.remote_addr
    if not rate_limit(f"qr_gen:{ip}", 5, 60):
        return jsonify({"error": "Too many QR requests. Try again later."}), 429

    token = base64.urlsafe_b64encode(os.urandom(32)).decode()

    qr_store[token] = {
        "status": "pending",
        "user_id": None,
        "created_at": time.time(),
        "origin_ip": request.remote_addr,
        "origin_ua": request.headers.get("User-Agent")
    }

    host_ip = get_local_ip()
    qr_url = f"http://{host_ip}:5000/qr_confirm/{token}"

    qr = segno.make(qr_url)
    buffer = BytesIO()
    qr.save(buffer, kind="png", scale=6)
    img_b64 = base64.b64encode(buffer.getvalue()).decode()

    return jsonify({"token": token, "qr_image": img_b64})




@app.route("/qr_poll/<token>")
def qr_poll(token):
    ip = request.remote_addr
    if not rate_limit(f"qr_poll:{ip}", 30, 60):
        return jsonify({"approved": False}), 429

    data = qr_store.get(token)
    if not data:
        return jsonify({"approved": False})

    # 🔒 Enforce origin binding
    if (
        data.get("origin_ip") != request.remote_addr or
        data.get("origin_ua") != request.headers.get("User-Agent")
    ):
        return jsonify({"approved": False}), 403

    # Expire after 2 minutes
    if time.time() - data["created_at"] > 120:
        qr_store.pop(token, None)
        return jsonify({"approved": False})

    if data["status"] == "approved" and data["user_id"]:
        user_id = data["user_id"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        username = cursor.fetchone()[0]
        cursor.close()
        conn.close()

        session.clear()
        session.permanent = True
        session["user_id"] = user_id
        session["username"] = username
        session["ip_address"] = request.remote_addr
        session["user_agent"] = request.headers.get("User-Agent")
        session["last_activity"] = time.time()

        qr_store.pop(token, None)

        log_security_event(user_id, "QR_LOGIN_SUCCESS")
        log_audit("QR_LOGIN_SUCCESS", user_id)

        return jsonify({"approved": True})

    return jsonify({"approved": False})




@app.route("/qr_confirm/<token>")
def qr_confirm(token):
    if token not in qr_store:
        return "QR expired or invalid."

    # Always go to the dedicated QR login page
    return redirect(url_for("qr_login", token=token))




from datetime import datetime, timedelta, UTC
import time

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        input_otp = (request.form.get("otp") or "").strip()
        user_id = session.get("pre_2fa_user_id")

        # 🔒 Basic validation
        if not user_id or not input_otp:
            return redirect(url_for("landing"))

        ip = request.remote_addr

        # 🔒 Rate limiting (OTP brute-force protection)
        if not rate_limit(f"otp:{user_id}:{ip}", 10, 300):
            return render_template(
                "verify_otp.html",
                error="Too many attempts. Try again later."
            )

        conn = get_db_connection()
        if conn is None:
            return render_template("verify_otp.html", error="Server error. Try again.")

        try:
            cursor = conn.cursor()

            # 🔍 Fetch OTP record
            cursor.execute(
                """
                SELECT otp, expires_at, attempts, locked_until
                FROM otp_verification
                WHERE user_id = %s
                """,
                (user_id,)
            )
            row = cursor.fetchone()

            if not row:
                return render_template(
                    "verify_otp.html",
                    error="Invalid or expired OTP."
                )

            otp, expires_at, attempts, locked_until = row
            now_utc = datetime.now(UTC)

            # 🔒 Lockout check
            if locked_until:
                locked_until = locked_until.replace(tzinfo=UTC)
                if now_utc < locked_until:
                    log_security_event(user_id, "OTP_BLOCKED_LOCKED", ip)
                    return render_template(
                        "verify_otp.html",
                        error="Too many attempts. Try again later."
                    )

            expires_at = expires_at.replace(tzinfo=UTC)

            # =====================================================
            # ✅ OTP SUCCESS
            # =====================================================
            if otp == input_otp and now_utc < expires_at:
                log_security_event(user_id, "OTP_VERIFIED_SUCCESS", ip)
                log_security_event(user_id, "LOGIN_SUCCESS", ip)

                # Update login timestamps
                cursor.execute(
                    """
                    UPDATE users
                    SET previous_login = last_login,
                        last_login = %s
                    WHERE id = %s
                    """,
                    (now_utc, user_id)
                )

                # Fetch session_version
                cursor.execute(
                    "SELECT session_version FROM users WHERE id = %s",
                    (user_id,)
                )
                session_version = cursor.fetchone()[0]

                # Fetch username
                cursor.execute(
                    "SELECT username FROM users WHERE id = %s",
                    (user_id,)
                )
                username = cursor.fetchone()[0]

                # 🔐 SESSION HARDENING
                session.clear()
                session.permanent = True

                session["user_id"] = user_id
                session["username"] = username
                session["session_version"] = session_version
                session["ip_address"] = request.remote_addr
                session["user_agent"] = request.headers.get("User-Agent")
                session["last_activity"] = time.time()

                # Cleanup OTP
                cursor.execute(
                    "DELETE FROM otp_verification WHERE user_id = %s",
                    (user_id,)
                )

                conn.commit()
                return redirect(url_for("dashboard"))

            # =====================================================
            # ❌ WRONG OTP
            # =====================================================
            attempts += 1

            if attempts >= 5:
                lock_until = now_utc + timedelta(minutes=10)
                cursor.execute(
                    """
                    UPDATE otp_verification
                    SET attempts = %s, locked_until = %s
                    WHERE user_id = %s
                    """,
                    (attempts, lock_until, user_id)
                )
                conn.commit()

                log_security_event(user_id, "OTP_LOCKED_BRUTE_FORCE", ip)

                return render_template(
                    "verify_otp.html",
                    error="Too many attempts. Try again later."
                )

            cursor.execute(
                "UPDATE otp_verification SET attempts = %s WHERE user_id = %s",
                (attempts, user_id)
            )
            conn.commit()

            log_security_event(user_id, "OTP_FAILED", ip)

            return render_template(
                "verify_otp.html",
                error="Invalid or expired OTP."
            )

        except Exception:
            conn.rollback()
            return render_template("verify_otp.html", error="Something went wrong.")

        finally:
            cursor.close()
            conn.close()

    return render_template("verify_otp.html")


@app.route("/mark_safe", methods=["POST"])
def mark_safe():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    conn = get_db_connection()
    if conn is None:
        flash("Database error", "error")
        return redirect(url_for("dashboard"))

    try:
        cursor = conn.cursor()

        # 🔴 (Optional) downgrade existing high-risk logs
        cursor.execute(
            """
            UPDATE security_logs
            SET risk_level = 'LOW'
            WHERE user_id = %s
              AND risk_level = 'HIGH'
            """,
            (user_id,)
        )

        conn.commit()

        # ✅ USER CONFIRMED THIS ACTIVITY WAS SAFE
        session["security_override_safe"] = True

        log_audit("SECURITY_MARKED_SAFE", user_id)
        flash("Security status restored to protected", "success")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("dashboard"))





from datetime import datetime, timedelta

@app.route("/security-logs")
def security_logs():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    risk_filter = request.args.get("risk")  # ?risk=high

    conn = get_db_connection()
    if conn is None:
        return "Database connection failed"

    cursor = conn.cursor(dictionary=True)

    if risk_filter == "high":
        cursor.execute(
            """
            SELECT event, ip_address, created_at, risk_level
            FROM security_logs
            WHERE user_id = %s
              AND risk_level = 'HIGH'
            ORDER BY created_at DESC
            LIMIT 100
            """,
            (user_id,)
        )
    else:
        cursor.execute(
            """
            SELECT event, ip_address, created_at, risk_level
            FROM security_logs
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 100
            """,
            (user_id,)
        )

    logs = cursor.fetchall()

    cursor.close()
    conn.close()

    # 🔑 Most recent IP (baseline) – still valid
    last_ip = logs[0]["ip_address"] if logs else None

    return render_template(
        "security_logs.html",
        logs=logs,
        last_ip=last_ip,
        risk_filter=risk_filter
    )



@app.route("/resend-otp")
def resend_otp():
    user_id = session.get("pre_2fa_user_id")
    username = session.get("pre_2fa_username")

    if not user_id or not username:
        return redirect(url_for("landing"))

    conn = get_db_connection()
    if conn is None:
        return "Database connection failed"

    try:
        cursor = conn.cursor()

        # ⏳ Cooldown check (60 seconds)
        cursor.execute(
            "SELECT last_sent_at FROM otp_verification WHERE user_id = %s",
            (user_id,)
        )
        row = cursor.fetchone()

        if row and row[0]:
            last_sent = row[0].replace(tzinfo=UTC)
            if datetime.now(UTC) < last_sent + timedelta(seconds=60):
                log_security_event(user_id, "OTP_RESEND_BLOCKED_COOLDOWN")
                return render_template(
                    "verify_otp.html",
                    error="Please wait 60 seconds before resending OTP."
                )

        # Generate new OTP
        otp = str(random.randint(100000, 999999))
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        sent_at = datetime.now(UTC)

        # Fetch email
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        receiver_email = cursor.fetchone()[0]

        # Reset OTP entry
        cursor.execute("DELETE FROM otp_verification WHERE user_id = %s", (user_id,))
        cursor.execute(
            """
            INSERT INTO otp_verification
            (user_id, otp, expires_at, attempts, locked_until, last_sent_at)
            VALUES (%s, %s, %s, 0, NULL, %s)
            """,
            (user_id, otp, expires_at, sent_at)
        )
        conn.commit()

        if receiver_email:
            send_otp_email(receiver_email, otp, subject="SecureVault 2FA OTP (Resent)")
            log_security_event(user_id, "OTP_RESENT")

    except Exception as e:
        return f"Error resending OTP: {str(e)}"

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("verify_otp"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))



# -------------------- Dashboard & Profile --------------------

from flask import make_response
from datetime import timezone, timedelta
import time
import os

@app.route("/dashboard")
def dashboard():
    # =====================================================
    # 🔐 AUTH CHECK
    # =====================================================
    if "user_id" not in session or "username" not in session:
        return redirect(url_for("landing"))

    # =====================================================
    # 🔐 SESSION SECURITY ENFORCEMENT
    # =====================================================
    now = time.time()
    last_activity = session.get("last_activity")

    if not last_activity or now - float(last_activity) > 300:
        log_security_event(session.get("user_id"), "SESSION_EXPIRED_INACTIVITY")
        session.clear()
        return redirect(url_for("landing"))

    if (
        session.get("ip_address") != request.remote_addr or
        session.get("user_agent") != request.headers.get("User-Agent")
    ):
        log_security_event(session.get("user_id"), "SESSION_HIJACK_DETECTED")
        session.clear()
        return redirect(url_for("landing"))

    session["last_activity"] = now

    user_id = session["user_id"]
    username = session["username"]

    log_audit("DASHBOARD_OPENED", user_id)

    # =====================================================
    # 👤 FETCH USER DATA (PHOTO + LAST LOGIN)
    # =====================================================
    conn = get_db_connection()
    if conn is None:
        return "Database connection failed", 500

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT photo, previous_login FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        cursor.close()
    finally:
        conn.close()

    # =====================================================
    # 🖼️ PROFILE PHOTO
    # =====================================================
    photo = user["photo"] if user and user.get("photo") else None

    if photo and os.path.exists(os.path.join(PROFILE_FOLDER, photo)):
        profile_photo_url = url_for(
            "static",
            filename=f"profile_photos/{photo}",
            v=int(time.time())
        )
    else:
        profile_photo_url = url_for(
            "static",
            filename=f"profile_photos/{DEFAULT_PHOTO}"
        )

    # =====================================================
    # 🕒 LAST LOGIN TIME (UTC → IST)
    # =====================================================
    last_login_time = user["previous_login"] if user else None
    if last_login_time:
        last_login_time = (
            last_login_time
            .replace(tzinfo=timezone.utc)
            .astimezone(timezone(timedelta(hours=5, minutes=30)))
        )

    # =====================================================
    # 🛡️ SECURITY STATUS (ORIGINAL LOGIC + USER OVERRIDE)
    # =====================================================
    security_status = "Protected"
    security_level = "secure"

    # ✅ USER CLICKED "MARK AS SAFE"
    if session.get("security_override_safe"):
        security_status = "Protected"
        security_level = "secure"
    else:
        conn = get_db_connection()
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT COUNT(*) AS failures
                FROM security_logs
                WHERE user_id = %s
                  AND event IN ('LOGIN_FAILED', 'SESSION_HIJACK_DETECTED')
                  AND created_at >= NOW() - INTERVAL 24 HOUR
                """,
                (user_id,)
            )
            failures = cursor.fetchone()["failures"]
            cursor.close()
        finally:
            conn.close()

        if failures >= 3:
            security_status = "At Risk"
            security_level = "danger"
        elif failures >= 1:
            security_status = "Warning"
            security_level = "warning"

    # =====================================================
    # 🎯 RENDER DASHBOARD (CACHE DISABLED)
    # =====================================================
    response = make_response(
        render_template(
            "dashboard.html",
            username=username,
            profile_photo_url=profile_photo_url,
            last_login_time=last_login_time,
            security_status=security_status,
            security_level=security_level
        )
    )

    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response




@app.route("/upload_photo", methods=["POST"])
def upload_photo():
    if "username" not in session:
        return redirect(url_for("landing"))

    file = request.files.get("profile_photo")
    if not file or file.filename == "":
        return redirect(url_for("dashboard"))

    if not allowed_file(file.filename):
        return redirect(url_for("dashboard"))

    # Ensure folder exists (important for hosting)
    os.makedirs(PROFILE_FOLDER, exist_ok=True)

    # Remove any existing profile photo for this user
    username = secure_filename(session["username"])
    for ext in [".png", ".jpg", ".jpeg", ".webp"]:
        old = os.path.join(PROFILE_FOLDER, f"{username}{ext}")
        if os.path.exists(old):
            os.remove(old)

    # Save new photo
    original = secure_filename(file.filename)
    ext = os.path.splitext(original)[1].lower()
    final_filename = f"{username}{ext}"
    filepath = os.path.join(PROFILE_FOLDER, final_filename)
    file.save(filepath)

    # Update DB
    conn = get_db_connection()
    if conn is None:
        return "Database connection failed", 500

    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET photo = %s WHERE username = %s",
            (final_filename, username)
        )
        conn.commit()
        cursor.close()
    finally:
        conn.close()

    return redirect(url_for("dashboard"))

@app.route("/update_name", methods=["POST"])
def update_name():
    if "user_id" not in session:
        return redirect(url_for("landing"))

    new_username = request.form.get("username", "").strip()
    user_id = session["user_id"]

    if not new_username:
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    if conn is None:
        return "Database error", 500

    try:
        cursor = conn.cursor(dictionary=True)

        # 🔍 Check current username
        cursor.execute(
            "SELECT username FROM users WHERE id = %s",
            (user_id,)
        )
        current = cursor.fetchone()["username"]

        # ✅ If same username, do nothing
        if new_username == current:
            return redirect(url_for("dashboard"))

        # 🔍 Check if username already exists
        cursor.execute(
            "SELECT id FROM users WHERE username = %s",
            (new_username,)
        )
        exists = cursor.fetchone()

        if exists:
            # Username taken → safe exit
            return redirect(url_for("dashboard", error="username_taken"))

        # ✅ Update username
        cursor.execute(
            "UPDATE users SET username = %s WHERE id = %s",
            (new_username, user_id)
        )
        conn.commit()

        # Update session so UI reflects immediately
        session["username"] = new_username

        cursor.close()
    finally:
        conn.close()

    return redirect(url_for("dashboard", updated="1"))

# -------------------- File Encryption --------------------


@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    if "user_id" not in session:
        return redirect(url_for("landing"))

    user_id = session["user_id"]

    uploaded_file = request.files.get("file")
    if uploaded_file is None or uploaded_file.filename == "":
        return "No file uploaded"

    password = request.form.get("password", "")
    filename = secure_filename(uploaded_file.filename)  # type: ignore
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    uploaded_file.save(filepath)

    encrypted_path = encrypt_file(filepath, password)

    # 📊 ACTIVITY LOG — context-rich
    log_audit(f"FILE_ENCRYPTED | file={filename}", user_id)

    return send_file(encrypted_path, as_attachment=True)




@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    if "user_id" not in session:
        return redirect(url_for("landing"))

    # 🔐 Require recent master-password verification
    if not session.get("re_auth"):
        return jsonify({"error": "Re-authentication required"}), 403

    # One-time permission
    session.pop("re_auth", None)

    user_id = session["user_id"]
    ip = request.remote_addr

    # 🔒 Rate limit (prevent abuse)
    if not rate_limit(f"decrypt:{user_id}:{ip}", 10, 60):
        return jsonify({"error": "Too many requests"}), 429

    uploaded_file = request.files.get("file")
    if uploaded_file is None or uploaded_file.filename == "":
        return jsonify({"error": "No file uploaded"}), 400

    # 🔒 Secure filename
    filename = secure_filename(uploaded_file.filename)

    # 🔒 File extension validation (only .enc allowed)
    if not filename.endswith(".enc"):
        return jsonify({"error": "Invalid file type"}), 400

    # 🔒 File size limit (5MB)
    uploaded_file.seek(0, os.SEEK_END)
    file_size = uploaded_file.tell()
    uploaded_file.seek(0)

    if file_size > 5 * 1024 * 1024:
        return jsonify({"error": "File too large (max 5MB)"}), 400

    # 🔒 Safe storage path (outside static)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    uploaded_file.save(filepath)

    password = request.form.get("password", "")

    try:
        decrypted_path = decrypt_file(filepath, password)

        # 📊 Audit log
        log_audit(f"FILE_DECRYPTED | file={filename}", user_id)

        return send_file(decrypted_path, as_attachment=True)

    except ValueError:
        return jsonify({"error": "Decryption failed"}), 400

    except Exception:
        return jsonify({"error": "Something went wrong"}), 500



# -------------------- Vault CRUD --------------------


@app.route("/add_password", methods=["POST"])
def add_password():
    if "user_id" not in session:
        return redirect(url_for("landing"))

    # 🔒 Rate limit (per user + IP)
    ip = request.remote_addr
    user_id = session["user_id"]
    if not rate_limit(f"vault:add:{user_id}:{ip}", 20, 60):
        return "Too many actions. Slow down.", 429

    service_name = request.form.get("service_name")
    service_username = request.form.get("service_username")
    service_password = request.form.get("service_password")

    if not service_name or not service_username or not service_password:
        return "All fields are required", 400

    encrypted_password = encrypt_password(service_password)

    conn = get_db_connection()
    if conn is None:
        return "Database connection failed."

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO vault (user_id, service_name, service_username, service_password)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, service_name, service_username, encrypted_password)
        )
        conn.commit()

        # 📊 ACTIVITY LOG — successful vault add
        log_audit(f"VAULT_PASSWORD_ADDED:{service_name}", user_id)

    except Exception as e:
        conn.rollback()
        return f"Error: {str(e)}"

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("dashboard"))




@app.route("/view_password/<int:password_id>")
def view_password(password_id):
    if "user_id" not in session:
        return {"error": "Unauthorized"}, 401

    user_id = session["user_id"]

    # 🔐 Ensure master password was verified
    if not session.get("re_auth"):
        return {"error": "Re-authentication required"}, 403

    conn = get_db_connection()
    if conn is None:
        return {"error": "Database connection failed"}, 500

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT service_name, service_password
            FROM vault
            WHERE id = %s AND user_id = %s
            """,
            (password_id, user_id)
        )
        row = cursor.fetchone()
        if not row:
            return {"error": "Password not found"}, 404

        decrypted = decrypt_password(row["service_password"])

        # 🔒 One-time permission
        session.pop("re_auth", None)

        # 📊 ACTIVITY LOG — password was viewed
        service_name = row.get("service_name", "UNKNOWN")
        log_audit(f"VAULT_PASSWORD_VIEWED:{service_name}", user_id)

        return {"password": decrypted}

    finally:
        cursor.close()
        conn.close()



@app.route("/search_passwords")
def search_passwords():
    if "user_id" not in session:
        return {"vault": []}
    query = request.args.get("q", "").strip()
    user_id = session["user_id"]
    conn = get_db_connection()
    if conn is None:
        return {"vault": []}
    try:
        cursor = conn.cursor(dictionary=True)  # type: ignore
        search_query = f"%{query}%"
        cursor.execute(
            "SELECT id, service_name, service_username, service_password FROM vault "
            "WHERE user_id = %s AND (service_name LIKE %s OR service_username LIKE %s)",
            (user_id, search_query, search_query)
        )
        results = cursor.fetchall() or []
        for entry in results:
            try:
                entry["service_password"] = decrypt_password(entry["service_password"])
            except:
                entry["service_password"] = "Decryption Error"
        cursor.close()
        conn.close()
        return {"vault": results}
    except Exception as e:
        return {"error": str(e), "vault": []}


@app.route("/delete_password/<int:password_id>")
def delete_password(password_id):
    if "user_id" not in session:
        return redirect(url_for("landing"))

    # 🔐 Require recent master-password verification
    if not session.get("re_auth"):
        return "Re-authentication required", 403

    # One-time permission
    session.pop("re_auth", None)

    # 🔒 Rate limit (per user + IP)
    ip = request.remote_addr
    user_id = session["user_id"]
    if not rate_limit(f"vault:delete:{user_id}:{ip}", 10, 60):
        return "Too many delete actions. Slow down.", 429

    conn = get_db_connection()
    if conn is None:
        return "Database connection failed."

    try:
        cursor = conn.cursor()

        # Fetch service name before deletion (for activity context)
        cursor.execute(
            "SELECT service_name FROM vault WHERE id = %s AND user_id = %s",
            (password_id, user_id)
        )
        row = cursor.fetchone()
        service_name = row[0] if row else "UNKNOWN"

        cursor.execute(
            "DELETE FROM vault WHERE id = %s AND user_id = %s",
            (password_id, user_id)
        )
        conn.commit()

        # 📊 ACTIVITY LOG — successful deletion
        log_audit(f"VAULT_PASSWORD_DELETED:{service_name}", user_id)

    except Exception as e:
        conn.rollback()
        return f"Error deleting password: {str(e)}"

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("dashboard"))







@app.route("/update_password/<int:password_id>", methods=["POST"])
def update_password(password_id):
    if "user_id" not in session:
        return redirect(url_for("landing"))

    # 🔐 Require recent master-password verification
    if not session.get("re_auth"):
        return "Re-authentication required", 403

    # One-time permission
    session.pop("re_auth", None)

    # 🔒 Rate limit (per user + IP)
    ip = request.remote_addr
    user_id = session["user_id"]
    if not rate_limit(f"vault:update:{user_id}:{ip}", 15, 60):
        return "Too many update actions. Slow down.", 429

    service_name = request.form.get("service_name")
    service_username = request.form.get("service_username")
    service_password = request.form.get("service_password")

    if not service_name or not service_username or not service_password:
        return "All fields are required", 400

    encrypted_password = encrypt_password(service_password)

    conn = get_db_connection()
    if conn is None:
        return "Database connection failed."

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE vault
            SET service_name = %s,
                service_username = %s,
                service_password = %s
            WHERE id = %s AND user_id = %s
            """,
            (service_name, service_username, encrypted_password, password_id, user_id)
        )
        conn.commit()

        # 📊 ACTIVITY LOG — successful update
        log_audit(f"VAULT_PASSWORD_UPDATED:{service_name}", user_id)

    except Exception as e:
        conn.rollback()
        return f"Error updating password: {str(e)}"

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("dashboard"))






# ========== Forgot Password (Separate OTP System) ==========


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    from flask import jsonify

    if request.method == 'GET':
        return render_template('forgot_password.html')

    # 🔒 Rate limit (per IP)
    ip = request.remote_addr
    if not rate_limit(f"forgot:{ip}", 5, 300):
        return jsonify({'status': 'error', 'message': 'Too many requests. Try later.'}), 429

    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'status': 'error', 'message': 'Email is required.'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'status': 'error', 'message': 'Database connection failed.'}), 500
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'status': 'error', 'message': 'No account found with that email.'})

        otp = str(random.randint(100000, 999999))
        expiration = datetime.now() + timedelta(minutes=5)

        cursor.execute(
            "INSERT INTO password_reset_otp (email, otp_code, expiration) VALUES (%s, %s, %s)",
            (email, otp, expiration)
        )
        conn.commit()

        try:
            html_content = f"""
            <html>
            <body>
              <h3>Your SecureVault Password Reset OTP is:</h3>
              <h2>{otp}</h2>
              <p>This OTP will expire in 5 minutes.</p>
            </body>
            </html>
            """
            send_html_email(email, "SecureVault Password Reset OTP", html_content)
        except Exception as e:
            print("Email sending error:", e)
            return jsonify({'status': 'error', 'message': 'Failed to send OTP. Try again later.'})

        return jsonify({'status': 'success', 'message': 'OTP sent to your email.'})

    finally:
        cursor.close()
        conn.close()



@app.route('/verify_reset_otp', methods=['POST'])
def verify_reset_otp():
    from flask import jsonify
    from werkzeug.security import generate_password_hash
    from datetime import datetime, timedelta

    # 🔒 Rate limit (per IP)
    ip = request.remote_addr
    if not rate_limit(f"reset_verify:{ip}", 10, 300):
        return jsonify({'status': 'error', 'message': 'Too many attempts. Try later.'}), 429

    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    if not all([email, otp, new_password]):
        return jsonify({'status': 'error', 'message': 'All fields are required.'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'status': 'error', 'message': 'Database connection failed.'}), 500

    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Fetch OTP record
        query = """
            SELECT id, email, otp_code, expiration, is_verified
            FROM password_reset_otp
            WHERE email = %s AND otp_code = %s AND is_verified = FALSE
            ORDER BY created_at DESC LIMIT 1
        """
        cursor.execute(query, (email, otp))
        otp_entry = cursor.fetchone()

        if not otp_entry or not isinstance(otp_entry, dict):
            return jsonify({'status': 'error', 'message': 'Invalid OTP.'})

        # ✅ Normalize expiration value
        expiration_time = otp_entry.get('expiration')

        if isinstance(expiration_time, (bytes, bytearray)):
            expiration_time = expiration_time.decode(errors="ignore")
        elif isinstance(expiration_time, memoryview):
            expiration_time = expiration_time.tobytes().decode(errors="ignore")

        if isinstance(expiration_time, str):
            try:
                expiration_time = datetime.strptime(expiration_time.split('.')[0], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                expiration_time = datetime.now() - timedelta(minutes=10)
        elif not isinstance(expiration_time, datetime):
            try:
                expiration_time = datetime.fromisoformat(str(expiration_time))
            except Exception:
                expiration_time = datetime.now() - timedelta(minutes=10)

        # ✅ Expiry check
        if datetime.now() > expiration_time:
            return jsonify({'status': 'error', 'message': 'OTP expired. Request a new one.'})

        # ✅ Mark OTP verified + update password safely
        otp_id = otp_entry.get('id')
        if otp_id is not None:
            cursor.execute("UPDATE password_reset_otp SET is_verified = TRUE WHERE id = %s", (int(otp_id),))

        hashed_pwd = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_pwd, email))
        conn.commit()

        return jsonify({'status': 'success', 'message': 'Password has been reset successfully!'})

    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {str(e)}'})

    finally:
        cursor.close()
        conn.close()


@app.route("/security-lab")
def security_lab():
    return render_template("security_lab.html")


# -------------------- App Bootstrap --------------------

@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )

    # 🔐 ADD THIS LINE
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response



if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "False") == "True"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)




