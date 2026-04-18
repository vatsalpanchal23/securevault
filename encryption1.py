from cryptography.fernet import Fernet
import os

# =========================
# 🔐 SECURE KEY MANAGEMENT
# =========================

def load_key():
    key = os.environ.get("FERNET_KEY")

    if key:
        try:
            return key.encode()
        except Exception:
            raise ValueError("Invalid FERNET_KEY format.")
    
    # Safe fallback for local development ONLY
    print("[WARNING] FERNET_KEY not set. Using temporary key (data will not persist across restarts).")
    return Fernet.generate_key()


key = load_key()
cipher = Fernet(key)


# =========================
# 🔑 PASSWORD ENCRYPTION
# =========================

def encrypt_password(plain_text):
    if not isinstance(plain_text, str) or not plain_text.strip():
        raise ValueError("Invalid input for encryption.")
    
    return cipher.encrypt(plain_text.encode()).decode()


def decrypt_password(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        raise ValueError("Decryption failed.")


# =========================
# 📁 FILE VALIDATION
# =========================

ALLOWED_EXTENSIONS = {
    '.txt', '.pdf', '.png', '.jpg', '.jpeg', '.docx', '.xlsx'
}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB


def validate_file(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError("File not found.")

    ext = os.path.splitext(filepath)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("File type not allowed.")

    size = os.path.getsize(filepath)
    if size > MAX_FILE_SIZE:
        raise ValueError("File too large (max 5MB).")


# =========================
# 🔒 FILE ENCRYPTION
# =========================

def encrypt_file(filepath, password=None):
    abs_path = os.path.abspath(filepath)

    validate_file(abs_path)

    with open(abs_path, 'rb') as file:
        data = file.read()

    encrypted_data = cipher.encrypt(data)

    # Secure directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    encrypted_dir = os.path.join(base_dir, "secure_uploads", "encrypted")
    os.makedirs(encrypted_dir, exist_ok=True)

    # Safe filename
    filename = os.path.basename(filepath)
    safe_name = filename.replace(" ", "_")
    encrypted_path = os.path.join(encrypted_dir, safe_name + ".enc")

    with open(encrypted_path, 'wb') as file:
        file.write(encrypted_data)

    return encrypted_path


# =========================
# 🔓 FILE DECRYPTION
# =========================

def decrypt_file(filepath, password=None):
    abs_path = os.path.abspath(filepath)

    if not os.path.exists(abs_path):
        raise FileNotFoundError("Encrypted file not found.")

    with open(abs_path, 'rb') as file:
        encrypted_data = file.read()

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except Exception:
        raise ValueError("Decryption failed. Invalid key or corrupted file.")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    decrypted_dir = os.path.join(base_dir, "secure_uploads", "decrypted")
    os.makedirs(decrypted_dir, exist_ok=True)

    filename = os.path.basename(filepath).replace('.enc', '')
    name, ext = os.path.splitext(filename)

    safe_name = name.replace(" ", "_")
    decrypted_path = os.path.join(decrypted_dir, safe_name + "_decrypted" + ext)

    with open(decrypted_path, 'wb') as file:
        file.write(decrypted_data)

    return decrypted_path


# =========================
# 🧪 OPTIONAL TEST
# =========================

if __name__ == "__main__":
    print("[INFO] Running encryption test...")

    test_file = "test.txt"

    if not os.path.exists(test_file):
        with open(test_file, "w") as f:
            f.write("This is a test file.")

    enc_path = encrypt_file(test_file)
    dec_path = decrypt_file(enc_path)

    with open(test_file, 'rb') as f1, open(dec_path, 'rb') as f2:
        print("[DEBUG] Match:", f1.read() == f2.read())



