import os
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

CONFIG_DIR = os.path.expanduser("~/.fastword")
SALT_FILE = os.path.join(CONFIG_DIR, "salt.bin")
VERIFY_FILE = os.path.join(CONFIG_DIR, "verify.txt")


def _get_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    else:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    return salt


def derive_key_from_password(password: str) -> bytes:
    salt = _get_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def save_verify_token(fernet: Fernet):
    token = fernet.encrypt(b"fastword_verification")
    with open(VERIFY_FILE, 'wb') as f:
        f.write(token)


def verify_master_password(fernet: Fernet) -> bool:
    try:
        with open(VERIFY_FILE, 'rb') as f:
            token = f.read()
        return fernet.decrypt(token) == b"fastword_verification"
    except:
        return False


def get_fernet(password: str) -> Fernet:
    key = derive_key_from_password(password)
    return Fernet(key)


def encrypt(fernet: Fernet, plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt(fernet: Fernet, ciphertext: str) -> str:
    return fernet.decrypt(ciphertext.encode()).decode()
