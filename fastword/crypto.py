import os
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from base64 import urlsafe_b64encode
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


CONFIG_DIR = os.path.expanduser("~/.fastword")
SALT_FILE = os.path.join(CONFIG_DIR, "salt.bin")
VERIFY_FILE = os.path.join(CONFIG_DIR, "verify.txt")


argon2_hasher = PasswordHasher()

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


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.ID
    )

def encrypt(key: bytes, plaintext: str) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt(key: bytes, encrypted_text: str) -> str:
    aesgcm = AESGCM(key)
    raw = base64.b64decode(encrypted_text)
    nonce, ciphertext = raw[:12], raw[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def hash_master_password(password: str) -> str:
    return argon2_hasher.hash(password)

def verify_master_password(password, salt):
    key = derive_key(password, salt)
    try:
        with open(VERIFY_FILE, "r") as f:
            token = f.read()
        return decrypt(key, token) == "valid"
    except Exception:
        return False

def save_verify_token(key):
    token = encrypt(key, "valid")
    with open(VERIFY_FILE, "w") as f:
        f.write(token)


def save_master_hash(password):
    hashed = hash_master_password(password)
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(VERIFY_FILE, "w") as f:
        f.write(hashed)


def load_master_hash():
    with open(VERIFY_FILE, "r") as f:
        return f.read().strip()

