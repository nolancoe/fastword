import os
import base64
import hashlib
import secrets
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from argon2 import PasswordHasher

CONFIG_DIR = os.path.expanduser("~/.fastword")
SALT_FILE = os.path.join(CONFIG_DIR, "salt.bin")
VERIFY_FILE = os.path.join(CONFIG_DIR, "verify.txt")
RECOVERY_FILE = os.path.join(CONFIG_DIR, "recovery.enc")
RECOVERY_WRAPPED_KEY = os.path.join(CONFIG_DIR, "wrapped_key.enc")

argon2_hasher = PasswordHasher()
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "wordlist.txt")  # You'll need a 2048-word BIP39-style list

# -------------------------
# Argon2 Key Derivation
# -------------------------
def _get_salt():
    if not os.path.exists(SALT_FILE):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        salt = os.urandom(16)
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

# -------------------------
# AES Encryption Helpers
# -------------------------
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

# -------------------------
# Password + Verify Token
# -------------------------
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

# -------------------------
# Recovery Phrase Handling
# -------------------------
def load_wordlist():
    with open(WORDLIST_PATH, "r") as f:
        return [w.strip() for w in f.readlines()]

def generate_mnemonic() -> str:
    entropy = secrets.token_bytes(16)  # 128 bits
    wordlist = load_wordlist()
    bits = bin(int.from_bytes(entropy, 'big'))[2:].zfill(128)
    indices = [int(bits[i:i+11], 2) for i in range(0, 132, 11)]
    words = [wordlist[i % len(wordlist)] for i in indices[:12]]
    return ' '.join(words)

def save_recovery_phrase(key, mnemonic: str):
    encrypted = encrypt(key, mnemonic)
    with open(RECOVERY_FILE, "w") as f:
        f.write(encrypted)

def load_recovery_phrase(key) -> str:
    with open(RECOVERY_FILE, "r") as f:
        encrypted = f.read()
    return decrypt(key, encrypted)

def derive_key_from_mnemonic(mnemonic: str) -> bytes:
    """
    Deterministically derives a master key from a 12-word mnemonic phrase.
    """
    words = mnemonic.strip().lower().split()
    if len(words) != 12:
        raise ValueError("Recovery phrase must contain exactly 12 words.")
    
    wordlist = load_wordlist()
    for word in words:
        if word not in wordlist:
            raise ValueError(f"Invalid word in recovery phrase: '{word}'")

    # Use the phrase as the input to the key derivation (salted to avoid collisions)
    phrase_str = ' '.join(words)
    salt = b"fastword-recovery"

    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=phrase_str.encode(),
        salt=salt,
        iterations=100000,
        dklen=32
    )

def save_wrapped_key(recovery_key, master_key):
    wrapped = encrypt(recovery_key, base64.b64encode(master_key).decode())
    with open(RECOVERY_WRAPPED_KEY, "w") as f:
        f.write(wrapped)

def load_wrapped_key(recovery_key):
    with open(RECOVERY_WRAPPED_KEY, "r") as f:
        wrapped = f.read()
    decoded = decrypt(recovery_key, wrapped)
    return base64.b64decode(decoded.encode())
