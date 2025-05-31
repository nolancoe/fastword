import secrets
import string
import os
import json


CONFIG_PATH = os.path.expanduser("~/.fastword/config.json")

def save_config(data):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f)

def load_config():
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


        

def generate_password(
    length=16,
    use_uppercase=True,
    use_lowercase=True,
    use_digits=True,
    use_symbols=True
):
    """
    Generate a secure password using the specified character types.
    
    Args:
        length (int): Length of the password.
        use_uppercase (bool): Include uppercase letters.
        use_lowercase (bool): Include lowercase letters.
        use_digits (bool): Include digits.
        use_symbols (bool): Include punctuation symbols.

    Returns:
        str: The generated password.
    """

    if not any([use_uppercase, use_lowercase, use_digits, use_symbols]):
        raise ValueError("At least one character type must be enabled.")

    charset = ""
    if use_uppercase:
        charset += string.ascii_uppercase
    if use_lowercase:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += string.punctuation

    return ''.join(secrets.choice(charset) for _ in range(length))
