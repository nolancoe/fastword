# Fastword

**Fastword** is a secure, offline password manager with a PyQt6 GUI. It allows users to generate and store strong passwords locally using AES-GCM encryption, with support for a master password and a 12-word mnemonic recovery phrase.

---

## Features

- Local-only storage (no cloud, no tracking)
- AES-GCM encryption with Argon2 key derivation
- 12-word recovery phrase for master password resets
- Auto sign-out timer
- Built-in password generator
- Update master password from settings
- Easy-to-use GUI built with PyQt6
- Cross-platform executable support (coming soon)

---

## Installation

### From PyPI

```
pip install fastword
```

Then run it with:

```
fastword
```


---

## Running from Source

Clone the repo:

```bash
git clone https://github.com/nolancoe/fastword.git
cd fastword
pip install -r requirements.txt
python -m fastword.main
```

---

## Usage

1. On first launch, you’ll be prompted to set a master password.
2. You'll be shown a 12-word recovery phrase — **WRITE IT DOWN!** This is your only way back in if you forget your master password. If you lose this, and forget your master password, there is no way to access your password vault!
3. Add, view, and manage your credentials securely.

---

## Resetting Your Vault

If you forget your master password:
- Launch the app and click **"Forgot Password"**
- Enter your 12-word recovery phrase
- Set a new master password
- Your vault will be re-encrypted using the new key

---

## Security Notes

- All passwords are encrypted with AES-GCM using a key derived from your master password via Argon2id
- The recovery phrase is used to derive a key that wraps the master key using symmetric encryption
- No data is ever transmitted over the internet — 100% local
- Decryption keys never leave memory during execution

---

## Requirements

- Python 3.10+
- PyQt6
- cryptography
- argon2-cffi

Install dependencies with:

```bash
pip install -r requirements.txt
```

---

## Executables
Windows and Linux executables available here https://github.com/nolancoe/fastword/releases

#Linux
Download the .deb file "Fastword" then run this command

```bash
sudo dpkg -i fastword_0.2.1_amd64.deb
```

#Windows
Download the .exe file "FastwordInstaller.exe" and run the installer.

---

## Contributing

Pull requests welcome!

---

## License

MIT License

---
