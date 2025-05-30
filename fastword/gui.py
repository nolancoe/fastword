import os
import sqlite3
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QMessageBox, QCheckBox, QSpinBox, QTextEdit, QStackedLayout, QInputDialog, QScrollArea, QFrame, QHBoxLayout
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QClipboard, QIcon
from crypto import (
    get_fernet, save_verify_token, verify_master_password, VERIFY_FILE, encrypt, decrypt
)
from utils import generate_password

DB_PATH = os.path.expanduser("~/.fastword/vault.db")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                encrypted_password TEXT NOT NULL
            )
        """)


def load_passwords(fernet):
    passwords = []
    with sqlite3.connect(DB_PATH) as conn:
        for row in conn.execute("SELECT name, encrypted_password FROM passwords"):
            name = row[0]
            try:
                decrypted = decrypt(fernet, row[1])
            except:
                decrypted = "[DECRYPTION FAILED]"
            passwords.append((name, decrypted))
    return passwords


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Fastword Login")
        self.resize(400, 200)
        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #E0E0E0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 16px;
            }
            QLineEdit {
                background-color: #1E1E1E;
                border: 2px solid #333;
                border-radius: 8px;
                padding: 10px;
                color: #E0E0E0;
            }
            QLineEdit:focus {
                border: 2px solid #0dd420;
                background-color: #1A1A1A;
            }
            QPushButton {
                background-color: #0dd420;
                color: #000;
                padding: 10px;
                border: none;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00e070;
            }
        """)

        self.layout = QVBoxLayout()
        self.layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setLayout(self.layout)

        self.label = QLabel("Enter Master Password:" if os.path.exists(VERIFY_FILE) else "Set New Master Password:")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.returnPressed.connect(self.handle_submit)
        self.layout.addWidget(self.password_input)

        self.submit_btn = QPushButton("Submit")
        self.submit_btn.clicked.connect(self.handle_submit)
        self.layout.addWidget(self.submit_btn)

    def handle_submit(self):
        password = self.password_input.text()
        self.fernet = get_fernet(password)

        if not os.path.exists(VERIFY_FILE):
            save_verify_token(self.fernet)
            self.open_vault()
        elif verify_master_password(self.fernet):
            self.open_vault()
        else:
            QMessageBox.warning(self, "Login Failed", "Incorrect master password.")

    def open_vault(self):
        self.vault = VaultWindow(self.fernet)
        self.vault.show()
        self.close()


class VaultWindow(QWidget):
    def __init__(self, fernet):
        super().__init__()
        self.fernet = fernet
        init_db()

        self.setWindowTitle("🔐 Fastword Vault")
        self.resize(300, 500)
        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #E0E0E0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 18px;
            }
            QLabel {
                padding: 8px;
            }
            QFrame {
                border: 1px solid #2e2e2e;
                border-radius: 10px;
                margin-bottom: 8px;
                background-color: #1E1E1E;
            }
            QPushButton {
                background-color: #0dd420;
                color: #000;
                padding: 10px;
                border: none;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00e070;
            }
        """)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.stack = QStackedLayout()

        self.vault_screen = QWidget()
        self.vault_layout = QVBoxLayout()
        self.vault_layout.setAlignment(Qt.AlignmentFlag.AlignTop)



        self.new_password_btn = QPushButton("New Password")
        self.new_password_btn.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        self.vault_layout.addWidget(self.new_password_btn)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.password_container = QWidget()
        self.password_layout = QVBoxLayout()
        self.password_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.password_container.setLayout(self.password_layout)
        self.scroll_area.setWidget(self.password_container)
        self.vault_layout.addWidget(self.scroll_area)

        self.vault_screen.setLayout(self.vault_layout)

        self.generator_screen = PasswordGeneratorScreen(
            back_callback=self.refresh_vault_screen,
            fernet=self.fernet
        )

        self.stack.addWidget(self.vault_screen)
        self.stack.addWidget(self.generator_screen)
        self.layout.addLayout(self.stack)

        self.populate_passwords()

    def refresh_vault_screen(self):
        self.populate_passwords()
        self.stack.setCurrentIndex(0)

    def populate_passwords(self):
        for i in reversed(range(self.password_layout.count())):
            self.password_layout.itemAt(i).widget().deleteLater()

        for name, pwd in load_passwords(self.fernet):
            entry = QFrame()
            entry_layout = QVBoxLayout()
            entry_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            entry.setLayout(entry_layout)

            name_btn = QPushButton(f"🔐 {name}")
            name_btn.setStyleSheet("QPushButton { background-color: transparent; color: #0dd420; font-weight: bold; border: none; font-size: 16px; text-align: center; }")
            name_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            name_btn.clicked.connect(lambda _, p=pwd: QApplication.clipboard().setText(p))

            button_row = QHBoxLayout()
            button_row.setAlignment(Qt.AlignmentFlag.AlignCenter)

            def create_icon_button(icon_path):
                btn = QPushButton()
                btn.setIcon(QIcon(icon_path))
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                btn.setFixedSize(36, 36)
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #0dd420;
                        border-radius: 6px;
                        border: none;
                    }
                    QPushButton:hover {
                        background-color: #00e070;
                    }
                """)
                return btn

            view_btn = create_icon_button("fastword/icons/eye.svg")
            edit_btn = create_icon_button("fastword/icons/pencil.svg")
            delete_btn = create_icon_button("fastword/icons/trash.svg")

            button_row.addWidget(view_btn)
            button_row.addWidget(edit_btn)
            button_row.addWidget(delete_btn)

            def make_toggle_fn(name_btn=name_btn, view_btn=view_btn, name=name, pwd=pwd):
                def toggle():
                    if name_btn.text() == f"🔐 {name}":
                        name_btn.setText(f"🔐 {pwd}")
                        view_btn.setIcon(QIcon("fastword/icons/eye-off.svg"))
                    else:
                        name_btn.setText(f"🔐 {name}")
                        view_btn.setIcon(QIcon("fastword/icons/eye.svg"))
                return toggle

            view_btn.clicked.connect(make_toggle_fn())

            entry_layout.addWidget(name_btn)
            entry_layout.addLayout(button_row)
            self.password_layout.addWidget(entry)


class PasswordGeneratorScreen(QWidget):
    def __init__(self, back_callback, fernet):
        super().__init__()
        self.fernet = fernet
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
                color: #e0e0e0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
            }
            QPushButton {
                background-color: #0dd420;
                color: #000;
                padding: 10px;
                border: none;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00e070;
            }
        """)

        layout = QVBoxLayout()

        self.length_input = QSpinBox()
        self.length_input.setRange(4, 64)
        self.length_input.setValue(16)
        layout.addWidget(QLabel("Password Length:"))
        layout.addWidget(self.length_input)

        self.use_upper = QCheckBox("Include Uppercase")
        self.use_upper.setChecked(True)
        self.use_lower = QCheckBox("Include Lowercase")
        self.use_lower.setChecked(True)
        self.use_digits = QCheckBox("Include Digits")
        self.use_digits.setChecked(True)
        self.use_symbols = QCheckBox("Include Symbols")
        self.use_symbols.setChecked(True)

        layout.addWidget(self.use_upper)
        layout.addWidget(self.use_lower)
        layout.addWidget(self.use_digits)
        layout.addWidget(self.use_symbols)

        self.generate_btn = QPushButton("Generate Password")
        self.generate_btn.clicked.connect(self.generate_password)
        layout.addWidget(self.generate_btn)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        self.save_btn = QPushButton("Save Password")
        self.save_btn.clicked.connect(self.save_password)
        layout.addWidget(self.save_btn)

        self.back_btn = QPushButton("Back to Vault")
        self.back_btn.clicked.connect(back_callback)
        layout.addWidget(self.back_btn)

        self.setLayout(layout)

    def generate_password(self):
        try:
            pwd = generate_password(
                length=self.length_input.value(),
                use_uppercase=self.use_upper.isChecked(),
                use_lowercase=self.use_lower.isChecked(),
                use_digits=self.use_digits.isChecked(),
                use_symbols=self.use_symbols.isChecked()
            )
            self.output.setText(pwd)
        except ValueError as e:
            QMessageBox.warning(self, "Invalid Input", str(e))

    def save_password(self):
        pwd = self.output.toPlainText()
        if not pwd:
            QMessageBox.warning(self, "No Password", "Please generate a password first.")
            return

        name, ok = QInputDialog.getText(self, "Save Password", "Name this password:")
        if ok and name:
            encrypted_pwd = encrypt(self.fernet, pwd)
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("INSERT INTO passwords (name, encrypted_password) VALUES (?, ?)", (name, encrypted_pwd))
            QMessageBox.information(self, "Saved", f"Password saved as '{name}'.")
