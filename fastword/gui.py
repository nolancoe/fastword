import os
import sqlite3
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QMessageBox, QCheckBox, QSpinBox, QTextEdit, 
    QStackedLayout, QInputDialog, QScrollArea, QFrame, QHBoxLayout, QGridLayout
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QClipboard, QIcon
from fastword.crypto import (
    derive_key, verify_master_password, VERIFY_FILE, encrypt, decrypt, save_verify_token, 
    generate_mnemonic, save_recovery_phrase, derive_key_from_mnemonic, save_wrapped_key, load_wrapped_key
)
from fastword.utils import save_config, load_config, generate_password, load_salt, save_salt
import importlib.resources

DB_PATH = os.path.expanduser("~/.fastword/vault.db")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                encrypted_password TEXT NOT NULL
            )
        """)



def get_icon_path(filename):
    return str(importlib.resources.files("fastword.icons").joinpath(filename))


def load_icon(filename):
    return QIcon(get_icon_path(filename))

def load_passwords(master_key):
    passwords = []
    with sqlite3.connect(DB_PATH) as conn:
        for row in conn.execute("SELECT name, encrypted_password FROM passwords"):
            name = row[0]
            try:
                decrypted = decrypt(master_key, row[1])
            except:
                decrypted = "[DECRYPTION FAILED]"
            passwords.append((name, decrypted))
    return passwords


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Fastword Login")
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

        self.recover_btn = QPushButton("Forgot Password?")
        self.recover_btn.clicked.connect(self.handle_recovery)
        self.layout.addWidget(self.recover_btn)


        # Reset App button
        self.reset_btn = QPushButton("Reset App")
        self.reset_btn.setStyleSheet("QPushButton { background-color: #ff3b30; color: white; } QPushButton:hover { background-color: #ff5e57; }")
        self.reset_btn.clicked.connect(self.confirm_reset)
        self.layout.addWidget(self.reset_btn)


    def handle_submit(self):
        password = self.password_input.text()
        salt = load_salt()
        master_key = derive_key(password, salt)

        if not os.path.exists(VERIFY_FILE):
            save_salt(salt)
            save_verify_token(master_key)

            recovery_mnemonic = generate_mnemonic()
            save_recovery_phrase(master_key, recovery_mnemonic)
            save_wrapped_key(derive_key_from_mnemonic(recovery_mnemonic), master_key)

            QMessageBox.information(self, "Recovery Key", 
                f"YOUR RECOVERY PHRASE\n\n**********\n{recovery_mnemonic}\n**********\n\nWrite this down and store it safely.\nIt’s the ONLY way to recover your vault if you forget your master password.")


            self.open_vault(master_key)
        elif verify_master_password(password, salt):
            self.open_vault(master_key)
        else:
            QMessageBox.warning(self, "Login Failed", "Incorrect master password.")

    def open_vault(self, master_key):
        self.vault = VaultWindow(master_key)
        self.vault.show()
        self.close()

    def handle_recovery(self):
        mnemonic, ok = QInputDialog.getText(self, "Recover Account", "Enter your 12-word recovery phrase:")
        if ok and mnemonic:
            try:
                recovery_key = derive_key_from_mnemonic(mnemonic)
                original_key = load_wrapped_key(recovery_key)

                # Ask user to set a new password
                new_pw, ok = QInputDialog.getText(self, "Set New Password", "Enter a new master password:", QLineEdit.EchoMode.Password)
                if not ok or not new_pw:
                    return

                # Generate and save new salt
                new_salt = os.urandom(16)
                save_salt(new_salt)
                new_key = derive_key(new_pw, new_salt)

                # Migrate old encrypted data to new key
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT name, encrypted_password FROM passwords")
                    rows = cursor.fetchall()

                    for name, enc_pwd in rows:
                        try:
                            decrypted = decrypt(original_key, enc_pwd)
                            re_encrypted = encrypt(new_key, decrypted)
                            cursor.execute("UPDATE passwords SET encrypted_password = ? WHERE name = ?", (re_encrypted, name))
                        except Exception as e:
                            print(f"[!] Failed to re-encrypt {name}: {e}")

                # Save verification token for login
                save_verify_token(new_key)

                # Generate and store new recovery key for the new master password
                new_mnemonic = generate_mnemonic()
                save_recovery_phrase(new_key, new_mnemonic)
                save_wrapped_key(derive_key_from_mnemonic(new_mnemonic), new_key)

                QMessageBox.information(self, "Recovery Successful", f"Your password has been reset.\n\nYour new recovery key is:\n\n{new_mnemonic}\n\nStore it securely!")

                self.open_vault(new_key)

            except Exception as e:
                import traceback
                traceback.print_exc()
                QMessageBox.critical(self, "Recovery Failed", f"Could not recover vault: {str(e)}")


    def confirm_reset(self):
        confirm1 = QMessageBox.warning(
            self,
            "Reset App",
            "This will permanently delete your vault, master password, and recovery phrase.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )

        if confirm1 == QMessageBox.StandardButton.Yes:
            confirm2 = QMessageBox.critical(
                self,
                "Final Confirmation",
                "This action is irreversible. All data will be lost.\nAre you ABSOLUTELY sure?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
            )

            if confirm2 == QMessageBox.StandardButton.Yes:
                import shutil
                try:
                    shutil.rmtree(os.path.expanduser("~/.fastword"))
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to reset app: {e}")
                    return

                QMessageBox.information(self, "Reset Complete", "Vault deleted. Please restart the app.")
                QApplication.quit()







class VaultWindow(QWidget):
    def __init__(self, master_key):
        super().__init__()
        self.master_key = master_key
        init_db()



        config = load_config()
        self.timeout_minutes = config.get('timeout_minutes', 5)
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.setInterval(self.timeout_minutes * 60 * 1000)
        self.inactivity_timer.timeout.connect(self.handle_timeout)
        self.inactivity_timer.start()
        self.installEventFilter(self)  # to track interactions


        self.setWindowTitle(" Fastword Vault")
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


        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search passwords...")
        self.search_input.textChanged.connect(self.filter_passwords)
        self.vault_layout.addWidget(self.search_input)


        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.password_container = QWidget()
        self.password_layout = QVBoxLayout()
        self.password_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.password_container.setLayout(self.password_layout)
        self.scroll_area.setWidget(self.password_container)
        self.vault_layout.addWidget(self.scroll_area)

        # Settings button
        settings_row = QHBoxLayout()
        settings_row.setAlignment(Qt.AlignmentFlag.AlignRight)

        settings_btn = QPushButton()
        settings_btn.setIcon(load_icon("settings.svg"))
        settings_btn.setFixedSize(36, 36)
        settings_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        settings_btn.setStyleSheet("""
            QPushButton {
                background-color: #0dd420;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover {
                background-color: #00e070;
            }
        """)
        settings_btn.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        settings_row.addWidget(settings_btn)



        self.settings_screen = SettingsScreen(
            back_callback=self.refresh_vault_screen,
            master_key=self.master_key,
            vault_window=self  # 👈 pass self here
        )            



        self.vault_layout.addLayout(settings_row)


        self.vault_screen.setLayout(self.vault_layout)

        self.generator_screen = PasswordGeneratorScreen(
            back_callback=self.refresh_vault_screen,
            master_key=self.master_key
        )

        self.stack.addWidget(self.vault_screen)
        self.stack.addWidget(self.generator_screen)
        self.stack.addWidget(self.settings_screen)
        self.layout.addLayout(self.stack)

        self.populate_passwords()

    def refresh_vault_screen(self):
        self.populate_passwords()
        self.stack.setCurrentIndex(0)


    def filter_passwords(self):
        text = self.search_input.text()
        self.populate_passwords(filter_text=text)


    def populate_passwords(self, filter_text="" ):
        for i in reversed(range(self.password_layout.count())):
            self.password_layout.itemAt(i).widget().deleteLater()

        for name, pwd in load_passwords(self.master_key):
            if filter_text.lower() not in name.lower():
                continue
            entry = QFrame()
            entry_layout = QVBoxLayout()
            entry_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            entry.setLayout(entry_layout)

            name_btn = QPushButton(f" {name}")
            name_btn.setStyleSheet("QPushButton { background-color: transparent; color: #0dd420; font-weight: bold; border: none; font-size: 16px; text-align: center; }")
            name_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            


            name_btn.clicked.connect(
                lambda _, b=name_btn, t=pwd, n=name: self.copy_and_notify(b, t, n)
            )




            button_row = QHBoxLayout()
            button_row.setAlignment(Qt.AlignmentFlag.AlignCenter)

            def create_icon_button(icon_path):
                btn = QPushButton()
                btn.setIcon(load_icon(icon_path))
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

            view_btn = create_icon_button("eye.svg")
            
            edit_btn = create_icon_button("pencil.svg")
            edit_btn.clicked.connect(lambda _, n=name, p=pwd: self.edit_password_dialog(n, p))

            delete_btn = create_icon_button("trash.svg")
            delete_btn.clicked.connect(lambda _, n=name: self.confirm_delete(n))


            button_row.addWidget(view_btn)
            button_row.addWidget(edit_btn)
            button_row.addWidget(delete_btn)

            def make_toggle_fn(name_btn=name_btn, view_btn=view_btn, name=name, pwd=pwd):
                def toggle():
                    if name_btn.text() == f" {name}":
                        name_btn.setText(f" {pwd}")
                        view_btn.setIcon(load_icon("eye-off.svg"))
                    else:
                        name_btn.setText(f" {name}")
                        view_btn.setIcon(load_icon("eye.svg"))
                return toggle

            view_btn.clicked.connect(make_toggle_fn())

            entry_layout.addWidget(name_btn)
            entry_layout.addLayout(button_row)
            self.password_layout.addWidget(entry)



    def copy_and_notify(self, btn, text, original_name):
        QApplication.clipboard().setText(text)
        old_icon = btn.icon()
        btn.setIcon(load_icon("copy.svg"))
        QTimer.singleShot(1200, lambda: btn.setIcon(old_icon))



    def confirm_delete(self, name):
        confirm1 = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if confirm1 == QMessageBox.StandardButton.Yes:
            confirm2 = QMessageBox.warning(
                self,
                "Permanent Deletion",
                f"This will permanently delete '{name}' and there is NO way to recover it.\nAre you 100% sure?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
            )

            if confirm2 == QMessageBox.StandardButton.Yes:
                self.delete_password(name)



    def eventFilter(self, obj, event):
        if event.type() in (event.Type.MouseMove, event.Type.KeyPress):
            self.inactivity_timer.start()
        return super().eventFilter(obj, event)

    def handle_timeout(self):
        self.inactivity_timer.stop()
        QMessageBox.information(self, "Signed Out", "You were signed out due to inactivity.")
        self.close()
        self.login_again()


    def closeEvent(self, event):
        self.inactivity_timer.stop()
        super().closeEvent(event)



    def login_again(self):
        self.login_window = LoginWindow()
        self.login_window.show()


    def delete_password(self, name):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM passwords WHERE name = ?", (name,))
        self.populate_passwords()

    def edit_password_dialog(self, old_name, old_password):
        dlg = QWidget()
        dlg.setWindowTitle("Edit Password Entry")
        dlg.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #E0E0E0;
                font-family: 'Segoe UI';
                font-size: 14px;
            }
        """)
        layout = QVBoxLayout()

        name_input = QLineEdit(old_name)
        password_input = QLineEdit(old_password)
        password_input.setEchoMode(QLineEdit.EchoMode.Normal)

        layout.addWidget(QLabel("New Name:"))
        layout.addWidget(name_input)
        layout.addWidget(QLabel("New Password:"))
        layout.addWidget(password_input)

        save_btn = QPushButton("Save Changes")
        cancel_btn = QPushButton("Cancel")

        layout.addWidget(save_btn)
        layout.addWidget(cancel_btn)

        dlg.setLayout(layout)

        def on_save():
            new_name = name_input.text().strip()
            new_password = password_input.text().strip()

            if not new_name or not new_password:
                QMessageBox.warning(dlg, "Invalid Input", "Name and password cannot be empty.")
                return

            if new_name != old_name:
                # Ensure new name doesn't conflict with an existing entry
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM passwords WHERE name = ?", (new_name,))
                    if cursor.fetchone()[0] > 0:
                        QMessageBox.warning(dlg, "Duplicate Name", f"A password named '{new_name}' already exists.")
                        return

            confirm = QMessageBox.question(
                dlg,
                "Confirm Save",
                "Saving will permanently overwrite the current password.\n\nDo you want to continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
            )

            if confirm == QMessageBox.StandardButton.Yes:
                with sqlite3.connect(DB_PATH) as conn:
                    encrypted_pwd = encrypt(self.master_key, new_password)
                    if new_name == old_name:
                        conn.execute("UPDATE passwords SET encrypted_password = ? WHERE name = ?", (encrypted_pwd, old_name))
                    else:
                        conn.execute("DELETE FROM passwords WHERE name = ?", (old_name,))
                        conn.execute("INSERT INTO passwords (name, encrypted_password) VALUES (?, ?)", (new_name, encrypted_pwd))

                dlg.close()
                self.populate_passwords()


        save_btn.clicked.connect(on_save)
        cancel_btn.clicked.connect(dlg.close)

        dlg.setFixedWidth(350)
        dlg.setFixedHeight(250)
        dlg.setWindowModality(Qt.WindowModality.ApplicationModal)
        dlg.show()



class PasswordGeneratorScreen(QWidget):
    def __init__(self, back_callback, master_key):
        super().__init__()
        self.master_key = master_key
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


        # Header row for back button
        header_row = QHBoxLayout()
        header_row.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self.back_btn = QPushButton()
        self.back_btn.setIcon(load_icon("back.svg"))
        self.back_btn.setFixedSize(36, 36)
        self.back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.back_btn.setStyleSheet("""
            QPushButton {
                background-color: #0dd420;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover {
                background-color: #00e070;
            }
        """)
        self.back_btn.clicked.connect(back_callback)

        header_row.addWidget(self.back_btn)
        layout.addLayout(header_row)


        length_row = QHBoxLayout()
        length_label = QLabel("Password Length:")
        self.length_input = QSpinBox()
        self.length_input.setRange(4, 64)
        self.length_input.setValue(16)

        length_row.addWidget(length_label)
        length_row.addWidget(self.length_input)
        layout.addLayout(length_row)


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
        self.output.setReadOnly(False)
        layout.addWidget(self.output)

        self.save_btn = QPushButton("Save Password")
        self.save_btn.clicked.connect(self.save_password)
        layout.addWidget(self.save_btn)

        self.back_btn = QPushButton("Back to Vault")
        self.back_btn.clicked.connect(back_callback)


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
            # Check for duplicate name
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM passwords WHERE name = ?", (name,))
                if cursor.fetchone()[0] > 0:
                    QMessageBox.warning(self, "Duplicate Name", f"A password named '{name}' already exists.\nPlease choose a different name.")
                    return

                # Proceed with saving if name is unique
                encrypted_pwd = encrypt(self.master_key, pwd)
                conn.execute("INSERT INTO passwords (name, encrypted_password) VALUES (?, ?)", (name, encrypted_pwd))
                QMessageBox.information(self, "Saved", f"Password saved as '{name}'.")


class SettingsScreen(QWidget):
    def __init__(self, back_callback, master_key, vault_window):
        super().__init__()
        self.master_key = master_key
        self.vault_window = vault_window
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

        top_settings_layout = QVBoxLayout()
        top_settings_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Header row (back + title)
        header_grid = QGridLayout()
        back_btn = QPushButton()
        back_btn.setIcon(load_icon("back.svg"))
        back_btn.setFixedSize(36, 36)
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.setStyleSheet("""
            QPushButton {
                background-color: #0dd420;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover {
                background-color: #00e070;
            }
        """)
        back_btn.clicked.connect(back_callback)

        title_label = QLabel("Settings")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("QLabel { font-size: 18px; font-weight: bold; }")

        header_grid.addWidget(back_btn, 0, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        header_grid.addWidget(title_label, 0, 1, alignment=Qt.AlignmentFlag.AlignCenter)
        header_grid.setColumnStretch(0, 1)
        header_grid.setColumnStretch(1, 2)
        header_grid.setColumnStretch(2, 1)

        top_settings_layout.addLayout(header_grid)

        # Change password button
        change_btn = QPushButton("Change Master Password")
        change_btn.clicked.connect(self.change_password)
        top_settings_layout.addWidget(change_btn)

        # Timeout row
        timeout_row = QHBoxLayout()
        timeout_label = QLabel("Auto Sign-Out Timeout (minutes):")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(5)

        timeout_row.addWidget(timeout_label)
        timeout_row.addWidget(self.timeout_spin)
        top_settings_layout.addLayout(timeout_row)

        # Add top layout
        layout.addLayout(top_settings_layout)

        # Add spacer so Apply button sticks to bottom
        layout.addStretch()

        # Apply button
        apply_btn = QPushButton("Apply Settings")
        apply_btn.clicked.connect(self.apply_settings)
        layout.addWidget(apply_btn)


        config = load_config()
        self.timeout_spin.setValue(config.get('timeout_minutes', 5))



        self.setLayout(layout)

    def change_password(self):
        salt = load_salt()

        old_pw, ok1 = QInputDialog.getText(self, "Verify Password", "Enter your current master password:", QLineEdit.EchoMode.Password)
        if not ok1 or not old_pw:
            return

        if not verify_master_password(old_pw, salt):
            QMessageBox.warning(self, "Incorrect Password", "The current master password you entered is incorrect.")
            return

        old_key = derive_key(old_pw, salt)
        old_master_key = old_key

        new_pw, ok2 = QInputDialog.getText(self, "New Password", "Enter a new master password:", QLineEdit.EchoMode.Password)
        if not ok2 or not new_pw:
            return

        confirm_pw, ok3 = QInputDialog.getText(self, "Confirm Password", "Re-enter new password:", QLineEdit.EchoMode.Password)
        if not ok3 or new_pw != confirm_pw:
            QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
            return

        new_key = derive_key(new_pw, salt)

        # Step 1: Decrypt and re-encrypt all passwords
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, encrypted_password FROM passwords")
            rows = cursor.fetchall()

            for name, enc_pwd in rows:
                try:
                    decrypted = decrypt(old_key, enc_pwd)
                    new_encrypted = encrypt(new_key, decrypted)
                    cursor.execute("UPDATE passwords SET encrypted_password = ? WHERE name = ?", (new_encrypted, name))
                except Exception as e:
                    print(f"[!] Failed to re-encrypt '{name}': {e}")

        # Step 2: Save new verification token
        save_verify_token(new_key)
        self.vault_window.master_key = new_key  # update running key
        QMessageBox.information(self, "Password Changed", "Your master password was successfully updated.")



    def apply_settings(self):
        timeout_minutes = self.timeout_spin.value()

        # Save to persistent config
        config = load_config()
        config['timeout_minutes'] = timeout_minutes
        save_config(config)

        # Apply to current session
        self.vault_window.timeout_minutes = timeout_minutes
        self.vault_window.inactivity_timer.setInterval(timeout_minutes * 60 * 1000)
        QMessageBox.information(self, "Settings Applied", f"Timeout set to {timeout_minutes} minutes.")


