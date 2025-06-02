import sys
from PyQt6.QtWidgets import QApplication
from fastword.gui import LoginWindow


def main():
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())



if __name__ == "__main__":
    main()
