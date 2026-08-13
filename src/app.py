"""
AegisLog GUI Entry Point

Launches the AegisLog PySide6 desktop application.

Usage:
    python src/app.py

The existing CLI tools remain fully functional:
    python src/investigation.py
    python src/windows_monitor.py
    python src/main.py <log_file>
"""

import sys
import os
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Path setup — ensure src/ is on sys.path so all backend modules import
# ─────────────────────────────────────────────────────────────────────────────

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Change working directory to project root so relative paths
# (data/aegislog.db, reports/) resolve correctly.
PROJECT_ROOT = SRC_DIR.parent
os.chdir(PROJECT_ROOT)

# ─────────────────────────────────────────────────────────────────────────────
# Qt imports
# ─────────────────────────────────────────────────────────────────────────────

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt

from gui.styles import DARK_STYLESHEET, FONT_FAMILY
from gui.main_window import MainWindow


# ─────────────────────────────────────────────────────────────────────────────
# Application entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # High-DPI rendering
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("AegisLog")
    app.setApplicationDisplayName("AegisLog")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("AegisLog Security")

    # Apply global stylesheet
    app.setStyleSheet(DARK_STYLESHEET)

    # Set default application font
    font = QFont("Segoe UI", 10)
    app.setFont(font)

    # Resolve database path relative to project root
    db_path = str(PROJECT_ROOT / "data" / "aegislog.db")

    # Create and show main window
    window = MainWindow(db_path=db_path)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
