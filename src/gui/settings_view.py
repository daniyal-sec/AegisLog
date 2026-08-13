"""
AegisLog Settings View

Displays application information and system status.
"""

import sys
import os
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QSizePolicy,
)
from PySide6.QtCore import Qt

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_OVERLAY,
    BORDER_SUBTLE, BORDER_DEFAULT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    STATUS_ACTIVE, STATUS_IDLE,
    SEVERITY_HIGH,
    FONT_FAMILY, FONT_MONO,
)

AEGISLOG_VERSION = "1.0.0"


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def info_row(label: str, value: str, mono: bool = False) -> QWidget:
    """A key/value row for the settings panel."""
    w = QWidget()
    w.setStyleSheet("background: transparent;")
    layout = QHBoxLayout(w)
    layout.setContentsMargins(0, 5, 0, 5)
    layout.setSpacing(0)

    lbl = QLabel(label)
    lbl.setFixedWidth(200)
    lbl.setStyleSheet(f"""
        color: {TEXT_MUTED};
        font-size: 12px;
        background: transparent;
    """)

    val = QLabel(value)
    val.setWordWrap(True)
    font_family = FONT_MONO if mono else FONT_FAMILY
    val.setStyleSheet(f"""
        color: {TEXT_PRIMARY};
        font-size: 12px;
        font-family: {font_family};
        background: transparent;
    """)

    layout.addWidget(lbl)
    layout.addWidget(val, stretch=1)
    return w


def status_row(label: str, ok: bool, ok_text: str, fail_text: str, detail: str = "") -> QWidget:
    """A key/value row with a status indicator."""
    w = QWidget()
    w.setStyleSheet("background: transparent;")
    layout = QHBoxLayout(w)
    layout.setContentsMargins(0, 5, 0, 5)
    layout.setSpacing(0)

    lbl = QLabel(label)
    lbl.setFixedWidth(200)
    lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px; background: transparent;")

    dot = QLabel("●")
    dot_color = STATUS_ACTIVE if ok else SEVERITY_HIGH
    dot.setStyleSheet(f"color: {dot_color}; font-size: 9px; background: transparent;")

    text_color = STATUS_ACTIVE if ok else SEVERITY_HIGH
    status_text = ok_text if ok else fail_text
    val = QLabel(f" {status_text}" + (f"  —  {detail}" if detail else ""))
    val.setStyleSheet(f"color: {text_color}; font-size: 12px; background: transparent;")

    layout.addWidget(lbl)
    layout.addWidget(dot)
    layout.addWidget(val, stretch=1)
    return w


def section_block(title: str) -> QWidget:
    """Section divider."""
    w = QWidget()
    w.setStyleSheet("background: transparent;")
    layout = QVBoxLayout(w)
    layout.setContentsMargins(0, 20, 0, 8)
    layout.setSpacing(4)

    lbl = QLabel(title.upper())
    lbl.setStyleSheet(f"""
        font-size: 9px;
        font-weight: 600;
        letter-spacing: 1.4px;
        color: {TEXT_MUTED};
        background: transparent;
    """)
    layout.addWidget(lbl)

    sep = QFrame()
    sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet(f"color: {BORDER_SUBTLE};")
    layout.addWidget(sep)

    return w


# ─────────────────────────────────────────────────────────────────────────────
# SETTINGS VIEW
# ─────────────────────────────────────────────────────────────────────────────

class SettingsView(QWidget):
    """Settings / About page."""

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path

        # Resolve paths
        src_dir       = Path(__file__).resolve().parent.parent
        self._project_root = src_dir.parent
        self._db_path  = self._project_root / db_path if not Path(db_path).is_absolute() else Path(db_path)

        self._build_ui()
        self._populate()

    def _build_ui(self):
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(f"background-color: {BG_BASE};")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        content = QWidget()
        content.setStyleSheet(f"background-color: {BG_BASE};")
        scroll.setWidget(content)

        self._layout = QVBoxLayout(content)
        self._layout.setContentsMargins(36, 28, 36, 36)
        self._layout.setSpacing(0)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignTop)

    def _populate(self):
        L = self._layout

        # ── Application ────────────────────────────────────────
        L.addWidget(section_block("Application"))
        L.addWidget(info_row("AegisLog Version",  AEGISLOG_VERSION))
        L.addWidget(info_row("Python Version",
                             f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"))

        try:
            import PySide6
            pyside_ver = PySide6.__version__
        except Exception:
            pyside_ver = "Unknown"
        L.addWidget(info_row("PySide6 Version", pyside_ver))

        L.addWidget(info_row("Platform",  sys.platform))

        # ── Storage ────────────────────────────────────────────
        L.addWidget(section_block("Storage"))
        L.addWidget(info_row("Database Path", str(self._db_path), mono=True))

        db_ok = self._db_path.exists()
        db_detail = f"{self._db_path.stat().st_size:,} bytes" if db_ok else ""
        L.addWidget(status_row(
            "Database",
            ok=db_ok,
            ok_text="Connected",
            fail_text="File not found",
            detail=db_detail,
        ))

        # Test SQLite connection
        if db_ok:
            sqlite_ok, sqlite_detail = self._check_sqlite()
        else:
            sqlite_ok, sqlite_detail = False, "Database file missing"

        L.addWidget(status_row(
            "SQLite",
            ok=sqlite_ok,
            ok_text="Operational",
            fail_text="Error",
            detail=sqlite_detail,
        ))

        # ── Windows Security Log ───────────────────────────────
        L.addWidget(section_block("Windows Security Log"))
        winlog_ok, winlog_detail = self._check_windows_log()
        L.addWidget(status_row(
            "Windows Security Log",
            ok=winlog_ok,
            ok_text="Available",
            fail_text="Unavailable",
            detail=winlog_detail,
        ))

        # ── Directories ────────────────────────────────────────
        L.addWidget(section_block("Directories"))
        reports_dir = self._project_root / "reports"
        report_count = len(list(reports_dir.glob("*.txt"))) if reports_dir.exists() else 0
        L.addWidget(info_row("Reports Directory",
                             str(reports_dir), mono=True))
        L.addWidget(info_row("Stored Reports",   str(report_count)))

        # ── CLI Reference ──────────────────────────────────────
        L.addWidget(section_block("CLI"))
        note = QLabel(
            "The AegisLog command-line interface remains fully functional.\n\n"
            "   python src/investigation.py    — interactive investigation console\n"
            "   python src/windows_monitor.py  — terminal live monitor\n"
            "   python src/main.py <log>       — analyse a log file"
        )
        note.setStyleSheet(f"""
            color: {TEXT_SECONDARY};
            font-size: 12px;
            font-family: {FONT_MONO};
            background-color: {BG_SURFACE};
            border: 1px solid {BORDER_SUBTLE};
            padding: 14px 16px;
            line-height: 1.6;
        """)
        note.setWordWrap(True)
        L.addWidget(note)

        L.addStretch()

    def _check_sqlite(self) -> tuple[bool, str]:
        try:
            from storage import SecurityStorage
            s = SecurityStorage(str(self._db_path))
            n_events   = s.count_auth_events()
            n_findings = s.count_findings()
            return True, f"{n_events} events, {n_findings} findings"
        except Exception as exc:
            return False, str(exc)

    def _check_windows_log(self) -> tuple[bool, str]:
        try:
            from windows_monitor import get_latest_record_number
            record = get_latest_record_number()
            return True, f"Latest record: {record}"
        except ImportError:
            return False, "pywin32 not installed"
        except Exception as exc:
            error_text = str(exc)
            if "Access" in error_text or "privilege" in error_text.lower():
                return False, "Requires Administrator privileges"
            return False, error_text[:80]

    def refresh(self):
        """Re-check system status on navigation."""
        # Clear and rebuild — simple approach for a settings page
        while self._layout.count():
            item = self._layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._populate()
