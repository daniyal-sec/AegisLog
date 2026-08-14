"""
AegisLog Launch View — Phase 8

The initial launch screen for the SOC workstation.
Displays the AegisLog brand and real-time status checks before workspace entry.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QSizePolicy
)
from PySide6.QtCore import Qt, Signal, QTimer, QThread, QObject, Slot
from PySide6.QtGui import QPainter, QColor, QPen, QPainterPath

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_OVERLAY,
    BORDER_SUBTLE, BORDER_DEFAULT, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT, STATUS_ACTIVE, STATUS_IDLE, SEVERITY_HIGH,
    FONT_FAMILY
)
from storage import SecurityStorage

# ─────────────────────────────────────────────────────────────────────────────
# ABSTRACT BRAND MARK
# ─────────────────────────────────────────────────────────────────────────────

class BrandMark(QWidget):
    """
    Minimalist geometric 'A' abstract mark painted natively.
    No image files or random Unicode characters.
    """
    def __init__(self, size: int = 48, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        # Main architectural A (Left and Right pillars)
        path = QPainterPath()
        path.moveTo(w * 0.22, h * 0.85)
        path.lineTo(w * 0.50, h * 0.15)
        path.lineTo(w * 0.78, h * 0.85)
        
        stroke = max(2.0, w * 0.12)
        pen_main = QPen(QColor("#F2F4F5"))
        pen_main.setWidthF(stroke)
        pen_main.setJoinStyle(Qt.PenJoinStyle.MiterJoin)
        pen_main.setCapStyle(Qt.PenCapStyle.FlatCap)
        painter.setPen(pen_main)
        painter.drawPath(path)

        # Log stream (white segment)
        stream_stroke = max(1.5, w * 0.09)
        pen_stream = QPen(QColor("#F2F4F5"))
        pen_stream.setWidthF(stream_stroke)
        pen_stream.setCapStyle(Qt.PenCapStyle.FlatCap)
        painter.setPen(pen_stream)
        painter.drawLine(w * 0.12, h * 0.65, w * 0.58, h * 0.65)

        # Data packet (amber segment)
        pen_amber = QPen(QColor("#D99100"))
        pen_amber.setWidthF(stream_stroke)
        pen_amber.setCapStyle(Qt.PenCapStyle.FlatCap)
        painter.setPen(pen_amber)
        painter.drawLine(w * 0.68, h * 0.65, w * 0.88, h * 0.65)

        painter.end()


# ─────────────────────────────────────────────────────────────────────────────
# STATUS MODULE
# ─────────────────────────────────────────────────────────────────────────────

class LaunchStatusModule(QWidget):
    """Status indicator block for the launch screen."""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setFixedHeight(50)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self._dot = QLabel("●")
        self._dot.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 14px;")

        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        text_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self._title_lbl = QLabel(title.upper())
        self._title_lbl.setStyleSheet(f"""
            color: {TEXT_SECONDARY};
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 1.5px;
        """)

        self._val_lbl = QLabel("CHECKING...")
        self._val_lbl.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 12px;
            font-weight: 700;
        """)

        text_layout.addWidget(self._title_lbl)
        text_layout.addWidget(self._val_lbl)

        layout.addWidget(self._dot)
        layout.addLayout(text_layout)
        layout.addStretch()

    def set_status(self, is_ok: bool, message: str):
        color = STATUS_ACTIVE if is_ok else SEVERITY_HIGH
        self._dot.setStyleSheet(f"color: {color}; font-size: 14px;")
        self._val_lbl.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 12px;
            font-weight: 700;
        """)
        self._val_lbl.setText(message.upper())


# ─────────────────────────────────────────────────────────────────────────────
# LAUNCH SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class LaunchView(QWidget):
    """
    First screen shown on startup.
    Evaluates DB and Windows Events availability before entry.
    """

    enter_workspace = Signal()

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self._check_thread = None
        self._build_ui()
        
        # Start async checks
        self._run_checks()

    def _build_ui(self):
        # We want the background to blend perfectly with MainWindow
        self.setStyleSheet("background: transparent;")

        root_layout = QVBoxLayout(self)
        root_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        container = QWidget()
        container.setFixedWidth(400)
        c_layout = QVBoxLayout(container)
        c_layout.setSpacing(32)
        c_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # ── 1. Branding ──────────────────────────────────────────
        brand_layout = QVBoxLayout()
        brand_layout.setSpacing(12)
        brand_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        mark = BrandMark(64)
        
        title = QLabel("AEGISLOG")
        title.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 32px;
            font-weight: 800;
            letter-spacing: 10px;
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("SECURITY INVESTIGATION")
        subtitle.setStyleSheet(f"""
            color: {TEXT_SECONDARY};
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 3px;
        """)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        tagline = QLabel("LOCAL SOC WORKSTATION")
        tagline.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 9px;
            letter-spacing: 1.5px;
        """)
        tagline.setAlignment(Qt.AlignmentFlag.AlignCenter)

        brand_layout.addWidget(mark, alignment=Qt.AlignmentFlag.AlignCenter)
        brand_layout.addWidget(title)
        brand_layout.addWidget(subtitle)
        brand_layout.addSpacing(8)
        brand_layout.addWidget(tagline)

        c_layout.addLayout(brand_layout)

        # ── Separator ───────────────────────────────────────────
        def make_sep():
            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.HLine)
            sep.setStyleSheet(f"color: {BORDER_SUBTLE};")
            return sep

        c_layout.addWidget(make_sep())

        # ── Keywords ────────────────────────────────────────────
        kw = QLabel("MONITOR     DETECT     INVESTIGATE")
        kw.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 3px;
        """)
        kw.setAlignment(Qt.AlignmentFlag.AlignCenter)
        c_layout.addWidget(kw)

        c_layout.addWidget(make_sep())

        # ── Status ──────────────────────────────────────────────
        status_layout = QVBoxLayout()
        status_layout.setSpacing(8)
        status_layout.setContentsMargins(40, 0, 40, 0)
        
        self._db_mod = LaunchStatusModule("Database")
        self._win_mod = LaunchStatusModule("Windows Security Log")
        self._mon_mod = LaunchStatusModule("Monitor")

        status_layout.addWidget(self._db_mod)
        status_layout.addWidget(self._win_mod)
        status_layout.addWidget(self._mon_mod)

        c_layout.addLayout(status_layout)

        c_layout.addWidget(make_sep())

        # ── Action ──────────────────────────────────────────────
        self._enter_btn = QPushButton("ENTER WORKSPACE →")
        self._enter_btn.setMinimumHeight(44)
        self._enter_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._enter_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                border: 1px solid {BORDER_DEFAULT};
                color: {TEXT_PRIMARY};
                font-size: 12px;
                font-weight: 600;
                letter-spacing: 2px;
            }}
            QPushButton:hover {{
                background-color: {BG_ELEVATED};
                border-color: {TEXT_SECONDARY};
                color: {TEXT_PRIMARY};
            }}
            QPushButton:pressed {{
                background-color: {BG_OVERLAY};
            }}
        """)
        self._enter_btn.clicked.connect(self.enter_workspace.emit)
        c_layout.addWidget(self._enter_btn)

        c_layout.addWidget(make_sep())

        # ── Version ─────────────────────────────────────────────
        version = QLabel("v1.0.0")
        version.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 10px;
            letter-spacing: 1px;
        """)
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        c_layout.addWidget(version)

        root_layout.addWidget(container)

    def _run_checks(self):
        """Evaluate real backend status non-destructively in a background thread."""
        try:
            if self._check_thread and self._check_thread.isRunning():
                return
        except RuntimeError:
            self._check_thread = None

        self._check_thread = QThread(self)
        self._worker = StartupWorker(self.db_path)
        self._worker.moveToThread(self._check_thread)

        self._check_thread.started.connect(self._worker.run)
        self._worker.checks_finished.connect(self._on_checks_finished)
        self._check_thread.start()

    def _on_checks_finished(self, results: dict):
        if self._check_thread:
            self._check_thread.quit()
            self._check_thread.wait()
            self._check_thread.deleteLater()
            self._check_thread = None

        if hasattr(self, "_worker") and self._worker:
            self._worker.deleteLater()
            self._worker = None

        self._db_mod.set_status(results.get("db_ok", False), results.get("db_msg", "UNAVAILABLE"))
        self._win_mod.set_status(results.get("win_ok", False), results.get("win_msg", "UNAVAILABLE"))
        self._mon_mod.set_status(results.get("mon_ok", True), results.get("mon_msg", "READY"))


class StartupWorker(QObject):
    checks_finished = Signal(dict)

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path

    @Slot()
    def run(self):
        import os
        results = {
            "db_ok": False,
            "db_msg": "UNAVAILABLE",
            "win_ok": False,
            "win_msg": "UNAVAILABLE",
            "mon_ok": True,
            "mon_msg": "READY"
        }

        # 1. DB Check
        try:
            from storage import SecurityStorage
            storage = SecurityStorage(self.db_path)
            # If we can query the count, it is operational
            storage.count_auth_events()
            results["db_ok"] = True
            results["db_msg"] = "OPERATIONAL"
        except Exception:
            results["db_ok"] = False
            results["db_msg"] = "UNAVAILABLE"

        # 2. Win Log Check
        try:
            import win32evtlog
            h_log = win32evtlog.OpenEventLog(None, "Security")
            if h_log:
                win32evtlog.CloseEventLog(h_log)
                results["win_ok"] = True
                results["win_msg"] = "AVAILABLE"
            else:
                results["win_ok"] = False
                results["win_msg"] = "UNAVAILABLE"
        except ImportError:
            results["win_ok"] = False
            results["win_msg"] = "WIN32 NOT INSTALLED"
        except Exception as e:
            if "Access is denied" in str(e):
                results["win_ok"] = False
                results["win_msg"] = "ACCESS DENIED (NO ADMIN)"
            else:
                results["win_ok"] = False
                results["win_msg"] = "UNAVAILABLE"

        self.checks_finished.emit(results)
