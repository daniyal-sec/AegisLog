"""
AegisLog Main Window

Defines the application shell:
- Sidebar navigation
- Stacked content area
- Top status strip
- Monitoring status indicator
"""

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QFrame,
    QSizePolicy,
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QFont, QFontMetrics

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_OVERLAY,
    BORDER_SUBTLE, BORDER_DEFAULT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT, STATUS_ACTIVE, STATUS_IDLE,
    FONT_FAMILY,
)


# ─────────────────────────────────────────────────────────────────────────────
# NAV BUTTON
# ─────────────────────────────────────────────────────────────────────────────

class NavButton(QPushButton):
    """Sidebar navigation item."""

    _ACTIVE_STYLE = f"""
        QPushButton {{
            background-color: {BG_OVERLAY};
            color: {TEXT_PRIMARY};
            border: none;
            border-left: 2px solid {ACCENT};
            text-align: left;
            padding: 10px 20px;
            font-size: 13px;
            font-family: {FONT_FAMILY};
            font-weight: 500;
        }}
    """
    _INACTIVE_STYLE = f"""
        QPushButton {{
            background-color: transparent;
            color: {TEXT_SECONDARY};
            border: none;
            border-left: 2px solid transparent;
            text-align: left;
            padding: 10px 20px;
            font-size: 13px;
            font-family: {FONT_FAMILY};
            font-weight: 400;
        }}
        QPushButton:hover {{
            background-color: {BG_ELEVATED};
            color: {TEXT_PRIMARY};
            border-left: 2px solid {BORDER_DEFAULT};
        }}
    """

    def __init__(self, label: str, parent=None):
        super().__init__(label, parent)
        self.setCheckable(False)
        self.setMinimumHeight(40)
        self.setFlat(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.set_active(False)

    def set_active(self, active: bool):
        self.setStyleSheet(
            self._ACTIVE_STYLE if active else self._INACTIVE_STYLE
        )


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────

class Sidebar(QWidget):
    """Left navigation sidebar."""

    NAV_ITEMS = [
        ("■   Dashboard",       0),
        ("●   Live Monitor",    1),
        ("▲   Security Alerts", 2),
        ("◆   Investigation",   3),
        ("≡   Reports",         4),
        ("⚙   Settings",        5),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(220)
        self.setObjectName("Sidebar")
        self.setStyleSheet(f"""
            #Sidebar {{
                background-color: {BG_SURFACE};
                border-right: 1px solid {BORDER_SUBTLE};
            }}
        """)

        self._nav_buttons: list[NavButton] = []
        self._on_navigate = None  # callback(index)

        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Brand block ────────────────────────────────────────
        brand = QWidget()
        brand.setFixedHeight(80)
        brand.setStyleSheet(f"""
            background-color: {BG_SURFACE};
            border-bottom: 1px solid {BORDER_SUBTLE};
        """)
        brand_layout = QHBoxLayout(brand)
        brand_layout.setContentsMargins(20, 0, 16, 0)
        brand_layout.setSpacing(12)

        from gui.launch_view import BrandMark
        mark = BrandMark(32)

        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(2)
        text_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        name_label = QLabel("AEGISLOG")
        name_label.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 15px;
            font-weight: 800;
            letter-spacing: 3px;
            background: transparent;
        """)

        tagline_label = QLabel("SECURITY INVESTIGATION")
        tagline_label.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 7px;
            font-weight: 600;
            letter-spacing: 1.5px;
            background: transparent;
        """)

        text_layout.addWidget(name_label)
        text_layout.addWidget(tagline_label)

        brand_layout.addWidget(mark)
        brand_layout.addLayout(text_layout)
        brand_layout.addStretch()
        layout.addWidget(brand)

        # ── Section label ──────────────────────────────────────
        nav_label = QLabel("NAVIGATION")
        nav_label.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 1.5px;
            padding: 16px 20px 6px 20px;
            background: transparent;
        """)
        layout.addWidget(nav_label)

        # ── Nav buttons ────────────────────────────────────────
        for label, index in self.NAV_ITEMS:
            btn = NavButton(label)
            btn.clicked.connect(lambda checked, i=index: self._handle_nav(i))
            self._nav_buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch()

        # ── Monitoring status ──────────────────────────────────
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet(f"color: {BORDER_SUBTLE};")
        layout.addWidget(separator)

        self._status_widget = MonitoringStatusWidget()
        layout.addWidget(self._status_widget)

    def _handle_nav(self, index: int):
        self.set_active_index(index)
        if self._on_navigate:
            self._on_navigate(index)

    def set_active_index(self, index: int):
        for i, btn in enumerate(self._nav_buttons):
            btn.set_active(i == index)

    def set_navigate_callback(self, callback):
        self._on_navigate = callback

    def set_monitoring_active(self, active: bool):
        self._status_widget.set_active(active)

    def navigate_to(self, index: int):
        """Programmatically navigate (used by other views)."""
        self._handle_nav(index)


# ─────────────────────────────────────────────────────────────────────────────
# MONITORING STATUS WIDGET (sidebar bottom)
# ─────────────────────────────────────────────────────────────────────────────

class MonitoringStatusWidget(QWidget):
    """Small status indicator at the bottom of the sidebar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(52)
        self.setStyleSheet(f"background-color: {BG_SURFACE};")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 8, 16, 10)
        layout.setSpacing(8)

        self._dot = QLabel("●")
        self._dot.setStyleSheet(f"""
            color: {STATUS_IDLE};
            font-size: 10px;
            background: transparent;
        """)

        self._label = QLabel("Monitor Idle")
        self._label.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 11px;
            background: transparent;
        """)

        layout.addWidget(self._dot)
        layout.addWidget(self._label)
        layout.addStretch()

    def set_active(self, active: bool):
        if active:
            self._dot.setStyleSheet(f"""
                color: {STATUS_ACTIVE};
                font-size: 10px;
                background: transparent;
            """)
            self._label.setStyleSheet(f"""
                color: {TEXT_PRIMARY};
                font-size: 11px;
                font-weight: 600;
                background: transparent;
            """)
            self._label.setText("MONITOR ACTIVE")
        else:
            self._dot.setStyleSheet(f"""
                color: {STATUS_IDLE};
                font-size: 10px;
                background: transparent;
            """)
            self._label.setStyleSheet(f"""
                color: {TEXT_MUTED};
                font-size: 11px;
                background: transparent;
            """)
            self._label.setText("MONITOR IDLE")


# ─────────────────────────────────────────────────────────────────────────────
# TOP HEADER STRIP
# ─────────────────────────────────────────────────────────────────────────────

class TopHeader(QWidget):
    """Thin status strip across the top of the content area."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(48)
        self.setObjectName("TopHeader")
        self.setStyleSheet(f"""
            #TopHeader {{
                background-color: {BG_SURFACE};
                border-bottom: 1px solid {BORDER_SUBTLE};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(0)

        # Section title
        self._title = QLabel("Dashboard")
        self._title.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 14px;
            font-weight: 600;
            letter-spacing: 0.2px;
            background: transparent;
        """)
        layout.addWidget(self._title)

        layout.addStretch()

        # DB status
        self._db_indicator = StatusPill("DB", connected=True)
        layout.addWidget(self._db_indicator)

        layout.addSpacing(12)

        # Monitor status
        self._monitor_indicator = StatusPill("MONITOR", connected=False)
        layout.addWidget(self._monitor_indicator)

    def set_section_title(self, title: str):
        self._title.setText(title)

    def set_db_connected(self, connected: bool):
        self._db_indicator.set_connected(connected)

    def set_monitor_active(self, active: bool):
        label = "MONITORING" if active else "MONITOR"
        self._monitor_indicator._label.setText(label)
        self._monitor_indicator.set_connected(active)


class StatusPill(QWidget):
    """Small status indicator pill for the top header."""

    def __init__(self, label: str, connected: bool = False, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(5)

        self._dot = QLabel("●")
        self._dot.setStyleSheet("font-size: 8px; background: transparent;")

        self._label = QLabel(label)
        self._label.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.8px;
            background: transparent;
        """)

        layout.addWidget(self._dot)
        layout.addWidget(self._label)

        self.setStyleSheet(f"""
            background-color: {BG_ELEVATED};
            border: 1px solid {BORDER_SUBTLE};
        """)

        self.set_connected(connected)

    def set_connected(self, connected: bool):
        color = STATUS_ACTIVE if connected else STATUS_IDLE
        text_color = STATUS_ACTIVE if connected else TEXT_MUTED
        self._dot.setStyleSheet(
            f"color: {color}; font-size: 8px; background: transparent;"
        )
        self._label.setStyleSheet(f"""
            color: {text_color};
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.8px;
            background: transparent;
        """)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN WINDOW
# ─────────────────────────────────────────────────────────────────────────────

PAGE_TITLES = [
    "DASHBOARD",
    "LIVE MONITOR",
    "SECURITY ALERTS",
    "INVESTIGATION",
    "REPORTS",
    "SETTINGS",
]


class MainWindow(QMainWindow):
    """AegisLog main application window."""

    def __init__(self, db_path: str = "data/aegislog.db"):
        super().__init__()
        self.db_path = db_path
        self._monitoring_active = False

        self.setWindowTitle("AegisLog — Security Investigation")
        self.setMinimumSize(QSize(1280, 800))
        self.resize(1440, 900)

        self._build_ui()
        self._check_db_status()

        # Start on Dashboard
        self._sidebar.set_active_index(0)
        self._header.set_section_title("Dashboard")

    def _build_ui(self):
        # We use a master stack to switch between LaunchView and the Workspace.
        self._master_stack = QStackedWidget()
        self.setCentralWidget(self._master_stack)

        from gui.launch_view import LaunchView
        self._launch_view = LaunchView(self.db_path)
        self._launch_view.enter_workspace.connect(self._enter_workspace)
        self._master_stack.addWidget(self._launch_view)

        # Workspace container
        self._workspace = QWidget()
        workspace_layout = QHBoxLayout(self._workspace)
        workspace_layout.setContentsMargins(0, 0, 0, 0)
        workspace_layout.setSpacing(0)

        # ── Sidebar ────────────────────────────────────────────
        self._sidebar = Sidebar()
        self._sidebar.set_navigate_callback(self._on_navigate)
        workspace_layout.addWidget(self._sidebar)

        # ── Right area (header + content) ──────────────────────
        right = QWidget()
        right.setStyleSheet("background: transparent;")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self._header = TopHeader()
        right_layout.addWidget(self._header)

        # Pages
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background: transparent;")
        right_layout.addWidget(self._stack)

        # Import and create page widgets (deferred to avoid circular imports)
        self._create_pages()

        workspace_layout.addWidget(right)
        self._master_stack.addWidget(self._workspace)
        
        # Start on Launch View
        self._master_stack.setCurrentWidget(self._launch_view)

    def _enter_workspace(self):
        from gui.onboarding_view import OnboardingDialog, should_show_onboarding
        if should_show_onboarding(self.db_path):
            dlg = OnboardingDialog(self.db_path, self)
            dlg.exec()
        self._master_stack.setCurrentWidget(self._workspace)

    def _create_pages(self):
        """Instantiate all page widgets and add to the stack."""
        from gui.dashboard import DashboardView
        from gui.monitor_view import MonitorView
        from gui.alerts_view import AlertsView
        from gui.investigation_view import InvestigationView
        from gui.reports_view import ReportsView
        from gui.settings_view import SettingsView

        self._dashboard    = DashboardView(self.db_path)
        self._monitor      = MonitorView(self.db_path)
        self._alerts       = AlertsView(self.db_path)
        self._investigation = InvestigationView(self.db_path)
        self._reports      = ReportsView(self.db_path)
        self._settings     = SettingsView(self.db_path)

        self._pages = [
            self._dashboard,
            self._monitor,
            self._alerts,
            self._investigation,
            self._reports,
            self._settings,
        ]

        for page in self._pages:
            self._stack.addWidget(page)

        # Wire cross-view navigation signals
        self._dashboard.investigate_requested.connect(
            self._open_investigation
        )
        self._alerts.investigate_requested.connect(
            self._open_investigation
        )

        # Wire monitoring status from monitor view
        self._monitor.monitoring_started.connect(
            lambda: self._set_monitoring_active(True)
        )
        self._monitor.monitoring_stopped.connect(
            lambda: self._set_monitoring_active(False)
        )

    def _on_navigate(self, index: int):
        self._stack.setCurrentIndex(index)
        self._header.set_section_title(PAGE_TITLES[index])

        # Refresh data when switching to data views
        page = self._pages[index]
        if hasattr(page, "refresh"):
            page.refresh()

    def _open_investigation(self, finding_id: int):
        """Navigate to Investigation and pre-select a finding."""
        self._sidebar.navigate_to(3)
        self._investigation.load_finding(finding_id)

    def _set_monitoring_active(self, active: bool):
        self._monitoring_active = active
        self._sidebar.set_monitoring_active(active)
        self._header.set_monitor_active(active)

    def _check_db_status(self):
        """Quick non-blocking check that the DB file exists."""
        import os
        connected = os.path.exists(self.db_path)
        self._header.set_db_connected(connected)

    def closeEvent(self, event):
        """Ensure monitoring is stopped before closing."""
        if hasattr(self._monitor, "stop_monitoring"):
            self._monitor.stop_monitoring()
        super().closeEvent(event)
