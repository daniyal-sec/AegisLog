"""
AegisLog Dashboard View  —  Phase 3

Displays real-time security statistics and recent activity.

Architecture:
  QTimer (5 s) → triggers DashboardDataLoader (QThread)
  DashboardDataLoader emits data_ready(dict) → main thread updates UI

The Qt GUI thread is never blocked by SQLite queries.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QSizePolicy, QScrollArea,
    QPushButton, QHeaderView,
)
from PySide6.QtCore import Qt, QTimer, QThread, QObject, Signal, Slot
from PySide6.QtGui import QFont, QColor

import sys
MONITOR_SOURCE_NAME = "Windows Security log" if sys.platform == "win32" else "systemd journal"

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_OVERLAY,
    BORDER_SUBTLE, BORDER_DEFAULT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    STATUS_SUCCESS_TEXT, STATUS_FAILED_TEXT,
    severity_color, status_text_color,
    FONT_FAMILY,
)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

RECENT_EVENT_LIMIT = 50   # rows shown in the events table
RECENT_ALERT_LIMIT = 5    # alert cards shown
REFRESH_INTERVAL_MS = 5_000  # 5-second auto-refresh


# ─────────────────────────────────────────────────────────────────────────────
# BACKGROUND DATA LOADER
# Runs on a QThread so SQLite queries never touch the GUI thread.
# ─────────────────────────────────────────────────────────────────────────────

class DashboardDataLoader(QObject):
    """
    Fetches all dashboard data from SQLite in one pass.

    Emits data_ready(dict) with the result, or load_error(str) on failure.
    Designed for moveToThread() — never instantiate on the GUI thread's
    blocking path.
    """

    data_ready  = Signal(dict)
    load_error  = Signal(str)

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path

    @Slot()
    def load(self):
        """Perform all queries and emit result."""
        try:
            from storage import SecurityStorage
            storage = SecurityStorage(self.db_path)

            # ── Auth events ─────────────────────────────────────
            total_events = storage.count_auth_events()

            # Fetch only the last RECENT_EVENT_LIMIT rows for the table
            # using a targeted query to avoid loading the entire table
            all_events = storage.get_auth_events()
            recent_events = list(reversed(all_events))[:RECENT_EVENT_LIMIT]

            success_count = sum(
                1 for e in all_events
                if e["status"] in ("SUCCESS", "ACCEPTED")
            )
            failed_count = sum(
                1 for e in all_events
                if e["status"] == "FAILED"
            )

            # ── Findings ────────────────────────────────────────
            all_findings = storage.get_findings()
            total_findings = len(all_findings)
            high_findings     = sum(1 for f in all_findings if f["severity"] == "HIGH")
            critical_findings = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
            medium_findings   = sum(1 for f in all_findings if f["severity"] == "MEDIUM")

            recent_findings = list(reversed(all_findings))[:RECENT_ALERT_LIMIT]

            self.data_ready.emit({
                "ok":               True,
                "total_events":     total_events,
                "success_count":    success_count,
                "failed_count":     failed_count,
                "total_findings":   total_findings,
                "high_findings":    high_findings,
                "critical_findings":critical_findings,
                "medium_findings":  medium_findings,
                "recent_events":    recent_events,
                "recent_findings":  recent_findings,
                "fetched_at":       datetime.now().strftime("%H:%M:%S"),
            })

        except Exception as exc:
            self.data_ready.emit({
                "ok":    False,
                "error": str(exc),
            })


# ─────────────────────────────────────────────────────────────────────────────
# STAT CARD
# ─────────────────────────────────────────────────────────────────────────────

class StatCard(QWidget):
    """
    A single metric card in the dashboard summary row.

    Shows a primary value and an optional secondary context string.
    """

    def __init__(
        self,
        label: str,
        value_color: str = TEXT_PRIMARY,
        parent=None,
    ):
        super().__init__(parent)
        self._value_color = value_color

        self.setObjectName("StatCard")
        self.setStyleSheet(f"""
            #StatCard {{
                background-color: {BG_SURFACE};
                border: 1px solid {BORDER_SUBTLE};
            }}
        """)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        self.setFixedHeight(96)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(2)

        # Primary value
        self._value_label = QLabel("—")
        self._value_label.setStyleSheet(f"""
            font-size: 24px;
            font-weight: 700;
            color: {value_color};
            background: transparent;
        """)
        layout.addWidget(self._value_label)

        # Label
        self._name_label = QLabel(label.upper())
        self._name_label.setStyleSheet(f"""
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 1.2px;
            color: {TEXT_MUTED};
            background: transparent;
        """)
        layout.addWidget(self._name_label)

        # Secondary context (e.g. "67% success rate")
        self._sub_label = QLabel("")
        self._sub_label.setStyleSheet(f"""
            font-size: 10px;
            color: {TEXT_MUTED};
            background: transparent;
        """)
        self._sub_label.hide()
        layout.addWidget(self._sub_label)

    def set_value(self, value: str, sub: str = ""):
        self._value_label.setText(value)
        if sub:
            self._sub_label.setText(sub)
            self._sub_label.show()
        else:
            self._sub_label.hide()


# ─────────────────────────────────────────────────────────────────────────────
# SECTION HEADER  (title + optional right-side metadata)
# ─────────────────────────────────────────────────────────────────────────────

class SectionHeader(QWidget):
    """Uppercase section label with a thin separator and optional right label."""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 6)

        self._title_lbl = QLabel(title.upper())
        self._title_lbl.setStyleSheet(f"""
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 1.5px;
            color: {TEXT_PRIMARY};
            background: transparent;
        """)
        row.addWidget(self._title_lbl)
        
        # Add a subtle vertical separator if there is meta
        self._sep_lbl = QLabel(" | ")
        self._sep_lbl.setStyleSheet(f"color: {BORDER_SUBTLE}; background: transparent;")
        self._sep_lbl.hide()
        row.addWidget(self._sep_lbl)
        
        row.addStretch()

        self._meta_lbl = QLabel("")
        self._meta_lbl.setStyleSheet(f"""
            font-size: 10px;
            color: {TEXT_MUTED};
            background: transparent;
        """)
        row.addWidget(self._meta_lbl)

        outer.addLayout(row)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {BORDER_SUBTLE};")
        outer.addWidget(sep)

    def set_meta(self, text: str):
        self._meta_lbl.setText(text)
        if text:
            self._sep_lbl.show()
        else:
            self._sep_lbl.hide()


# ─────────────────────────────────────────────────────────────────────────────
# STATE WIDGETS:  empty  /  error
# ─────────────────────────────────────────────────────────────────────────────

class EmptyStateWidget(QWidget):
    """Shown when a section has zero data (not an error)."""

    def __init__(self, message: str, hint: str = "", parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            background-color: {BG_SURFACE};
            border: 1px solid {BORDER_SUBTLE};
        """)
        self.setFixedHeight(72)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(4)

        # Add abstract subtle icon
        icon = QLabel("⊘")
        icon.setStyleSheet(f"color: {BORDER_SUBTLE}; font-size: 24px; background: transparent;")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)

        msg = QLabel(message)
        msg.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 12px;
            font-weight: 600;
            background: transparent;
        """)
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(msg)

        if hint:
            h = QLabel(hint)
            h.setStyleSheet(f"""
                color: {TEXT_MUTED};
                font-size: 10px;
                background: transparent;
            """)
            h.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(h)


class ErrorStateWidget(QWidget):
    """Shown when a section failed to load (database/system error)."""

    def __init__(self, message: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            background-color: {BG_SURFACE};
            border: 1px solid {BORDER_SUBTLE};
            border-left: 3px solid {SEVERITY_HIGH};
        """)
        self.setFixedHeight(52)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 0)

        icon = QLabel("⚠")
        icon.setStyleSheet(f"color: {SEVERITY_HIGH}; font-size: 14px; background: transparent;")
        layout.addWidget(icon)

        msg = QLabel(message)
        msg.setStyleSheet(f"color: {SEVERITY_HIGH}; font-size: 11px; background: transparent;")
        layout.addWidget(msg)
        layout.addStretch()


# ─────────────────────────────────────────────────────────────────────────────
# ALERT SUMMARY CARD  (compact, for the dashboard)
# ─────────────────────────────────────────────────────────────────────────────

class AlertSummaryCard(QWidget):
    """
    Compact alert card used in the dashboard Recent Alerts section.
    Shows severity stripe, attack type, source/target, key metrics,
    IP classification badge, and Investigate button.
    """

    investigate_clicked = Signal(int)

    def __init__(self, finding: dict, parent=None):
        super().__init__(parent)
        self._finding_id = finding.get("id", -1)
        severity  = finding.get("severity", "LOW")
        sev_color = severity_color(severity)

        self.setObjectName("AlertSummaryCard")
        self.setStyleSheet(f"""
            #AlertSummaryCard {{
                background-color: {BG_SURFACE};
                border: 1px solid {BORDER_SUBTLE};
                border-top: none;
            }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Thin severity stripe
        stripe = QWidget()
        stripe.setFixedHeight(2)
        stripe.setStyleSheet(f"background-color: {sev_color};")
        root.addWidget(stripe)

        # Body
        body = QWidget()
        body.setStyleSheet("background: transparent;")
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(16, 10, 16, 10)
        body_layout.setSpacing(20)
        root.addWidget(body)

        # Left block: severity badge + attack type + source → target
        left = QVBoxLayout()
        left.setSpacing(3)

        sev_lbl = QLabel(severity)
        sev_lbl.setStyleSheet(f"""
            color: {sev_color};
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 1px;
            background: transparent;
        """)
        left.addWidget(sev_lbl)

        attack_lbl = QLabel(finding.get("attack_type", "Unknown"))
        attack_lbl.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 13px;
            font-weight: 600;
            background: transparent;
        """)
        left.addWidget(attack_lbl)

        # Source → target with IP class badge
        src_ip   = finding.get("source_ip", "—")
        target   = finding.get("target_user", "—")
        ip_class = finding.get("ip_classification", "")

        flow = QHBoxLayout()
        flow.setSpacing(6)

        src_lbl = QLabel(f"{src_ip}  →  {target}")
        src_lbl.setStyleSheet(f"""
            color: {TEXT_SECONDARY};
            font-size: 11px;
            background: transparent;
        """)
        flow.addWidget(src_lbl)

        if ip_class and ip_class.lower() not in ("unknown", ""):
            badge = QLabel(ip_class.upper())
            badge.setStyleSheet(f"""
                color: {TEXT_MUTED};
                font-size: 9px;
                font-weight: 600;
                letter-spacing: 0.5px;
                background-color: {BG_ELEVATED};
                border: 1px solid {BORDER_SUBTLE};
                padding: 0px 5px;
            """)
            flow.addWidget(badge)

        flow.addStretch()
        left.addLayout(flow)
        body_layout.addLayout(left, stretch=3)

        # Middle block: attempts + failed + duration
        mid = QHBoxLayout()
        mid.setSpacing(20)

        def metric(val, lbl_text):
            col = QVBoxLayout()
            col.setSpacing(1)
            v = QLabel(str(val))
            v.setStyleSheet(f"""
                font-size: 17px;
                font-weight: 700;
                color: {TEXT_PRIMARY};
                background: transparent;
            """)
            l = QLabel(lbl_text.upper())
            l.setStyleSheet(f"""
                font-size: 9px;
                letter-spacing: 0.6px;
                color: {TEXT_MUTED};
                background: transparent;
            """)
            col.addWidget(v)
            col.addWidget(l)
            return col

        mid.addLayout(metric(finding.get("attempts", 0), "Attempts"))
        dur = finding.get("duration_seconds", 0)
        mid.addLayout(metric(f"{dur:.0f}s", "Duration"))
        mid.addLayout(metric(finding.get("failed_attempts", 0), "Failed"))
        body_layout.addLayout(mid, stretch=2)

        # Right block: timestamps + investigate button
        right = QVBoxLayout()
        right.setSpacing(3)
        right.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)

        def ts_line(prefix: str, raw) -> QLabel:
            ts = str(raw).replace("T", " ").split(".")[0]
            lbl = QLabel(f"{prefix}  {ts}")
            lbl.setStyleSheet(f"""
                color: {TEXT_MUTED};
                font-size: 10px;
                background: transparent;
            """)
            lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
            return lbl

        right.addWidget(ts_line("First", finding.get("first_seen", "—")))
        right.addWidget(ts_line("Last ", finding.get("last_seen",  "—")))
        right.addStretch()

        inv_btn = QPushButton("Investigate")
        inv_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {TEXT_SECONDARY};
                border: 1px solid {BORDER_DEFAULT};
                padding: 4px 12px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                color: {TEXT_PRIMARY};
                border-color: {TEXT_MUTED};
                background: {BG_OVERLAY};
            }}
        """)
        inv_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        inv_btn.clicked.connect(
            lambda: self.investigate_clicked.emit(self._finding_id)
        )
        right.addWidget(inv_btn)

        body_layout.addLayout(right, stretch=1)


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD VIEW
# ─────────────────────────────────────────────────────────────────────────────

class DashboardView(QWidget):
    """
    Main dashboard — security statistics, recent auth events,
    recent security alerts.

    Data is loaded on a background QThread every REFRESH_INTERVAL_MS.
    The GUI thread only renders; it never calls SQLite directly.
    """

    investigate_requested = Signal(int)

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path    = db_path
        self._loading   = False   # prevent overlapping loads
        self._last_data: dict | None = None

        self._build_ui()

        # Initial load
        self.refresh()

        # Periodic refresh
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(REFRESH_INTERVAL_MS)

    # ── UI construction ────────────────────────────────────────────────────

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

        self._cl = QVBoxLayout(content)
        self._cl.setContentsMargins(28, 24, 28, 28)
        self._cl.setSpacing(20)

        # ── Top bar: status + last-refresh ────────────────────
        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)

        self._db_status_lbl = QLabel("")
        self._db_status_lbl.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 11px; background: transparent;"
        )
        top_row.addWidget(self._db_status_lbl)
        top_row.addStretch()

        self._refresh_lbl = QLabel("")
        self._refresh_lbl.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 11px; background: transparent;"
        )
        top_row.addWidget(self._refresh_lbl)
        self._cl.addLayout(top_row)

        # ── Database error banner (hidden by default) ──────────
        self._db_error_banner = ErrorStateWidget(
            "Cannot connect to database. Check the database path in Settings."
        )
        self._db_error_banner.hide()
        self._cl.addWidget(self._db_error_banner)

        # ── Stat cards ─────────────────────────────────────────
        stat_row = QWidget()
        stat_row.setStyleSheet("background: transparent;")
        sr_layout = QHBoxLayout(stat_row)
        sr_layout.setContentsMargins(0, 0, 0, 0)
        sr_layout.setSpacing(8)

        self._card_total    = StatCard("Auth Events")
        self._card_success  = StatCard("Successful",    value_color=STATUS_SUCCESS_TEXT)
        self._card_failed   = StatCard("Failed",        value_color=STATUS_FAILED_TEXT)
        self._card_findings = StatCard("Findings")
        self._card_high     = StatCard("High Severity", value_color=SEVERITY_HIGH)
        self._card_critical = StatCard("Critical",      value_color=SEVERITY_CRITICAL)

        for card in [
            self._card_total, self._card_success, self._card_failed,
            self._card_findings, self._card_high, self._card_critical,
        ]:
            sr_layout.addWidget(card)

        self._cl.addWidget(stat_row)

        # ── Recent auth events ─────────────────────────────────
        self._events_header = SectionHeader("Recent Authentication Activity")
        self._cl.addWidget(self._events_header)

        self._events_table = self._build_events_table()
        self._cl.addWidget(self._events_table)

        self._events_empty = EmptyStateWidget(
            "No authentication events recorded.",
            f"Start Live Monitoring to capture {MONITOR_SOURCE_NAME} events.",
        )
        self._events_empty.hide()
        self._cl.addWidget(self._events_empty)

        self._events_error = ErrorStateWidget("Failed to load authentication events.")
        self._events_error.hide()
        self._cl.addWidget(self._events_error)

        # ── Recent security alerts ─────────────────────────────
        self._alerts_header = SectionHeader("Recent Security Alerts")
        self._cl.addWidget(self._alerts_header)

        self._alerts_container = QWidget()
        self._alerts_container.setStyleSheet("background: transparent;")
        self._alerts_layout = QVBoxLayout(self._alerts_container)
        self._alerts_layout.setContentsMargins(0, 0, 0, 0)
        self._alerts_layout.setSpacing(0)
        self._cl.addWidget(self._alerts_container)

        self._alerts_empty = EmptyStateWidget(
            "No security findings recorded.",
            "Findings appear here when the detection engine identifies threats.",
        )
        self._alerts_empty.hide()
        self._cl.addWidget(self._alerts_empty)

        self._alerts_error = ErrorStateWidget("Failed to load security findings.")
        self._alerts_error.hide()
        self._cl.addWidget(self._alerts_error)

        self._cl.addStretch()

    def _build_events_table(self) -> QTableWidget:
        headers = ["Time", "Status", "Username", "Source IP", "Service"]
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setSortingEnabled(False)

        # Limit visible height to ~10 rows
        table.setMaximumHeight(340)
        table.setMinimumHeight(0)

        hh = table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        return table

    # ── Background data loading ────────────────────────────────────────────

    def refresh(self):
        """
        Trigger a background data load.
        Silently skips if a load is already in progress.
        """
        if self._loading:
            return

        self._loading = True
        self._refresh_lbl.setText("Refreshing…")

        # Spin up a loader on a fresh thread
        self._load_thread = QThread(self)
        self._loader = DashboardDataLoader(self.db_path)
        self._loader.moveToThread(self._load_thread)

        self._load_thread.started.connect(self._loader.load)
        self._loader.data_ready.connect(self._on_data_ready)
        self._load_thread.finished.connect(self._load_thread.deleteLater)

        self._load_thread.start()

    @Slot(dict)
    def _on_data_ready(self, data: dict):
        """Receive loaded data on the main thread and update UI."""
        self._loading = False

        # Stop and clean up the thread
        self._load_thread.quit()
        self._load_thread.wait()

        self._last_data = data

        if not data.get("ok"):
            self._show_db_error(data.get("error", "Unknown error"))
            return

        self._db_error_banner.hide()
        self._db_status_lbl.setText(
            f"Database  ●  {data['total_events']} events  ·  "
            f"{data['total_findings']} findings"
        )
        self._refresh_lbl.setText(f"Updated {data['fetched_at']}")

        self._render_stats(data)
        self._render_events(data["recent_events"])
        self._render_alerts(data["recent_findings"])

    def _show_db_error(self, error: str):
        self._db_error_banner.show()
        self._db_status_lbl.setText("")
        self._refresh_lbl.setText(
            f"Last attempt {datetime.now().strftime('%H:%M:%S')}"
        )

        # Show error state on all sections
        self._events_table.hide()
        self._events_empty.hide()
        self._events_error.show()

        self._clear_alerts_layout()
        self._alerts_empty.hide()
        self._alerts_error.show()

    # ── Render helpers ─────────────────────────────────────────────────────

    def _render_stats(self, data: dict):
        total   = data["total_events"]
        success = data["success_count"]
        failed  = data["failed_count"]
        total_f = data["total_findings"]
        high_f  = data["high_findings"]
        crit_f  = data["critical_findings"]

        # Success rate sub-label
        if total > 0:
            rate = int(success / total * 100)
            self._card_success.set_value(str(success), f"{rate}% of events")
            fail_rate = int(failed / total * 100)
            self._card_failed.set_value(str(failed), f"{fail_rate}% of events")
        else:
            self._card_success.set_value(str(success))
            self._card_failed.set_value(str(failed))

        self._card_total.set_value(str(total))
        self._card_findings.set_value(
            str(total_f),
            f"{data['medium_findings']} medium" if data["medium_findings"] else "",
        )
        self._card_high.set_value(str(high_f))
        self._card_critical.set_value(str(crit_f))

    def _render_events(self, events: list[dict]):
        # Hide error state
        self._events_error.hide()

        if not events:
            self._events_table.hide()
            self._events_empty.show()
            self._events_header.set_meta("0 events")
            return

        self._events_empty.hide()
        self._events_table.show()
        self._events_header.set_meta(
            f"{len(events)} of last {RECENT_EVENT_LIMIT}"
        )

        # Populate table — suppress sorting signals while loading
        self._events_table.setSortingEnabled(False)
        self._events_table.setRowCount(len(events))

        for row, ev in enumerate(events):
            ts = str(ev.get("timestamp", ""))
            # Normalize ISO → readable local format
            ts = ts.replace("T", " ").split(".")[0]

            status  = ev.get("status", "")
            uname   = ev.get("username", "")
            src_ip  = ev.get("source_ip", "")
            service = ev.get("service", "")

            cells = [ts, status, uname, src_ip, service]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(str(val))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

                if col == 1:
                    # Status: colour-coded
                    item.setForeground(QColor(status_text_color(status)))
                    item.setFont(QFont(FONT_FAMILY, 11, QFont.Weight.Medium))
                elif col == 0:
                    # Timestamp: muted
                    item.setForeground(QColor(TEXT_MUTED))

                self._events_table.setItem(row, col, item)

        self._events_table.resizeRowsToContents()

    def _render_alerts(self, findings: list[dict]):
        self._clear_alerts_layout()
        self._alerts_error.hide()

        if not findings:
            self._alerts_empty.show()
            self._alerts_header.set_meta("0 findings")
            return

        self._alerts_empty.hide()
        self._alerts_header.set_meta(f"{len(findings)} recent")

        for finding in findings:
            card = AlertSummaryCard(finding)
            card.investigate_clicked.connect(self.investigate_requested)
            self._alerts_layout.addWidget(card)

    def _clear_alerts_layout(self):
        """Remove all child widgets from the alerts layout."""
        while self._alerts_layout.count():
            item = self._alerts_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
