"""
AegisLog Live Monitor View

Provides start/stop control for Windows Security Event Log monitoring.
Runs the monitoring loop inside a QThread worker.
The Qt GUI thread is never blocked.
"""

import sys
import time
import threading

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QFrame, QSizePolicy,
    QHeaderView, QScrollArea,
)
from PySide6.QtCore import Qt, QThread, QObject, Signal, Slot
from PySide6.QtGui import QColor, QFont

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_OVERLAY,
    BORDER_SUBTLE, BORDER_DEFAULT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    SEVERITY_HIGH, SEVERITY_CRITICAL, SEVERITY_MEDIUM,
    STATUS_ACTIVE, STATUS_IDLE,
    STATUS_SUCCESS_TEXT, STATUS_FAILED_TEXT,
    severity_color, status_text_color,
    FONT_FAMILY, FONT_MONO,
)

MAX_EVENT_ROWS = 500
POLL_INTERVAL  = 1.0   # seconds between Windows log polls


# ─────────────────────────────────────────────────────────────────────────────
# WORKER — runs on a QThread, never on the GUI thread
# ─────────────────────────────────────────────────────────────────────────────

class WindowsMonitorWorker(QObject):
    """
    Thin orchestration layer that wraps the existing Windows monitoring logic.

    Imports and calls:
        windows_monitor.get_latest_record_number()
        windows_monitor.get_new_events()
        windows_parser.parse_windows_event()
        live_detector.LiveDetector
        storage.SecurityStorage

    Emits normalized dicts to the GUI via Qt signals.
    All blocking work (win32evtlog, time.sleep) happens here.
    """

    event_detected   = Signal(dict)    # normalized AuthEvent as dict
    finding_detected = Signal(dict)    # ThreatFinding as dict
    monitor_error    = Signal(str)     # error message string
    status_message   = Signal(str)     # informational status string

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self._running = False

    @Slot()
    def run(self):
        """Main monitoring loop — called by QThread.started signal."""
        self._running = True

        try:
            from windows_monitor import get_latest_record_number, get_new_events
            from windows_parser import parse_windows_event
            from live_detector import LiveDetector
            from storage import SecurityStorage
        except ImportError as exc:
            self.monitor_error.emit(
                f"Import error: {exc}\n"
                "Ensure pywin32 is installed and this is running on Windows."
            )
            return
        except Exception as exc:
            self.monitor_error.emit(f"Startup error: {exc}")
            return

        # Initialise storage and detector
        try:
            storage  = SecurityStorage(self.db_path)
            detector = LiveDetector()
        except Exception as exc:
            self.monitor_error.emit(f"Storage/Detector init error: {exc}")
            return

        # Get current position in the event log
        try:
            last_record = get_latest_record_number()
        except Exception as exc:
            self.monitor_error.emit(
                f"Cannot read Windows Security log: {exc}\n"
                "Run AegisLog as Administrator to access Security events."
            )
            return

        SUCCESSFUL_LOGON = 4624
        FAILED_LOGON     = 4625

        self.status_message.emit(
            f"Monitoring started. Last record: {last_record}"
        )

        while self._running:
            try:
                new_events = get_new_events(last_record)
            except Exception as exc:
                self.monitor_error.emit(
                    f"Error reading Security log: {exc}"
                )
                time.sleep(POLL_INTERVAL)
                continue

            # Process oldest → newest
            new_events.sort(key=lambda e: e.RecordNumber)

            for raw_event in new_events:
                if not self._running:
                    break

                record_number = raw_event.RecordNumber
                last_record = max(last_record, record_number)

                event_id = raw_event.EventID & 0xFFFF
                if event_id not in (SUCCESSFUL_LOGON, FAILED_LOGON):
                    continue

                auth_event = parse_windows_event(raw_event)
                if auth_event is None:
                    continue

                # Persist
                try:
                    storage.save_auth_event(auth_event)
                except Exception:
                    pass

                # Emit to GUI (convert to dict for thread-safe transport)
                self.event_detected.emit({
                    "timestamp":   str(auth_event.timestamp),
                    "status":      auth_event.status,
                    "username":    auth_event.username,
                    "source_ip":   auth_event.source_ip,
                    "source_port": auth_event.source_port,
                    "service":     auth_event.service,
                    "event_id":    event_id,
                    "record":      record_number,
                })

                # Live detection
                try:
                    findings = detector.add_event(auth_event)
                except Exception:
                    findings = []

                for finding in findings:
                    try:
                        storage.save_finding(finding)
                    except Exception:
                        pass

                    self.finding_detected.emit({
                        "attack_type":         finding.attack_type,
                        "severity":            finding.severity,
                        "source_ip":           finding.source_ip,
                        "target_user":         finding.target_user,
                        "attempts":            finding.attempts,
                        "service":             finding.service,
                        "first_seen":          str(finding.first_seen),
                        "last_seen":           str(finding.last_seen),
                        "recommendation":      finding.recommendation,
                        "ip_classification":   finding.ip_classification,
                        "event_count":         finding.event_count,
                        "failed_attempts":     finding.failed_attempts,
                        "successful_attempts": finding.successful_attempts,
                        "duration_seconds":    finding.duration_seconds,
                    })

            time.sleep(POLL_INTERVAL)

        self.status_message.emit("Monitoring stopped.")

    def stop(self):
        """Signal the worker loop to exit cleanly."""
        self._running = False


# ─────────────────────────────────────────────────────────────────────────────
# LIVE EVENT ROW WIDGET (used inside alerts section)
# ─────────────────────────────────────────────────────────────────────────────

class LiveAlertBanner(QWidget):
    """Compact banner for a live security finding."""

    def __init__(self, finding: dict, parent=None):
        super().__init__(parent)
        severity = finding.get("severity", "LOW")
        self.setObjectName("LiveAlertBanner")
        self.setStyleSheet(f"""
            #LiveAlertBanner {{
                background-color: {BG_ELEVATED};
                border: 1px solid {BORDER_SUBTLE};
                border-left: 3px solid {severity_color(severity)};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(12)

        sev_lbl = QLabel(severity)
        sev_lbl.setStyleSheet(f"""
            color: {severity_color(severity)};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.8px;
            min-width: 60px;
            background: transparent;
        """)
        layout.addWidget(sev_lbl)

        attack_lbl = QLabel(finding.get("attack_type", "Unknown"))
        attack_lbl.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 12px;
            font-weight: 500;
            background: transparent;
        """)
        layout.addWidget(attack_lbl)

        layout.addStretch()

        detail_lbl = QLabel(
            f"{finding.get('source_ip', '—')} → {finding.get('target_user', '—')} "
            f"({finding.get('attempts', 0)} attempts)"
        )
        detail_lbl.setStyleSheet(f"""
            color: {TEXT_SECONDARY};
            font-size: 11px;
            background: transparent;
        """)
        layout.addWidget(detail_lbl)


# ─────────────────────────────────────────────────────────────────────────────
# MONITOR VIEW
# ─────────────────────────────────────────────────────────────────────────────

class MonitorView(QWidget):
    """Live Windows Security Event Log monitor page."""

    monitoring_started = Signal()
    monitoring_stopped = Signal()

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self._thread: QThread | None = None
        self._worker: WindowsMonitorWorker | None = None
        self._event_count = 0

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Control bar ────────────────────────────────────────
        ctrl_bar = QWidget()
        ctrl_bar.setFixedHeight(56)
        ctrl_bar.setObjectName("CtrlBar")
        ctrl_bar.setStyleSheet(f"""
            #CtrlBar {{
                background-color: {BG_SURFACE};
                border-bottom: 1px solid {BORDER_SUBTLE};
            }}
        """)
        ctrl_layout = QHBoxLayout(ctrl_bar)
        ctrl_layout.setContentsMargins(24, 0, 24, 0)
        ctrl_layout.setSpacing(10)

        self._status_dot = QLabel("●")
        self._status_dot.setStyleSheet(
            f"color: {STATUS_IDLE}; font-size: 12px; background: transparent;"
        )
        ctrl_layout.addWidget(self._status_dot)

        self._status_label = QLabel("Monitor Idle — Windows Security Log")
        self._status_label.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 12px; background: transparent;"
        )
        ctrl_layout.addWidget(self._status_label)

        ctrl_layout.addStretch()

        self._event_count_label = QLabel("")
        self._event_count_label.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 11px; background: transparent;"
        )
        ctrl_layout.addWidget(self._event_count_label)

        ctrl_layout.addSpacing(16)

        self._start_btn = QPushButton("Start Monitoring")
        self._start_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {BG_ELEVATED};
                color: {STATUS_ACTIVE};
                border: 1px solid {STATUS_ACTIVE};
                padding: 6px 16px;
                font-size: 12px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {STATUS_ACTIVE};
                color: #0A0A0B;
            }}
            QPushButton:disabled {{
                color: {TEXT_MUTED};
                border-color: {BORDER_SUBTLE};
                background-color: {BG_SURFACE};
            }}
        """)
        self._start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._start_btn.clicked.connect(self.start_monitoring)
        ctrl_layout.addWidget(self._start_btn)

        self._stop_btn = QPushButton("Stop Monitoring")
        self._stop_btn.setEnabled(False)
        self._stop_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {STATUS_FAILED_TEXT};
                border: 1px solid {STATUS_FAILED_TEXT};
                padding: 6px 16px;
                font-size: 12px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {STATUS_FAILED_TEXT};
                color: {TEXT_PRIMARY};
            }}
            QPushButton:disabled {{
                color: {TEXT_MUTED};
                border-color: {BORDER_SUBTLE};
            }}
        """)
        self._stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._stop_btn.clicked.connect(self.stop_monitoring)
        ctrl_layout.addWidget(self._stop_btn)

        layout.addWidget(ctrl_bar)

        # ── Main content split ─────────────────────────────────
        content = QWidget()
        content.setStyleSheet(f"background-color: {BG_BASE};")
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        layout.addWidget(content)

        # Left: event stream table
        left_panel = QWidget()
        left_panel.setStyleSheet(f"background-color: {BG_BASE};")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(24, 20, 12, 20)
        left_layout.setSpacing(12)

        event_hdr = self._section_label("Authentication Event Stream")
        left_layout.addWidget(event_hdr)

        self._events_table = self._build_events_table()
        left_layout.addWidget(self._events_table)

        self._events_empty = self._empty_state(
            "Waiting for authentication events…",
            "Start monitoring to capture Windows Security log events.",
        )
        self._events_empty.hide()
        left_layout.addWidget(self._events_empty)

        content_layout.addWidget(left_panel, stretch=3)

        # Vertical divider
        vline = QFrame()
        vline.setFrameShape(QFrame.Shape.VLine)
        vline.setStyleSheet(f"color: {BORDER_SUBTLE};")
        content_layout.addWidget(vline)

        # Right: live findings / alerts
        right_panel = QWidget()
        right_panel.setStyleSheet(f"background-color: {BG_BASE};")
        right_panel.setMinimumWidth(280)
        right_panel.setMaximumWidth(380)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(12, 20, 20, 20)
        right_layout.setSpacing(10)

        alerts_hdr = self._section_label("Live Security Alerts")
        right_layout.addWidget(alerts_hdr)

        self._alerts_scroll = QScrollArea()
        self._alerts_scroll.setWidgetResizable(True)
        self._alerts_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._alerts_scroll.setStyleSheet(f"background: transparent;")

        self._alerts_inner = QWidget()
        self._alerts_inner.setStyleSheet("background: transparent;")
        self._alerts_list_layout = QVBoxLayout(self._alerts_inner)
        self._alerts_list_layout.setContentsMargins(0, 0, 0, 0)
        self._alerts_list_layout.setSpacing(6)
        self._alerts_list_layout.addStretch()

        self._alerts_scroll.setWidget(self._alerts_inner)
        right_layout.addWidget(self._alerts_scroll)

        self._no_alerts_label = QLabel("No live alerts yet.")
        self._no_alerts_label.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 12px; background: transparent;"
        )
        self._no_alerts_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_layout.addWidget(self._no_alerts_label)

        content_layout.addWidget(right_panel, stretch=1)

        # ── Error / status message bar ─────────────────────────
        self._msg_bar = QLabel("")
        self._msg_bar.setStyleSheet(f"""
            background-color: {BG_ELEVATED};
            color: {TEXT_SECONDARY};
            font-size: 11px;
            padding: 6px 24px;
            border-top: 1px solid {BORDER_SUBTLE};
        """)
        self._msg_bar.hide()
        layout.addWidget(self._msg_bar)

    def _section_label(self, text: str) -> QLabel:
        lbl = QLabel(text.upper())
        lbl.setStyleSheet(f"""
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 1.4px;
            color: {TEXT_MUTED};
            background: transparent;
            border-bottom: 1px solid {BORDER_SUBTLE};
            padding-bottom: 8px;
        """)
        return lbl

    def _build_events_table(self) -> QTableWidget:
        headers = ["Time", "Rec#", "Event ID", "Status", "Username", "Source IP", "Service"]
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)

        hh = table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        return table

    def _empty_state(self, message: str, hint: str) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        msg = QLabel(message)
        msg.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 13px; background: transparent;")
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(msg)

        if hint:
            h = QLabel(hint)
            h.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px; background: transparent;")
            h.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(h)

        return w

    # ── Monitoring control ─────────────────────────────────────────────────

    @Slot()
    def start_monitoring(self):
        if self._thread and self._thread.isRunning():
            return

        self._thread = QThread(self)
        self._worker = WindowsMonitorWorker(self.db_path)
        self._worker.moveToThread(self._thread)

        # Wire signals
        self._thread.started.connect(self._worker.run)
        self._worker.event_detected.connect(self._on_event)
        self._worker.finding_detected.connect(self._on_finding)
        self._worker.monitor_error.connect(self._on_error)
        self._worker.status_message.connect(self._on_status)
        self._thread.finished.connect(self._on_thread_finished)

        self._thread.start()

        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._set_status_active(True)
        self.monitoring_started.emit()

    @Slot()
    def stop_monitoring(self):
        if self._worker:
            self._worker.stop()
        if self._thread:
            self._thread.quit()
            self._thread.wait(3000)

        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._set_status_active(False)
        self.monitoring_stopped.emit()

    def _set_status_active(self, active: bool):
        if active:
            self._status_dot.setStyleSheet(
                f"color: {STATUS_ACTIVE}; font-size: 12px; background: transparent;"
            )
            self._status_label.setStyleSheet(
                f"color: {STATUS_ACTIVE}; font-size: 12px; font-weight: 500; background: transparent;"
            )
            self._status_label.setText("Monitoring Active — Windows Security Log")
        else:
            self._status_dot.setStyleSheet(
                f"color: {STATUS_IDLE}; font-size: 12px; background: transparent;"
            )
            self._status_label.setStyleSheet(
                f"color: {TEXT_SECONDARY}; font-size: 12px; background: transparent;"
            )
            self._status_label.setText("Monitor Idle — Windows Security Log")

    # ── Slots receiving worker signals (always on main thread) ─────────────

    @Slot(dict)
    def _on_event(self, ev: dict):
        self._event_count += 1
        self._event_count_label.setText(
            f"{self._event_count} event{'s' if self._event_count != 1 else ''} captured"
        )

        # Trim table if too large
        if self._events_table.rowCount() >= MAX_EVENT_ROWS:
            self._events_table.removeRow(0)

        row = self._events_table.rowCount()
        self._events_table.insertRow(row)

        ts = ev.get("timestamp", "")
        if "T" in ts:
            ts = ts.replace("T", " ").split(".")[0]

        status = ev.get("status", "")
        cells = [
            ts,
            str(ev.get("record", "")),
            str(ev.get("event_id", "")),
            status,
            ev.get("username", ""),
            ev.get("source_ip", ""),
            ev.get("service", ""),
        ]
        for col, val in enumerate(cells):
            item = QTableWidgetItem(val)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            if col == 3:  # Status
                item.setForeground(QColor(status_text_color(status)))
                item.setFont(QFont(FONT_FAMILY, 11, QFont.Weight.Medium))
            self._events_table.setItem(row, col, item)

        self._events_table.scrollToBottom()

        if self._events_empty.isVisible():
            self._events_empty.hide()

    @Slot(dict)
    def _on_finding(self, finding: dict):
        # Add banner to alerts panel (insert before stretch)
        banner = LiveAlertBanner(finding)
        count = self._alerts_list_layout.count()
        self._alerts_list_layout.insertWidget(count - 1, banner)
        self._no_alerts_label.hide()

    @Slot(str)
    def _on_error(self, message: str):
        self._msg_bar.setText(f"⚠  {message}")
        self._msg_bar.setStyleSheet(f"""
            background-color: {BG_ELEVATED};
            color: {SEVERITY_HIGH};
            font-size: 11px;
            padding: 6px 24px;
            border-top: 1px solid {BORDER_SUBTLE};
        """)
        self._msg_bar.show()
        # If monitoring failed to start, reset buttons
        self.stop_monitoring()

    @Slot(str)
    def _on_status(self, message: str):
        self._msg_bar.setText(message)
        self._msg_bar.setStyleSheet(f"""
            background-color: {BG_ELEVATED};
            color: {TEXT_SECONDARY};
            font-size: 11px;
            padding: 6px 24px;
            border-top: 1px solid {BORDER_SUBTLE};
        """)
        self._msg_bar.show()

    @Slot()
    def _on_thread_finished(self):
        self._thread = None
        self._worker = None

    def refresh(self):
        """Called when user navigates to this page — no-op (stream is live)."""
        pass
