"""
AegisLog Investigation View  —  Phase 6 Redesign

Professional incident investigation workspace.
Workflow:
  - Select finding on left (loads async)
  - View full incident context, timeline, summary, and recommendation on right
"""

from __future__ import annotations
from datetime import datetime

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget,
    QListWidgetItem, QTableWidget, QTableWidgetItem, QFrame,
    QScrollArea, QSplitter, QPushButton, QHeaderView, QDialog
)
from PySide6.QtCore import Qt, Signal, QThread, QObject, Slot, QTimer
from PySide6.QtGui import QColor, QFont

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_OVERLAY,
    BORDER_SUBTLE, BORDER_DEFAULT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
    STATUS_SUCCESS_TEXT, STATUS_FAILED_TEXT,
    severity_color, status_text_color,
    FONT_FAMILY, FONT_MONO, ACCENT
)

REFRESH_INTERVAL_MS = 10_000


# ─────────────────────────────────────────────────────────────────────────────
# DATA LOADERS (Background QThread)
# ─────────────────────────────────────────────────────────────────────────────

class InvestigationFindingsLoader(QObject):
    data_ready = Signal(dict)

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path

    @Slot()
    def load(self):
        try:
            from storage import SecurityStorage
            storage = SecurityStorage(self.db_path)
            findings = storage.get_findings()
            # Sort newest first, tie-break by ID
            findings.sort(key=lambda f: (str(f.get("last_seen", "")), f.get("id", -1)), reverse=True)
            self.data_ready.emit({"ok": True, "findings": findings})
        except Exception as exc:
            self.data_ready.emit({"ok": False, "error": str(exc)})


class TimelineDataLoader(QObject):
    data_ready = Signal(dict)

    def __init__(self, db_path: str, finding: dict, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self.finding = finding

    @Slot()
    def load(self):
        try:
            from storage import SecurityStorage
            storage = SecurityStorage(self.db_path)
            
            # Fetch events between first and last seen
            first_seen = datetime.fromisoformat(str(self.finding["first_seen"]))
            last_seen  = datetime.fromisoformat(str(self.finding["last_seen"]))
            events = storage.get_auth_events_between(first_seen, last_seen)
            
            # Correlate
            related_events = [
                e for e in events
                if e["source_ip"] == self.finding["source_ip"]
                and e["username"] == self.finding["target_user"]
            ]
            
            # Chronological order
            related_events.sort(key=lambda e: str(e.get("timestamp", "")))
            
            self.data_ready.emit({"ok": True, "events": related_events})
        except Exception as exc:
            self.data_ready.emit({"ok": False, "error": str(exc)})


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_ts(raw) -> str:
    """Normalize an ISO timestamp to a readable string."""
    s = str(raw).replace("T", " ").split(".")[0]
    return s


def _detail_block(label: str, value: str) -> QWidget:
    """Compact label + value block for the overview grid."""
    w = QWidget()
    w.setStyleSheet("background: transparent;")
    layout = QVBoxLayout(w)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(2)

    lbl = QLabel(label.upper())
    lbl.setStyleSheet(f"font-size: 9px; font-weight: 600; letter-spacing: 0.8px; color: {TEXT_MUTED};")
    val = QLabel(str(value))
    val.setStyleSheet(f"font-size: 13px; font-weight: 500; color: {TEXT_PRIMARY};")
    
    layout.addWidget(lbl)
    layout.addWidget(val)
    return w


def _section_header(title: str) -> QWidget:
    """Uppercase section label with a thin separator."""
    w = QWidget()
    w.setStyleSheet("background: transparent;")
    layout = QVBoxLayout(w)
    layout.setContentsMargins(0, 24, 0, 12)
    layout.setSpacing(6)

    lbl = QLabel(title.upper())
    lbl.setStyleSheet(f"font-size: 11px; font-weight: 600; letter-spacing: 1.5px; color: {TEXT_PRIMARY};")
    layout.addWidget(lbl)

    sep = QFrame()
    sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet(f"color: {BORDER_SUBTLE};")
    sep.setFixedHeight(1)
    layout.addWidget(sep)
    return w


# ─────────────────────────────────────────────────────────────────────────────
# EVENT DETAILS DIALOG
# ─────────────────────────────────────────────────────────────────────────────

class EventDetailsDialog(QDialog):
    """Shows raw/complete details of a selected timeline event."""
    def __init__(self, event: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Event Details")
        self.setMinimumWidth(500)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {BG_SURFACE}; border: 1px solid {BORDER_SUBTLE}; }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        hdr = QLabel("Event Details")
        hdr.setStyleSheet(f"font-size: 14px; font-weight: 600; color: {TEXT_PRIMARY};")
        layout.addWidget(hdr)

        grid = QWidget()
        grid_layout = QVBoxLayout(grid)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        grid_layout.setSpacing(12)

        fields = [
            ("Timestamp", _fmt_ts(event.get("timestamp", ""))),
            ("Status", event.get("status", "")),
            ("Username", event.get("username", "")),
            ("Source IP", event.get("source_ip", "")),
            ("Source Port", str(event.get("source_port", ""))),
            ("Hostname", event.get("hostname", "")),
            ("Service", event.get("service", "")),
            ("PID", str(event.get("pid", ""))),
            ("Protocol", event.get("protocol", "")),
            ("Invalid User", str(event.get("invalid_user", ""))),
        ]

        for label, value in fields:
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(100)
            lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
            val = QLabel(value)
            val.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 12px; font-weight: 500;")
            
            # Coloring status
            if label == "Status":
                val.setStyleSheet(f"color: {status_text_color(value)}; font-size: 12px; font-weight: 600;")
            
            row.addWidget(lbl)
            row.addWidget(val, stretch=1)
            grid_layout.addLayout(row)

        layout.addWidget(grid)

        # Raw log
        raw_lbl = QLabel("Raw Log")
        raw_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
        layout.addWidget(raw_lbl)

        raw_val = QLabel(event.get("raw_log", ""))
        raw_val.setWordWrap(True)
        raw_val.setStyleSheet(f"""
            color: {TEXT_SECONDARY};
            font-size: 11px;
            font-family: {FONT_MONO};
            background-color: {BG_BASE};
            border: 1px solid {BORDER_SUBTLE};
            padding: 8px;
        """)
        layout.addWidget(raw_val)

        btn = QPushButton("Close")
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {BG_ELEVATED};
                color: {TEXT_PRIMARY};
                border: 1px solid {BORDER_DEFAULT};
                padding: 6px 12px;
                font-size: 11px;
            }}
            QPushButton:hover {{ background-color: {BG_OVERLAY}; }}
        """)
        btn.clicked.connect(self.accept)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(btn)
        layout.addLayout(btn_layout)


# ─────────────────────────────────────────────────────────────────────────────
# INVESTIGATION VIEW
# ─────────────────────────────────────────────────────────────────────────────

class InvestigationView(QWidget):
    """
    Professional incident investigation workspace.
    Loads data via background threads to preserve responsiveness.
    """

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self._findings: list[dict] = []
        self._selected_finding_id: int | None = None
        self._selected_finding: dict | None = None
        
        self._load_thread: QThread | None = None
        self._tl_load_thread: QThread | None = None
        
        self._build_ui()
        self.refresh()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(REFRESH_INTERVAL_MS)

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {BORDER_SUBTLE};
                width: 1px;
            }}
        """)
        layout.addWidget(splitter)

        # ── Left: findings list ────────────────────────────────
        left = QWidget()
        left.setMinimumWidth(280)
        left.setMaximumWidth(400)
        left.setStyleSheet(f"background-color: {BG_SURFACE};")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        list_header = QWidget()
        list_header.setFixedHeight(44)
        list_header.setStyleSheet(f"""
            background-color: {BG_SURFACE};
            border-bottom: 1px solid {BORDER_SUBTLE};
        """)
        lh_layout = QHBoxLayout(list_header)
        lh_layout.setContentsMargins(16, 0, 16, 0)
        
        lbl = QLabel("FINDINGS")
        lbl.setStyleSheet(f"""
            font-size: 9px; font-weight: 600; letter-spacing: 1.4px;
            color: {TEXT_MUTED}; background: transparent;
        """)
        lh_layout.addWidget(lbl)
        lh_layout.addStretch()
        
        self._list_count = QLabel("")
        self._list_count.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px; background: transparent;")
        lh_layout.addWidget(self._list_count)
        left_layout.addWidget(list_header)

        self._findings_list = QListWidget()
        self._findings_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {BG_SURFACE};
                border: none;
                outline: none;
            }}
            QListWidget::item {{
                padding: 12px 16px;
                border-bottom: 1px solid {BORDER_SUBTLE};
                color: {TEXT_SECONDARY};
            }}
            QListWidget::item:selected {{
                background-color: {BG_OVERLAY};
                color: {TEXT_PRIMARY};
                border-left: 3px solid {ACCENT};
            }}
            QListWidget::item:hover:!selected {{
                background-color: {BG_ELEVATED};
                color: {TEXT_PRIMARY};
            }}
        """)
        self._findings_list.currentRowChanged.connect(self._on_list_row_changed)
        left_layout.addWidget(self._findings_list)

        self._list_empty = QLabel("No findings recorded.")
        self._list_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._list_empty.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px; background: {BG_SURFACE}; padding: 20px;")
        self._list_empty.hide()
        left_layout.addWidget(self._list_empty)

        splitter.addWidget(left)

        # ── Right: workspace pane ──────────────────────────────
        right = QWidget()
        right.setStyleSheet(f"background-color: {BG_BASE};")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self._ws_scroll = QScrollArea()
        self._ws_scroll.setWidgetResizable(True)
        self._ws_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._ws_scroll.setStyleSheet(f"background-color: {BG_BASE};")

        self._ws_content = QWidget()
        self._ws_content.setStyleSheet(f"background-color: {BG_BASE};")
        self._ws_layout = QVBoxLayout(self._ws_content)
        self._ws_layout.setContentsMargins(40, 30, 40, 40)
        self._ws_layout.setSpacing(0)

        self._ws_scroll.setWidget(self._ws_content)
        right_layout.addWidget(self._ws_scroll)

        splitter.addWidget(right)
        splitter.setSizes([320, 1000])

        self._show_placeholder("Select a finding to begin investigation.")

    def _show_placeholder(self, msg: str):
        self._clear_workspace()
        placeholder = QLabel(msg)
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 13px; background: transparent;")
        self._ws_layout.addStretch()
        self._ws_layout.addWidget(placeholder)
        self._ws_layout.addStretch()

    def _clear_workspace(self):
        while self._ws_layout.count():
            item = self._ws_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    # ── Background Data Loading ────────────────────────────────────────────

    def refresh(self):
        try:
            if self._load_thread and self._load_thread.isRunning():
                return
        except RuntimeError:
            self._load_thread = None
        
        self._load_thread = QThread(self)
        self._loader = InvestigationFindingsLoader(self.db_path)
        self._loader.moveToThread(self._load_thread)
        
        self._load_thread.started.connect(self._loader.load)
        self._loader.data_ready.connect(self._on_findings_loaded)
        self._load_thread.start()

    @Slot(dict)
    def _on_findings_loaded(self, data: dict):
        if self._load_thread:
            self._load_thread.quit()
            self._load_thread.wait()
            self._load_thread.deleteLater()
            self._load_thread = None
            
        if hasattr(self, "_loader") and self._loader:
            self._loader.deleteLater()
            self._loader = None

        if not data.get("ok"):
            self._list_empty.setText("Database error.")
            self._list_empty.show()
            self._findings_list.hide()
            return

        self._findings = data.get("findings", [])
        self._update_list_ui()

    def _update_list_ui(self):
        # Update without breaking selection
        self._list_count.setText(str(len(self._findings)))
        
        if not self._findings:
            self._findings_list.hide()
            self._list_empty.show()
            self._show_placeholder("No security findings currently stored.")
            self._selected_finding_id = None
            self._selected_finding = None
            return

        self._findings_list.show()
        self._list_empty.hide()

        # Rebuild list keeping selection
        self._findings_list.blockSignals(True)
        self._findings_list.clear()

        selected_idx = -1
        for i, f in enumerate(self._findings):
            f_id = f.get("id", -1)
            severity = f.get("severity", "LOW")
            attack = f.get("attack_type", "Unknown")
            target = f.get("target_user", "—")
            display = f"[{severity}] {attack}\n{target}"
            
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, f_id)
            item.setForeground(QColor(severity_color(severity)))
            self._findings_list.addItem(item)
            
            if self._selected_finding_id == f_id:
                selected_idx = i

        if selected_idx != -1:
            self._findings_list.setCurrentRow(selected_idx)
            # Update workspace if details changed
            if self._selected_finding != self._findings[selected_idx]:
                self._selected_finding = self._findings[selected_idx]
                self._render_workspace()
        else:
            # Finding was deleted, or no selection
            if self._selected_finding_id is not None:
                self._show_placeholder("The selected finding is no longer available.")
            self._selected_finding_id = None
            self._selected_finding = None

        self._findings_list.blockSignals(False)

    def load_finding(self, finding_id: int):
        """Called externally to jump to a specific finding."""
        self._selected_finding_id = finding_id
        self.refresh()  # Force load, which will select it. Wait, async!
        # If we already have findings, we can select it immediately.
        for i, f in enumerate(self._findings):
            if f.get("id") == finding_id:
                self._findings_list.setCurrentRow(i)
                return

    # ── Selection & Rendering ──────────────────────────────────────────────

    def _on_list_row_changed(self, row: int):
        if row < 0 or row >= len(self._findings):
            return
        finding = self._findings[row]
        self._selected_finding_id = finding.get("id", -1)
        self._selected_finding = finding
        self._render_workspace()

    def _render_workspace(self):
        self._clear_workspace()
        f = self._selected_finding
        if not f:
            return

        severity = f.get("severity", "LOW")
        sev_color = severity_color(severity)

        # ── 1. Finding Header ──────────────────────────────────
        hdr = QWidget()
        hdr.setStyleSheet("background: transparent;")
        hdr_layout = QVBoxLayout(hdr)
        hdr_layout.setContentsMargins(0, 0, 0, 24)
        hdr_layout.setSpacing(4)

        top_row = QHBoxLayout()
        id_lbl = QLabel(f"FINDING #{f.get('id', '—')}")
        id_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px; font-weight: 600; letter-spacing: 1px;")
        top_row.addWidget(id_lbl)
        top_row.addStretch()
        hdr_layout.addLayout(top_row)

        attack_lbl = QLabel(f.get("attack_type", "Unknown"))
        attack_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 24px; font-weight: 600; letter-spacing: -0.5px;")
        hdr_layout.addWidget(attack_lbl)
        
        sev_lbl = QLabel(severity)
        sev_lbl.setStyleSheet(f"color: {sev_color}; font-size: 11px; font-weight: 700; letter-spacing: 1px;")
        hdr_layout.addWidget(sev_lbl)

        self._ws_layout.addWidget(hdr)

        # ── 2. Source → Target ─────────────────────────────────
        flow = QWidget()
        flow.setStyleSheet(f"background-color: transparent;")
        flow_layout = QHBoxLayout(flow)
        flow_layout.setContentsMargins(0, 0, 0, 0)
        flow_layout.setSpacing(40)

        # Source
        src_box = QVBoxLayout()
        src_lbl = QLabel("SOURCE")
        src_lbl.setStyleSheet(f"font-size: 9px; font-weight: 600; color: {TEXT_MUTED}; letter-spacing: 1px;")
        src_val = QLabel(f.get("source_ip", "—"))
        src_val.setStyleSheet(f"font-size: 15px; font-weight: 500; color: {TEXT_PRIMARY};")
        src_class = QLabel(f.get("ip_classification", ""))
        src_class.setStyleSheet(f"font-size: 10px; color: {TEXT_SECONDARY};")
        src_box.addWidget(src_lbl)
        src_box.addWidget(src_val)
        if src_class.text() and src_class.text().lower() not in ("—", "unknown"):
            src_box.addWidget(src_class)
        flow_layout.addLayout(src_box)

        # Arrow
        arrow = QLabel("─────→")
        arrow.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 14px;")
        arrow.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        flow_layout.addWidget(arrow)

        # Target
        tgt_box = QVBoxLayout()
        tgt_lbl = QLabel("TARGET")
        tgt_lbl.setStyleSheet(f"font-size: 9px; font-weight: 600; color: {TEXT_MUTED}; letter-spacing: 1px;")
        tgt_val = QLabel(f.get("target_user", "—"))
        tgt_val.setStyleSheet(f"font-size: 15px; font-weight: 500; color: {TEXT_PRIMARY};")
        tgt_svc = QLabel(f.get("service", ""))
        tgt_svc.setStyleSheet(f"font-size: 10px; color: {TEXT_SECONDARY};")
        tgt_box.addWidget(tgt_lbl)
        tgt_box.addWidget(tgt_val)
        if tgt_svc.text() and tgt_svc.text().lower() not in ("—", "unknown"):
            tgt_box.addWidget(tgt_svc)
        flow_layout.addLayout(tgt_box)
        flow_layout.addStretch()

        self._ws_layout.addWidget(flow)

        # ── 3. Incident Overview Grid ──────────────────────────
        self._ws_layout.addWidget(_section_header("Incident Overview"))
        
        grid = QWidget()
        grid.setStyleSheet("background: transparent;")
        grid_layout = QHBoxLayout(grid)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        grid_layout.setSpacing(30)

        dur = f.get("duration_seconds", 0)
        dur_str = f"{dur:.0f}s" if dur < 3600 else f"{dur/3600:.1f}h"

        grid_layout.addWidget(_detail_block("Attempts", f.get("attempts", 0)))
        grid_layout.addWidget(_detail_block("Event Count", f.get("event_count", 0)))
        grid_layout.addWidget(_detail_block("Failed", f.get("failed_attempts", 0)))
        grid_layout.addWidget(_detail_block("Successful", f.get("successful_attempts", 0)))
        grid_layout.addWidget(_detail_block("Duration", dur_str))
        grid_layout.addStretch()
        self._ws_layout.addWidget(grid)

        # Timestamps line
        ts_row = QWidget()
        ts_row.setStyleSheet("background: transparent;")
        ts_layout = QHBoxLayout(ts_row)
        ts_layout.setContentsMargins(0, 16, 0, 0)
        ts_layout.setSpacing(20)
        
        ts_layout.addWidget(_detail_block("First Seen", _fmt_ts(f.get("first_seen", "—"))))
        ts_layout.addWidget(_detail_block("Last Seen", _fmt_ts(f.get("last_seen", "—"))))
        ts_layout.addStretch()
        self._ws_layout.addWidget(ts_row)

        # ── 4. Incident Timeline (Async Load) ──────────────────
        self._ws_layout.addWidget(_section_header("Correlated Event Timeline"))
        
        self._timeline_container = QWidget()
        self._timeline_container.setStyleSheet("background: transparent;")
        self._tl_layout = QVBoxLayout(self._timeline_container)
        self._tl_layout.setContentsMargins(0, 0, 0, 0)
        
        loading_lbl = QLabel("Loading timeline...")
        loading_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
        self._tl_layout.addWidget(loading_lbl)
        
        self._ws_layout.addWidget(self._timeline_container)

        self._load_timeline(f)

        # ── 5. Investigation Summary & Recommendation ──────────
        self._ws_layout.addWidget(_section_header("Investigation Summary"))
        
        events_n = f.get("event_count", 0)
        failed_n = f.get("failed_attempts", 0)
        success_n = f.get("successful_attempts", 0)
        summary_text = (
            f"The backend correlated {events_n} events over {dur_str} matching this source and target. "
            f"Of these, {failed_n} were failed attempts and {success_n} were successful."
        )
        
        summ_lbl = QLabel(summary_text)
        summ_lbl.setWordWrap(True)
        summ_lbl.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; line-height: 1.5;")
        self._ws_layout.addWidget(summ_lbl)

        self._ws_layout.addWidget(_section_header("Analyst Recommendation"))
        
        rec_box = QWidget()
        rec_box.setStyleSheet(f"""
            background-color: {BG_SURFACE};
            border: 1px solid {BORDER_SUBTLE};
            border-left: 3px solid {sev_color};
        """)
        rec_layout = QVBoxLayout(rec_box)
        rec_layout.setContentsMargins(20, 16, 20, 16)
        
        rec_lbl = QLabel(f.get("recommendation", "No recommendation available."))
        rec_lbl.setWordWrap(True)
        rec_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 13px; font-weight: 500; line-height: 1.6;")
        rec_layout.addWidget(rec_lbl)
        self._ws_layout.addWidget(rec_box)

        self._ws_layout.addStretch()

    # ── Timeline Loading ───────────────────────────────────────────────────

    def _load_timeline(self, finding: dict):
        try:
            if self._tl_load_thread and self._tl_load_thread.isRunning():
                self._tl_load_thread.quit()
                self._tl_load_thread.wait()
                self._tl_load_thread.deleteLater()
                self._tl_load_thread = None
        except RuntimeError:
            self._tl_load_thread = None

        self._tl_load_thread = QThread(self)
        self._tl_loader = TimelineDataLoader(self.db_path, finding)
        self._tl_loader.moveToThread(self._tl_load_thread)

        self._tl_load_thread.started.connect(self._tl_loader.load)
        self._tl_loader.data_ready.connect(self._on_timeline_loaded)
        self._tl_load_thread.start()

    @Slot(dict)
    def _on_timeline_loaded(self, data: dict):
        if self._tl_load_thread:
            self._tl_load_thread.quit()
            self._tl_load_thread.wait()
            self._tl_load_thread.deleteLater()
            self._tl_load_thread = None
            
        if hasattr(self, "_tl_loader") and self._tl_loader:
            self._tl_loader.deleteLater()
            self._tl_loader = None

        # Clear loading label
        while self._tl_layout.count():
            item = self._tl_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not data.get("ok"):
            err = QLabel("NO CORRELATED EVENTS")
            err.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
            self._tl_layout.addWidget(err)
            return

        events = data.get("events", [])
        if not events:
            empty = QLabel("NO CORRELATED EVENTS\n\nThe finding exists, but no matching authentication events are currently available for this investigation window.")
            empty.setWordWrap(True)
            empty.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px; line-height: 1.5;")
            self._tl_layout.addWidget(empty)
            return

        headers = ["Time", "Status", "Username", "Source IP", "Service"]
        table = QTableWidget(len(events), len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)

        hh = table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        # Keep a reference to raw events for dialog
        self._current_timeline_events = events

        for row, ev in enumerate(events):
            status = ev.get("status", "")
            cells = [
                _fmt_ts(ev.get("timestamp", "")),
                status,
                ev.get("username", ""),
                ev.get("source_ip", ""),
                ev.get("service", ""),
            ]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(str(val))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 1:
                    item.setForeground(QColor(status_text_color(status)))
                    item.setFont(QFont(FONT_FAMILY, 11, QFont.Weight.Medium))
                table.setItem(row, col, item)

        table.resizeRowsToContents()
        table.setMaximumHeight(min(40 + len(events) * 30, 400))
        table.cellDoubleClicked.connect(self._on_event_double_clicked)
        
        # Also support single click if desired, but double click or enter is standard for detail
        self._tl_layout.addWidget(table)
        
        hint = QLabel("Double-click an event to view full details and raw log.")
        hint.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px; margin-top: 4px;")
        self._tl_layout.addWidget(hint)

    def _on_event_double_clicked(self, row: int, col: int):
        if not hasattr(self, "_current_timeline_events"):
            return
        if row < 0 or row >= len(self._current_timeline_events):
            return
        
        event = self._current_timeline_events[row]
        dlg = EventDetailsDialog(event, self)
        dlg.exec()
