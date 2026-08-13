"""
AegisLog Investigation View

Displays stored findings in a list and allows deep-diving into
individual incidents, including the correlated event timeline.
Reuses SecurityStorage queries exactly as InvestigationConsole does.
"""

from datetime import datetime

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget,
    QListWidgetItem, QTableWidget, QTableWidgetItem, QFrame,
    QScrollArea, QSplitter, QSizePolicy, QHeaderView,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_OVERLAY,
    BORDER_SUBTLE, BORDER_DEFAULT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    SEVERITY_HIGH, SEVERITY_CRITICAL, SEVERITY_MEDIUM,
    STATUS_SUCCESS_TEXT, STATUS_FAILED_TEXT,
    severity_color, status_text_color,
    FONT_FAMILY, FONT_MONO,
)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def fmt_ts(raw) -> str:
    """Format an ISO timestamp string for display."""
    s = str(raw)
    return s.replace("T", " ").split(".")[0]


def detail_row(label: str, value: str, value_color: str = TEXT_PRIMARY) -> QWidget:
    """A label + value pair for the finding detail pane."""
    w = QWidget()
    w.setStyleSheet("background: transparent;")
    layout = QHBoxLayout(w)
    layout.setContentsMargins(0, 3, 0, 3)
    layout.setSpacing(0)

    lbl = QLabel(label)
    lbl.setFixedWidth(140)
    lbl.setStyleSheet(f"""
        color: {TEXT_MUTED};
        font-size: 11px;
        letter-spacing: 0.3px;
        background: transparent;
    """)

    val = QLabel(value)
    val.setWordWrap(True)
    val.setStyleSheet(f"""
        color: {value_color};
        font-size: 12px;
        font-weight: 500;
        background: transparent;
    """)

    layout.addWidget(lbl)
    layout.addWidget(val, stretch=1)
    return w


def section_sep(title: str) -> QWidget:
    """A labeled section separator."""
    w = QWidget()
    w.setStyleSheet("background: transparent;")
    layout = QVBoxLayout(w)
    layout.setContentsMargins(0, 16, 0, 8)
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
# INVESTIGATION VIEW
# ─────────────────────────────────────────────────────────────────────────────

class InvestigationView(QWidget):
    """
    Investigation page.

    Left: scrollable list of findings.
    Right: finding detail + correlated incident timeline.
    """

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self._storage = None
        self._findings: list[dict] = []
        self._selected_finding: dict | None = None

        self._init_storage()
        self._build_ui()
        self.refresh()

    def _init_storage(self):
        try:
            from storage import SecurityStorage
            self._storage = SecurityStorage(self.db_path)
        except Exception:
            self._storage = None

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
        left.setMinimumWidth(270)
        left.setMaximumWidth(380)
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
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 1.4px;
            color: {TEXT_MUTED};
            background: transparent;
        """)
        lh_layout.addWidget(lbl)
        lh_layout.addStretch()
        self._list_count = QLabel("")
        self._list_count.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 10px; background: transparent;"
        )
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
                padding: 10px 16px;
                border-bottom: 1px solid {BORDER_SUBTLE};
                color: {TEXT_SECONDARY};
            }}
            QListWidget::item:selected {{
                background-color: {BG_OVERLAY};
                color: {TEXT_PRIMARY};
                border-left: 3px solid {TEXT_MUTED};
            }}
            QListWidget::item:hover:!selected {{
                background-color: {BG_ELEVATED};
                color: {TEXT_PRIMARY};
            }}
        """)
        self._findings_list.currentRowChanged.connect(self._on_finding_selected)
        left_layout.addWidget(self._findings_list)

        self._list_empty = QLabel("No findings recorded.")
        self._list_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._list_empty.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 12px; background: {BG_SURFACE}; padding: 20px;"
        )
        self._list_empty.hide()
        left_layout.addWidget(self._list_empty)

        splitter.addWidget(left)

        # ── Right: detail pane ─────────────────────────────────
        right = QWidget()
        right.setStyleSheet(f"background-color: {BG_BASE};")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self._detail_scroll = QScrollArea()
        self._detail_scroll.setWidgetResizable(True)
        self._detail_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._detail_scroll.setStyleSheet(f"background-color: {BG_BASE};")

        self._detail_content = QWidget()
        self._detail_content.setStyleSheet(f"background-color: {BG_BASE};")
        self._detail_layout = QVBoxLayout(self._detail_content)
        self._detail_layout.setContentsMargins(28, 24, 28, 28)
        self._detail_layout.setSpacing(4)

        self._detail_scroll.setWidget(self._detail_content)
        right_layout.addWidget(self._detail_scroll)

        splitter.addWidget(right)
        splitter.setSizes([300, 900])

        self._show_placeholder()

    def _show_placeholder(self):
        self._clear_detail()
        placeholder = QLabel("Select a finding to begin investigation.")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 13px; background: transparent;"
        )
        self._detail_layout.addStretch()
        self._detail_layout.addWidget(placeholder)
        self._detail_layout.addStretch()

    def _clear_detail(self):
        while self._detail_layout.count():
            item = self._detail_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    # ── Data loading ───────────────────────────────────────────────────────

    def refresh(self):
        if self._storage is None:
            self._init_storage()
            if self._storage is None:
                return
        try:
            self._findings = list(reversed(self._storage.get_findings()))
        except Exception:
            self._findings = []

        self._populate_list()

    def _populate_list(self):
        self._findings_list.clear()
        self._list_count.setText(str(len(self._findings)))

        if not self._findings:
            self._findings_list.hide()
            self._list_empty.show()
            self._show_placeholder()
            return

        self._findings_list.show()
        self._list_empty.hide()

        for f in self._findings:
            severity  = f.get("severity", "LOW")
            attack    = f.get("attack_type", "Unknown")
            target    = f.get("target_user", "—")
            display   = f"{attack}\n{target}"
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, f.get("id", -1))

            # Color severity in the list item via foreground
            item.setForeground(QColor(severity_color(severity)))
            self._findings_list.addItem(item)

    def load_finding(self, finding_id: int):
        """Called from outside (Dashboard / Alerts) to jump to a finding."""
        self.refresh()
        for i, f in enumerate(self._findings):
            if f.get("id") == finding_id:
                self._findings_list.setCurrentRow(i)
                break

    # ── Selection ──────────────────────────────────────────────────────────

    def _on_finding_selected(self, row: int):
        if row < 0 or row >= len(self._findings):
            return
        finding = self._findings[row]
        self._selected_finding = finding
        self._render_detail(finding)

    def _render_detail(self, finding: dict):
        self._clear_detail()

        severity   = finding.get("severity", "LOW")
        sev_color  = severity_color(severity)
        attack     = finding.get("attack_type", "Unknown")

        # ── Finding header ─────────────────────────────────────
        hdr = QWidget()
        hdr.setStyleSheet(f"""
            background-color: {BG_SURFACE};
            border-bottom: 1px solid {BORDER_SUBTLE};
            border-left: 3px solid {sev_color};
        """)
        hdr_layout = QVBoxLayout(hdr)
        hdr_layout.setContentsMargins(18, 14, 18, 14)
        hdr_layout.setSpacing(4)

        sev_lbl = QLabel(severity)
        sev_lbl.setStyleSheet(f"""
            color: {sev_color};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
            background: transparent;
        """)

        attack_lbl = QLabel(attack)
        attack_lbl.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 17px;
            font-weight: 700;
            background: transparent;
        """)

        id_lbl = QLabel(f"Finding ID: {finding.get('id', '—')}")
        id_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px; background: transparent;")

        hdr_layout.addWidget(sev_lbl)
        hdr_layout.addWidget(attack_lbl)
        hdr_layout.addWidget(id_lbl)

        self._detail_layout.addWidget(hdr)

        # ── Finding details ────────────────────────────────────
        self._detail_layout.addWidget(section_sep("Source & Target"))
        self._detail_layout.addWidget(detail_row("Source IP",      finding.get("source_ip", "—")))
        self._detail_layout.addWidget(detail_row("Target User",    finding.get("target_user", "—")))
        self._detail_layout.addWidget(detail_row("IP Class",       finding.get("ip_classification", "—")))
        self._detail_layout.addWidget(detail_row("Service",        finding.get("service", "—")))

        self._detail_layout.addWidget(section_sep("Activity"))
        self._detail_layout.addWidget(detail_row("Attempts",       str(finding.get("attempts", 0))))
        self._detail_layout.addWidget(detail_row("Events",         str(finding.get("event_count", 0))))
        self._detail_layout.addWidget(detail_row("Failed",         str(finding.get("failed_attempts", 0))))
        self._detail_layout.addWidget(detail_row("Successful",     str(finding.get("successful_attempts", 0))))
        self._detail_layout.addWidget(detail_row("Duration",       f"{finding.get('duration_seconds', 0):.1f} seconds"))
        self._detail_layout.addWidget(detail_row("First Seen",     fmt_ts(finding.get("first_seen", "—"))))
        self._detail_layout.addWidget(detail_row("Last Seen",      fmt_ts(finding.get("last_seen",  "—"))))

        # ── Incident timeline ──────────────────────────────────
        self._detail_layout.addWidget(section_sep("Incident Timeline"))

        timeline = self._build_timeline(finding)
        self._detail_layout.addWidget(timeline)

        # ── Recommendation ─────────────────────────────────────
        self._detail_layout.addWidget(section_sep("Recommendation"))

        rec_text = finding.get("recommendation", "No recommendation available.")
        rec_box = QWidget()
        rec_box.setStyleSheet(f"""
            background-color: {BG_SURFACE};
            border: 1px solid {BORDER_SUBTLE};
            border-left: 3px solid {sev_color};
        """)
        rec_layout = QVBoxLayout(rec_box)
        rec_layout.setContentsMargins(16, 10, 16, 10)

        rec_lbl = QLabel(rec_text)
        rec_lbl.setWordWrap(True)
        rec_lbl.setStyleSheet(f"""
            color: {TEXT_SECONDARY};
            font-size: 12px;
            line-height: 1.5;
            background: transparent;
        """)
        rec_layout.addWidget(rec_lbl)
        self._detail_layout.addWidget(rec_box)

        self._detail_layout.addStretch()

    def _build_timeline(self, finding: dict) -> QWidget:
        """Build the correlated event timeline table."""
        container = QWidget()
        container.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # Query related events from storage
        related_events = []
        if self._storage:
            try:
                first_seen = datetime.fromisoformat(str(finding["first_seen"]))
                last_seen  = datetime.fromisoformat(str(finding["last_seen"]))
                events = self._storage.get_auth_events_between(first_seen, last_seen)
                related_events = [
                    e for e in events
                    if e["source_ip"] == finding["source_ip"]
                    and e["username"]  == finding["target_user"]
                ]
            except Exception:
                pass

        if not related_events:
            note = QLabel("No related events found in the time window.")
            note.setStyleSheet(
                f"color: {TEXT_MUTED}; font-size: 12px; background: transparent;"
            )
            layout.addWidget(note)
            return container

        # Timeline table
        headers = ["Timestamp", "Status", "Username", "Source IP", "Service"]
        table = QTableWidget(len(related_events), len(headers))
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

        for row, ev in enumerate(related_events):
            status = ev.get("status", "")
            cells = [
                fmt_ts(ev.get("timestamp", "")),
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
        table.setMaximumHeight(min(40 + len(related_events) * 30, 400))
        layout.addWidget(table)

        # Timeline summary
        n_failed = sum(1 for e in related_events if e.get("status") == "FAILED")
        n_success = sum(1 for e in related_events
                        if e.get("status") in ("SUCCESS", "ACCEPTED"))
        summary = QLabel(
            f"Events: {len(related_events)}   "
            f"Failed: {n_failed}   "
            f"Successful: {n_success}"
        )
        summary.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 11px; background: transparent;"
        )
        layout.addWidget(summary)

        return container
