"""
AegisLog Security Alerts View  —  Phase 5

Information hierarchy per finding (top-to-bottom reading):

    ┌──────────────────────────────────────────────────────┐
    │  HIGH    Authentication Brute Force  [NEW] [Investigate] │
    │  local  ──→  danyyy                          │
    │  ────────────────────────────────────────────────    │
    │  ATTEMPTS   DURATION   FAILED   SUCCESSFUL           │
    │  5          16s        5        0                    │
    │  ────────────────────────────────────────────────    │
    │  First Seen   2026-08-12 17:01:45                    │
    │  Last Seen    2026-08-12 17:02:01                    │
    └──────────────────────────────────────────────────────┘

All data from SecurityStorage. Data loaded via background QThread.
Findings are smartly updated to preserve scroll position.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QSizePolicy,
)
from PySide6.QtCore import Qt, QTimer, QThread, QObject, Signal, Slot

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_OVERLAY,
    BORDER_SUBTLE, BORDER_DEFAULT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT, SEVERITY_HIGH, SEVERITY_CRITICAL,
    severity_color,
    FONT_FAMILY,
)

REFRESH_INTERVAL_MS = 5_000


# ─────────────────────────────────────────────────────────────────────────────
# BACKGROUND DATA LOADER
# ─────────────────────────────────────────────────────────────────────────────

class AlertsDataLoader(QObject):
    """
    Fetches all findings from SQLite in one pass on a background thread.
    """

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
            
            # Sort newest first based on last_seen, then ID descending
            findings.sort(
                key=lambda f: (str(f.get("last_seen", "")), f.get("id", -1)),
                reverse=True
            )

            self.data_ready.emit({
                "ok": True,
                "findings": findings,
                "fetched_at": datetime.now().strftime("%H:%M:%S"),
            })
        except Exception as exc:
            self.data_ready.emit({
                "ok": False,
                "error": str(exc)
            })


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_ts(raw) -> str:
    """Normalize an ISO timestamp to a readable string."""
    s = str(raw).replace("T", " ").split(".")[0]
    return s


def _thin_sep(parent=None) -> QFrame:
    """Thin horizontal separator using the subtle border color."""
    sep = QFrame(parent)
    sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet(f"color: {BORDER_SUBTLE};")
    sep.setFixedHeight(1)
    return sep


# ─────────────────────────────────────────────────────────────────────────────
# INCIDENT PANEL  —  the core finding widget
# ─────────────────────────────────────────────────────────────────────────────

class FindingPanel(QWidget):
    """
    Displays one security finding as a self-contained incident panel.
    """

    investigate_clicked = Signal(int)

    def __init__(self, finding: dict, is_new: bool = False, parent=None):
        super().__init__(parent)
        self._finding_id = finding.get("id", -1)
        self._severity = finding.get("severity", "LOW").upper()
        self._sev_color = severity_color(self._severity)
        self._is_new = is_new

        self.setObjectName("FindingPanel")
        self.setStyleSheet(f"""
            #FindingPanel {{
                background-color: {BG_SURFACE};
                border: 1px solid {BORDER_SUBTLE};
                border-left: 3px solid {self._sev_color};
            }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(0)

        # ── 1. Header row ──────────────────────────────────────
        hdr = QHBoxLayout()
        hdr.setSpacing(12)
        hdr.setContentsMargins(0, 0, 0, 10)

        self._sev_lbl = QLabel(self._severity)
        self._sev_lbl.setFixedWidth(70)
        self._sev_lbl.setStyleSheet(f"""
            color: {self._sev_color};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1.2px;
            background: transparent;
        """)
        hdr.addWidget(self._sev_lbl)

        self._attack_lbl = QLabel(finding.get("attack_type", "Unknown"))
        self._attack_lbl.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 15px;
            font-weight: 600;
            background: transparent;
        """)
        hdr.addWidget(self._attack_lbl)

        self._new_badge = QLabel("NEW")
        self._new_badge.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 1px;
            background: transparent;
            border: 1px solid {ACCENT};
            padding: 1px 4px;
            border-radius: 2px;
        """)
        self._new_badge.setVisible(self._is_new)
        hdr.addWidget(self._new_badge)
        hdr.addStretch()

        inv_btn = QPushButton("Investigate →")
        inv_btn.setFixedHeight(28)
        inv_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {TEXT_SECONDARY};
                border: 1px solid {BORDER_DEFAULT};
                padding: 0px 14px;
                font-size: 11px;
                font-family: {FONT_FAMILY};
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
        hdr.addWidget(inv_btn)
        root.addLayout(hdr)

        # ── 2. Source → Target row ─────────────────────────────
        src_row = QHBoxLayout()
        src_row.setSpacing(0)
        src_row.setContentsMargins(0, 0, 0, 14)

        # Source block
        self._src_val_lbl = QLabel()
        self._src_val_lbl.setStyleSheet(f"font-size: 13px; font-weight: 500; color: {TEXT_PRIMARY}; background: transparent;")
        self._src_sub_lbl = QLabel()
        self._src_sub_lbl.setStyleSheet(f"font-size: 10px; color: {TEXT_MUTED}; background: transparent;")
        
        src_block = self._build_source_block("SOURCE", self._src_val_lbl, self._src_sub_lbl)
        src_row.addWidget(src_block)

        arrow_lbl = QLabel("  ──→  ")
        arrow_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 13px; background: transparent;")
        arrow_lbl.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        src_row.addWidget(arrow_lbl)

        # Target block
        self._tgt_val_lbl = QLabel()
        self._tgt_val_lbl.setStyleSheet(f"font-size: 13px; font-weight: 500; color: {TEXT_PRIMARY}; background: transparent;")
        self._tgt_sub_lbl = QLabel()
        self._tgt_sub_lbl.setStyleSheet(f"font-size: 10px; color: {TEXT_MUTED}; background: transparent;")

        tgt_block = self._build_source_block("TARGET", self._tgt_val_lbl, self._tgt_sub_lbl)
        src_row.addWidget(tgt_block)
        src_row.addStretch()
        root.addLayout(src_row)

        # ── 3. Separator ───────────────────────────────────────
        root.addWidget(_thin_sep())
        root.addSpacing(12)

        # ── 4. Metric strip ────────────────────────────────────
        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(0)
        metrics_row.setContentsMargins(0, 0, 0, 12)

        self._metric_lbls = {}
        metric_names = ["ATTEMPTS", "DURATION", "FAILED", "SUCCESSFUL"]

        for i, lbl_text in enumerate(metric_names):
            if i > 0:
                vline = QFrame()
                vline.setFrameShape(QFrame.Shape.VLine)
                vline.setStyleSheet(f"color: {BORDER_SUBTLE};")
                vline.setFixedWidth(1)
                metrics_row.addWidget(vline)
                metrics_row.addSpacing(20)

            col = QVBoxLayout()
            col.setSpacing(3)
            col.setContentsMargins(0 if i == 0 else 0, 0, 20, 0)

            val_lbl = QLabel()
            val_lbl.setStyleSheet(f"font-size: 20px; font-weight: 700; color: {TEXT_PRIMARY}; background: transparent;")
            col.addWidget(val_lbl)
            self._metric_lbls[lbl_text] = val_lbl

            name_lbl = QLabel(lbl_text)
            name_lbl.setStyleSheet(f"font-size: 9px; font-weight: 600; letter-spacing: 1px; color: {TEXT_MUTED}; background: transparent;")
            col.addWidget(name_lbl)
            metrics_row.addLayout(col)

        metrics_row.addStretch()
        root.addLayout(metrics_row)

        # ── 5. Separator ───────────────────────────────────────
        root.addWidget(_thin_sep())
        root.addSpacing(10)

        # ── 6. Timestamps ──────────────────────────────────────
        ts_layout = QHBoxLayout()
        ts_layout.setSpacing(28)
        ts_layout.setContentsMargins(0, 0, 0, 0)

        self._ts_first = QLabel()
        self._ts_first.setStyleSheet(f"font-size: 11px; color: {TEXT_SECONDARY}; background: transparent;")
        ts_layout.addWidget(self._build_ts_pair("First Seen", self._ts_first))

        self._ts_last = QLabel()
        self._ts_last.setStyleSheet(f"font-size: 11px; color: {TEXT_SECONDARY}; background: transparent;")
        ts_layout.addWidget(self._build_ts_pair("Last Seen", self._ts_last))
        
        ts_layout.addStretch()
        root.addLayout(ts_layout)

        # Populate with data
        self.update_data(finding)

    def update_data(self, finding: dict):
        """Update finding panel labels without recreating the widget."""
        # Header
        self._attack_lbl.setText(finding.get("attack_type", "Unknown"))
        
        new_severity = finding.get("severity", "LOW").upper()
        if new_severity != self._severity:
            self._severity = new_severity
            self._sev_color = severity_color(self._severity)
            self._sev_lbl.setText(self._severity)
            self._sev_lbl.setStyleSheet(f"color: {self._sev_color}; font-size: 10px; font-weight: 700; letter-spacing: 1.2px; background: transparent;")
            self.setStyleSheet(f"#FindingPanel {{ background-color: {BG_SURFACE}; border: 1px solid {BORDER_SUBTLE}; border-left: 3px solid {self._sev_color}; }}")

        # Source / Target
        self._src_val_lbl.setText(finding.get("source_ip", "—"))
        ip_class = finding.get("ip_classification", "")
        if ip_class and ip_class.lower() not in ("—", "unknown", ""):
            self._src_sub_lbl.setText(ip_class)
            self._src_sub_lbl.show()
        else:
            self._src_sub_lbl.hide()

        self._tgt_val_lbl.setText(finding.get("target_user", "—"))
        service = finding.get("service", "")
        if service and service.lower() not in ("—", "unknown", ""):
            self._tgt_sub_lbl.setText(service)
            self._tgt_sub_lbl.show()
        else:
            self._tgt_sub_lbl.hide()

        # Metrics
        dur = finding.get("duration_seconds", 0)
        dur_str = f"{dur:.0f}s" if dur < 3600 else f"{dur/3600:.1f}h"
        self._metric_lbls["ATTEMPTS"].setText(str(finding.get("attempts", 0)))
        self._metric_lbls["DURATION"].setText(dur_str)
        self._metric_lbls["FAILED"].setText(str(finding.get("failed_attempts", 0)))
        self._metric_lbls["SUCCESSFUL"].setText(str(finding.get("successful_attempts", 0)))

        # Timestamps
        self._ts_first.setText(_fmt_ts(finding.get("first_seen", "—")))
        self._ts_last.setText(_fmt_ts(finding.get("last_seen", "—")))

    def remove_new_badge(self):
        self._is_new = False
        self._new_badge.hide()

    def get_finding_id(self) -> int:
        return self._finding_id

    def get_severity(self) -> str:
        return self._severity

    def _build_source_block(self, role: str, val_lbl: QLabel, sub_lbl: QLabel) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        role_lbl = QLabel(role)
        role_lbl.setStyleSheet(f"font-size: 9px; font-weight: 600; letter-spacing: 1px; color: {TEXT_MUTED}; background: transparent;")
        layout.addWidget(role_lbl)
        layout.addWidget(val_lbl)
        layout.addWidget(sub_lbl)
        return w

    def _build_ts_pair(self, label: str, val_lbl: QLabel) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QHBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        lbl = QLabel(label)
        lbl.setFixedWidth(72)
        lbl.setStyleSheet(f"font-size: 11px; color: {TEXT_MUTED}; background: transparent;")
        layout.addWidget(lbl)
        layout.addWidget(val_lbl)
        return w


# ─────────────────────────────────────────────────────────────────────────────
# FILTER BAR
# ─────────────────────────────────────────────────────────────────────────────

class SeverityFilterBar(QWidget):
    """Horizontal severity filter: ALL / CRITICAL / HIGH / MEDIUM / LOW"""
    filter_changed = Signal(str)
    FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]

    _ACTIVE = f"""
        QPushButton {{
            background: transparent;
            color: {ACCENT};
            border: none;
            border-bottom: 2px solid {ACCENT};
            padding: 9px 18px;
            font-size: 11px;
            font-weight: 600;
            font-family: {FONT_FAMILY};
            letter-spacing: 0.3px;
        }}
    """
    _INACTIVE = f"""
        QPushButton {{
            background: transparent;
            color: {TEXT_MUTED};
            border: none;
            border-bottom: 2px solid transparent;
            padding: 9px 18px;
            font-size: 11px;
            font-family: {FONT_FAMILY};
        }}
        QPushButton:hover {{
            color: {TEXT_SECONDARY};
            background-color: {BG_ELEVATED};
        }}
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("FilterBar")
        self.setFixedHeight(44)
        self.setStyleSheet(f"""
            #FilterBar {{
                background-color: {BG_SURFACE};
                border-bottom: 1px solid {BORDER_SUBTLE};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(0)

        self._buttons: dict[str, QPushButton] = {}
        for f in self.FILTERS:
            btn = QPushButton(f)
            btn.setFlat(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(self._INACTIVE)
            btn.clicked.connect(lambda checked, sev=f: self._select(sev))
            self._buttons[f] = btn
            layout.addWidget(btn)

        layout.addStretch()
        self._select("ALL")

    def _select(self, severity: str):
        for name, btn in self._buttons.items():
            btn.setStyleSheet(self._ACTIVE if name == severity else self._INACTIVE)
        self.filter_changed.emit(severity)

    def current(self) -> str:
        for name, btn in self._buttons.items():
            if btn.styleSheet() == self._ACTIVE:
                return name
        return "ALL"


# ─────────────────────────────────────────────────────────────────────────────
# ALERTS VIEW
# ─────────────────────────────────────────────────────────────────────────────

class AlertsView(QWidget):
    """
    Security Alerts page.
    All data from SecurityStorage. Data is loaded in a background thread.
    Finding panels are smartly updated to prevent jumpiness.
    """

    investigate_requested = Signal(int)

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self._all_findings: list[dict] = []
        self._current_filter = "ALL"
        self._loading = False
        
        self._known_finding_ids = set()
        self._finding_panels: dict[int, FindingPanel] = {}

        self._build_ui()

        # Initial load
        self.refresh()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(REFRESH_INTERVAL_MS)

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Filter bar
        self._filter_bar = SeverityFilterBar()
        self._filter_bar.filter_changed.connect(self._on_filter_changed)
        layout.addWidget(self._filter_bar)

        # Meta bar: count + refresh time
        meta_bar = QWidget()
        meta_bar.setFixedHeight(38)
        meta_bar.setStyleSheet(f"""
            background-color: {BG_BASE};
            border-bottom: 1px solid {BORDER_SUBTLE};
        """)
        meta_layout = QHBoxLayout(meta_bar)
        meta_layout.setContentsMargins(28, 0, 28, 0)

        self._count_lbl = QLabel("")
        self._count_lbl.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px; background: transparent;")
        meta_layout.addWidget(self._count_lbl)
        meta_layout.addStretch()

        self._refresh_lbl = QLabel("")
        self._refresh_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px; background: transparent;")
        meta_layout.addWidget(self._refresh_lbl)
        layout.addWidget(meta_bar)

        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(f"background-color: {BG_BASE};")
        layout.addWidget(scroll)

        # Inner container
        outer_container = QWidget()
        outer_container.setStyleSheet(f"background-color: {BG_BASE};")
        outer_layout = QHBoxLayout(outer_container)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self._panels_widget = QWidget()
        self._panels_widget.setStyleSheet(f"background-color: {BG_BASE};")
        self._panels_widget.setMaximumWidth(960)

        self._panels_layout = QVBoxLayout(self._panels_widget)
        self._panels_layout.setContentsMargins(28, 20, 28, 28)
        self._panels_layout.setSpacing(10)
        self._panels_layout.addStretch()

        outer_layout.addWidget(self._panels_widget)
        outer_layout.addStretch()
        scroll.setWidget(outer_container)

        # Empty state
        self._empty_widget = self._make_empty_state(
            "NO SECURITY FINDINGS",
            "No detected security incidents are currently stored.",
        )
        self._empty_widget.hide()
        layout.addWidget(self._empty_widget)

        # Error state
        self._error_widget = self._make_error_state()
        self._error_widget.hide()
        layout.addWidget(self._error_widget)

    def _make_empty_state(self, title: str, subtitle: str) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background-color: {BG_BASE};")
        layout = QVBoxLayout(w)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)

        t = QLabel(title)
        t.setStyleSheet(f"font-size: 13px; font-weight: 600; letter-spacing: 1.5px; color: {TEXT_MUTED}; background: transparent;")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(t)

        s = QLabel(subtitle)
        s.setStyleSheet(f"font-size: 11px; color: {TEXT_MUTED}; background: transparent;")
        s.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(s)

        return w

    def _make_error_state(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background-color: {BG_BASE};")
        layout = QVBoxLayout(w)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)

        t = QLabel("DATABASE ERROR")
        t.setStyleSheet(f"font-size: 13px; font-weight: 600; letter-spacing: 1.5px; color: {SEVERITY_HIGH}; background: transparent;")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(t)

        self._error_detail_lbl = QLabel("Unable to load security findings.")
        self._error_detail_lbl.setStyleSheet(f"font-size: 11px; color: {TEXT_MUTED}; background: transparent;")
        self._error_detail_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._error_detail_lbl)

        return w

    # ── Background data loading ────────────────────────────────────────────

    def refresh(self):
        if self._loading:
            return

        self._loading = True
        self._refresh_lbl.setText("Refreshing…")

        self._load_thread = QThread(self)
        self._loader = AlertsDataLoader(self.db_path)
        self._loader.moveToThread(self._load_thread)

        self._load_thread.started.connect(self._loader.load)
        self._loader.data_ready.connect(self._on_data_ready)
        self._load_thread.finished.connect(self._load_thread.deleteLater)

        self._load_thread.start()

    @Slot(dict)
    def _on_data_ready(self, data: dict):
        self._loading = False
        self._load_thread.quit()
        self._load_thread.wait()

        if not data.get("ok"):
            self._show_error(data.get("error", "Unknown error"))
            return

        self._all_findings = data["findings"]
        self._refresh_lbl.setText(f"Updated {data['fetched_at']}")
        
        self._render_panels()

    def _on_filter_changed(self, severity: str):
        self._current_filter = severity
        self._render_panels()

    # ── Rendering ──────────────────────────────────────────────────────────

    def _render_panels(self):
        self._error_widget.hide()

        # Apply filter
        if self._current_filter == "ALL":
            visible = self._all_findings
        else:
            visible = [
                f for f in self._all_findings
                if f.get("severity", "").upper() == self._current_filter
            ]

        # Update count label
        n = len(visible)
        filter_suffix = "" if self._current_filter == "ALL" else f" — {self._current_filter}"
        self._count_lbl.setText(f"{n} security finding{'s' if n != 1 else ''}{filter_suffix}")

        if not visible:
            self._panels_widget.hide()
            self._empty_widget.show()
            return

        self._empty_widget.hide()
        self._panels_widget.show()

        # Determine which findings are newly seen in this app session
        # Do not mark as "NEW" on the very first load
        first_load = len(self._known_finding_ids) == 0

        # Maintain order in layout according to 'visible'
        # To avoid flicker and lost scroll position, we selectively add/remove
        # panels and reposition them.

        visible_ids = []
        for index, finding in enumerate(visible):
            f_id = finding.get("id", -1)
            visible_ids.append(f_id)

            if f_id not in self._finding_panels:
                is_new = not first_load and (f_id not in self._known_finding_ids)
                panel = FindingPanel(finding, is_new=is_new)
                panel.investigate_clicked.connect(self.investigate_requested)
                self._finding_panels[f_id] = panel
                self._known_finding_ids.add(f_id)
            else:
                self._finding_panels[f_id].update_data(finding)

            # Ensure it is at the correct position in the layout
            current_widget = self._panels_layout.itemAt(index).widget()
            if current_widget != self._finding_panels[f_id]:
                # Remove it from wherever it is and insert it here
                self._panels_layout.insertWidget(index, self._finding_panels[f_id])

        # Remove panels that no longer match the filter
        # Keep them in `_finding_panels` cache so they aren't marked "NEW" if filter changes back
        layout_count = self._panels_layout.count()
        # The last item is a stretch, so we iterate up to count-1
        items_to_remove = []
        for i in range(layout_count - 1):
            widget = self._panels_layout.itemAt(i).widget()
            if isinstance(widget, FindingPanel) and widget.get_finding_id() not in visible_ids:
                items_to_remove.append(widget)

        for widget in items_to_remove:
            self._panels_layout.removeWidget(widget)
            widget.setParent(None)

    def _show_error(self, error_msg: str):
        self._empty_widget.hide()
        self._panels_widget.hide()
        self._error_detail_lbl.setText(f"Unable to load security findings.\n{error_msg}")
        self._error_widget.show()
        self._count_lbl.setText("")

