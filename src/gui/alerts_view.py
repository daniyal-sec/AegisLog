"""
AegisLog Security Alerts View  —  Phase 4 Redesign

Information hierarchy per finding (top-to-bottom reading):

    ┌──────────────────────────────────────────────────────┐
    │  HIGH    Authentication Brute Force   [Investigate]  │
    │  local  ──→  danyyy                          │
    │  ────────────────────────────────────────────────    │
    │  ATTEMPTS   DURATION   FAILED   SUCCESSFUL           │
    │  5          16s        5        0                    │
    │  ────────────────────────────────────────────────    │
    │  First Seen   2026-08-12 17:01:45                    │
    │  Last Seen    2026-08-12 17:02:01                    │
    └──────────────────────────────────────────────────────┘

Each finding reads as a single coherent incident.
All data from SecurityStorage. No detection logic duplicated.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QSizePolicy,
)
from PySide6.QtCore import Qt, QTimer, Signal

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_OVERLAY,
    BORDER_SUBTLE, BORDER_DEFAULT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT, SEVERITY_HIGH, SEVERITY_CRITICAL,
    severity_color,
    FONT_FAMILY,
)

REFRESH_INTERVAL_MS = 10_000


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

    Vertical information flow:
        1. Header row: severity chip  |  attack type  |  Investigate
        2. Source → Target
        3. Separator
        4. Metric strip: Attempts / Duration / Failed / Successful
        5. Separator
        6. Timestamps: First Seen / Last Seen
    """

    investigate_clicked = Signal(int)

    def __init__(self, finding: dict, parent=None):
        super().__init__(parent)
        self._finding_id = finding.get("id", -1)

        severity  = finding.get("severity", "LOW").upper()
        sev_color = severity_color(severity)

        self.setObjectName("FindingPanel")
        self.setStyleSheet(f"""
            #FindingPanel {{
                background-color: {BG_SURFACE};
                border: 1px solid {BORDER_SUBTLE};
                border-left: 3px solid {sev_color};
            }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(0)

        # ── 1. Header row ──────────────────────────────────────
        hdr = QHBoxLayout()
        hdr.setSpacing(12)
        hdr.setContentsMargins(0, 0, 0, 10)

        # Severity chip
        sev_lbl = QLabel(severity)
        sev_lbl.setFixedWidth(70)
        sev_lbl.setStyleSheet(f"""
            color: {sev_color};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1.2px;
            background: transparent;
        """)
        hdr.addWidget(sev_lbl)

        # Attack type — primary headline
        attack_lbl = QLabel(finding.get("attack_type", "Unknown"))
        attack_lbl.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 15px;
            font-weight: 600;
            background: transparent;
        """)
        hdr.addWidget(attack_lbl, stretch=1)

        # Investigate button — anchored to the header
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

        src_ip     = finding.get("source_ip", "—")
        target     = finding.get("target_user", "—")
        ip_class   = finding.get("ip_classification", "")
        service    = finding.get("service", "")

        # Source block
        src_block = self._source_block("SOURCE", src_ip, ip_class)
        src_row.addWidget(src_block)

        # Arrow
        arrow_lbl = QLabel("  ──→  ")
        arrow_lbl.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 13px;
            background: transparent;
        """)
        arrow_lbl.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        src_row.addWidget(arrow_lbl)

        # Target block
        tgt_block = self._source_block("TARGET", target, service)
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

        dur = finding.get("duration_seconds", 0)
        dur_str = f"{dur:.0f}s" if dur < 3600 else f"{dur/3600:.1f}h"

        metrics_data = [
            ("ATTEMPTS",   str(finding.get("attempts", 0))),
            ("DURATION",   dur_str),
            ("FAILED",     str(finding.get("failed_attempts", 0))),
            ("SUCCESSFUL", str(finding.get("successful_attempts", 0))),
        ]

        for i, (lbl_text, val_text) in enumerate(metrics_data):
            if i > 0:
                # Thin vertical rule between metrics
                vline = QFrame()
                vline.setFrameShape(QFrame.Shape.VLine)
                vline.setStyleSheet(f"color: {BORDER_SUBTLE};")
                vline.setFixedWidth(1)
                metrics_row.addWidget(vline)
                metrics_row.addSpacing(20)

            col = QVBoxLayout()
            col.setSpacing(3)
            col.setContentsMargins(0 if i == 0 else 0, 0, 20, 0)

            val_lbl = QLabel(val_text)
            val_lbl.setStyleSheet(f"""
                font-size: 20px;
                font-weight: 700;
                color: {TEXT_PRIMARY};
                background: transparent;
            """)
            col.addWidget(val_lbl)

            name_lbl = QLabel(lbl_text)
            name_lbl.setStyleSheet(f"""
                font-size: 9px;
                font-weight: 600;
                letter-spacing: 1px;
                color: {TEXT_MUTED};
                background: transparent;
            """)
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

        ts_layout.addWidget(
            self._ts_pair("First Seen", finding.get("first_seen", "—"))
        )
        ts_layout.addWidget(
            self._ts_pair("Last Seen", finding.get("last_seen", "—"))
        )
        ts_layout.addStretch()
        root.addLayout(ts_layout)

    # ── Sub-widget builders ────────────────────────────────────────────────

    def _source_block(self, role: str, value: str, sub: str = "") -> QWidget:
        """
        Two-line block showing ROLE label + value + optional sub-label.
        Used for both SOURCE and TARGET.
        """
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        role_lbl = QLabel(role)
        role_lbl.setStyleSheet(f"""
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 1px;
            color: {TEXT_MUTED};
            background: transparent;
        """)
        layout.addWidget(role_lbl)

        val_lbl = QLabel(value)
        val_lbl.setStyleSheet(f"""
            font-size: 13px;
            font-weight: 500;
            color: {TEXT_PRIMARY};
            background: transparent;
        """)
        layout.addWidget(val_lbl)

        if sub and sub.lower() not in ("—", "unknown", ""):
            sub_lbl = QLabel(sub)
            sub_lbl.setStyleSheet(f"""
                font-size: 10px;
                color: {TEXT_MUTED};
                background: transparent;
            """)
            layout.addWidget(sub_lbl)

        return w

    def _ts_pair(self, label: str, raw) -> QWidget:
        """Compact label + value timestamp pair."""
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QHBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        lbl = QLabel(label)
        lbl.setFixedWidth(72)
        lbl.setStyleSheet(f"""
            font-size: 11px;
            color: {TEXT_MUTED};
            background: transparent;
        """)
        layout.addWidget(lbl)

        val = QLabel(_fmt_ts(raw))
        val.setStyleSheet(f"""
            font-size: 11px;
            color: {TEXT_SECONDARY};
            background: transparent;
        """)
        layout.addWidget(val)
        return w


# ─────────────────────────────────────────────────────────────────────────────
# FILTER BAR
# ─────────────────────────────────────────────────────────────────────────────

class SeverityFilterBar(QWidget):
    """
    Horizontal severity filter: ALL / CRITICAL / HIGH / MEDIUM / LOW

    Active filter is highlighted with the amber accent and a bottom border.
    Inactive filters use muted text with hover.
    """

    filter_changed = Signal(str)

    FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]

    _BTN_BASE = f"""
        QPushButton {{
            background: transparent;
            border: none;
            border-bottom: 2px solid transparent;
            padding: 9px 18px;
            font-size: 11px;
            font-family: {FONT_FAMILY};
            letter-spacing: 0.3px;
        }}
    """
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
            btn.setStyleSheet(
                self._ACTIVE if name == severity else self._INACTIVE
            )
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

    Layout:
        ┌─ filter bar (ALL / CRITICAL / HIGH / MEDIUM / LOW) ──────────┐
        │  N security findings                          [last refreshed]│
        ├──────────────────────────────────────────────────────────────┤
        │  Scrollable list of FindingPanel widgets                     │
        │  (constrained max-width; not stretched across full window)   │
        └──────────────────────────────────────────────────────────────┘

    All data from SecurityStorage. Auto-refreshes every 10 s.
    """

    investigate_requested = Signal(int)

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self._storage = None
        self._all_findings: list[dict] = []
        self._current_filter = "ALL"
        self._db_error: str | None = None

        self._init_storage()
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(REFRESH_INTERVAL_MS)

        self.refresh()

    def _init_storage(self):
        try:
            from storage import SecurityStorage
            self._storage = SecurityStorage(self.db_path)
            self._db_error = None
        except Exception as exc:
            self._storage = None
            self._db_error = str(exc)

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
        self._count_lbl.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 11px; background: transparent;"
        )
        meta_layout.addWidget(self._count_lbl)
        meta_layout.addStretch()

        self._refresh_lbl = QLabel("")
        self._refresh_lbl.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 10px; background: transparent;"
        )
        meta_layout.addWidget(self._refresh_lbl)
        layout.addWidget(meta_bar)

        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(f"background-color: {BG_BASE};")
        layout.addWidget(scroll)

        # Inner container — constrained width so panels don't spread full screen
        outer_container = QWidget()
        outer_container.setStyleSheet(f"background-color: {BG_BASE};")
        outer_layout = QHBoxLayout(outer_container)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # The actual panel list sits in a width-constrained inner widget
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
        t.setStyleSheet(f"""
            font-size: 13px;
            font-weight: 600;
            letter-spacing: 1.5px;
            color: {TEXT_MUTED};
            background: transparent;
        """)
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(t)

        s = QLabel(subtitle)
        s.setStyleSheet(f"""
            font-size: 11px;
            color: {TEXT_MUTED};
            background: transparent;
        """)
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
        t.setStyleSheet(f"""
            font-size: 13px;
            font-weight: 600;
            letter-spacing: 1.5px;
            color: {SEVERITY_HIGH};
            background: transparent;
        """)
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(t)

        self._error_detail_lbl = QLabel("Unable to load security findings.")
        self._error_detail_lbl.setStyleSheet(f"""
            font-size: 11px;
            color: {TEXT_MUTED};
            background: transparent;
        """)
        self._error_detail_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._error_detail_lbl)

        return w

    # ── Data ───────────────────────────────────────────────────────────────

    def refresh(self):
        if self._storage is None:
            self._init_storage()
            if self._storage is None:
                self._show_error()
                return

        try:
            self._all_findings = self._storage.get_findings()
            self._all_findings = list(reversed(self._all_findings))  # newest first
            self._db_error = None
        except Exception as exc:
            self._db_error = str(exc)
            self._show_error()
            return

        from datetime import datetime
        self._refresh_lbl.setText(
            f"Updated {datetime.now().strftime('%H:%M:%S')}"
        )
        self._render_panels()

    def _on_filter_changed(self, severity: str):
        self._current_filter = severity
        self._render_panels()

    # ── Rendering ──────────────────────────────────────────────────────────

    def _render_panels(self):
        """Clear and rebuild the finding panels for the active filter."""
        self._error_widget.hide()

        # Filter
        if self._current_filter == "ALL":
            visible = self._all_findings
        else:
            visible = [
                f for f in self._all_findings
                if f.get("severity", "").upper() == self._current_filter
            ]

        # Update count label
        n = len(visible)
        filter_suffix = (
            "" if self._current_filter == "ALL"
            else f" — {self._current_filter}"
        )
        self._count_lbl.setText(
            f"{n} security finding{'s' if n != 1 else ''}{filter_suffix}"
        )

        # Clear existing panels (keep the trailing stretch)
        while self._panels_layout.count() > 1:
            item = self._panels_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not visible:
            self._empty_widget.show()
            self._panels_widget.hide()
            return

        self._empty_widget.hide()
        self._panels_widget.show()

        for finding in visible:
            panel = FindingPanel(finding)
            panel.investigate_clicked.connect(self.investigate_requested)
            self._panels_layout.insertWidget(
                self._panels_layout.count() - 1, panel
            )

    def _show_error(self):
        """Show the database error state."""
        self._clear_panels()
        self._empty_widget.hide()
        self._panels_widget.hide()
        self._error_detail_lbl.setText(
            f"Unable to load security findings."
            + (f"\n{self._db_error}" if self._db_error else "")
        )
        self._error_widget.show()
        self._count_lbl.setText("")
        self._refresh_lbl.setText("")

    def _clear_panels(self):
        while self._panels_layout.count() > 1:
            item = self._panels_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
