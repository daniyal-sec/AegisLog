"""
AegisLog Reports View

Lists existing report files and supports viewing, opening,
and exporting investigation reports.
"""

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QPlainTextEdit, QFrame,
    QSplitter, QSizePolicy, QFileDialog, QMessageBox,
)
from PySide6.QtCore import Qt, Signal

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_OVERLAY,
    BORDER_SUBTLE, BORDER_DEFAULT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT, STATUS_SUCCESS_TEXT,
    FONT_FAMILY, FONT_MONO,
)


# ─────────────────────────────────────────────────────────────────────────────
# REPORTS VIEW
# ─────────────────────────────────────────────────────────────────────────────

class ReportsView(QWidget):
    """Reports page — list + viewer + export."""

    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path

        # Resolve project root (reports/ is at the project root)
        src_dir = Path(__file__).resolve().parent.parent
        self._reports_dir = src_dir.parent / "reports"

        self._build_ui()
        self.refresh()

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

        # ── Left panel: report list ────────────────────────────
        left = QWidget()
        left.setMinimumWidth(240)
        left.setMaximumWidth(340)
        left.setStyleSheet(f"background-color: {BG_SURFACE};")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        # List header
        list_hdr = QWidget()
        list_hdr.setFixedHeight(44)
        list_hdr.setStyleSheet(f"""
            background-color: {BG_SURFACE};
            border-bottom: 1px solid {BORDER_SUBTLE};
        """)
        lh_layout = QHBoxLayout(list_hdr)
        lh_layout.setContentsMargins(16, 0, 12, 0)

        lbl = QLabel("REPORTS")
        lbl.setStyleSheet(f"""
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 1.4px;
            color: {TEXT_MUTED};
            background: transparent;
        """)
        lh_layout.addWidget(lbl)
        lh_layout.addStretch()

        refresh_btn = QPushButton("↻")
        refresh_btn.setFixedSize(24, 24)
        refresh_btn.setToolTip("Refresh list")
        refresh_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {TEXT_MUTED};
                border: none;
                font-size: 14px;
            }}
            QPushButton:hover {{
                color: {TEXT_PRIMARY};
            }}
        """)
        refresh_btn.clicked.connect(self.refresh)
        lh_layout.addWidget(refresh_btn)
        left_layout.addWidget(list_hdr)

        self._report_list = QListWidget()
        self._report_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {BG_SURFACE};
                border: none;
                outline: none;
            }}
            QListWidget::item {{
                padding: 10px 16px;
                border-bottom: 1px solid {BORDER_SUBTLE};
                color: {TEXT_SECONDARY};
                font-size: 11px;
            }}
            QListWidget::item:selected {{
                background-color: {BG_OVERLAY};
                color: {TEXT_PRIMARY};
                border-left: 2px solid {ACCENT};
            }}
            QListWidget::item:hover:!selected {{
                background-color: {BG_ELEVATED};
                color: {TEXT_PRIMARY};
            }}
        """)
        self._report_list.currentRowChanged.connect(self._on_report_selected)
        left_layout.addWidget(self._report_list)

        self._list_empty = QLabel("No reports found.")
        self._list_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._list_empty.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 12px; background: {BG_SURFACE}; padding: 20px;"
        )
        self._list_empty.hide()
        left_layout.addWidget(self._list_empty)

        splitter.addWidget(left)

        # ── Right panel: viewer ────────────────────────────────
        right = QWidget()
        right.setStyleSheet(f"background-color: {BG_BASE};")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Action bar
        action_bar = QWidget()
        action_bar.setFixedHeight(48)
        action_bar.setObjectName("ActionBar")
        action_bar.setStyleSheet(f"""
            #ActionBar {{
                background-color: {BG_SURFACE};
                border-bottom: 1px solid {BORDER_SUBTLE};
            }}
        """)
        ab_layout = QHBoxLayout(action_bar)
        ab_layout.setContentsMargins(20, 0, 20, 0)
        ab_layout.setSpacing(10)

        self._report_title = QLabel("Select a report to view")
        self._report_title.setStyleSheet(f"""
            color: {TEXT_SECONDARY};
            font-size: 12px;
            background: transparent;
        """)
        ab_layout.addWidget(self._report_title)
        ab_layout.addStretch()

        self._open_btn = QPushButton("Open in Editor")
        self._open_btn.setEnabled(False)
        self._open_btn.setStyleSheet(f"""
            QPushButton {{
                background: {BG_ELEVATED};
                color: {TEXT_SECONDARY};
                border: 1px solid {BORDER_DEFAULT};
                padding: 5px 12px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                color: {TEXT_PRIMARY};
                border-color: {TEXT_MUTED};
            }}
            QPushButton:disabled {{
                color: {TEXT_MUTED};
                border-color: {BORDER_SUBTLE};
            }}
        """)
        self._open_btn.clicked.connect(self._open_in_editor)
        ab_layout.addWidget(self._open_btn)

        self._export_btn = QPushButton("Export Copy…")
        self._export_btn.setEnabled(False)
        self._export_btn.setStyleSheet(f"""
            QPushButton {{
                background: {BG_ELEVATED};
                color: {TEXT_SECONDARY};
                border: 1px solid {BORDER_DEFAULT};
                padding: 5px 12px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                color: {TEXT_PRIMARY};
                border-color: {TEXT_MUTED};
            }}
            QPushButton:disabled {{
                color: {TEXT_MUTED};
                border-color: {BORDER_SUBTLE};
            }}
        """)
        self._export_btn.clicked.connect(self._export_copy)
        ab_layout.addWidget(self._export_btn)

        self._gen_btn = QPushButton("Generate New Report…")
        self._gen_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {STATUS_SUCCESS_TEXT};
                border: 1px solid {STATUS_SUCCESS_TEXT};
                padding: 5px 12px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background: {STATUS_SUCCESS_TEXT};
                color: #0A0A0B;
            }}
        """)
        self._gen_btn.clicked.connect(self._generate_report)
        ab_layout.addWidget(self._gen_btn)

        right_layout.addWidget(action_bar)

        # Report content viewer
        self._viewer = QPlainTextEdit()
        self._viewer.setReadOnly(True)
        self._viewer.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {BG_BASE};
                color: {TEXT_PRIMARY};
                font-family: {FONT_MONO};
                font-size: 12px;
                border: none;
                padding: 20px;
                selection-background-color: {BG_OVERLAY};
            }}
        """)
        self._viewer.setPlaceholderText("Select a report from the list to view its contents.")
        right_layout.addWidget(self._viewer)

        splitter.addWidget(right)
        splitter.setSizes([280, 900])

        self._current_path: Path | None = None

    # ── Data loading ───────────────────────────────────────────────────────

    def refresh(self):
        """Rescan the reports directory."""
        self._report_list.clear()
        self._current_path = None
        self._viewer.clear()
        self._open_btn.setEnabled(False)
        self._export_btn.setEnabled(False)
        self._report_title.setText("Select a report to view")

        if not self._reports_dir.exists():
            self._list_empty.show()
            return

        reports = sorted(
            [f for f in self._reports_dir.glob("*.txt") if f.is_file()],
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )

        if not reports:
            self._report_list.hide()
            self._list_empty.show()
            return

        self._report_list.show()
        self._list_empty.hide()

        for report in reports:
            item = QListWidgetItem(report.name)
            item.setData(Qt.ItemDataRole.UserRole, str(report))
            self._report_list.addItem(item)

    def _on_report_selected(self, row: int):
        item = self._report_list.item(row)
        if item is None:
            return

        path = Path(item.data(Qt.ItemDataRole.UserRole))
        self._current_path = path
        self._report_title.setText(path.name)

        try:
            content = path.read_text(encoding="utf-8")
            self._viewer.setPlainText(content)
        except Exception as exc:
            self._viewer.setPlainText(f"Error reading report:\n{exc}")

        self._open_btn.setEnabled(True)
        self._export_btn.setEnabled(True)

    # ── Actions ─────────────────────────────────────────────────────────────

    def _open_in_editor(self):
        if self._current_path is None:
            return
        try:
            if sys.platform == "win32":
                os.startfile(str(self._current_path))
            else:
                subprocess.Popen(["xdg-open", str(self._current_path)])
        except Exception as exc:
            QMessageBox.warning(self, "Open Failed", f"Could not open file:\n{exc}")

    def _export_copy(self):
        if self._current_path is None:
            return

        dest, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            str(Path.home() / self._current_path.name),
            "Text Files (*.txt);;All Files (*)",
        )
        if not dest:
            return

        try:
            content = self._current_path.read_text(encoding="utf-8")
            Path(dest).write_text(content, encoding="utf-8")
            QMessageBox.information(self, "Export Complete", f"Report exported to:\n{dest}")
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", f"Could not export:\n{exc}")

    def _generate_report(self):
        """Generate a new report from current database contents."""
        try:
            from storage import SecurityStorage
            from report_generator import generate_report, save_report

            storage = SecurityStorage(self.db_path)
            events  = storage.get_auth_events()
            findings_raw = storage.get_findings()

            # Convert findings dicts back into ThreatFinding-like objects
            # by using a simple namespace — report_generator only reads attributes
            from types import SimpleNamespace
            finding_objs = []
            for f in findings_raw:
                obj = SimpleNamespace(**f)
                # Ensure datetime attributes for strftime calls
                for attr in ("first_seen", "last_seen"):
                    raw = getattr(obj, attr, "")
                    if isinstance(raw, str):
                        try:
                            setattr(obj, attr, datetime.fromisoformat(raw))
                        except Exception:
                            pass
                finding_objs.append(obj)

            # Auth events are dicts; report_generator expects objects with .status etc.
            event_objs = [SimpleNamespace(**e) for e in events]

            report_text = generate_report(event_objs, finding_objs, "aegislog.db")

            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            report_path = self._reports_dir / f"report_{timestamp}.txt"
            self._reports_dir.mkdir(parents=True, exist_ok=True)
            save_report(report_text, report_path)

            self.refresh()

            # Auto-select the new report
            self._report_list.setCurrentRow(0)

        except Exception as exc:
            QMessageBox.warning(self, "Generation Failed", f"Could not generate report:\n{exc}")

    def export_investigation(self, finding_id: int):
        """
        Export an investigation report for a specific finding,
        including finding details and correlated event timeline.
        Called by InvestigationView.
        """
        try:
            from storage import SecurityStorage
            from types import SimpleNamespace

            storage  = SecurityStorage(self.db_path)
            finding  = storage.get_finding_by_id(finding_id)
            if finding is None:
                QMessageBox.warning(self, "Not Found", f"Finding {finding_id} not found.")
                return

            first_seen = datetime.fromisoformat(str(finding["first_seen"]))
            last_seen  = datetime.fromisoformat(str(finding["last_seen"]))
            events     = storage.get_auth_events_between(first_seen, last_seen)
            related    = [
                e for e in events
                if e["source_ip"] == finding["source_ip"]
                and e["username"]  == finding["target_user"]
            ]

            lines = [
                "=" * 60,
                "         AEGISLOG INVESTIGATION REPORT",
                "=" * 60,
                "",
                f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Finding ID : {finding['id']}",
                "",
                "FINDING DETAILS",
                "-" * 60,
                f"Attack Type      : {finding['attack_type']}",
                f"Severity         : {finding['severity']}",
                f"Source IP        : {finding['source_ip']}",
                f"Target User      : {finding['target_user']}",
                f"Attempts         : {finding['attempts']}",
                f"IP Classification: {finding['ip_classification']}",
                f"Events           : {finding['event_count']}",
                f"Failed           : {finding['failed_attempts']}",
                f"Successful       : {finding['successful_attempts']}",
                f"Duration         : {finding['duration_seconds']:.1f} seconds",
                f"First Seen       : {finding['first_seen']}",
                f"Last Seen        : {finding['last_seen']}",
                f"Recommendation   : {finding['recommendation']}",
                "",
                "INCIDENT TIMELINE",
                "-" * 60,
            ]
            for ev in related:
                ts = str(ev.get("timestamp", "")).replace("T", " ").split(".")[0]
                lines.append(
                    f"{ts}   {ev.get('status',''):<9} "
                    f"{ev.get('username','')}   {ev.get('source_ip','')}"
                )
            lines += [
                "",
                f"Timeline Events  : {len(related)}",
                "=" * 60,
            ]

            report_text = "\n".join(lines)

            dest, _ = QFileDialog.getSaveFileName(
                self,
                "Export Investigation Report",
                str(Path.home() / f"aegislog_investigation_{finding_id}.txt"),
                "Text Files (*.txt);;All Files (*)",
            )
            if not dest:
                return
            Path(dest).write_text(report_text, encoding="utf-8")
            QMessageBox.information(
                self, "Export Complete", f"Investigation report saved to:\n{dest}"
            )
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", f"Could not export:\n{exc}")
