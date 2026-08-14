import sys
import json
from pathlib import Path

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QWidget, QCheckBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from gui.styles import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, TEXT_PRIMARY, TEXT_SECONDARY,
    TEXT_MUTED, BORDER_SUBTLE, STATUS_ACTIVE, FONT_FAMILY
)

class OnboardingDialog(QDialog):
    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self.settings_file = Path(self.db_path).parent / "settings.json"
        
        self.setWindowTitle("Welcome to AegisLog")
        self.setFixedSize(500, 600)
        self.setModal(True)
        
        # Remove default dialog frame for a cleaner SOC look, or just style it
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {BG_BASE};
                border: 1px solid {BORDER_SUBTLE};
            }}
        """)
        
        self._build_ui()
        
    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Welcome to AegisLog")
        title.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 20px;
            font-weight: 800;
            background: transparent;
        """)
        layout.addWidget(title)
        
        subtitle = QLabel("Local security monitoring for your workstation.")
        subtitle.setStyleSheet(f"""
            color: {STATUS_ACTIVE};
            font-size: 14px;
            font-weight: 500;
            background: transparent;
        """)
        layout.addWidget(subtitle)
        
        desc = QLabel(
            "AegisLog watches authentication activity on this computer, "
            "detects suspicious patterns, and helps you investigate security incidents."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"""
            color: {TEXT_SECONDARY};
            font-size: 13px;
            background: transparent;
            margin-top: 10px;
        """)
        layout.addWidget(desc)
        
        # Sections
        sections_widget = QWidget()
        sections_widget.setStyleSheet(f"""
            background-color: {BG_SURFACE};
            border: 1px solid {BORDER_SUBTLE};
            border-radius: 4px;
        """)
        sections_layout = QVBoxLayout(sections_widget)
        sections_layout.setContentsMargins(20, 20, 20, 20)
        sections_layout.setSpacing(15)
        
        def add_section(title_text, body_text):
            sec_layout = QVBoxLayout()
            sec_layout.setSpacing(4)
            lbl_title = QLabel(title_text)
            lbl_title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-weight: 700; font-size: 12px; background: transparent;")
            lbl_body = QLabel(body_text)
            lbl_body.setWordWrap(True)
            lbl_body.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; background: transparent;")
            sec_layout.addWidget(lbl_title)
            sec_layout.addWidget(lbl_body)
            sections_layout.addLayout(sec_layout)
            
        add_section("1. MONITOR", "Watch authentication events as they happen.")
        add_section("2. DETECT", "Identify suspicious activity such as repeated failed logins and brute-force attempts.")
        add_section("3. INVESTIGATE", "Review detected incidents, timelines, affected accounts, and recommended actions.")
        
        layout.addWidget(sections_widget)
        
        # Platform specific
        platform_widget = QWidget()
        platform_widget.setStyleSheet(f"""
            background-color: {BG_ELEVATED};
            border: 1px solid {BORDER_SUBTLE};
            border-radius: 4px;
        """)
        plat_layout = QVBoxLayout(platform_widget)
        plat_layout.setContentsMargins(15, 15, 15, 15)
        
        plat_text = (
            "Windows:\nAegisLog monitors the Windows Security Event Log."
            if sys.platform == "win32" else
            "Linux:\nAegisLog monitors the systemd journal for authentication activity."
        )
        plat_lbl = QLabel(plat_text)
        plat_lbl.setWordWrap(True)
        plat_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 12px; font-weight: 500; background: transparent;")
        plat_layout.addWidget(plat_lbl)
        layout.addWidget(platform_widget)
        
        # Next step
        step_lbl = QLabel("Your first step")
        step_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 14px; font-weight: 700; margin-top: 10px; background: transparent;")
        layout.addWidget(step_lbl)
        
        step_desc_text = (
            "Open Live Monitor and select Start Monitoring to begin collecting Windows Security Log events."
            if sys.platform == "win32" else
            "Open Live Monitor and select Start Monitoring to begin collecting systemd journal events."
        )
        step_desc = QLabel(step_desc_text)
        step_desc.setWordWrap(True)
        step_desc.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; background: transparent;")
        layout.addWidget(step_desc)
        
        note = QLabel("AegisLog monitors locally. It does not require a cloud account or external security service.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px; font-style: italic; background: transparent;")
        layout.addWidget(note)
        
        layout.addStretch()
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        self.dont_show_cb = QCheckBox("Don't show this again")
        self.dont_show_cb.setStyleSheet(f"""
            QCheckBox {{
                color: {TEXT_SECONDARY};
                font-size: 12px;
                background: transparent;
            }}
            QCheckBox::indicator {{
                width: 14px;
                height: 14px;
            }}
        """)
        self.dont_show_cb.setChecked(True)
        btn_layout.addWidget(self.dont_show_cb)
        
        btn_layout.addStretch()
        
        self.start_btn = QPushButton("Get Started")
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {STATUS_ACTIVE};
                color: #0A0A0B;
                border: none;
                padding: 8px 20px;
                font-size: 13px;
                font-weight: 600;
                border-radius: 2px;
            }}
            QPushButton:hover {{
                background-color: #55c470;
            }}
        """)
        self.start_btn.clicked.connect(self._on_start)
        btn_layout.addWidget(self.start_btn)
        
        layout.addLayout(btn_layout)

    def _on_start(self):
        if self.dont_show_cb.isChecked():
            self._save_preference()
        self.accept()
        
    def _save_preference(self):
        prefs = {}
        if self.settings_file.exists():
            try:
                prefs = json.loads(self.settings_file.read_text())
            except Exception:
                pass
        prefs["show_onboarding"] = False
        try:
            self.settings_file.write_text(json.dumps(prefs, indent=2))
        except Exception:
            pass

def should_show_onboarding(db_path: str) -> bool:
    settings_file = Path(db_path).parent / "settings.json"
    if not settings_file.exists():
        return True
    try:
        prefs = json.loads(settings_file.read_text())
        return prefs.get("show_onboarding", True)
    except Exception:
        return True
