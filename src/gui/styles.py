"""
AegisLog Design System

Defines the complete visual language for AegisLog:
colors, typography, spacing, component styles.

Applied globally via QApplication.setStyleSheet().
"""


# ─────────────────────────────────────────────────────────────────────────────
# DESIGN TOKENS
# ─────────────────────────────────────────────────────────────────────────────

# Background hierarchy
BG_BASE       = "#0A0A0B"   # Deepest background — app base
BG_SURFACE    = "#111214"   # Primary panels, sidebar
BG_ELEVATED   = "#17191C"   # Cards, table headers, secondary panels
BG_OVERLAY    = "#1E2124"   # Hover states, selected rows

# Borders
BORDER_SUBTLE  = "#25272A"  # Default borders, dividers
BORDER_DEFAULT = "#2D3033"  # Prominent borders, focus rings

# Typography
TEXT_PRIMARY   = "#F2F2F2"  # Headings, key values
TEXT_SECONDARY = "#92979D"  # Labels, captions
TEXT_MUTED     = "#62676D"  # Placeholders, timestamps, metadata

# Severity palette — used ONLY to communicate security state
SEVERITY_CRITICAL = "#E5253A"   # Critical findings
SEVERITY_HIGH     = "#C0392B"   # High severity
SEVERITY_MEDIUM   = "#D4820A"   # Medium / amber
SEVERITY_LOW      = "#4A5568"   # Low / muted slate

# Status colors — used sparingly
STATUS_SUCCESS  = "#2D6A4F"   # Muted green background
STATUS_SUCCESS_TEXT = "#52B788"  # Muted green text
STATUS_FAILED_TEXT  = "#E5253A"  # Failed auth text
STATUS_ACTIVE   = "#52B788"   # Monitoring active indicator dot
STATUS_IDLE     = "#62676D"   # Monitoring idle indicator dot

# Interactive elements
ACCENT          = "#D4820A"   # Amber — used for active nav, focus, buttons
ACCENT_HOVER    = "#B86E08"
BTN_PRIMARY_BG  = "#1E2124"
BTN_PRIMARY_HOVER = "#25272A"

# Font
FONT_FAMILY = "Segoe UI, Arial, sans-serif"
FONT_MONO   = "Consolas, Courier New, monospace"


# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": SEVERITY_CRITICAL,
    "HIGH":     SEVERITY_HIGH,
    "MEDIUM":   SEVERITY_MEDIUM,
    "LOW":      SEVERITY_LOW,
}

STATUS_TEXT_COLORS = {
    "FAILED":   STATUS_FAILED_TEXT,
    "SUCCESS":  STATUS_SUCCESS_TEXT,
    "ACCEPTED": STATUS_SUCCESS_TEXT,
}

def severity_color(level: str) -> str:
    """Return the hex color for a severity level string."""
    return SEVERITY_COLORS.get(level.upper(), TEXT_MUTED)

def status_text_color(status: str) -> str:
    """Return the hex color for an auth event status."""
    return STATUS_TEXT_COLORS.get(status.upper(), TEXT_SECONDARY)


# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL QSS STYLESHEET
# ─────────────────────────────────────────────────────────────────────────────

DARK_STYLESHEET = f"""

/* ── Application base ─────────────────────────────────────────── */

QWidget {{
    background-color: {BG_BASE};
    color: {TEXT_PRIMARY};
    font-family: {FONT_FAMILY};
    font-size: 13px;
    selection-background-color: {BG_OVERLAY};
    selection-color: {TEXT_PRIMARY};
}}

QMainWindow {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0F0F11, stop:1 #060607);
}}

/* ── Scroll bars ──────────────────────────────────────────────── */

QScrollBar:vertical {{
    background: {BG_SURFACE};
    width: 6px;
    margin: 0;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {BORDER_DEFAULT};
    border-radius: 3px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background: {TEXT_MUTED};
}}
QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: 0;
    width: 0;
}}
QScrollBar:horizontal {{
    background: {BG_SURFACE};
    height: 6px;
    border: none;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER_DEFAULT};
    border-radius: 3px;
    min-width: 20px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {TEXT_MUTED};
}}
QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {{
    height: 0;
    width: 0;
}}

/* ── Buttons ──────────────────────────────────────────────────── */

QPushButton {{
    background-color: {BTN_PRIMARY_BG};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_DEFAULT};
    padding: 6px 14px;
    font-size: 12px;
    font-family: {FONT_FAMILY};
    letter-spacing: 0.3px;
}}
QPushButton:hover {{
    background-color: {BTN_PRIMARY_HOVER};
    border-color: {TEXT_MUTED};
}}
QPushButton:pressed {{
    background-color: {BG_OVERLAY};
}}
QPushButton:disabled {{
    color: {TEXT_MUTED};
    border-color: {BORDER_SUBTLE};
    background-color: {BG_SURFACE};
}}

/* Primary action button */
QPushButton[class="primary"] {{
    background-color: {ACCENT};
    color: #0A0A0B;
    border: none;
    font-weight: 600;
    padding: 7px 16px;
}}
QPushButton[class="primary"]:hover {{
    background-color: {ACCENT_HOVER};
}}

/* Danger button */
QPushButton[class="danger"] {{
    background-color: transparent;
    color: {SEVERITY_HIGH};
    border: 1px solid {SEVERITY_HIGH};
}}
QPushButton[class="danger"]:hover {{
    background-color: {SEVERITY_HIGH};
    color: {TEXT_PRIMARY};
}}

/* Flat/ghost button */
QPushButton[class="flat"] {{
    background-color: transparent;
    border: none;
    color: {TEXT_SECONDARY};
    padding: 4px 10px;
}}
QPushButton[class="flat"]:hover {{
    color: {TEXT_PRIMARY};
    background-color: {BG_OVERLAY};
}}

/* ── Labels ───────────────────────────────────────────────────── */

QLabel {{
    background: transparent;
    color: {TEXT_PRIMARY};
}}
QLabel[class="secondary"] {{
    color: {TEXT_SECONDARY};
    font-size: 12px;
}}
QLabel[class="muted"] {{
    color: {TEXT_MUTED};
    font-size: 11px;
}}
QLabel[class="heading"] {{
    font-size: 18px;
    font-weight: 600;
    color: {TEXT_PRIMARY};
    letter-spacing: 0.2px;
}}
QLabel[class="subheading"] {{
    font-size: 11px;
    font-weight: 500;
    color: {TEXT_MUTED};
    letter-spacing: 1.2px;
    text-transform: uppercase;
}}
QLabel[class="stat-value"] {{
    font-size: 28px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
}}
QLabel[class="stat-label"] {{
    font-size: 10px;
    font-weight: 500;
    color: {TEXT_MUTED};
    letter-spacing: 0.8px;
}}

/* ── Tables ───────────────────────────────────────────────────── */

QTableWidget {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: 0;
    gridline-color: {BORDER_SUBTLE};
    font-size: 12px;
    alternate-background-color: {BG_ELEVATED};
    selection-background-color: {BG_OVERLAY};
}}
QTableWidget::item {{
    padding: 6px 10px;
    border: none;
    color: {TEXT_PRIMARY};
}}
QTableWidget::item:hover {{
    background-color: {BG_OVERLAY};
}}
QTableWidget::item:selected {{
    background-color: {BORDER_SUBTLE};
    color: {TEXT_PRIMARY};
}}
QHeaderView::section {{
    background-color: {BG_ELEVATED};
    color: {TEXT_MUTED};
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.8px;
    padding: 7px 10px;
    border: none;
    border-bottom: 1px solid {BORDER_DEFAULT};
    border-right: 1px solid {BORDER_SUBTLE};
}}
QHeaderView::section:last {{
    border-right: none;
}}
QHeaderView {{
    background-color: {BG_ELEVATED};
}}
QTableCornerButton::section {{
    background-color: {BG_ELEVATED};
    border: none;
}}

/* ── List widget ──────────────────────────────────────────────── */

QListWidget {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER_SUBTLE};
    font-size: 12px;
    outline: none;
}}
QListWidget::item {{
    padding: 8px 12px;
    border-bottom: 1px solid {BORDER_SUBTLE};
    color: {TEXT_SECONDARY};
}}
QListWidget::item:selected {{
    background-color: {BG_OVERLAY};
    color: {TEXT_PRIMARY};
    border-left: 2px solid {ACCENT};
}}
QListWidget::item:hover {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
}}

/* ── Text / Input ─────────────────────────────────────────────── */

QPlainTextEdit, QTextEdit {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_SUBTLE};
    font-family: {FONT_MONO};
    font-size: 12px;
    padding: 8px;
    selection-background-color: {BG_OVERLAY};
}}
QLineEdit {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_DEFAULT};
    padding: 5px 10px;
    font-size: 12px;
}}
QLineEdit:focus {{
    border-color: {ACCENT};
}}

/* ── Combo box ────────────────────────────────────────────────── */

QComboBox {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_DEFAULT};
    padding: 5px 10px;
    font-size: 12px;
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
}}
QComboBox QAbstractItemView {{
    background-color: {BG_ELEVATED};
    border: 1px solid {BORDER_DEFAULT};
    selection-background-color: {BG_OVERLAY};
    color: {TEXT_PRIMARY};
}}

/* ── Splitter ─────────────────────────────────────────────────── */

QSplitter::handle {{
    background-color: {BORDER_SUBTLE};
    width: 1px;
    height: 1px;
}}

/* ── Frame ────────────────────────────────────────────────────── */

QFrame[frameShape="4"],
QFrame[frameShape="5"] {{
    color: {BORDER_SUBTLE};
}}

/* ── Tooltip ──────────────────────────────────────────────────── */

QToolTip {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_DEFAULT};
    padding: 4px 8px;
    font-size: 12px;
}}

/* ── Message box ──────────────────────────────────────────────── */

QMessageBox {{
    background-color: {BG_SURFACE};
}}
QMessageBox QLabel {{
    color: {TEXT_PRIMARY};
}}

/* ── Tab bar ──────────────────────────────────────────────────── */

QTabBar::tab {{
    background-color: {BG_SURFACE};
    color: {TEXT_SECONDARY};
    border: none;
    border-bottom: 2px solid transparent;
    padding: 8px 16px;
    font-size: 12px;
    margin-right: 2px;
}}
QTabBar::tab:selected {{
    color: {TEXT_PRIMARY};
    border-bottom: 2px solid {ACCENT};
    background-color: {BG_ELEVATED};
}}
QTabBar::tab:hover {{
    color: {TEXT_PRIMARY};
    background-color: {BG_ELEVATED};
}}
QTabWidget::pane {{
    border: 1px solid {BORDER_SUBTLE};
    background-color: {BG_SURFACE};
}}

"""
