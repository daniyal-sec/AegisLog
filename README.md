<p align="center">
  <img src="assets/banner/github-banner.png" alt="AegisLog Banner" width="100%">
</p>

<h1 align="center">AEGISLOG</h1>

<p align="center">
  <b>SECURITY INVESTIGATION</b>
</p>

<p align="center">
  Transforming Authentication Logs into Actionable Security Intelligence
</p>

<p align="center">
  A Python-based security log investigation and detection platform for Blue Teamers, SOC analysts, DFIR practitioners, and cybersecurity learners.
</p>

<p align="center">






</p>

📖 About AegisLog

Modern systems generate large volumes of authentication events. Buried inside normal activity can be failed login attempts, brute-force behavior, username enumeration, password spraying, unauthorized access attempts, and successful logins following repeated failures.

AegisLog turns that raw authentication activity into structured security data, detections, correlated findings, investigation timelines, and human-readable reports.

The project combines a modular Python detection backend with a PySide6 desktop SOC-style investigation workspace.

Core workflow

INGEST
  ↓
PARSE & NORMALIZE
  ↓
DETECT
  ↓
CORRELATE
  ↓
CLASSIFY
  ↓
ALERT
  ↓
INVESTIGATE
  ↓
REPORT

✨ What AegisLog Does

🔍 Authentication Log Processing

✅ Linux OpenSSH authentication log parsing

✅ Windows Security Event Log monitoring

✅ Windows Event ID 4624 support

✅ Windows Event ID 4625 support

✅ File-based authentication log analysis

✅ Real-time Linux authentication monitoring

✅ Real-time Windows authentication monitoring

✅ Shared AuthEvent data model

✅ Username extraction

✅ Source IP extraction and classification

✅ Authentication status extraction

✅ SSH service and connection information

✅ Invalid-user identification

✅ Unsupported-event filtering

✅ Input validation and error handling

🧠 Detection Engine

✅ Authentication Brute Force Detection

✅ Username Enumeration Detection

✅ Password Spraying Detection

✅ Successful Login After Multiple Failures Detection

✅ Severity classification

✅ Source/account-based event grouping

✅ Structured ThreatFinding results

✅ Shared detection pipeline for Linux and Windows events

📡 Real-Time Monitoring

✅ Linux authentication monitoring

✅ Windows Security Event Log monitoring

✅ New-event detection

✅ Existing-event filtering at monitor startup

✅ Live security alerts

✅ Real-time threat correlation

✅ Background monitoring without blocking the GUI

🖥️ Desktop Investigation Workspace

The AegisLog PySide6 GUI now provides a complete analyst workflow:

✅ Launch / startup screen

✅ Database health check

✅ Windows Security Log availability check

✅ Monitor readiness status

✅ Dashboard

✅ Live Monitor

✅ Security Alerts

✅ Investigation workspace

✅ Reports

✅ Settings / diagnostics

✅ Cross-view navigation

✅ Finding-to-investigation workflow

✅ Dark SOC workstation visual system

✅ AegisLog geometric brand identity

🚨 Security Alerts

The Security Alerts workspace provides:

Severity filtering: ALL, CRITICAL, HIGH, MEDIUM, LOW

Finding summaries

Source → Target relationships

Attempts, duration, failed, and successful metrics

First Seen / Last Seen timestamps

Automatic background refresh

[NEW] finding indicators for newly detected incidents

Direct Investigate navigation

Empty and database-error states

🔎 Investigation

The Investigation workspace provides:

Finding selection

Finding severity and attack type

Source → Target context

Incident overview metrics

First Seen / Last Seen timestamps

Correlated event timeline

Event status, username, source IP, and service

Double-click event details

Raw Windows event information

Investigation summary

Backend-generated recommendations

📄 Reporting

✅ Structured threat findings

✅ Human-readable investigation reports

✅ Severity summaries

✅ Source IP information

✅ Target account information

✅ First/Last Seen timestamps

✅ Security recommendations

✅ GUI report generation and viewing

✅ Local report export

⚙️ Diagnostics & Settings

The Settings workspace exposes application/runtime information including:

Python version

PySide6 version

Platform

Database state

Windows security-log availability

Relevant directories

CLI/application configuration

Graceful unavailable/error states

🔎 Detection Rules

Detection

Description

Severity

Authentication Brute Force

Repeated failed authentication attempts against the same account

HIGH

Username Enumeration

Multiple invalid usernames attempted from the same source

MEDIUM

Password Spraying

One source attempts authentication against multiple accounts

HIGH

Successful Login After Failures

Successful authentication following repeated failures

CRITICAL

The detection engine is shared between Linux and Windows authentication events.

🌐 Supported Platforms

Platform

Log Source

Analysis

Real-Time

GUI

Linux

OpenSSH Authentication Logs

✅

✅

⚠️

Windows

Security Event Log

✅

✅

✅

Windows Events

AegisLog currently monitors:

4624 - Successful Logon
4625 - Failed Logon

Windows authentication events are normalized into the same AuthEvent model used by Linux authentication events.

Windows note: Security Event Log monitoring may require Administrator privileges depending on the local system configuration.

🏗 Architecture

AegisLog keeps ingestion, normalization, detection, storage, correlation, monitoring, reporting, and presentation separated.

                    AEGISLOG
                       │
          ┌────────────┴────────────┐
          │                         │
        Linux                    Windows
          │                         │
   OpenSSH Logs              Security Event Log
          │                         │
      parser.py              windows_parser.py
          │                         │
          └────────────┬────────────┘
                       │
                    AuthEvent
                       │
                ┌──────┴──────┐
                │             │
          Detection       Storage
           Engine         / SQLite
                │             │
          ThreatFinding      │
                │             │
          Correlation ◄───────┘
                │
         Security Alert
                │
       ┌────────┼────────┐
       │        │        │
    Monitor  GUI     Reports
       │        │        │
       │   ┌────┴────┐   │
       │   │Dashboard│   │
       │   │Alerts   │   │
       │   │Investig.│   │
       │   │Settings │   │
       │   └─────────┘   │
       └────────┬────────┘
                │
       Investigation Report

🧩 Authentication Event Model

Linux and Windows authentication events are normalized into the shared AuthEvent structure.

AuthEvent
│
├── timestamp
├── hostname
├── service
├── pid
├── status
├── username
├── source_ip
├── source_port
├── protocol
├── invalid_user
└── raw_log

This common model allows different operating-system sources to pass through the same detection and investigation pipeline.

🖥️ Desktop GUI

AegisLog now launches into a dedicated startup screen before entering the analyst workspace.

┌──────────────────────────────────────────────────────────┐
│                     AEGISLOG                             │
│                 SECURITY INVESTIGATION                   │
│                                                          │
│                    LOCAL SOC WORKSTATION                 │
│                                                          │
│        MONITOR        DETECT        INVESTIGATE          │
│                                                          │
│        DATABASE                  OPERATIONAL             │
│        WINDOWS SECURITY LOG      AVAILABLE               │
│        MONITOR                   READY                   │
│                                                          │
│                 ENTER WORKSPACE →                        │
└──────────────────────────────────────────────────────────┘

After entering the workspace, the analyst can move through:

Dashboard
   │
   ├── Live Monitor
   │
   ├── Security Alerts
   │
   ├── Investigation
   │
   ├── Reports
   │
   └── Settings

GUI design principles

The interface intentionally uses a restrained dark SOC workstation aesthetic:

Near-black application background

Graphite surfaces

White primary typography

Muted blue-gray secondary text

Amber accent for active states

Severity-specific colors only where useful

Minimal borders and separators

Consistent navigation

No decorative UI that interferes with investigation workflows

Threading

Database and monitoring operations are kept away from the main Qt event loop where required.

The GUI uses Qt worker threads for operations such as:

Dashboard data loading

Security Alert refreshes

Investigation finding loading

Investigation timeline loading

Startup health checks

Windows event monitoring

This keeps the interface responsive during database queries and live event collection.

🚀 Usage

1. Launch the Desktop Application

python src/app.py

The application opens on the AegisLog launch screen and performs startup checks before entering the workspace.

2. Analyze an Authentication Log

python src/main.py sample_logs/linux_auth.log

Or provide another supported OpenSSH authentication log:

python src/main.py path/to/authentication.log

AegisLog will:

Validate the supplied file.

Parse supported authentication events.

Normalize events into structured data.

Run detection rules.

Classify source information.

Generate security findings.

Generate an investigation report.

3. Linux Real-Time Monitoring

python src/monitor.py

The Linux monitor watches for new authentication events and sends them through the live detection engine.

4. Windows Real-Time Monitoring

Run the terminal as Administrator when required:

python src/windows_monitor.py

AegisLog monitors the Windows Security log for new authentication events.

Previously existing events are ignored when the monitor starts.

5. Investigation CLI

The existing investigation workflow remains available:

python src/investigation.py

🧪 Testing

AegisLog uses automated tests to protect the backend detection and correlation logic while the GUI evolves.

Run the complete test suite:

python -m pytest -v

Current verification

66 passed
0 failed

The GUI work was implemented without changing the core backend detection/correlation behavior.

A safe Windows detection test is also available:

python tests/test_windows_detection.py

This uses simulated authentication events rather than intentionally generating repeated failed logins against a real account.

🧪 Real-World Validation

AegisLog has been validated using authentication activity from a real OpenSSH server running inside an isolated Kali Linux virtual-machine environment.

Testing verified:

Genuine OpenSSH authentication parsing

Failed authentication detection

Successful authentication detection

Repeated authentication failure detection

Successful login following multiple failures

Invalid username detection

Multiple-account authentication activity

Source IP extraction

Real-time Linux monitoring

Security report generation

Windows testing has also verified:

Security Event Log access

New-event monitoring

Event ID 4624

Event ID 4625

Username extraction

Local authentication handling

Loopback authentication handling

Source IP extraction when available

Windows event normalization

Shared LiveDetector integration

GUI integration with real SQLite data

Sensitive environment-specific information should be removed before publishing logs or screenshots.

🔐 IP Classification

AegisLog classifies authentication source addresses to provide investigation context.

Supported classifications include:

Local
Loopback
Private
Public
Reserved
Documentation
Unknown

Example:

Source IP : 192.168.1.50
IP Type   : Private

For local authentication:

Source IP : local
IP Type   : Local

Windows authentication events may not always expose a remote source IP depending on the authentication type and system configuration.

🚨 Security Alerts

When suspicious activity is detected, AegisLog produces a structured finding such as:

==================================================
            AEGISLOG SECURITY ALERT
==================================================

Attack Type : Authentication Brute Force
Severity    : HIGH
Source IP   : 192.168.1.50
Target User : TEST_USER
Attempts    : 5
First Seen  : Aug 09 16:10:01
Last Seen   : Aug 09 16:10:17

Recommendation
Investigate source IP immediately.

==================================================

The desktop Security Alerts view exposes the same investigation data through a persistent analyst workspace.

📄 Reports

AegisLog generates human-readable investigation reports containing information such as:

Analysis summary

Threat count

Severity classification

Attack type

Source IP

IP classification

Target account

Attempt count

First Seen timestamp

Last Seen timestamp

Security recommendation

Reports can also be generated and opened through the desktop Reports workspace.

Generated local reports should not be committed when they contain environment-specific information.

📸 Screenshots

AegisLog Logo

<p align="center">
  <img src="assets/logo/aegislog-logo.png" alt="AegisLog Logo" width="220">
</p>

Desktop Workspace

The desktop application provides a dark SOC-style investigation workspace with Dashboard, Live Monitor, Security Alerts, Investigation, Reports, and Settings views.

Real OpenSSH Detection

<p align="center">
  <img src="screenshots/linux-real-log-detection.png" alt="AegisLog Real OpenSSH Detection" width="900">
</p>

Sensitive environment-specific information should be redacted before publishing screenshots.

📂 Project Structure

AegisLog
│
├── assets/
│   ├── banner/
│   ├── icons/
│   └── logo/
│
├── data/
│   └── aegislog.db
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ROADMAP.md
│   ├── LOG_FORMAT.md
│   ├── DETECTION_ENGINE.md
│   └── TESTING.md
│
├── reports/
│
├── sample_logs/
│   └── linux_auth.log
│
├── screenshots/
│   └── linux-real-log-detection.png
│
├── src/
│   ├── app.py
│   ├── main.py
│   ├── investigation.py
│   ├── parser.py
│   ├── detector.py
│   ├── live_detector.py
│   ├── monitor.py
│   ├── windows_monitor.py
│   ├── windows_parser.py
│   ├── models.py
│   ├── report_generator.py
│   ├── storage.py
│   ├── utils.py
│   │
│   └── gui/
│       ├── __init__.py
│       ├── launch_view.py
│       ├── main_window.py
│       ├── dashboard.py
│       ├── monitor_view.py
│       ├── alerts_view.py
│       ├── investigation_view.py
│       ├── reports_view.py
│       ├── settings_view.py
│       └── styles.py
│
├── tests/
│
├── .gitignore
├── README.md
├── LICENSE
├── requirements.txt
└── requirements-dev.txt

data/aegislog.db and generated reports are local runtime artifacts and should not contain sensitive data in a public repository.

⚙️ Installation

Requirements

Python 3.11+

Windows or Linux for backend functionality

Administrator privileges when required for Windows Security Event Log access

PySide6 for the desktop GUI

pywin32 for Windows Event Log functionality

Backend dependencies

portalocker==4.1.0
pywin32==312

Development dependency

pytest==9.1.1

GUI dependency: The current requirements.txt does not yet declare PySide6. Until it is added to the project dependency file, install it separately with python -m pip install PySide6.

Clone the Repository

git clone https://github.com/daniyal-sec/AegisLog.git
cd AegisLog

Create a Virtual Environment

Windows:

python -m venv .venv

Activate:

.venv\Scripts\Activate.ps1

Install project dependencies:

python -m pip install -r requirements.txt

Install GUI dependency:

python -m pip install PySide6

Install development/test dependencies:

python -m pip install -r requirements-dev.txt

Launch the GUI:

python src/app.py

🔐 Security & Privacy

Authentication logs can contain sensitive information including:

Usernames

Internal IP addresses

Hostnames

Authentication timestamps

Infrastructure information

Windows Security Event details

Do not commit:

Passwords

API keys

Authentication tokens

Private credentials

Sensitive Windows event data

Personal authentication logs

Local Python environments

Use synthetic or sanitized data for public examples.

Only monitor systems and accounts for which you have appropriate authorization.

🗺 Development Status

Foundation — Complete ✅

Repository architecture

Branding

Documentation

Core project structure

Detection Engine — Complete ✅

Authentication parsing

Shared AuthEvent model

Brute-force detection

Username enumeration

Password spraying

Successful-after-failures detection

Severity classification

Source IP classification

Cross-platform detection pipeline

Platform & Monitoring — Complete ✅

Linux authentication monitoring

Windows Security Event monitoring

Windows 4624 / 4625

Real-time security alerts

Existing-event filtering

Shared live detection pipeline

Investigation & Reporting — Functional 🚧

Correlated findings

Investigation workspace

Event timelines

Event details

Recommendations

Human-readable reports

GUI report workflow

Advanced correlation improvements

Additional report formats

Desktop Application — Functional 🚧

Launch screen

Startup health checks

Dashboard

Live Monitor

Security Alerts

Investigation

Reports

Settings

Thread-safe background loading

Dark SOC workstation UI

Cross-view investigation workflow

Automated regression verification

Next Development Focus 🚧

Dependency cleanup and packaging

Expanded automated GUI testing

Additional detection rules

More advanced event correlation

JSON/HTML reporting

Investigation timeline improvements

Configuration and detection thresholds

Release preparation

🎯 Long-Term Vision

AegisLog is evolving from an authentication-log parser into a lightweight local Blue Team investigation platform.

The long-term objective is to provide:

Multi-source authentication log analysis

Detection engineering

Event correlation

Threat classification

IP enrichment

Real-time monitoring

Interactive investigation workflows

Investigation timelines

Security reporting

Windows and Linux analysis

A responsive analyst desktop workspace

AegisLog is intentionally focused on understanding the security data pipeline rather than attempting to replace a production SIEM, EDR, XDR, or enterprise SOC platform.

⚠️ Project Status

AegisLog is currently in active development.

The backend detection and monitoring pipeline is functional, and the PySide6 desktop investigation workspace is now operational.

Current validation includes:

Backend / Detection        ✅
Linux Monitoring           ✅
Windows Monitoring         ✅
Security Alerts            ✅
Investigation Workflow     ✅
Reports                    ✅
Settings / Diagnostics     ✅
Desktop Launch Screen      ✅
Thread-Safe GUI Loading    ✅
Automated Tests             66 passed

The project should currently be considered an educational and investigation-support platform rather than production security infrastructure.

🤝 Contributing

Suggestions, improvements, and constructive feedback are welcome.

You can:

Open an Issue

Submit a Pull Request

Suggest new detection rules

Report parser compatibility issues

Improve documentation

Contribute sanitized test cases

Improve GUI workflows

Add additional platform support

📄 License

This project is licensed under the MIT License.

<p align="center">

<b>Built for the Cybersecurity Community</b>

<br>

Analyze • Detect • Correlate • Investigate

<br><br>

⭐ If you find AegisLog useful, consider giving the project a star.

</p>