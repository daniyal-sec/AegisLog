<p align="center">
  <img src="assets/banner/github-banner.png" alt="AegisLog Banner" width="100%">
</p>

<h1 align="center">🛡️ AegisLog</h1>

<p align="center">
  <b>Transforming Authentication Logs into Actionable Security Intelligence</b>
</p>

<p align="center">
  A Python-based Security Log Investigation & Detection Engine for Blue Teamers, SOC Analysts, DFIR Practitioners, and Cybersecurity Learners.
</p>

<p align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0F172A?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-success?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-In%20Development-orange?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-66%20Passing-brightgreen?style=for-the-badge)

</p>

<p align="center">
  <a href="#-about-aegislog">About</a> •
  <a href="#-current-features">Features</a> •
  <a href="#-current-detection-rules">Detections</a> •
  <a href="#-usage">Usage</a> •
  <a href="#️-installation">Installation</a> •
  <a href="#-development-roadmap">Roadmap</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## 📖 About AegisLog

Modern systems generate huge volumes of authentication events — and hidden inside that noise can be:

- 🔓 Failed login attempts
- 💣 SSH brute-force attacks
- 🕵️ Username enumeration
- 🎯 Password spraying
- 🚪 Unauthorized access attempts
- ⚠️ Successful logins following repeated failures

Manually reviewing authentication logs for these patterns is slow, tedious, and error-prone.

**AegisLog** automates it: it parses authentication logs, converts raw events into structured data, correlates related activity, and applies detection rules to surface suspicious behavior — turning raw authentication noise into real, actionable security findings.

---

## 🚀 Why AegisLog?

After completing **Nexorium Pulse** — a multithreaded TCP port scanner — I wanted to move from offensive-security fundamentals into practical **Blue Team and SOC engineering**.

AegisLog is built around the skills used in real security monitoring and investigation work:

`Authentication Log Analysis` · `Detection Engineering` · `Event Correlation` · `Threat Classification` · `IP Enrichment` · `Real-Time Monitoring` · `Security Reporting` · `Incident Investigation`

The project is built incrementally with modular Python components, automated testing, living documentation, and validation against real authentication logs — not just synthetic data.

---

## ✨ Current Features

<table>
<tr><td valign="top">

**Log Processing**
- Linux OpenSSH log parsing
- Windows Security Event Log monitoring
- Windows Event IDs `4624` / `4625`
- File-based & real-time analysis (Linux + Windows)
- Structured `AuthEvent` data model
- Source IP + username extraction & classification
- Invalid-user identification
- Unsupported-event filtering
- File input validation & error handling

</td><td valign="top">

**Detection Engine**
- Authentication brute-force detection
- Username enumeration detection
- Password spraying detection
- Successful login after multiple failures
- Severity classification
- Source IP & account-based event grouping
- Structured `ThreatFinding` results
- Shared engine across Linux and Windows

</td></tr>
<tr><td valign="top">

**Real-Time Monitoring**
- Linux authentication log monitoring
- Windows Security Event Log monitoring
- New-event detection with startup filtering
- Live security alerts
- Real-time threat correlation

</td><td valign="top">

**Reporting & Testing**
- Human-readable investigation reports
- Threat severity summaries + recommendations
- Synthetic and real-log test coverage
- Kali Linux systemd journal validation
- Safe Windows brute-force detection tests
- Cross-platform detection workflow

</td></tr>
</table>

---

## 🔎 Current Detection Rules

| Detection | Description | Severity |
|---|---|:---:|
| **Authentication Brute Force** | Repeated failed authentication attempts against the same account | 🟠 HIGH |
| **Username Enumeration** | Multiple invalid usernames attempted from the same source | 🟡 MEDIUM |
| **Password Spraying** | One source attempts authentication against multiple accounts | 🟠 HIGH |
| **Successful Login After Failures** | Successful authentication following repeated failures | 🔴 CRITICAL |

The detection engine is shared between Linux and Windows authentication events.

---

## 🌐 Supported Platforms

| Platform | Log Source | Analysis | Real-Time |
|---|---|:---:|:---:|
| 🐧 Linux | OpenSSH Authentication Logs | ✅ | ✅ |
| 🪟 Windows | Security Event Log | ✅ | ✅ |

**Windows Events monitored:**

```text
4624 - Successful Logon
4625 - Failed Logon
```

Windows events are normalized into the same `AuthEvent` model used by Linux authentication events.

---

## 🏗 System Architecture

```text
                    AEGISLOG
                        |
            +-----------+-----------+
            |                       |
          Linux                   Windows
            |                       |
       Authentication          Security Event
           Logs                     Log
            |                       |
        parser.py             windows_parser.py
            |                       |
            +-----------+-----------+
                        |
                     AuthEvent
                        |
                  LiveDetector
                        |
                Detection Engine
                        |
                  ThreatFinding
                        |
                  IP Enrichment
                        |
                 Security Alert
                        |
                 Report Generator
                        |
              Investigation Report
```

AegisLog separates log ingestion, event normalization, detection, enrichment, and reporting — so new log sources and detection rules can be added without redesigning the application.

---

## 🧩 Authentication Event Model

Linux and Windows authentication events are normalized into the same `AuthEvent` structure, letting events from different operating systems flow through one detection pipeline:

```text
AuthEvent
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
```

---

## 🚀 Usage

### Analyze an Authentication Log

```powershell
python src/main.py sample_logs/linux_auth.log
```

Or point it at any supported OpenSSH authentication log:

```powershell
python src/main.py path/to/authentication.log
```

AegisLog will:

1. Validate the supplied file
2. Parse supported authentication events
3. Convert them into structured events
4. Run the available detection rules
5. Classify source information
6. Generate security findings
7. Generate an investigation report

**Example output:**

```text
Events Parsed : 18
Threats Found : 4

Attack Type : Authentication Brute Force
Severity    : HIGH

Attack Type : Username Enumeration
Severity    : MEDIUM

Attack Type : Successful Login After Multiple Failures
Severity    : CRITICAL

Attack Type : Password Spraying
Severity    : HIGH
```

---

## 🖥️ Linux Real-Time Monitoring

```powershell
python src/monitor.py
```

The monitor watches for new authentication events and feeds them through the live detection engine.

```text
==================================================
             AEGISLOG LIVE MONITOR
==================================================

[Aug 09 16:10:01] FAILED   kali            192.168.19.1
[Aug 09 16:10:05] FAILED   kali            192.168.19.1
[Aug 09 16:10:09] FAILED   kali            192.168.19.1
[Aug 09 16:10:13] FAILED   kali            192.168.19.1
[Aug 09 16:10:17] FAILED   kali            192.168.19.1

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
AEGISLOG SECURITY ALERT
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Attack Type : Authentication Brute Force
Severity    : HIGH
Source IP   : 192.168.19.1
Target User : kali
Attempts    : 5
First Seen  : Aug 09 16:10:01
Last Seen   : Aug 09 16:10:17

Recommendation
Investigate source IP immediately.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

---

## 🪟 Windows Real-Time Monitoring

Windows Security Event Log monitoring requires elevated privileges. Run your terminal **as Administrator**, then start:

```powershell
python src/windows_monitor.py
```

AegisLog begins monitoring from the current Security Event record — previously existing events are ignored, and only authentication events generated **after** the monitor starts are processed.

```text
============================================================
          AEGISLOG WINDOWS LIVE MONITOR
============================================================
Log        : Security
Status     : ACTIVE
Events     : 4624, 4625
Detection  : ENABLED
Press Ctrl+C to stop.
============================================================

Starting after event record: XXXXX

Waiting for NEW authentication events...
```

```text
------------------------------------------------------------
WINDOWS SUCCESSFUL AUTHENTICATION
------------------------------------------------------------
Username    : USERNAME
Source IP   : local
Status      : SUCCESS
Event ID    : 4624
Record      : XXXXX
------------------------------------------------------------
```

> ⚠️ Sensitive usernames, IP addresses, and system information should always be removed before publishing screenshots or logs.

---

## 🔐 IP Classification

AegisLog classifies authentication source addresses to add investigation context:

```text
Local · Loopback · Private · Public · Reserved · Documentation · Unknown
```

```text
Source IP : 192.168.1.50        Source IP : local
IP Type   : Private             IP Type   : Local
```

> Windows authentication events may not always provide a remote source IP, depending on the authentication type and system configuration.

---

## 🚨 Security Alerts

When suspicious activity is detected, AegisLog generates a structured security alert:

```text
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
```

---

## 📄 Reports

AegisLog generates human-readable investigation reports containing:

`Analysis summary` · `Threat count` · `Severity classification` · `Attack type` · `Source IP & classification` · `Target account` · `Attempt count` · `First/last seen timestamps` · `Security recommendation`

```text
Generated on : Aug 09 2026 15:33:54
Log File     : linux_auth.log

ANALYSIS SUMMARY

Events Parsed : 18
Threats Found : 4

THREAT SEVERITY

Critical : 1
High     : 2
Medium   : 1
Low      : 0
```

Generated local reports are excluded from Git where appropriate.

---

## 🧪 Testing

### Safe Windows Detection Test

No need to intentionally fail logins against a real Windows account — AegisLog ships a safe simulated test that runs synthetic events through the actual `LiveDetector`:

```powershell
python tests/test_windows_detection.py
```

```text
============================================================
       AEGISLOG WINDOWS DETECTION TEST
============================================================

Attempt 1
Attempt 2
Attempt 3
Attempt 4
Attempt 5

Attack Type : Authentication Brute Force
Severity    : HIGH
Attempts    : 5
```

### Real-World Testing

AegisLog has been validated against a real **OpenSSH server on Kali Linux**, running inside an isolated VM. Controlled authentication activity was generated, recorded by the Kali `systemd` journal, exported, and analyzed directly by AegisLog.

**Linux testing confirmed:**
Genuine OpenSSH parsing · Failed/successful authentication detection · Repeated-failure detection · Successful login after failures · Invalid-username detection · Multi-account activity · Source IP extraction · Real-time monitoring · Report generation

**Windows testing confirmed:**
Security Event Log access · New-event monitoring · Event IDs `4624`/`4625` · Username extraction · Local & loopback authentication handling · Source IP extraction (when available) · Event normalization · `LiveDetector` integration

> Sensitive environment-specific information is excluded from public documentation and screenshots.

---

## 📸 Screenshots

<p align="center">
  <img src="assets/logo/aegislog-logo.png" alt="AegisLog Logo" width="220">
</p>

**Desktop Investigation Workspace** — a PySide6 desktop application providing a dark, SOC-style workspace for monitoring, alert review, investigation, reporting, and diagnostics.

**Real OpenSSH Detection** — output produced while analyzing authentication events from a real OpenSSH server in the controlled Kali Linux test environment:

<p align="center">
  <img src="screenshots/linux-real-log-detection.png" alt="AegisLog Real OpenSSH Detection" width="900">
</p>

> Sensitive environment-specific information has been redacted from public screenshots.

---

## 📚 Documentation

AegisLog is documented alongside development, not only after the fact. Available now inside [`docs/`](docs/):

`Architecture` · `Development Roadmap` · `Supported Log Format` · `Detection Engine` · `Real-World Testing` · `Windows Monitoring`

**Planned:** Advanced Event Correlation · JSON Reports · HTML Investigation Reports · Investigation Timeline · GUI Design · Expanded Automated Testing · Changelog

---

## 📂 Project Structure

```text
AegisLog
│
├── assets/                    Banners, icons, logo
├── docs/                      ARCHITECTURE, ROADMAP, LOG_FORMAT, DETECTION_ENGINE, TESTING
├── reports/                   Generated investigation reports
├── sample_logs/                linux_auth.log
├── screenshots/                linux-real-log-detection.png
│
├── src/
│   ├── main.py                CLI entry point (file analysis)
│   ├── parser.py               Linux OpenSSH log parser
│   ├── windows_parser.py       Windows Security Event Log parser
│   ├── models.py                AuthEvent / ThreatFinding models
│   ├── detector.py              Detection engine
│   ├── live_detector.py         Shared real-time detection engine
│   ├── monitor.py               Linux real-time monitor
│   ├── windows_monitor.py       Windows real-time monitor
│   ├── report_generator.py     Investigation report builder
│   └── utils.py
│
├── tests/
│   └── test_windows_detection.py
│
├── .gitignore
├── README.md
├── LICENSE
└── requirements.txt
```

---

## ⚙️ Installation

**Requirements**
- Python 3.11+
- Windows or Linux
- Administrator privileges for Windows Security Event Log monitoring

**Dependencies**

```text
portalocker==4.1.0
pywin32==312
PySide6
```

**Clone the repository**

```bash
git clone https://github.com/daniyal-sec/AegisLog.git
cd AegisLog
```

**Create and activate a virtual environment** (Windows)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Install dependencies**

```powershell
python -m pip install -r requirements.txt
```

> `.venv/` is intentionally excluded from Git.

---

## 🔐 Security & Privacy

Authentication logs may contain sensitive information, including usernames, internal IP addresses, hostnames, timestamps, and infrastructure details. Real authentication logs used during development are **never** committed — only synthetic or sanitized sample logs are.

**Never commit:** passwords, API keys, authentication tokens, private credentials, sensitive Windows event data, personal authentication logs, or local Python environments (`.venv/`).

Generated reports and local testing logs are excluded from Git where appropriate.

> ⚠️ Only monitor systems and accounts for which you have appropriate authorization.

---

## 🗺 Development Roadmap

| Phase | Focus | Status |
|---|---|:---:|
| 1 | Foundation — repo setup, branding, initial docs, architecture | ✅ Complete |
| 2 | Detection Engine — parser, `AuthEvent`, brute force / enumeration / spraying detection, severity & IP classification | ✅ Complete |
| 3 | Platform & Real-Time Monitoring — Linux + Windows monitoring, shared detection pipeline, live alerts | ✅ Complete |
| 4 | Investigation & Reporting — investigation workspace, correlated timelines, report generation | ✅ Complete |
| 5 | Desktop GUI Foundation — PySide6 app, dashboard, live monitor, alerts, investigation, reports, settings | ✅ Complete |
| 6 | Investigation Integration & Stability — backend-integrated views, QThread fixes, 66 automated tests | ✅ Complete |
| 7 | End-to-End GUI Integration — full manual verification across all views | ✅ Complete |
| 8 | Visual Identity & GUI Aesthetics — dark SOC visual system, BrandMark, launch screen | ✅ Complete |
| — | **Pre-Release Hardening** — dependency cleanup, expanded tests, advanced correlation, additional detection rules, configurable thresholds, JSON/HTML reporting, packaging, final security review | 🚧 In Progress |

<details>
<summary><b>Full phase-by-phase breakdown</b> (click to expand)</summary>

**Phase 1 — Foundation ✅**
Repository Setup · Branding · Initial Documentation · Project Architecture

**Phase 2 — Detection Engine ✅**
Authentication Log Parser · `AuthEvent` Model · Brute Force Detection · Username Enumeration Detection · Successful Login After Multiple Failures · Password Spraying Detection · File Input Handling · Real Linux Log Testing · Severity Classification · Source IP Classification

**Phase 3 — Platform & Real-Time Monitoring ✅**
Linux Real-Time Monitoring · Windows Event Log Support (4624 / 4625) · Windows Event Parsing · Shared Cross-Platform Detection Pipeline · Real-Time Security Alerts · Investigation Report Generation
🚧 Advanced Event Correlation · 🚧 Additional Detection Rules

**Phase 4 — Investigation & Reporting ✅**
Investigation Workspace · Correlated Event Timeline · Event Detail Inspection · Investigation Summary · Recommendations · Report Generation
🚧 JSON Reports · 🚧 HTML Investigation Reports · 🚧 Advanced Correlation · 🚧 Configurable Detection Thresholds

**Phase 5 — Desktop GUI Foundation ✅**
PySide6 Desktop Application · Dashboard · Live Monitor · Security Alerts · Investigation · Reports · Settings · SQLite-backed GUI data loading · Background worker threads · Responsive navigation

**Phase 6 — Investigation Integration & Stability ✅**
Backend-integrated Investigation view · Correlated timelines · Event detail dialog · Finding selection persistence · Cross-view Investigate workflow · QThread lifecycle fixes · 66 automated tests passing

**Phase 7 — End-to-End GUI Integration ✅**
Manual end-to-end verification across Dashboard, Live Monitor, Security Alerts, Investigation, Reports, and Settings · Backend logic preserved

**Phase 8 — Visual Identity & GUI Aesthetics ✅**
Dark SOC workstation visual system · Application-wide styling · Sidebar branding refinement · Section header system · Table hover states · Live event row highlighting · View refinements across Alerts, Investigation, Reports, Settings

**Phase 8.1 — BrandMark & Launch Screen ✅**
Dedicated Launch Screen · Native geometric AegisLog BrandMark · Wordmark hierarchy · Security Investigation tagline · Startup status modules (database, Windows Security Log, monitor readiness) · Enter Workspace flow · Sidebar BrandMark integration

**Phase 8.2 — Database & Branding Refinement ✅**
Resolved launch-screen database status issue · Shared absolute database path · Operational database verification · Refined geometric BrandMark · Consistent sidebar iconography · Launch/workspace branding alignment · 66/66 tests passing · No backend logic modified

**Next — Pre-Release Hardening 🚧**
Dependency and installation cleanup · Expanded GUI/integration tests · Advanced event correlation · Additional detection rules · Configurable detection thresholds · JSON/HTML reporting · Release packaging · Final security/privacy review · Public release preparation

</details>

### 🎯 Long-Term Vision

AegisLog is designed to evolve beyond a simple authentication log parser into a lightweight **Blue Team investigation platform** — combining multi-source authentication log analysis, detection engineering, event correlation, threat classification, IP enrichment, real-time monitoring, investigation timelines, and cross-platform (Windows + Linux) analysis in a local SOC-style analyst workspace.

---

## ⚠️ Project Status

AegisLog has reached a **functional cross-platform authentication monitoring and investigation MVP**, currently supporting:

Linux & Windows authentication analysis and real-time monitoring · Windows 4624/4625 processing · Shared cross-platform detection · IP classification · Real-time security alerts · SQLite-backed event and finding storage · Investigation workspace with correlated event timelines · Human-readable investigation reports · A full PySide6 desktop application (Dashboard, Live Monitor, Security Alerts, Investigation, Reports, Settings) with launch-time health checks, a dark SOC visual system, thread-safe background data loading, and **66 automated tests passing**.

The project is now moving from core application development into **pre-release hardening and feature expansion** — advanced correlation, additional detection rules, configurable thresholds, additional report formats, dependency cleanup, expanded testing, packaging, and final release review.

> AegisLog should currently be considered an **educational and investigation-support tool**, not a replacement for production SIEM, EDR, XDR, or enterprise security-monitoring platforms.

---

## 🤝 Contributing

Suggestions, improvements, and constructive feedback are welcome! You can:

- 🐛 Open an Issue
- 🔧 Submit a Pull Request
- 💡 Suggest new detection rules
- 📋 Report parser compatibility issues
- 📝 Improve documentation
- 🧪 Contribute sanitized test cases

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">

<b>Built for the Cybersecurity Community</b>

<br>

Analyze • Detect • Correlate • Investigate

<br><br>

⭐ If you find AegisLog useful, consider giving the project a star.

</p>