<p align="center">
  <img src="assets/banner/github-banner.png" alt="AegisLog Banner" width="100%">
</p>

<h1 align="center">🛡️ AegisLog</h1>

<p align="center">
<b>Transforming Authentication Logs into Actionable Security Intelligence</b>
</p>

<p align="center">
A Python-based Security Log Investigation & Detection Engine built for Blue Teamers, SOC Analysts, DFIR Practitioners, and Cybersecurity Learners.
</p>

<p align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0F172A?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-success?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-In%20Development-orange?style=for-the-badge)

</p>

---

# 📖 About AegisLog

Modern systems generate thousands of authentication events every day.

Among these events may be:

- Failed login attempts
- Brute-force attacks
- Username enumeration
- Password spraying
- Unauthorized access attempts
- Suspicious successful logins

Finding these manually is time-consuming and error-prone.

**AegisLog** automates the investigation process by parsing authentication logs, detecting suspicious activity, correlating related events, and generating investigation-ready findings.

The goal is not simply to parse logs—but to transform raw authentication events into meaningful security intelligence.

---

# 🚀 Why AegisLog?

After completing **Nexorium Pulse**, a multithreaded TCP port scanner, I wanted to move beyond offensive security fundamentals into **Blue Team engineering**.

AegisLog is the second major project in my cybersecurity portfolio and focuses on practical SOC analyst skills:

- Authentication Log Analysis
- Detection Engineering
- Event Correlation
- Security Reporting
- Threat Investigation

Every feature is designed with clean architecture, modular development, and detailed documentation to simulate professional software engineering practices.

---

# ✨ Current Features

- ✅ Parse Linux SSH authentication logs
- ✅ Parse complete authentication log files
- ✅ Convert raw logs into structured `AuthEvent` objects
- ✅ SSH Brute Force Detection
- ✅ Username Enumeration Detection
- ✅ Modular Detection Engine
- ✅ ThreatFinding Data Model
- ✅ Cross-platform (Windows & Linux)
- ✅ Enterprise-inspired Project Architecture
- ✅ Professional Documentation

---

# 🚧 Detection Roadmap

## ✅ Implemented

- SSH Brute Force Detection
- Username Enumeration Detection

## 🚧 In Progress

- Successful Login After Multiple Failures
- Password Spray Detection
- Root Login Detection
- Suspicious IP Detection
- Severity Classification
- Event Correlation
- Timeline Generation
- HTML Investigation Reports
- JSON Reports
- Desktop GUI

---

# 🏗 System Architecture

```
Authentication Logs
        │
        ▼
     parser.py
        │
        ▼
   AuthEvent Model
        │
        ▼
    detector.py
        │
        ▼
 ThreatFinding Model
        │
        ▼
 Report Generator
        │
        ▼
 Investigation Report
        │
        ▼
 Desktop GUI
```

Detailed documentation is available inside:

```
docs/
```

---

# 📂 Project Structure

```
AegisLog
│
├── assets/
│   ├── banner/
│   ├── icons/
│   └── logo/
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ROADMAP.md
│   ├── LOG_FORMAT.md
│   └── DETECTION_ENGINE.md
│
├── reports/
│
├── sample_logs/
│   └── linux_auth.log
│
├── screenshots/
│
├── src/
│   ├── main.py
│   ├── parser.py
│   ├── detector.py
│   ├── models.py
│   ├── report_generator.py
│   └── utils.py
│
├── README.md
├── LICENSE
└── requirements.txt
```

---

# 📸 Screenshots

### Project Logo

<p align="center">
<img src="assets/logo/aegislog-logo.png" width="220">
</p>

### Console Output

Console screenshots and GUI previews will be added as development progresses.

---

# 📚 Documentation

Project documentation grows together with the codebase.

Current documentation includes:

- ✅ Architecture
- ✅ Roadmap
- ✅ Log Format

Upcoming documentation:

- Detection Engine
- Report Generator
- GUI Design
- Testing Guide
- Changelog

---

# 🗺 Development Roadmap

## Phase 1 ✅

- Repository Setup
- Branding
- Documentation
- Project Architecture

## Phase 2 🚧

- Authentication Log Parser
- Event Models
- Detection Engine

## Phase 3

- Event Correlation
- Report Generator
- HTML & JSON Reports

## Phase 4

- Desktop GUI
- Performance Optimization
- Release v1.0

---

# ⚙ Installation

Clone the repository

```bash
git clone https://github.com/daniyal-sec/AegisLog.git
```

Enter the project

```bash
cd AegisLog
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# 🚀 Usage

Run AegisLog

```bash
python src/main.py
```

Current output includes:

- Parsed Authentication Events
- SSH Brute Force Detection
- Username Enumeration Detection

Additional reporting capabilities are currently under development.

---

# 🎯 Long-Term Vision

AegisLog is designed to evolve beyond a simple log parser.

The objective is to become a lightweight Blue Team investigation platform capable of:

- Authentication Log Analysis
- Detection Engineering
- Event Correlation
- Threat Classification
- Investigation Report Generation
- Interactive Desktop Dashboard

---

# 🤝 Contributing

Suggestions, improvements, and constructive feedback are always welcome.

Feel free to:

- Open an Issue
- Submit a Pull Request
- Suggest new detection rules
- Improve documentation

---

# 📄 License

This project is licensed under the MIT License.

---

<p align="center">

## Built for the Cybersecurity Community

### Analyze • Detect • Correlate • Investigate

⭐ If you find this project useful, consider giving it a star.

</p>