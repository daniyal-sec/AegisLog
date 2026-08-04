<p align="center">
  <img src="assets/banner/github-banner.png" alt="AegisLog Banner" width="100%">
</p>

<h1 align="center">🛡️ AegisLog</h1>

<p align="center">
<b>Transforming Authentication Logs into Actionable Security Intelligence</b>
</p>

<p align="center">
A Python-based Security Log Investigation & Detection Engine for Blue Teamers, SOC Analysts, and Cybersecurity Learners.
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
- Credential stuffing
- Unauthorized access attempts
- Suspicious successful logins

Finding these manually is time-consuming and error-prone.

**AegisLog** automates this investigation process by analyzing authentication logs, detecting suspicious activity, correlating related events, and generating investigation-ready reports.

The goal is not just to parse logs—but to transform raw authentication events into meaningful security intelligence.

---

# 🚀 Why AegisLog?

After completing **Nexorium Pulse**, a multithreaded TCP port scanner, I wanted to move from offensive security fundamentals toward **Blue Team operations**.

AegisLog is the second major project in my cybersecurity portfolio and focuses on one of the most important skills for SOC Analysts:

- Authentication Log Analysis
- Detection Engineering
- Event Correlation
- Security Reporting

Every feature is being documented from planning to implementation to demonstrate professional software engineering practices.

---

# ✨ Current Features

- Authentication Log Parsing
- Log Validation
- Structured Event Processing
- Investigation Report Generation
- Cross-platform Support
- Modular Python Architecture
- Enterprise-inspired Documentation

---

# 🚧 Planned Detection Capabilities

- Failed Login Detection
- Brute Force Detection
- Password Spray Detection
- Successful Login After Multiple Failures
- Account Lock Detection
- Severity Classification
- Event Correlation
- Suspicious IP Detection
- Timeline Generation
- HTML Investigation Reports
- Desktop GUI

---

# 🏗 Architecture

```
Authentication Logs
        │
        ▼
   Log Parser
        │
        ▼
 Event Validation
        │
        ▼
 Detection Engine
        │
        ▼
 Event Correlation
        │
        ▼
 Severity Engine
        │
        ▼
 Report Generator
        │
        ▼
 Investigation Report
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
│   └── LOG_FORMAT.md
│
├── reports/
│
├── sample_logs/
│
├── screenshots/
│
├── src/
│   ├── parser.py
│   ├── models.py
│   ├── detector.py
│   ├── report_generator.py
│   ├── utils.py
│   └── main.py
│
├── README.md
└── requirements.txt
```

---

# 📸 Screenshots

### Logo

<p align="center">
<img src="assets/logo/aegislog-logo.png" width="220">
</p>

### Application

GUI screenshots will be added as development progresses.

---

# 📚 Documentation

Project documentation is maintained throughout development.

Current documents include:

- Architecture
- Roadmap
- Log Format

Additional documentation will include:

- Detection Rules
- Report Engine
- GUI Design
- Testing Guide
- Changelog

---

# 🗺 Development Roadmap

### Phase 1

- Project Setup
- Documentation
- Branding

### Phase 2

- Log Parsing
- Event Models
- Detection Engine

### Phase 3

- Report Generation
- Event Correlation
- HTML Reports

### Phase 4

- Desktop GUI
- Performance Improvements
- Release v1.0

---

# ⚙ Installation

Clone the repository:

```bash
git clone https://github.com/daniyal-sec/AegisLog.git
```

Enter the project directory:

```bash
cd AegisLog
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# 🚀 Usage

Development is currently in progress.

The first public release will support:

- Authentication Log Parsing
- Detection Engine
- Investigation Reports

---

# 🎯 Future Vision

AegisLog is designed to evolve beyond a log parser.

The long-term goal is to become a lightweight desktop investigation platform capable of assisting Blue Teamers and SOC Analysts during authentication log investigations.

---

# 🤝 Contributing

Suggestions, ideas, and constructive feedback are always welcome.

If you discover a bug or have an improvement in mind, feel free to open an Issue or submit a Pull Request.

---

# 📄 License

This project is licensed under the MIT License.

---

<p align="center">

### Built with ❤️ for the Cybersecurity Community

**Analyze • Detect • Correlate • Investigate**

</p>