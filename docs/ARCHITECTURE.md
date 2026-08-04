# 🏗️ AegisLog Architecture

## Overview

AegisLog follows a modular architecture where each component has a single responsibility.

The goal is to separate log parsing, detection, correlation, severity analysis, and report generation into independent modules.

---

## Processing Pipeline

Authentication Log
        │
        ▼
Log Parser
        │
        ▼
Event Objects
        │
        ▼
Detection Engine
        │
        ▼
Correlation Engine
        │
        ▼
Severity Engine
        │
        ▼
Report Generator

---

## Components

### Log Parser

Reads authentication logs and converts each log entry into structured event objects.

---

### Event Model

Represents a single authentication event.

Each event contains:

- Timestamp
- Username
- Source IP
- Event Type

---

### Detection Engine

Analyzes parsed events and identifies suspicious activity.

Examples:

- Failed login
- Brute force
- Successful login after failures

---

### Correlation Engine

Groups related authentication events together to build a security timeline.

---

### Severity Engine

Assigns a severity level:

- Low
- Medium
- High
- Critical

---

### Report Generator

Produces investigation-ready reports in:

- TXT
- JSON
- HTML (planned)

---

## Future Expansion

The architecture allows future support for:

- Windows Event Logs
- Linux auth.log
- SSH logs
- Apache logs
- GUI interface
- REST API