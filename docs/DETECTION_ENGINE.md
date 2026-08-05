# AegisLog Detection Engine

## Overview

The Detection Engine is responsible for analyzing parsed authentication events and identifying suspicious activity.

Input:

```
List[AuthEvent]
```

Output:

```
List[ThreatFinding]
```

Each detection rule is implemented independently, allowing new detection capabilities to be added without modifying the parser.

---

# Detection Pipeline

```
Authentication Logs
        │
        ▼
Parser
        │
        ▼
AuthEvent
        │
        ▼
Detection Rules
        │
        ▼
ThreatFinding
        │
        ▼
Report Generator
```

---

# Implemented Detection Rules

## 1. SSH Brute Force Detection

### Description

Detects repeated failed login attempts against the same account from the same source IP.

### Detection Logic

- Same Source IP
- Same Username
- Authentication Status = FAILED
- Attempts ≥ 5

### Severity

HIGH

### Example

```
203.0.113.45

FAILED
FAILED
FAILED
FAILED
FAILED
```

### Output

```
Attack Type:
SSH Brute Force

Severity:
HIGH

Recommendation:
Investigate immediately.
```

---

## 2. Username Enumeration

### Description

Detects repeated login attempts using multiple invalid usernames from the same source IP.

### Detection Logic

- Same Source IP
- Invalid usernames only
- Three or more unique usernames

### Severity

MEDIUM

### Example

```
198.51.100.27

invalid user test

invalid user guest

invalid user administrator
```

### Output

```
Attack Type:
Username Enumeration

Severity:
MEDIUM

Recommendation:
Investigate repeated invalid username attempts.
```

---

# Planned Detection Rules

- Successful Login After Multiple Failures
- Password Spraying
- Root Login Detection
- Account Lock Detection
- Suspicious New IP Login
- Event Correlation
- Timeline Analysis
- Severity Classification

---

# Detection Philosophy

Every detector follows the same principles:

- One detector performs one task.
- Detectors operate on `AuthEvent` objects.
- Detectors return `ThreatFinding` objects.
- Detection rules remain independent and modular.
- New detection rules can be added without modifying existing ones.