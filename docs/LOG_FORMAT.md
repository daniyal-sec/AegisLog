# 📝 AegisLog Authentication Log Format

## Overview

AegisLog v1.0 uses a structured authentication log format inspired by real-world authentication events.

Each log entry represents a single authentication event.

---

## Log Structure

YYYY-MM-DD HH:MM:SS | EVENT_TYPE | USERNAME | SOURCE_IP

---

## Example Log Entries

2026-08-04 09:15:03 | LOGIN_FAILED  | admin   | 192.168.1.44

2026-08-04 09:15:05 | LOGIN_FAILED  | admin   | 192.168.1.44

2026-08-04 09:15:07 | LOGIN_FAILED  | admin   | 192.168.1.44

2026-08-04 09:15:12 | LOGIN_SUCCESS | admin   | 192.168.1.44

---

## Fields

### Timestamp

Format:

YYYY-MM-DD HH:MM:SS

Example:

2026-08-04 09:15:03

---

### Event Type

Supported values:

LOGIN_SUCCESS

LOGIN_FAILED

LOGOUT

ACCOUNT_LOCKED

PASSWORD_CHANGED

---

### Username

Represents the account involved.

Example:

admin

john

alice

---

### Source IP

IPv4 address of the client initiating the request.

Example:

192.168.1.44

10.10.10.15

172.16.5.8

---

## Validation Rules

- Timestamp must follow the correct format.
- Event type must be supported.
- Username cannot be empty.
- Source IP must be a valid IPv4 address.

---

## Future Expansion

Future versions may include:

- Hostname
- Device Name
- Country
- User Agent
- Session ID
- Event ID