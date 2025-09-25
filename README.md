# Simple Log Parser for Failed Login Attempts

This is a beginner-friendly Python script that parses system log files and extracts **failed login attempts**.  
It supports SSH, PAM, and `sudo` authentication failures, and prints results in a simple table.

---

## ✨ Features

- Parses standard syslog-style lines (e.g. `/var/log/auth.log`)
- Detects:
  - SSH failed password attempts
  - SSH invalid users
  - PAM authentication failures (including `sudo`)
- Normalizes data into a structured format (timestamp, user, IP, reason)
- Outputs results in a human-readable table

---

## 📦 Requirements

- Python **3.6+**
- No external dependencies (only standard library)

---

## 🚀 Usage

Clone this repository:

```bash
git clone https://github.com/yourusername/log-parser.git
cd log-parser
