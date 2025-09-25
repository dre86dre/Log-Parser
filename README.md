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
```

Make the script executable:

```bash
chmod +x log_parser.py
```

Run the parser on a log file:

```bash
./log_parser.py /var/log/auth.log
```

Or with Python explicitly:

```bash
python3 log_parser.py /var/log/auth.log
```

---

## 🧪 Testing with Sample Data

A sample log file is provided for testing: `sample_auth.log`

Run the parser against it:

```bash
./log_parser.py sample_auth.log
```

Expected output (example):

```bash
Time                 Service  User        Source           Reason
----------------------------------------------------------------------
2025-09-17T12:03:21  sshd     root        192.168.1.45     failed password
2025-09-17T12:05:10  sshd     admin       203.0.113.5      invalid user
2025-09-17T12:06:42  sshd     tester      192.0.2.1        pam authentication failure
2025-09-17T12:08:15  sudo     user1       localhost        pam authentication failure
2025-09-17T12:10:22  sshd     guest       198.51.100.77    failed password (invalid user)
```

---

## 🔒 Permissions

- Reading `/var/log/auth.log` may require `sudo`:

```bash
sudo ./log_parser.py /var/log/auth.log
```
