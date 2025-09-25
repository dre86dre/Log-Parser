#!/usr/bin/env python3

"""
This is a simple log parser for failed login attempts

This script:
- reads a system log file line by line
- parses syslog entries
- detects failed login attempts (SSH, PAM, sudo)
- prints results in a simple table
"""

import re
import sys
import argparse
import datetime
import ipaddress

"""
Regex patterns for detectors
"""

# SSHD failed password (with or without "invalid user")
FAILED_SSHD_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+|[0-9a-fA-F:]+)(?: port (\d+))?"
)

# SSHD invalid user
INVALID_USER_RE = re.compile(
    r"Invalid user (\S+) from ([\d\.]+|[0-9a-fA-F:]+)(?: port (\d+))?"
)

# PAM authenticationfailure (user + rhost)
PAM_RE = re.compile(
    r"user=(\S+).+rhost=([\d.]+|[0-9a-fA-F:]+)?"
)

"""
Parsing syslog lines
"""

def parse_syslog_line(line):
    """
    Parse a raw syslog line into structured fields.
    e.g.
        'Sep 17 12:03:21 myserver sshd[24567]: Failed password ...'
    Returns a dict with timestamp, host, program, pid, message.
    """

    tokens = line.strip().split()

    # Skip empty or malformed lines
    if len(tokens) < 5:
        return None
    
    # First 3 tokens = timestamp (month, day, time)
    ts_raw = " ".join(tokens[0:3]) # e.g. "Sep 17 12:03:21"

    # Hostname is next
    host = tokens[3]

    # The rest = program[pid]: message
    rest = " ".join(tokens[4:])

    # Program regex
    m = re.match(r"^(\S+?)(?:\[(\d+)\])?:\s*(.*)$", rest)
    if m:
        program, pid, message = m.groups()
    else:
        program, pid, message = None, None, rest

    # Parse timestamp into datetime (syslog omits year, so add current)
    try:
        ts_obj = datetime.datetime.strptime(ts_raw, "%b %d %H:%M:%S")
        ts_obj = ts_obj.replace(year=datetime.datetime.now().year)
    except ValueError:
        ts_obj = None

    return {
        "timestamp": ts_obj,
        "timestamp_raw": ts_raw,
        "host": host,
        "program": program,
        "pid": pid,
        "message": message,
    }

"""
Detectors for failed logins
"""

def detect_sshd_failed(parsed):
    """Detect 'Failed password' attempts from sshd"""
    if parsed["program"] != "sshd":
        return None
    if "Failed password" not in parsed["message"]:
        return None
    
    m = FAILED_SSHD_RE.search(parsed["message"])
    if not m:
        return None
    
    user, ip, port = m.groups()
    reason = "failed password"
    if "invalid user" in parsed["message"]:
        reason += " (invalid user)"

    return build_record(parsed, user, ip, port, reason)

def detect_invalid_user(parsed):
    """Detect 'Invelid user' attempts from sshd"""
    if parsed["program"] != "sshd":
        return None
    if "Invalid user" not in parsed["message"]:
        return None
    
    m = INVALID_USER_RE.search(parsed["message"])
    if not m:
        return None
    
    user, ip, port = m.groups()
    return build_record(parsed, user, ip, port, "invalid user")

def detect_pam_failure(parsed):
    """Detect PAM authentication failures (e.g. sudo, sshd)"""
    if "authentication failure" not in parsed["message"]:
        return None
    
    m = PAM_RE.search(parsed["message"])
    if not m:
        return None
    
    user, ip = m.groups()
    ip = ip or "local host"
    return build_record(parsed, user, ip, None, "pam authentication failure")

"""
Helpers
"""

def build_record(parsed, user, ip, port, reason):
    """Return a normalised record for a failed attempt"""
    # Validate IP if possible
    try:
        ipaddress.ip_address(ip)
    except Exception:
        ip = ip # leave raw if not valid

    return{
        "timestamp": parsed["timestamp"].isoformat() if parsed["timestamp"] else parsed["timestamp_raw"],
        "service": parsed["program"],
        "user": user,
        "src": ip,
        "port": port,
        "reason": reason,
        "raw_message": parsed["message"],
    }

"""
Reporter (prints results)
"""

def print_table(records):
    """Print results in a simple table"""
    if not records:
        print("No failed login attempts found.")
        return
    
    # Header
    print(f"{'Time':19} {'Service':6} {'User':10} {'Source':15} {'Reason'}")
    print("-" * 70)

    # Rows
    for rec in records:
        print(
            f"{rec['timestamp'][:19]:19}  "
            f"{rec['service'] or '-':6}  "
            f"{rec['user'] or '-':10}  "
            f"{rec['src'] or '-':15}  "
            f"{rec['reason']}"
        )

"""
Main program
"""

def main():
    # CLI arguments
    parser = argparse.ArgumentParser(description="Simple log parser for failed login attempts")
    parser.add_argument("path", help="Path to log file (e.g. /var/log/auth.log)")
    args = parser.parse_args()

    detectors = [detect_sshd_failed, detect_invalid_user, detect_pam_failure]
    results = []

    # Open file and process line by line
    try:
        with open(args.path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = parse_syslog_line(line)
                if not parsed:
                    continue
                for detector in detectors:
                    rec = detector(parsed)
                    if rec:
                        results.append(rec)
    except FileNotFoundError:
        print(f"Error: file not found: {args.path}")
        sys.exit(1)

    # Print results
    print_table(results)

if __name__== "__main__":
    main()