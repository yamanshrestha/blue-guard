import re
from datetime import datetime
from typing import Optional, Dict, Any

TIMESTAMP_RE = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
# Failed SSH login
# Handles both:
# Failed password for root from 1.2.3.4 ...
# Failed password for invalid user admin from 1.2.3.4 ...
FAILED_LOGIN_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
)

# Successful SSH login
# Handles:
# Accepted password for yaman from 1.2.3.4 ...
# Accepted publickey for yaman from 1.2.3.4 ...
ACCEPTED_LOGIN_RE = re.compile(
    r"Accepted (?P<auth_method>password|publickey) for (?P<username>\S+) "
    r"from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
)

# Sudo command usage
# Example:
# sudo:    yaman : TTY=pts/0 ; PWD=/home/yaman ; USER=root ; COMMAND=/bin/cat /etc/shadow
SUDO_COMMAND_RE = re.compile(
    r"sudo:\s+(?P<username>\S+)\s*:"
)

# Sudo authentication failure
# Example:
# sudo: pam_unix(sudo:auth): authentication failure; ... user=yaman
SUDO_AUTH_FAILURE_RE = re.compile(
    r"sudo: .*authentication failure.*(?:user=)(?P<username>\S+)"
)


def parse_timestamp(line: str, year: Optional[int] = None) -> Optional[datetime]:
    """
    Extract the syslog-style timestamp from the beginning of an auth.log line.
    auth.log usually does not include a year, so we inject one.
    """
    match = TIMESTAMP_RE.match(line)
    if not match:
        return None

    year = year or datetime.now().year
    timestamp_str = f"{match.group('month')} {match.group('day')} {year} {match.group('time')}"

    try:
        return datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")
    except ValueError:
        return None


def parse_auth_line(line: str, year: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """
    Parse one auth.log line into a structured event dictionary.

    Returns:
        dict for supported event types
        None for irrelevant/unparsed lines
    """
    timestamp = parse_timestamp(line, year=year)
    if not timestamp:
        return None

    failed_match = FAILED_LOGIN_RE.search(line)
    if failed_match:
        return {
            "timestamp": timestamp,
            "event_type": "failed_login",
            "username": failed_match.group("username"),
            "source_ip": failed_match.group("source_ip"),
            "raw": line.strip(),
        }

    accepted_match = ACCEPTED_LOGIN_RE.search(line)
    if accepted_match:
        return {
            "timestamp": timestamp,
            "event_type": "accepted_login",
            "username": accepted_match.group("username"),
            "source_ip": accepted_match.group("source_ip"),
            "auth_method": accepted_match.group("auth_method"),
            "raw": line.strip(),
        }

    sudo_fail_match = SUDO_AUTH_FAILURE_RE.search(line)
    if sudo_fail_match:
        return {
            "timestamp": timestamp,
            "event_type": "sudo_auth_failure",
            "username": sudo_fail_match.group("username"),
            "source_ip": None,
            "raw": line.strip(),
        }

    sudo_cmd_match = SUDO_COMMAND_RE.search(line)
    if sudo_cmd_match:
        return {
            "timestamp": timestamp,
            "event_type": "sudo_command",
            "username": sudo_cmd_match.group("username"),
            "source_ip": None,
            "raw": line.strip(),
        }

    return None