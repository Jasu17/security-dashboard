import re
from collections import defaultdict


# --- Patterns ---

FAILED_SSH = re.compile(r"Failed password for (?:invalid user )?(\w+) from (\S+)")
SUCCESSFUL_SSH = re.compile(r"Accepted (?:password|publickey) for (\w+) from (\S+)")
INVALID_USER = re.compile(r"Invalid user (\w+) from (\S+)")
IP_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

BRUTE_FORCE_THRESHOLD = 5


# --- Source of truth ---

LOG_TYPES = {
    "openssh": "OpenSSH",
    "apache_access": "Apache Access Log",
    "apache_error": "Apache Error Log",
}


# --- Dispatcher ---

def analyze(filepath, log_type):
    parser = PARSERS.get(log_type)
    if not parser:
        raise ValueError(f"Unsupported log type: {log_type}")
    return parser(filepath)


# --- OpenSSH ---

def _analyze_openssh(filepath):
    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    total_lines = len(lines)
    ips = set()
    users = set()
    events = []
    failed_attempts = defaultdict(int)
    invalid_users = defaultdict(int)

    for line in lines:
        ip_match = IP_PATTERN.search(line)
        if ip_match:
            ips.add(ip_match.group(1))

        if FAILED_SSH.search(line):
            match = FAILED_SSH.search(line)
            user = match.group(1)
            ip = match.group(2)
            users.add(user)
            failed_attempts[ip] += 1
            events.append({
                "type": "Failed SSH Login",
                "severity": "danger",
                "user": user,
                "ip": ip,
                "line": line.strip(),
            })

        elif SUCCESSFUL_SSH.search(line):
            match = SUCCESSFUL_SSH.search(line)
            user = match.group(1)
            ip = match.group(2)
            users.add(user)
            events.append({
                "type": "Successful SSH Login",
                "severity": "success",
                "user": user,
                "ip": ip,
                "line": line.strip(),
            })

        elif INVALID_USER.search(line):
            match = INVALID_USER.search(line)
            user = match.group(1)
            ip = match.group(2)
            users.add(user)
            invalid_users[user] += 1
            events.append({
                "type": "Invalid User",
                "severity": "warning",
                "user": user,
                "ip": ip,
                "line": line.strip(),
            })

    findings = _generate_openssh_findings(failed_attempts, invalid_users)
    sorted_ips = sorted(ips)

    return {
        "log_type": "openssh",
        "total_lines": total_lines,
        "total_events": len(events),
        "ips": sorted_ips,
        "users": sorted(users),
        "events": events,
        "findings": findings,
        "extras": {},
        "metrics": [
            {"label": "Líneas procesadas", "value": total_lines},
            {"label": "Eventos detectados", "value": len(events)},
            {"label": "IPs identificadas", "value": len(sorted_ips)},
            {"label": "Usuarios identificados", "value": len(users)},
        ],
    }


def _generate_openssh_findings(failed_attempts, invalid_users):
    findings = []

    for ip, count in failed_attempts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            findings.append({
                "severity": "high",
                "message": f"Posible ataque de fuerza bruta desde {ip} — {count} intentos fallidos.",
            })

    for user, count in invalid_users.items():
        if count >= 2:
            findings.append({
                "severity": "medium",
                "message": f"Usuario inválido recurrente: '{user}' — {count} intentos.",
            })

    return findings


# --- Apache Access (stub) ---

def _analyze_apache_access(filepath):
    return {
        "log_type": "apache_access",
        "total_lines": 0,
        "total_events": 0,
        "ips": [],
        "users": [],
        "events": [],
        "findings": [],
        "extras": {},
        "metrics": [],
    }


# --- Apache Error (stub) ---

def _analyze_apache_error(filepath):
    return {
        "log_type": "apache_error",
        "total_lines": 0,
        "total_events": 0,
        "ips": [],
        "users": [],
        "events": [],
        "findings": [],
        "extras": {},
        "metrics": [],
    }


# --- Parser registry ---

PARSERS = {
    "openssh": _analyze_openssh,
    "apache_access": _analyze_apache_access,
    "apache_error": _analyze_apache_error,
}