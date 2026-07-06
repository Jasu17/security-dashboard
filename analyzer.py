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
    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    total_lines = len(lines)
    ips = set()
    events = []
    failed_attempts = defaultdict(int)
    status_codes = defaultdict(int)
    top_urls = defaultdict(int)
    methods = defaultdict(int)

    access_pattern = re.compile(
        r'(\S+) \S+ \S+ \[.*?\] "(\w+) (\S+) \S+" (\d{3}) \S+'
    )

    for line in lines:
        match = access_pattern.search(line)
        if not match:
            continue

        ip = match.group(1)
        method = match.group(2)
        url = match.group(3)
        status = match.group(4)

        ips.add(ip)
        failed_attempts[ip] += 1
        status_codes[status] += 1
        top_urls[url] += 1
        methods[method] += 1

        if status.startswith("5"):
            event_type = "5xx Error"
            severity = "danger"
        elif status.startswith("4"):
            event_type = "4xx Error"
            severity = "warning"
        else:
            event_type = "OK"
            severity = "success"

        events.append({
            "type": event_type,
            "severity": severity,
            "user": "-",
            "ip": ip,
            "line": line.strip(),
        })

    findings = _generate_apache_access_findings(failed_attempts, status_codes)
    sorted_ips = sorted(ips)
    top_urls_sorted = sorted(top_urls.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "log_type": "apache_access",
        "total_lines": total_lines,
        "total_events": len(events),
        "ips": sorted_ips,
        "users": [],
        "events": events,
        "findings": findings,
        "extras": {
            "status_codes": dict(status_codes),
            "top_urls": top_urls_sorted,
            "methods": dict(methods),
        },
        "metrics": [
            {"label": "Líneas procesadas", "value": total_lines},
            {"label": "IPs identificadas", "value": len(sorted_ips)},
            {"label": "Requests totales", "value": sum(status_codes.values())},
            {"label": "Errores detectados", "value": sum(
                v for k, v in status_codes.items() if k.startswith("4") or k.startswith("5")
            )},
        ],
    }


def _generate_apache_access_findings(failed_attempts, status_codes):
    findings = []

    SCANNER_THRESHOLD = 100

    for ip, count in failed_attempts.items():
        if count >= SCANNER_THRESHOLD:
            findings.append({
                "severity": "high",
                "message": f"Posible scanner o bot detectado desde {ip} — {count} requests.",
            })

    total_5xx = sum(v for k, v in status_codes.items() if k.startswith("5"))
    if total_5xx >= 10:
        findings.append({
            "severity": "medium",
            "message": f"Alto número de errores 5xx detectados — {total_5xx} ocurrencias.",
        })

    return findings

# --- Apache Error (stub) ---

def _analyze_apache_error(filepath):
    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    total_lines = len(lines)
    ips = set()
    events = []
    error_levels = defaultdict(int)
    modules = defaultdict(int)

    error_pattern = re.compile(
        r'\[(?:.*?)\] \[(\w+):(\w+)\] \[pid \d+\].*?\[client (\S+):\d+\] (.+)'
    )

    error_pattern_simple = re.compile(
        r'\[(?:.*?)\] \[(\w+)\] \[pid \d+\].*?\[client (\S+):\d+\] (.+)'
    )

    for line in lines:
        match = error_pattern.search(line)
        if match:
            module = match.group(1)
            level = match.group(2)
            ip = match.group(3)
            message = match.group(4)
        else:
            match = error_pattern_simple.search(line)
            if not match:
                continue
            module = "core"
            level = match.group(1)
            ip = match.group(2)
            message = match.group(3)
        
        ips.add(ip)
        error_levels[level] += 1
        modules[module] += 1

        if level in ("emerg", "alert", "crit", "error"):
            severity = "danger"
        elif level == "warn":
            severity = "warning"
        else:
            severity = "secondary"

        events.append({
            "type": f"Apache {level.upper()}",
            "severity": severity,
            "user": "-",
            "ip": ip,
            "line": line.strip(),
        })
    
    findings = _generate_apache_error_findings(error_levels, modules)
    sorted_ips = sorted(ips)

    return {
        "log_type": "apache_error",
        "total_lines": total_lines,
        "total_events": len(events),
        "ips": sorted_ips,
        "users": [],
        "events": events,
        "findings": findings,
        "extras": {
            "error_levels": dict(error_levels),
            "modules": dict(modules),
        },
        "metrics": [
            {"label": "Líneas procesadas", "value": total_lines},
            {"label": "Eventos detectados", "value": len(events)},
            {"label": "IPs identificadas", "value": len(sorted_ips)},
            {"label": "Errores criticos", "value":sum(
                v for k, v in error_levels.items() if k in ("emerg", "alert", "crit", "error")
            )},
        ],
    }

def _generate_apache_error_findings(error_levels, modules):
    findings = []

    critical = sum(v for k, v in error_levels.items() if k in ("emerg", "alert", "crit", "error"))
    if critical >=5:
        findings.append({
            "severity": "high",
            "message": f"Alto número de errores críticos detectados -> {critical} ocurrencias.",
        })

    for module, count in modules.items():
        if count >=20:
            findings.append({
                "severity": "medium",
                "message": f"Modulo '{module}' con alto número de errores -> {count} ocurrencias.",
            })

    return findings


# --- Parser registry ---

PARSERS = {
    "openssh": _analyze_openssh,
    "apache_access": _analyze_apache_access,
    "apache_error": _analyze_apache_error,
}