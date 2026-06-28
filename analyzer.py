import re

def analyze(filepath):
    with open(filepath, "r") as f:
        lines=f.readlines()
    
    total_lines = len(lines)
    ips = set()
    users = set()
    events = []

    ip_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    user_pattern = re.compile(r"(?:user|for)\s+(\w+)", re.IGNORECASE)

    for line in lines:
        ip_match = ip_pattern.search(line)
        if ip_match:
            ips.add(ip_match.group(1))

    return {
        "total_lines" : total_lines,
        "total_events" : len(events),
        "ips" : sorted(ips),
        "users": sorted(users),
        "events" : events,
        "findings" : [],
    }
