"""Log and browser history parser."""
import json
import re
from datetime import datetime
from pathlib import Path


# Patterns that flag suspicious syslog activity
SUSPICIOUS_LOG_PATTERNS = [
    (re.compile(r'\bshred\b', re.IGNORECASE),         'Secure file deletion (shred)'),
    (re.compile(r'\brm\s+-rf\b', re.IGNORECASE),      'Recursive force-delete'),
    (re.compile(r'\brsync\b.*bytes', re.IGNORECASE),  'Large data transfer (rsync)'),
    (re.compile(r'USB device connected', re.IGNORECASE), 'USB device connected'),
    (re.compile(r'USB device removed', re.IGNORECASE),   'USB device removed'),
    (re.compile(r'sudo.*COMMAND', re.IGNORECASE),     'Privileged command (sudo)'),
    (re.compile(r'\.hidden', re.IGNORECASE),           'Hidden directory accessed'),
    (re.compile(r'cleanup\.py|export_db\.py', re.IGNORECASE), 'Suspicious script executed'),
]

# URLs / search terms that flag suspicious browser activity
SUSPICIOUS_URL_KEYWORDS = [
    'delete files permanently', 'eraser', 'shred', 'anonymous email',
    'vpn', 'tor browser', 'pastebin', 'wetransfer', 'employee database',
    'hide ip', 'protonmail', 'nordvpn',
]


def parse_browser_history(filepath: str) -> dict:
    """Parse a JSON browser history file."""
    with open(filepath) as f:
        entries = json.load(f)

    flagged = []
    for entry in entries:
        url_lower = entry.get('url', '').lower()
        title_lower = entry.get('title', '').lower()
        combined = url_lower + ' ' + title_lower
        for keyword in SUSPICIOUS_URL_KEYWORDS:
            if keyword in combined:
                flagged.append({**entry, 'reason': f'Keyword match: "{keyword}"'})
                break

    return {
        'source': filepath,
        'total_entries': len(entries),
        'flagged_entries': flagged,
        'all_entries': entries,
    }


def parse_syslog(filepath: str) -> dict:
    """Parse a plain-text syslog file and flag suspicious lines."""
    with open(filepath) as f:
        lines = f.readlines()

    flagged = []
    for i, line in enumerate(lines, 1):
        for pattern, reason in SUSPICIOUS_LOG_PATTERNS:
            if pattern.search(line):
                flagged.append({
                    'line_number': i,
                    'content': line.strip(),
                    'reason': reason,
                })
                break  # one flag per line

    return {
        'source': filepath,
        'total_lines': len(lines),
        'flagged_lines': flagged,
        'all_lines': [l.strip() for l in lines],
    }


def parse_directory(dirpath: str) -> list[dict]:
    """Auto-detect and parse all log/history files in a directory."""
    results = []
    for path in sorted(Path(dirpath).rglob('*')):
        if not path.is_file():
            continue
        if path.suffix == '.json':
            try:
                results.append(parse_browser_history(str(path)))
            except (json.JSONDecodeError, KeyError):
                pass
        elif path.suffix == '.log' or path.name.endswith('.log'):
            results.append(parse_syslog(str(path)))
    return results
