"""Timeline reconstruction from file metadata and log timestamps."""
import json
import os
import re
from datetime import datetime
from pathlib import Path


# Regex to pull timestamps from syslog lines (e.g. "Mar 10 08:02:44")
SYSLOG_TS = re.compile(
    r'^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})'
)
MONTHS = {m: i for i, m in enumerate(
    ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'], 1
)}


def _parse_syslog_ts(line: str, year: int = 2024) -> datetime | None:
    m = SYSLOG_TS.match(line)
    if not m:
        return None
    month = MONTHS.get(m.group('month'))
    if not month:
        return None
    day = int(m.group('day'))
    h, mi, s = map(int, m.group('time').split(':'))
    return datetime(year, month, day, h, mi, s)


def events_from_syslog(filepath: str) -> list[dict]:
    events = []
    with open(filepath) as f:
        for line in f:
            ts = _parse_syslog_ts(line.strip())
            if ts:
                events.append({
                    'timestamp': ts.isoformat(),
                    'source': os.path.basename(filepath),
                    'type': 'syslog',
                    'description': line.strip(),
                })
    return events


def events_from_browser_history(filepath: str) -> list[dict]:
    events = []
    with open(filepath) as f:
        entries = json.load(f)
    for entry in entries:
        events.append({
            'timestamp': entry.get('timestamp', ''),
            'source': os.path.basename(filepath),
            'type': 'browser',
            'description': f"Visited: {entry.get('title', '')} — {entry.get('url', '')}",
        })
    return events


def events_from_filesystem(dirpath: str) -> list[dict]:
    """Collect mtime/ctime events for all files."""
    events = []
    for path in sorted(Path(dirpath).rglob('*')):
        if path.is_file():
            stat = path.stat()
            events.append({
                'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'source': 'filesystem',
                'type': 'file_modified',
                'description': f"File modified: {path}",
            })
    return events


def build_timeline(case_dir: str) -> list[dict]:
    """Aggregate all events from case_dir into a sorted timeline."""
    events = []

    for path in sorted(Path(case_dir).rglob('*.log')):
        events.extend(events_from_syslog(str(path)))

    for path in sorted(Path(case_dir).rglob('*.json')):
        try:
            events.extend(events_from_browser_history(str(path)))
        except (json.JSONDecodeError, KeyError):
            pass

    events.extend(events_from_filesystem(case_dir))

    # Sort by timestamp string (ISO format sorts lexicographically)
    events.sort(key=lambda e: e.get('timestamp', ''))
    return events
