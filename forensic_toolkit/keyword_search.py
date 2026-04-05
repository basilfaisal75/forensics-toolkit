"""Keyword search across all text-readable files in a directory."""
import os
import re
from pathlib import Path


DEFAULT_KEYWORDS = [
    'password', 'passwd', 'secret', 'confidential', 'credential',
    'private key', 'api key', 'token', 'encrypt', 'decrypt',
    'hidden', 'delete', 'shred', 'wipe', 'cover', 'trace',
    'export', 'transfer', 'upload', 'anonymous', 'untraceable',
    'rendezvous', 'contact', 'meeting', 'cash', 'wire transfer',
]

TEXT_EXTENSIONS = {
    '.txt', '.log', '.json', '.csv', '.xml', '.html', '.htm',
    '.md', '.cfg', '.conf', '.ini', '.py', '.sh', '.bat',
    '.sql', '.yaml', '.yml',
}


def _is_text_file(filepath: str) -> bool:
    ext = Path(filepath).suffix.lower()
    if ext in TEXT_EXTENSIONS:
        return True
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(512)
        return b'\x00' not in chunk  # crude binary check
    except OSError:
        return False


def search_file(filepath: str, keywords: list[str]) -> list[dict]:
    """Return all lines in filepath that contain any of the keywords."""
    if not _is_text_file(filepath):
        return []

    hits = []
    patterns = [(kw, re.compile(re.escape(kw), re.IGNORECASE)) for kw in keywords]

    try:
        with open(filepath, errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                for kw, pat in patterns:
                    if pat.search(line):
                        hits.append({
                            'file': filepath,
                            'line': lineno,
                            'keyword': kw,
                            'content': line.strip(),
                        })
                        break  # one hit per line
    except OSError:
        pass

    return hits


def search_directory(dirpath: str, keywords: list[str] | None = None) -> dict:
    """Search every file under dirpath for suspicious keywords."""
    keywords = keywords or DEFAULT_KEYWORDS
    all_hits = []
    files_scanned = 0

    for path in sorted(Path(dirpath).rglob('*')):
        if path.is_file():
            files_scanned += 1
            all_hits.extend(search_file(str(path), keywords))

    # Group by file for cleaner reporting
    by_file: dict[str, list] = {}
    for hit in all_hits:
        by_file.setdefault(hit['file'], []).append(hit)

    return {
        'files_scanned': files_scanned,
        'total_hits': len(all_hits),
        'keywords_used': keywords,
        'hits_by_file': by_file,
    }
