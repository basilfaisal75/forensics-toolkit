"""File hashing module — MD5, SHA1, SHA256."""
import hashlib
import os
from pathlib import Path


CHUNK_SIZE = 65536  # 64 KB


def hash_file(filepath: str) -> dict:
    """Return MD5, SHA1, and SHA256 hashes for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    stat = os.stat(filepath)
    return {
        'file': str(filepath),
        'size_bytes': stat.st_size,
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
        'modified': stat.st_mtime,
    }


def hash_directory(dirpath: str) -> list[dict]:
    """Hash every file recursively under dirpath."""
    results = []
    for path in sorted(Path(dirpath).rglob('*')):
        if path.is_file():
            try:
                results.append(hash_file(str(path)))
            except (PermissionError, OSError) as e:
                results.append({'file': str(path), 'error': str(e)})
    return results
