"""
Steganography detector for PNG images.

Checks performed:
  1. Metadata / tEXt chunk inspection — hidden text embedded in PNG chunks
  2. LSB (Least Significant Bit) anomaly — statistical deviation in blue
     channel LSBs, a classic sign of LSB steganography
  3. EXIF / unusual chunk presence
"""
import struct
import zlib
from pathlib import Path


PNG_SIG = b'\x89PNG\r\n\x1a\n'
SUSPICIOUS_CHUNK_TYPES = {b'zTXt', b'iTXt', b'tEXt'}


def _read_png_chunks(data: bytes) -> list[dict]:
    """Parse a PNG byte string into its constituent chunks."""
    if not data.startswith(PNG_SIG):
        return []

    chunks = []
    offset = 8  # skip signature
    while offset < len(data):
        if offset + 8 > len(data):
            break
        length = struct.unpack('>I', data[offset:offset+4])[0]
        chunk_type = data[offset+4:offset+8]
        chunk_data = data[offset+8:offset+8+length]
        crc = data[offset+8+length:offset+12+length]
        chunks.append({
            'type': chunk_type,
            'length': length,
            'data': chunk_data,
            'crc': crc,
        })
        offset += 12 + length
    return chunks


def _extract_text_chunks(chunks: list[dict]) -> list[dict]:
    """Extract readable text from tEXt / iTXt / zTXt chunks."""
    findings = []
    for chunk in chunks:
        ctype = chunk['type']
        if ctype == b'tEXt':
            raw = chunk['data']
            if b'\x00' in raw:
                keyword, value = raw.split(b'\x00', 1)
                findings.append({
                    'chunk': 'tEXt',
                    'keyword': keyword.decode('latin-1', errors='replace'),
                    'value': value.decode('latin-1', errors='replace'),
                })
            else:
                findings.append({'chunk': 'tEXt', 'keyword': '', 'value': raw.decode('latin-1', errors='replace')})
        elif ctype == b'zTXt':
            raw = chunk['data']
            if b'\x00' in raw:
                keyword, rest = raw.split(b'\x00', 1)
                try:
                    value = zlib.decompress(rest[1:])  # skip compression method byte
                    findings.append({
                        'chunk': 'zTXt',
                        'keyword': keyword.decode('latin-1', errors='replace'),
                        'value': value.decode('latin-1', errors='replace'),
                    })
                except zlib.error:
                    findings.append({'chunk': 'zTXt', 'keyword': '?', 'value': '[decompression failed]'})
        elif ctype == b'iTXt':
            findings.append({'chunk': 'iTXt', 'keyword': '?', 'value': chunk['data'].decode('utf-8', errors='replace')})
    return findings


def _lsb_anomaly_score(chunks: list[dict]) -> float:
    """
    Decompress IDAT data and measure how non-random the blue-channel LSBs are.
    A natural image tends toward ~50% 1-bits in the LSB; LSB steganography
    often shifts this toward exactly 50% (more uniform) or shows unusual
    patterns. Returns a simple deviation score (0.0 = perfectly random).
    """
    # Collect all IDAT data
    idat_raw = b''
    for chunk in chunks:
        if chunk['type'] == b'IDAT':
            idat_raw += chunk['data']

    if not idat_raw:
        return 0.0

    try:
        raw = zlib.decompress(idat_raw)
    except zlib.error:
        return 0.0

    # Find image dimensions from IHDR
    width = height = 0
    for chunk in chunks:
        if chunk['type'] == b'IHDR':
            width, height = struct.unpack('>II', chunk['data'][:8])
            break

    if width == 0 or height == 0:
        return 0.0

    # Extract blue-channel bytes (filter byte + R G B per pixel, filter=None)
    blue_lsbs = []
    stride = 1 + width * 3  # filter byte + RGB
    for row in range(height):
        row_start = row * stride + 1  # skip filter byte
        for col in range(width):
            pixel_offset = row_start + col * 3
            if pixel_offset + 2 < len(raw):
                blue_byte = raw[pixel_offset + 2]
                blue_lsbs.append(blue_byte & 1)

    if not blue_lsbs:
        return 0.0

    ratio = sum(blue_lsbs) / len(blue_lsbs)
    # Deviation from 0.5 — perfect randomness expected in LSBs of natural images
    return abs(ratio - 0.5)


def analyse_image(filepath: str) -> dict:
    """Run all steganography checks on a PNG file."""
    result = {
        'file': filepath,
        'is_png': False,
        'suspicious': False,
        'findings': [],
        'lsb_anomaly_score': 0.0,
        'text_chunks': [],
    }

    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except OSError as e:
        result['error'] = str(e)
        return result

    if not data.startswith(PNG_SIG):
        result['findings'].append('Not a valid PNG file')
        return result

    result['is_png'] = True
    chunks = _read_png_chunks(data)
    chunk_types = [c['type'] for c in chunks]

    # Check for text chunks
    text_chunks = _extract_text_chunks(chunks)
    result['text_chunks'] = text_chunks
    for tc in text_chunks:
        if tc.get('value', '').strip():
            result['suspicious'] = True
            result['findings'].append(
                f"Hidden text in {tc['chunk']} chunk — "
                f"keyword='{tc['keyword']}' value='{tc['value']}'"
            )

    # Check for unusual chunks
    for ctype in chunk_types:
        if ctype in SUSPICIOUS_CHUNK_TYPES and ctype not in [b'tEXt']:
            result['suspicious'] = True
            result['findings'].append(f"Unusual PNG chunk present: {ctype.decode()}")

    # LSB analysis
    score = _lsb_anomaly_score(chunks)
    result['lsb_anomaly_score'] = round(score, 4)
    if score < 0.02:  # very close to 50% — could indicate steganography
        result['suspicious'] = True
        result['findings'].append(
            f"LSB anomaly detected (score={score:.4f}): "
            "blue-channel LSBs are suspiciously uniform — possible LSB steganography"
        )

    if not result['findings']:
        result['findings'].append('No steganographic indicators found')

    return result


def analyse_directory(dirpath: str) -> list[dict]:
    """Analyse all PNG images in a directory."""
    results = []
    for path in sorted(Path(dirpath).rglob('*.png')):
        results.append(analyse_image(str(path)))
    return results
