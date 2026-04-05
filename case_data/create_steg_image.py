"""
Script to generate a simulated image with embedded steganographic data.
Run once to create the test image: python3 case_data/create_steg_image.py
"""
import struct
import zlib
import os

def create_png_with_hidden_text(filepath, hidden_message):
    """Create a minimal valid PNG with a hidden tEXt chunk."""
    width, height = 100, 100

    def make_chunk(chunk_type, data):
        chunk_len = struct.pack('>I', len(data))
        chunk_data = chunk_type + data
        crc = struct.pack('>I', zlib.crc32(chunk_data) & 0xFFFFFFFF)
        return chunk_len + chunk_data + crc

    # PNG signature
    sig = b'\x89PNG\r\n\x1a\n'

    # IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    ihdr = make_chunk(b'IHDR', ihdr_data)

    # Hidden tEXt chunk (steganographic metadata)
    text_data = b'SecretMessage\x00' + hidden_message.encode('utf-8')
    text_chunk = make_chunk(b'tEXt', text_data)

    # IDAT chunk — plain red pixels
    raw_rows = b''
    for _ in range(height):
        row = b'\x00'  # filter type none
        for _ in range(width):
            row += b'\xFF\x00\x00'  # RGB red pixel
        raw_rows += row
    compressed = zlib.compress(raw_rows)
    idat = make_chunk(b'IDAT', compressed)

    # IEND chunk
    iend = make_chunk(b'IEND', b'')

    png_bytes = sig + ihdr + text_chunk + idat + iend

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'wb') as f:
        f.write(png_bytes)
    print(f"Created: {filepath}")

if __name__ == '__main__':
    create_png_with_hidden_text(
        'case_data/images/office_photo.png',
        'meeting_location=warehouse_district;contact=shadow99;transfer_code=XK-7741'
    )
    # Normal image (no hidden data)
    create_png_with_hidden_text(
        'case_data/images/team_photo.png',
        ''
    )
    print("Done.")
