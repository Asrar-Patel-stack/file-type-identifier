#!/usr/bin/env python3
"""
file_type_identifier.py
Detects file type by magic bytes (headers), compares with extension,
and optionally prints MD5/SHA256 for malware DB checks.
"""

import os
import sys
import argparse
import hashlib
from typing import Optional, Tuple

# -- Signature database: mapping type -> list of (offset, magic_bytes, description)
# Offset = byte offset in file where magic bytes appear (0 for most).
SIGNATURE_DB = {
    "jpg":  [(0, b"\xFF\xD8\xFF", "JPEG (JFIF / Exif)")],
    "png":  [(0, b"\x89PNG\r\n\x1A\n", "PNG image")],
    "gif":  [(0, b"GIF87a", "GIF87a"), (0, b"GIF89a", "GIF89a")],
    "pdf":  [(0, b"%PDF-", "PDF document")],
    "zip":  [(0, b"PK\x03\x04", "ZIP archive (incl. DOCX, ODT, EPUB)")],
    "rar":  [(0, b"Rar!\x1A\x07\x00", "RAR archive (v1.5->v4)"), (0, b"Rar!\x1A\x07\x01\x00", "RAR (v5+)")],
    "exe":  [(0, b"MZ", "Windows PE (MZ header)")],
    "elf":  [(0, b"\x7fELF", "Linux ELF executable")],
    "bmp":  [(0, b"BM", "Bitmap image")],
    "mp3":  [(0, b"ID3", "MP3 (ID3 tag)"), (0, b"\xFF\xFB", "MP3 frame")],
    "wav":  [(0, b"RIFF", "RIFF/WAV (needs further 'WAVE' check at offset 8)")],
    "tar":  [(257, b"ustar", "TAR archive (ustar)")]
}

# Helper: extract extension from filename (without leading dot), lowercased
def get_extension(filename: str) -> Optional[str]:
    base = os.path.basename(filename)
    if '.' not in base:
        return None
    return base.rsplit('.', 1)[-1].lower()

# Read first N bytes (and any specific offsets we might need)
def read_bytes(path: str, num_bytes: int = 512) -> bytes:
    with open(path, "rb") as f:
        return f.read(num_bytes)

# Compute hashes (MD5, SHA256)
def compute_hashes(path: str) -> Tuple[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()

# Detect signature from bytes
def detect_signature(file_bytes: bytes) -> Optional[Tuple[str, str]]:
    # Check each signature: some require reading at offset
    for filetype, sig_list in SIGNATURE_DB.items():
        for offset, magic, desc in sig_list:
            # make sure we have enough bytes to compare
            if offset + len(magic) <= len(file_bytes):
                if file_bytes[offset:offset + len(magic)] == magic:
                    # Special check: WAV needs "WAVE" at offset 8 after "RIFF"
                    if filetype == "wav":
                        if len(file_bytes) >= 12 and file_bytes[8:12] != b"WAVE":
                            continue
                    return filetype, desc
    return None

def analyze_file(path: str, show_hashes: bool = True, show_bytes: bool = False) -> dict:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"No such file: {path}")
    file_bytes = read_bytes(path, 1024)  # read first 1KB for signatures that use later offsets
    detected = detect_signature(file_bytes)
    ext = get_extension(path)

    result = {
        "path": path,
        "extension": ext,
        "detected_type": detected[0] if detected else None,
        "detected_description": detected[1] if detected else None,
        "suspicious": False,
    }

    # If detected and extension exists, compare
    if detected and ext:
        # many compressed/office formats are zip-based (docx/xlsx/pptx)
        # map some extensions to their canonical container types
        ext_map = {
            "docx": "zip", "xlsx": "zip", "pptx": "zip", "odt": "zip",
            "epub": "zip", "jar": "zip"
        }
        canonical_ext = ext_map.get(ext, ext)
        if detected[0] != canonical_ext:
            result["suspicious"] = True

    # If no extension but detected, not necessarily suspicious (just missing extension)
    if show_hashes:
        md5, sha256 = compute_hashes(path)
        result["md5"] = md5
        result["sha256"] = sha256

    if show_bytes:
        result["header_bytes_hex"] = file_bytes[:32].hex()

    return result

def pretty_print_result(res: dict):
    print("="*60)
    print(f"File: {res['path']}")
    print(f"Extension: {res['extension']}")
    print(f"Detected Type: {res['detected_type']} ({res.get('detected_description')})")
    if res.get("md5"):
        print(f"MD5:    {res['md5']}")
        print(f"SHA256: {res['sha256']}")
    if res.get("header_bytes_hex"):
        print(f"Header (hex): {res['header_bytes_hex']}")
    print("Verdict:", "SUSPICIOUS" if res["suspicious"] else "Looks consistent")
    print("="*60)

def main():
    parser = argparse.ArgumentParser(description="File Type Identifier & Malware Hint Scanner")
    parser.add_argument("file", help="File path to analyze")
    parser.add_argument("--no-hash", action="store_true", help="Don't compute MD5/SHA256")
    parser.add_argument("--show-bytes", action="store_true", help="Show first bytes (hex)")
    args = parser.parse_args()

    try:
        res = analyze_file(args.file, show_hashes=not args.no_hash, show_bytes=args.show_bytes)
        pretty_print_result(res)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
