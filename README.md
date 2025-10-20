# File Type Identifier & Malware Hint Scanner

A simple Python CLI tool to detect file type using magic bytes (file headers), compare to the file extension, and optionally compute MD5/SHA256 hashes for further malware checks.

## Features
- Detects file type by reading file header (magic bytes).
- Compares detected type with file extension; marks mismatches as **Suspicious**.
- Small signature database included (JPG, PNG, PDF, EXE, ZIP, etc).
- Optional MD5 and SHA256 generation.

## Usage
```bash
python file_type_identifier.py /path/to/file
python file_type_identifier.py suspicious.jpg --show-bytes
python file_type_identifier.py archive.docx

