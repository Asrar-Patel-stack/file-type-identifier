# File Type Identifier & Malware Hint Scanner

A simple Python CLI tool to detect file type using magic bytes (file headers), compare to the file extension, and optionally compute MD5/SHA256 hashes for further malware checks.
---

## 📘 Overview
The **File Type Identifier & Malware Hint Scanner** is a lightweight yet powerful malware detection tool designed for early threat identification. It reads file headers (magic bytes) to determine true file types, compares them with their extensions, and flags discrepancies—an indicator of file obfuscation or malicious intent.  
This tool also generates **MD5** and **SHA-256** hashes for each scanned file, which can be used for further verification in malware signature databases.

---

## ❗ Problem Statement
Modern malware often disguises itself by changing file extensions (e.g., `malware.jpg` or `invoice.pdf.exe`) to bypass detection.  
Traditional antivirus tools might overlook such obfuscation techniques.  
This project addresses this challenge by performing **file header analysis** and **cryptographic hashing** to detect inconsistencies between declared and actual file types.

---

## 📂 Dataset
This project does not rely on a pre-existing dataset.  
Instead, it analyzes real-world files directly from the user’s filesystem.  
The internal database includes **magic byte signatures** for over **15 common file formats**, such as:
- JPEG, PNG, PDF, DOCX  
- EXE, ELF, ZIP, TAR, and others.

---

## 🛠️ Tools and Technologies
- **Programming Language:** Python 3.13  
- **Libraries Used:** `os`, `hashlib`, `argparse`, `struct`, `pyinstaller`  
- **Environment:** Virtual Environment (`venv`)  
- **Deployment Tool:** PyInstaller (for creating standalone executables)  
- **Platform:** Windows / Linux SOC environments

---

## ⚙️ Methods
1. **Magic Byte Inspection:**  
   Extracts and verifies the first few bytes of a file to determine its real type.  
2. **Extension Comparison:**  
   Compares detected type with the file extension to detect mismatches.  
3. **Hash Generation:**  
   Computes MD5 and SHA-256 hashes for malware signature cross-referencing.  
4. **Automated Detection:**  
   Supports detection for more than 15 file formats.  
5. **Executable Packaging:**  
   Bundled into a standalone `.exe` or binary using PyInstaller.

---

## 💡 Key Insights
- File type mismatches are strong indicators of suspicious activity.  
- Simple static analysis using magic bytes can uncover stealthy malware.  
- Hash-based verification enhances detection reliability and supports integration with threat intelligence databases.

---
## 🚀 How to Run This Project

**1. Clone the repository:**
```bash
git clone https://github.com/Asrar-Patel-stack/file-type-identifier.git
cd file-type-identifier  

---

**2. Clone the repository:**

## Usage
```bash
python file_type_identifier.py /path/to/file
python file_type_identifier.py suspicious.jpg --show-bytes
python file_type_identifier.py archive.docx



