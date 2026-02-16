# 🛡️ File-Integrity-Analyzer

A professional-grade cybersecurity tool built in Python to identify the **true identity** of files by analyzing their binary headers (Magic Numbers), effectively detecting extension spoofing and common malware evasion techniques.

---

## 🔍 The Cybersecurity Problem
Hackers often hide malicious payloads by renaming executable files (like `.exe` or `.sh`) to innocent-looking extensions (like `.jpg` or `.pdf`). Traditional file filters that only look at extensions can be easily bypassed.

This tool solves that by performing a **deep inspection of the file's first bytes** to verify if the internal data matches the declared extension.

## ✨ Key Features
* **Deep Binary Inspection**: Analyzes the hex header (Magic Numbers) of files.
* **Interactive Menu**: Choose between analyzing a single file or an entire directory.
* **Smart Detection**: Flags inconsistencies (e.g., a file named `.pdf` that is actually a `.jpg`).
* **Audit Logging**: Automatically generates a technical report (`audit_report.txt`) after folder scans.
* **Universal Selection**: Uses a visual file explorer to select targets anywhere on your system.

## 🛠️ Technology Stack
* **Language**: Python 3.x
* **GUI Components**: `tkinter` (File/Folder dialogs)
* **Logic**: Binary file I/O and Hexadecimal mapping.

## 🚀 How to Use
1.  **Clone the repository**:
    ```bash
    git clone [https://github.com/Ullloa/File-Integrity-Analyzer.git](https://github.com/Ullloa/File-Integrity-Analyzer.git)
    ```
2.  **Run the script**:
    ```bash
    python cyber_scanner_pro.py
    ```
3.  **Select Action**: Follow the on-screen menu to start auditing your files.

## 📝 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
