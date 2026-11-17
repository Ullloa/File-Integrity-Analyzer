# 🛡️ File-Integrity-Analyzer

A professional-grade cybersecurity tool built in Python to identify the **true identity** of files by analyzing their binary signatures (Magic Numbers), effectively detecting extension spoofing and common malware evasion techniques.

---

## 🔍 The Cybersecurity Problem
Hackers often hide malicious payloads by renaming executable files (like `.exe` or `.sh`) to innocent-looking extensions (like `.jpg` or `.pdf`), or by stripping the extension entirely. Traditional file filters that only look at extensions can be bypassed in seconds.

This tool performs a **deep inspection of the file's first bytes** and compares what the file *is* against what its name *claims* to be.

## ✨ Key Features
* **Declarative signature table**: every known format declares the extensions that are legitimate for it, so both the detection and the mismatch check come from the same source of truth.
* **Offset-aware matching**: handles formats whose magic number is not at byte 0 (MP4 at offset 4, TAR at offset 257).
* **Archive-aware**: `.docx`, `.xlsx`, `.pptx`, `.jar`, `.apk`, `.epub` and friends are all ZIP containers internally and are correctly reported as clean instead of being flagged.
* **Extensionless detection**: a payload with no extension at all (`payload` containing `MZ`) is flagged, not silently passed.
* **Double-extension detection**: `invoice.pdf.exe` is caught even though its declared extension matches its content.
* **SHA-256 fingerprints**: every file gets a streaming SHA-256 hash, ready for threat-intelligence lookups.
* **Unreadable files are reported**, never silently skipped — a scan can no longer say "clean" while having skipped locked files.
* **ClamAV integration**: opt-in signature-based detection via `--engine clamav` or `--engine both`, using a running daemon when available and the CLI otherwise.
* **Scriptable**: a full CLI with JSON output and CI-friendly exit codes.
* **Interactive menu** retained for manual, GUI-assisted use.

## 🛠️ Technology Stack
* **Language**: Python 3.8+ (standard library only)
* **GUI Components**: `tkinter` for file/folder dialogs (optional — the tool falls back to a typed path when Tk is unavailable)
* **Logic**: binary file I/O, magic-number mapping, streaming hashing

## 🚀 How to Use

### Non-interactive (recommended)
```bash
# Scan a folder
python cyber_scanner_pro.py scan ~/Downloads

# Recurse into subfolders and write a JSON report
python cyber_scanner_pro.py scan ~/Downloads -r --json report.json

# Inspect a single file
python cyber_scanner_pro.py scan suspicious.jpg

# Fast mode: skip hashing
python cyber_scanner_pro.py scan ~/Downloads -r --no-hash
```

### Signature scanning with ClamAV
```bash
# ClamAV signatures only
python cyber_scanner_pro.py scan ~/Downloads -r --engine clamav

# Heuristics and ClamAV merged into one verdict per file
python cyber_scanner_pro.py scan ~/Downloads -r --engine both --json report.json
```
ClamAV is reached through a running `clamd` daemon when one is available (via the `clamd` Python client or the `clamdscan` CLI), and through `clamscan` otherwise. Point it at a non-default daemon with `--clamd-socket PATH` or `--clamd-host HOST --clamd-port PORT`, or with the `CLAMAV_SOCKET`, `CLAMAV_HOST` and `CLAMAV_PORT` environment variables.

If no ClamAV installation is found, `--engine clamav` prints installation instructions and exits with code `2` instead of silently scanning nothing. `--engine both` warns and continues with heuristics only, so a scheduled scan keeps working.

### Interactive
```bash
python cyber_scanner_pro.py
```
Follow the on-screen menu to analyze a single file or audit a folder. Folder audits also write a human-readable `audit_report.txt`.

## 📊 Verdicts

| Verdict | Meaning |
| --- | --- |
| `clean` | Content matches the declared extension. |
| `spoofed` | Content contradicts the extension, the file has no extension but known content, or the name uses a double extension. |
| `infected` | ClamAV matched a malware signature. Always outranks the other verdicts. |
| `unknown` | No signature matched (e.g. plain text). Not a judgement either way. |
| `unreadable` | The file could not be opened — excluded from the clean count on purpose. |

## 🚦 Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Scan finished, nothing flagged. |
| `1` | Scan finished, at least one spoofed file found. |
| `2` | Bad arguments or an unusable path. |

This makes the tool usable in CI or a scheduled task:
```bash
python cyber_scanner_pro.py scan ./uploads -r -q || echo "Quarantine the uploads folder"
```

## 🗺️ Roadmap
* Entropy analysis and PE parsing (`pefile`) for packer detection
* YARA rules for behavioural detection
* Threat-intelligence lookups by SHA-256 (VirusTotal, MalwareBazaar)
* Quarantine vault with restore

## 📝 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
