#!/usr/bin/env python3
"""
CyberShield - file integrity analyzer.

Identifies a file's true format from its binary signature (magic numbers) and
compares that against the extension its name declares. Catches three evasion
classes: extension spoofing, payloads shipped with no extension at all, and
double-extension disguises such as ``invoice.pdf.exe``.

Interactive menu (no arguments):
    python cyber_scanner_pro.py

Non-interactive scan:
    python cyber_scanner_pro.py scan PATH [--recursive] [--json report.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

TOOL_NAME = "CyberShield"
TOOL_VERSION = "2.0.0"

HEAD_SIZE = 512          # enough to cover the TAR magic at offset 257
HASH_CHUNK = 1024 * 1024

EXIT_OK = 0              # scan finished, nothing flagged
EXIT_FLAGGED = 1         # scan finished, at least one file flagged
EXIT_USAGE = 2           # bad arguments or unusable target


class Verdict(str, Enum):
    CLEAN = "clean"
    SPOOFED = "spoofed"
    INFECTED = "infected"
    UNKNOWN = "unknown"
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class Signature:
    """A binary signature plus the extensions that are legitimate for it."""

    name: str
    magic: bytes
    offset: int
    extensions: frozenset

    def matches(self, head: bytes) -> bool:
        end = self.offset + len(self.magic)
        return head[self.offset:end] == self.magic


# Every entry declares which extensions are honest for that format. A filename
# whose extension is absent from the set is a mismatch, which is the whole
# point of the tool. ZIP-container formats share one signature on purpose:
# docx/xlsx/pptx/jar/apk/epub are all real ZIP files and must not be flagged.
SIGNATURES: Tuple[Signature, ...] = (
    Signature("JPEG Image", b"\xff\xd8\xff", 0,
              frozenset({"jpg", "jpeg", "jpe", "jfif"})),
    Signature("PNG Image", b"\x89PNG", 0, frozenset({"png"})),
    Signature("GIF Image", b"GIF8", 0, frozenset({"gif"})),
    Signature("TIFF Image", b"II\x2a\x00", 0, frozenset({"tif", "tiff"})),
    Signature("TIFF Image", b"MM\x00\x2a", 0, frozenset({"tif", "tiff"})),
    Signature("ICO Icon", b"\x00\x00\x01\x00", 0, frozenset({"ico"})),
    Signature("PDF Document", b"%PDF", 0, frozenset({"pdf"})),
    Signature("PostScript Document", b"%!", 0, frozenset({"ps", "eps"})),
    Signature("RTF Document", b"{\\rtf", 0, frozenset({"rtf"})),
    Signature("Windows Executable (PE)", b"MZ", 0,
              frozenset({"exe", "dll", "sys", "scr", "cpl", "ocx", "drv", "efi"})),
    Signature("OLE Compound Document", b"\xd0\xcf\x11\xe0", 0,
              frozenset({"doc", "xls", "ppt", "msi", "msg", "vsd", "pub"})),
    Signature("Windows Shortcut (LNK)", b"\x4c\x00\x00\x00", 0, frozenset({"lnk"})),
    Signature("ZIP Archive", b"PK\x03\x04", 0,
              frozenset({"zip", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm",
                         "jar", "apk", "epub", "odt", "ods", "odp", "whl",
                         "vsix", "ipa"})),
    Signature("ZIP Archive (empty)", b"PK\x05\x06", 0,
              frozenset({"zip", "docx", "xlsx", "pptx", "jar", "apk", "epub"})),
    Signature("RAR Archive", b"Rar!\x1a\x07", 0, frozenset({"rar"})),
    Signature("7-Zip Archive", b"7z\xbc\xaf\x27\x1c", 0, frozenset({"7z"})),
    Signature("Gzip Archive", b"\x1f\x8b", 0, frozenset({"gz", "tgz"})),
    Signature("Bzip2 Archive", b"BZh", 0, frozenset({"bz2", "tbz2"})),
    Signature("XZ Archive", b"\xfd7zXZ\x00", 0, frozenset({"xz", "txz"})),
    Signature("TAR Archive", b"ustar", 257, frozenset({"tar"})),
    Signature("ELF Binary", b"\x7fELF", 0,
              frozenset({"elf", "so", "o", "ko", "bin", "axf", "prx"})),
    Signature("Java Class File", b"\xca\xfe\xba\xbe", 0, frozenset({"class"})),
    Signature("SQLite Database", b"SQLite format 3\x00", 0,
              frozenset({"db", "sqlite", "sqlite3", "db3"})),
    Signature("MP4 Video", b"ftyp", 4, frozenset({"mp4", "m4v", "mov", "m4a"})),
    Signature("OGG Media", b"OggS", 0, frozenset({"ogg", "oga", "ogv", "opus"})),
    Signature("FLAC Audio", b"fLaC", 0, frozenset({"flac"})),
    Signature("WOFF Font", b"wOFF", 0, frozenset({"woff"})),
    Signature("WOFF2 Font", b"wOF2", 0, frozenset({"woff2"})),
)

# Final extensions that execute or get interpreted when opened.
EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "msi", "cpl", "dll", "lnk", "jar", "reg", "chm",
})

# Extensions commonly used as the innocent-looking half of a double extension.
DECOY_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "avi", "mov", "mkv",
    "wav", "zip", "rar", "7z", "tar", "gz", "iso", "html", "htm", "xml",
    "json", "log", "dat", "tmp",
})


def extension_of(name: str) -> str:
    """Lowercase extension without the dot, or '' when the name has none."""
    return os.path.splitext(name)[1].lower().lstrip(".")


def double_extension_reason(name: str) -> Optional[str]:
    """Explain why *name* looks like a disguise, or return None."""
    parts = [part.lower() for part in name.split(".")]
    if len(parts) < 3:
        return None
    final, decoy = parts[-1], parts[-2]
    if final in EXECUTABLE_EXTENSIONS and decoy in DECOY_EXTENSIONS:
        return (f"double extension: the name suggests a .{decoy} file but the "
                f".{final} ending makes it execute")
    return None


@dataclass
class FileResult:
    path: str
    relative_path: str
    name: str
    extension: str
    detected: str
    verdict: Verdict
    reasons: List[str]
    size: Optional[int] = None
    modified: Optional[str] = None
    sha256: Optional[str] = None
    clamav_signature: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "relative_path": self.relative_path,
            "name": self.name,
            "extension": self.extension,
            "detected": self.detected,
            "verdict": self.verdict.value,
            "reasons": list(self.reasons),
            "size": self.size,
            "modified": self.modified,
            "sha256": self.sha256,
            "clamav_signature": self.clamav_signature,
        }


class FileAnalyzer:
    def __init__(self, signatures: Sequence[Signature] = SIGNATURES,
                 hash_files: bool = True) -> None:
        self.signatures = signatures
        self.hash_files = hash_files

    @staticmethod
    def _read_head(path: str) -> Tuple[bytes, Optional[str]]:
        try:
            with open(path, "rb") as handle:
                return handle.read(HEAD_SIZE), None
        except OSError as exc:
            return b"", exc.strerror or str(exc)

    @staticmethod
    def _sha256(path: str) -> Tuple[Optional[str], Optional[str]]:
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(HASH_CHUNK), b""):
                    digest.update(chunk)
        except OSError as exc:
            return None, exc.strerror or str(exc)
        return digest.hexdigest(), None

    def detect(self, head: bytes) -> Optional[Signature]:
        for signature in self.signatures:
            if signature.matches(head):
                return signature
        return None

    def analyze(self, path: str, root: str) -> FileResult:
        name = os.path.basename(path)
        ext = extension_of(name)
        relative = os.path.relpath(path, root)

        size = modified = None
        try:
            stat = os.stat(path)
            size = stat.st_size
            modified = datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat(timespec="seconds")
        except OSError:
            pass

        head, read_error = self._read_head(path)
        reasons: List[str] = []

        if read_error:
            verdict = Verdict.UNREADABLE
            detected = "Unknown"
            reasons.append(f"could not read file: {read_error}")
            sha256 = None
        else:
            signature = self.detect(head)
            detected = signature.name if signature else "Unknown"

            if signature is None:
                verdict = Verdict.UNKNOWN
            else:
                if ext == "":
                    reasons.append(
                        f"no extension declared, but the content is {detected}")
                elif ext not in signature.extensions:
                    reasons.append(
                        f"declared .{ext} but the content is {detected}")
                verdict = Verdict.SPOOFED if reasons else Verdict.CLEAN

            disguise = double_extension_reason(name)
            if disguise:
                reasons.append(disguise)
                verdict = Verdict.SPOOFED

            sha256 = None
            if self.hash_files:
                sha256, hash_error = self._sha256(path)
                if hash_error:
                    # Never let a hashing problem turn a clean file into a
                    # flagged one; record it and leave the verdict alone.
                    reasons.append(f"sha256 unavailable: {hash_error}")

        return FileResult(
            path=path,
            relative_path=relative,
            name=name,
            extension=ext,
            detected=detected,
            verdict=verdict,
            reasons=reasons,
            size=size,
            modified=modified,
            sha256=sha256,
        )


CLAMAV_TIMEOUT = 300

INSTALL_HINT = (
    "  No ClamAV installation was found. Install one of:\n"
    "    - the ClamAV daemon plus its Python client:\n"
    "        pip install clamd          (then start clamd)\n"
    "    - the ClamAV command line tools:\n"
    "        apt install clamav         (Debian/Ubuntu)\n"
    "        brew install clamav        (macOS)\n"
    "        winget install ClamAV.ClamAV  (Windows)\n"
    "  Verify the installation with: clamscan --version"
)


class ClamAVUnavailable(RuntimeError):
    """Raised when no usable ClamAV backend can be found."""

    def __init__(self) -> None:
        super().__init__(INSTALL_HINT)


@dataclass
class ClamFinding:
    """One ClamAV result: a signature, an error, or neither (clean)."""

    signature: Optional[str] = None
    error: Optional[str] = None


class ClamAVScanner:
    """Signature-based scanning, preferring a running daemon over the CLI.

    Backends, in order of preference:
      clamd      - a live daemon reached through the Python client (fastest)
      clamdscan  - the CLI talking to that same daemon (fast)
      clamscan   - standalone CLI, batched so the signature DB loads once
    """

    SOCKET_CANDIDATES = (
        "/var/run/clamav/clamd.ctl",
        "/run/clamav/clamd.ctl",
        "/tmp/clamd.socket",
    )
    BATCH_SIZE = 50
    # 'clamd' exposes scan(); 'pyclamd' exposes scan_file(). Support both.
    SCAN_METHODS = ("scan_file", "scan")

    def __init__(self, socket_path: Optional[str] = None,
                 host: Optional[str] = None,
                 port: Optional[int] = None) -> None:
        self.socket_path = socket_path or os.environ.get("CLAMAV_SOCKET")
        self.host = host or os.environ.get("CLAMAV_HOST") or "127.0.0.1"
        self.port = int(port or os.environ.get("CLAMAV_PORT") or 3310)
        self.backend: Optional[str] = None
        self._client = None
        self._scan_method: Optional[str] = None
        self._detect_backend()

    # -- backend discovery -------------------------------------------------
    def _detect_backend(self) -> None:
        client, method = self._connect_client()
        if client is not None and method is not None:
            self._client = client
            self._scan_method = method
            self.backend = "clamd"
            return
        for name in ("clamdscan", "clamscan"):
            if shutil.which(name):
                self.backend = name
                return
        raise ClamAVUnavailable()

    def _connect_client(self):
        module = None
        for name in ("clamd", "pyclamd"):
            try:
                module = __import__(name)
                break
            except ImportError:
                continue
        if module is None:
            return None, None

        targets = []
        if self.socket_path:
            targets.append(("socket", self.socket_path))
        else:
            targets.extend(("socket", path) for path in self.SOCKET_CANDIDATES)
        targets.append(("network", (self.host, self.port)))

        for kind, target in targets:
            try:
                # A timeout matters: a wedged daemon must never hang the scan.
                if kind == "socket":
                    client = module.ClamdUnixSocket(target, CLAMAV_TIMEOUT)
                else:
                    client = module.ClamdNetworkSocket(
                        target[0], target[1], CLAMAV_TIMEOUT)
                client.ping()
            except Exception:
                continue
            method = self._scan_method_name(client)
            if method is None:
                # A client that cannot scan is no better than no client.
                continue
            return client, method
        return None, None

    @classmethod
    def _scan_method_name(cls, client) -> Optional[str]:
        for name in cls.SCAN_METHODS:
            if callable(getattr(client, name, None)):
                return name
        return None

    def describe(self) -> str:
        return self.backend or "unavailable"

    # -- scanning ----------------------------------------------------------
    def scan_files(self, paths: Sequence[str]) -> Dict[str, ClamFinding]:
        if not paths:
            return {}
        if self.backend == "clamd":
            return {path: self._scan_with_client(path) for path in paths}
        return self._scan_with_cli(self.backend, paths,
                                   per_file=self.backend == "clamdscan")

    def _scan_with_client(self, path: str) -> ClamFinding:
        try:
            raw = getattr(self._client, self._scan_method)(path)
        except Exception as exc:
            return ClamFinding(error=str(exc))
        if not raw:
            return ClamFinding()
        for value in raw.values():
            status = str(value[0]).upper()
            detail = value[1] if len(value) > 1 else None
            if status == "FOUND":
                return ClamFinding(signature=detail or "unknown signature")
            if status == "ERROR":
                return ClamFinding(error=detail or "scan error")
        return ClamFinding()

    def _scan_with_cli(self, binary: Optional[str], paths: Sequence[str],
                       per_file: bool) -> Dict[str, ClamFinding]:
        if not binary:
            return {path: ClamFinding(error="no ClamAV backend")
                    for path in paths}

        if per_file:
            batches = [[path] for path in paths]
        else:
            batches = [list(paths[index:index + self.BATCH_SIZE])
                       for index in range(0, len(paths), self.BATCH_SIZE)]

        findings: Dict[str, ClamFinding] = {}
        for batch in batches:
            try:
                completed = subprocess.run(
                    [binary, "--no-summary", "--stdout", *batch],
                    capture_output=True, text=True, timeout=CLAMAV_TIMEOUT,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                for path in batch:
                    findings[path] = ClamFinding(error=str(exc))
                continue

            parsed = self._parse_cli_output(completed.stdout)
            fallback = None
            if completed.returncode == 2:
                message = (completed.stderr or "clamscan reported an error").strip()
                fallback = message.splitlines()[-1] if message else "clamscan error"

            for path in batch:
                finding = parsed.get(os.path.abspath(path))
                if finding is None:
                    finding = ClamFinding(error=fallback) if fallback else ClamFinding()
                findings[path] = finding
        return findings

    @staticmethod
    def _parse_cli_output(stdout: str) -> Dict[str, ClamFinding]:
        """Turn 'path: Signature FOUND' / 'path: OK' lines into findings."""
        results: Dict[str, ClamFinding] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line or ": " not in line:
                continue
            path, detail = line.rsplit(": ", 1)
            key = os.path.abspath(path)
            if detail.endswith(" FOUND"):
                signature = detail[:-len(" FOUND")].strip()
                results[key] = ClamFinding(signature=signature or "unknown signature")
            elif detail.strip().upper() == "OK":
                results[key] = ClamFinding()
            elif "ERROR" in detail.upper() or "PERMISSION" in detail.upper():
                results[key] = ClamFinding(error=detail)
        return results


def engine_label(engine: str, clamav: Optional[ClamAVScanner]) -> str:
    if engine == "heuristic":
        return "heuristic"
    backend = clamav.describe() if clamav else "unavailable"
    if engine == "clamav":
        return f"clamav ({backend})"
    return f"heuristic + clamav ({backend})"


def apply_clamav(results: List[FileResult], paths: Sequence[str],
                 scanner: Optional[ClamAVScanner]) -> List[FileResult]:
    """Merge ClamAV findings into heuristic results, infection winning."""
    if scanner is None:
        return results

    findings = scanner.scan_files(paths)
    for result in results:
        finding = findings.get(result.path)
        if finding is None:
            continue
        if finding.signature:
            result.clamav_signature = finding.signature
            result.reasons.append(f"ClamAV signature: {finding.signature}")
            result.verdict = Verdict.INFECTED
        elif finding.error:
            result.reasons.append(f"ClamAV could not scan the file: {finding.error}")
    return results


def collect_paths(root: str, recursive: bool) -> List[str]:
    if recursive:
        found: List[str] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            for filename in sorted(filenames):
                found.append(os.path.join(dirpath, filename))
        return found

    paths: List[str] = []
    with os.scandir(root) as entries:
        for entry in entries:
            try:
                if entry.is_file():
                    paths.append(entry.path)
            except OSError:
                continue
    return sorted(paths)


def scan(root: str, recursive: bool = False, hash_files: bool = True,
         progress: bool = False, engine: str = "heuristic",
         clamav: Optional[ClamAVScanner] = None) -> dict:
    if os.path.isfile(root):
        base = os.path.dirname(os.path.abspath(root)) or "."
        paths = [root]
        recursive = False
    else:
        base = root
        paths = collect_paths(root, recursive)

    analyzer = FileAnalyzer(hash_files=hash_files)
    results: List[FileResult] = []
    started = time.monotonic()

    for index, path in enumerate(paths, start=1):
        results.append(analyzer.analyze(path, base))
        if progress and sys.stderr.isatty():
            sys.stderr.write(f"\r  scanning {index}/{len(paths)} ...")
            sys.stderr.flush()

    if progress and sys.stderr.isatty() and paths:
        sys.stderr.write("\r" + " " * 40 + "\r")
        sys.stderr.flush()

    if engine in ("clamav", "both"):
        results = apply_clamav(results, paths, clamav)

    return build_report(base, results, recursive,
                        round(time.monotonic() - started, 3),
                        engine_label(engine, clamav))


def build_report(root: str, results: List[FileResult], recursive: bool,
                 duration: float, engine: str = "heuristic") -> dict:
    counts = {verdict: 0 for verdict in Verdict}
    for result in results:
        counts[result.verdict] += 1

    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root": os.path.abspath(root),
        "recursive": recursive,
        "engine": engine,
        "duration_seconds": duration,
        "summary": {
            "total": len(results),
            "clean": counts[Verdict.CLEAN],
            "spoofed": counts[Verdict.SPOOFED],
            "infected": counts[Verdict.INFECTED],
            "unknown": counts[Verdict.UNKNOWN],
            "unreadable": counts[Verdict.UNREADABLE],
        },
        "files": [result.to_dict() for result in results],
    }


def print_report(report: dict, verbose: bool = False) -> None:
    files = report["files"]
    summary = report["summary"]

    if verbose:
        print()
        for item in files:
            print(f"  [{item['verdict'].upper():<10}] {item['relative_path']}")
            print(f"      declared: .{item['extension'] or '(none)':<8} "
                  f"detected: {item['detected']}")

    sections = (("INFECTED", "infected"), ("FLAGGED", "spoofed"),
                ("UNREADABLE", "unreadable"))
    for title, verdict in sections:
        group = [f for f in files if f["verdict"] == verdict]
        if not group:
            continue
        print(f"\n{title} ({len(group)})")
        for item in group:
            print(f"  [!] {item['relative_path']}")
            print(f"      declared: .{item['extension'] or '(none)':<8} "
                  f"detected: {item['detected']}")
            for reason in item["reasons"]:
                print(f"      - {reason}")

    print()
    print(f"Engine: {report.get('engine', 'heuristic')}")
    print(f"{summary['total']} files scanned in {report['duration_seconds']}s | "
          f"{summary['clean']} clean | {summary['spoofed']} spoofed | "
          f"{summary['infected']} infected | "
          f"{summary['unknown']} unknown | "
          f"{summary['unreadable']} unreadable")

    if summary["infected"]:
        print("Result: INFECTED - isolate the flagged files before using them.")
    elif summary["spoofed"]:
        print("Result: FLAGGED - review the files listed above.")
    elif summary["unreadable"]:
        print("Result: INCOMPLETE - some files could not be read.")
    else:
        print("Result: no spoofed or infected files detected.")


def write_json(report: dict, destination: str, only_flagged: bool) -> None:
    payload = dict(report)
    if only_flagged:
        payload["files"] = [f for f in report["files"]
                            if f["verdict"] in ("infected", "spoofed", "unreadable")]
    with open(destination, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyber_scanner_pro.py",
        description="Detect files whose content contradicts their extension.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan", help="scan a file or directory and report spoofed files")
    scan_parser.add_argument("path", help="file or directory to scan")
    scan_parser.add_argument("-r", "--recursive", action="store_true",
                             help="descend into subdirectories")
    scan_parser.add_argument("-j", "--json", metavar="FILE", default=None,
                             help="write a JSON report to FILE")
    scan_parser.add_argument("--only-flagged", action="store_true",
                             help="keep only spoofed/unreadable files in the JSON")
    scan_parser.add_argument("--no-hash", action="store_true",
                             help="skip SHA-256 hashing (faster, no fingerprints)")
    scan_parser.add_argument("-v", "--verbose", action="store_true",
                             help="list every scanned file, not just problems")
    scan_parser.add_argument("-q", "--quiet", action="store_true",
                             help="print only the summary line")
    scan_parser.add_argument(
        "--engine", choices=("heuristic", "clamav", "both"),
        default="heuristic",
        help="detection engine: magic-number heuristics (default), ClamAV "
             "signatures, or both")
    scan_parser.add_argument("--clamd-socket", metavar="PATH", default=None,
                             help="path to the clamd unix socket")
    scan_parser.add_argument("--clamd-host", metavar="HOST", default=None,
                             help="clamd TCP host (default 127.0.0.1)")
    scan_parser.add_argument("--clamd-port", metavar="PORT", type=int,
                             default=None,
                             help="clamd TCP port (default 3310)")
    return parser


def run_scan_command(args: argparse.Namespace) -> int:
    target = args.path
    if not os.path.exists(target):
        print(f"error: no such file or directory: {target}", file=sys.stderr)
        return EXIT_USAGE
    if not (os.path.isfile(target) or os.path.isdir(target)):
        print(f"error: unsupported target: {target}", file=sys.stderr)
        return EXIT_USAGE

    engine = args.engine
    scanner: Optional[ClamAVScanner] = None
    if engine in ("clamav", "both"):
        try:
            scanner = ClamAVScanner(socket_path=args.clamd_socket,
                                    host=args.clamd_host, port=args.clamd_port)
        except ClamAVUnavailable as hint:
            if engine == "clamav":
                print("error: the ClamAV engine was requested but is "
                      "unavailable.", file=sys.stderr)
                print(str(hint), file=sys.stderr)
                return EXIT_USAGE
            # 'both' degrades instead of failing: heuristics still run.
            print("warning: ClamAV is unavailable, continuing with heuristic "
                  "checks only.", file=sys.stderr)
            print(str(hint), file=sys.stderr)
            engine = "heuristic"

    report = scan(target, recursive=args.recursive,
                  hash_files=not args.no_hash, progress=not args.quiet,
                  engine=engine, clamav=scanner)

    if args.quiet:
        summary = report["summary"]
        print(f"{summary['total']} files | {summary['infected']} infected | "
              f"{summary['spoofed']} spoofed | "
              f"{summary['unreadable']} unreadable")
    else:
        print_report(report, verbose=args.verbose or os.path.isfile(target))

    if args.json:
        write_json(report, args.json, args.only_flagged)
        if not args.quiet:
            print(f"[+] JSON report written to {args.json}")

    summary = report["summary"]
    flagged = summary["infected"] or summary["spoofed"]
    return EXIT_FLAGGED if flagged else EXIT_OK


def print_banner() -> None:
    print("\n" + "=" * 64)
    print(f"      CYBERSHIELD AUDIT TOOL - V{TOOL_VERSION}")
    print("=" * 64)
    print(" 1. Analyze Single File      2. Audit Folder      3. Exit")
    print("=" * 64)


def ask_path(kind: str) -> Optional[str]:
    """Use a native dialog when tkinter exists, otherwise prompt on stdin."""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception:
        entered = input(f"Enter {kind} path: ").strip().strip('"')
        return entered or None

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        if kind == "file":
            return filedialog.askopenfilename() or None
        return filedialog.askdirectory() or None
    finally:
        root.destroy()


def interactive_menu() -> int:
    analyzer = FileAnalyzer()
    markers = {"clean": "[OK]", "spoofed": "[!] SPOOFED",
               "infected": "[!] INFECTED", "unknown": "[?]",
               "unreadable": "[x]"}

    while True:
        print_banner()
        choice = input("\n> Select action: ").strip()

        if choice == "1":
            target = ask_path("file")
            if not target:
                continue
            print("\n[*] Inspecting file header...")
            result = analyzer.analyze(target, os.path.dirname(target) or ".")
            print(f"{markers[result.verdict.value]} | {result.name} | "
                  f"declared: {result.extension or '(none)'} | "
                  f"real: {result.detected}")
            for reason in result.reasons:
                print(f"      - {reason}")
            if result.sha256:
                print(f"      sha256: {result.sha256}")

        elif choice == "2":
            folder = ask_path("folder")
            if not folder:
                continue
            print(f"\n[*] Auditing directory: {folder}")
            report = scan(folder, recursive=False, hash_files=True,
                          progress=True)
            print_report(report)

            flagged = [f for f in report["files"] if f["verdict"] == "spoofed"]
            with open("audit_report.txt", "w", encoding="utf-8") as handle:
                handle.write(f"{TOOL_NAME} Audit - {report['generated_at']}\n")
                handle.write(f"Root: {report['root']}\n\n")
                if not flagged:
                    handle.write("No spoofed files detected.\n")
                for item in flagged:
                    handle.write(f"{item['relative_path']}\n")
                    handle.write(f"  declared: {item['extension'] or '(none)'}"
                                 f" | detected: {item['detected']}\n")
                    for reason in item["reasons"]:
                        handle.write(f"  - {reason}\n")
                    handle.write(f"  sha256: {item['sha256']}\n\n")
            print("\n[+] Report saved to 'audit_report.txt'")

        elif choice == "3":
            print("System offline. Stay secure.")
            return EXIT_OK

        else:
            print("Invalid selection. Choose 1, 2 or 3.")


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Bare invocation keeps the original interactive experience.
    if not argv:
        return interactive_menu()

    args = build_parser().parse_args(argv)

    try:
        return run_scan_command(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
