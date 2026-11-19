#!/usr/bin/env python3
"""Local secrets and credential leak scanner.

Scans files (and optionally git history) for exposed keys, tokens, passwords,
and private links. Writes a Markdown report whose main job is a rotation
checklist: what leaked, where, who can reach it, how to revoke it, and how to
prove the old credential is dead.

No cloud services. No third-party packages. Nothing leaves this machine.

Usage:
    python scanner.py C:\path\to\folder
    python scanner.py . --git
    python scanner.py . --git --out report.md --json findings.json
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path

from detectors import BINARY_EXTENSIONS, Finding, RULES, SEVERITY_ORDER, scan_line
from report import group_findings, render_markdown, Group

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "venv", ".venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache",
    "dist", "build", "target", "coverage", ".next", ".nuxt", ".cache",
    "AppData", "Windows", "Program Files", "Program Files (x86)",
}
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_LINE_CHARS = 5000


def display_path(path: Path, base: Path | None = None) -> str:
    """Prefer a short path, and never show your home folder by name."""
    target = path.resolve()
    if base is not None:
        try:
            return str(target.relative_to(base.resolve()))
        except ValueError:
            pass
    try:
        return str(target.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(target).replace(str(Path.home()), "~", 1)


def plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


class IgnoreRules:
    """Patterns from .secretsignore, applied to files and zip members."""

    def __init__(self, patterns: list[str] | None = None):
        self.patterns = []
        for raw in patterns or []:
            pattern = raw.strip().replace("\\", "/")
            if pattern and not pattern.startswith("#"):
                self.patterns.append(pattern)

    @classmethod
    def load(cls, roots: list[Path], extra: str | None = None) -> "IgnoreRules":
        files: list[Path] = []
        if extra:
            files.append(Path(extra).expanduser())
        cwd_file = Path.cwd() / ".secretsignore"
        if cwd_file.is_file():
            files.append(cwd_file)
        for root in roots:
            folder = root if root.is_dir() else root.parent
            candidate = folder / ".secretsignore"
            if candidate.is_file() and candidate not in files:
                files.append(candidate)

        patterns: list[str] = []
        seen: set[str] = set()
        for file in files:
            try:
                lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError as error:
                print(f"[warn] Could not read ignore file {file}: {error}")
                continue
            for line in lines:
                if line.strip() and line.strip() not in seen:
                    seen.add(line.strip())
                    patterns.append(line.strip())
        return cls(patterns)

    def matches_rel(self, relative: str, is_dir: bool = False) -> bool:
        rel = relative.replace("\\", "/").lstrip("./")
        if not rel:
            return False
        probe = rel + "/" if is_dir and not rel.endswith("/") else rel
        for raw in self.patterns:
            pattern = raw.replace("\\", "/").lstrip("./")
            if pattern.endswith("/"):
                prefix = pattern.rstrip("/")
                if probe == prefix or probe.startswith(prefix + "/"):
                    return True
                if f"/{prefix}/" in f"/{probe}":
                    return True
            elif fnmatch.fnmatch(probe, pattern):
                return True
            elif fnmatch.fnmatch(rel.rstrip("/").split("/")[-1], pattern):
                return True
        return False

    def matches(self, path: Path, base: Path | None = None) -> bool:
        try:
            relative = (
                str(path.resolve().relative_to(base.resolve()))
                if base
                else str(path.resolve().relative_to(Path.cwd().resolve()))
            )
        except ValueError:
            relative = path.name
        return self.matches_rel(relative, path.is_dir())


def iter_files(start: Path, ignore: IgnoreRules | None = None):
    """Yield readable files under a path, skipping heavy or ignored folders."""
    ignore = ignore or IgnoreRules()
    if start.is_file():
        if not ignore.matches(start, start.parent):
            yield start
        return
    for root, dirs, files in os.walk(start):
        dirs[:] = [
            name
            for name in dirs
            if name.lower() not in {item.lower() for item in SKIP_DIRS}
            and not name.startswith(".git")
            and not ignore.matches(Path(root) / name, start)
        ]
        for name in files:
            if name == ".secretsignore":
                continue
            path = Path(root) / name
            if not ignore.matches(path, start):
                yield path


def is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(4096)
    except OSError:
        return True


def scan_file(path: Path, base: Path | None = None) -> list[Finding]:
    if is_binary(path):
        return []
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    shown = display_path(path, base)
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line or len(line) > MAX_LINE_CHARS:
            continue
        findings.extend(scan_line(line, shown, number))
    return findings


MAX_ZIP_MEMBERS = 5000


def scan_zip(
    path: Path,
    base: Path | None = None,
    ignore: IgnoreRules | None = None,
) -> tuple[list[Finding], int, int]:
    """Read text members inside a .zip without extracting anything to disk.

    Google Takeout and Drive exports usually arrive as several zip files, so
    this is the adapter for them. Members that are binary, huge, or ignored are
    skipped and counted.
    """
    ignore = ignore or IgnoreRules()
    label_base = display_path(path, base)
    findings: list[Finding] = []
    scanned = 0
    skipped = 0
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                print(
                    f"[warn] {label_base} has {len(members)} members; "
                    f"reading the first {MAX_ZIP_MEMBERS}"
                )
                members = members[:MAX_ZIP_MEMBERS]
            for info in members:
                if info.is_dir():
                    continue
                member = info.filename
                label = f"{label_base}!{member}"
                if ignore.matches_rel(member) or ignore.matches_rel(label):
                    skipped += 1
                    continue
                if (
                    info.file_size > MAX_FILE_BYTES
                    or Path(member).suffix.lower() in BINARY_EXTENSIONS
                ):
                    skipped += 1
                    continue
                try:
                    with archive.open(info) as handle:
                        data = handle.read(MAX_FILE_BYTES + 1)
                except (KeyError, RuntimeError, zipfile.BadZipFile):
                    skipped += 1
                    continue
                if len(data) > MAX_FILE_BYTES or b"\x00" in data[:4096]:
                    skipped += 1
                    continue
                scanned += 1
                text = data.decode("utf-8", "ignore")
                for number, line in enumerate(text.splitlines(), 1):
                    if not line or len(line) > MAX_LINE_CHARS:
                        continue
                    findings.extend(scan_line(line, label, number))
    except (OSError, zipfile.BadZipFile) as error:
        print(f"[warn] Could not read zip {label_base}: {error}")
    return findings, scanned, skipped


def scan_git_history(repo: Path, ignore: IgnoreRules | None = None) -> list[Finding]:
    """Walk `git log -p` and scan only the added lines of every commit."""
    ignore = ignore or IgnoreRules()
    command = [
        "git", "-C", str(repo), "log", "-p", "--all", "--unified=0",
        "--no-color", "--no-ext-diff", "--format=@@@%H|%aI|%an",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, errors="replace", timeout=900
        )
    except (OSError, subprocess.SubprocessError) as error:
        print(f"[warn] Could not read git history in {repo}: {error}")
        return []
    if result.returncode != 0:
        print(f"[warn] git log failed in {repo}")
        return []

    findings: list[Finding] = []
    commit = date = author = ""
    current_path = ""
    new_line = 0
    for raw in result.stdout.splitlines():
        if raw.startswith("@@@"):
            parts = raw[3:].split("|", 2)
            commit = parts[0] if parts else ""
            date = parts[1] if len(parts) > 1 else ""
            author = parts[2] if len(parts) > 2 else ""
            continue
        if raw.startswith("diff --git"):
            current_path = ""
            continue
        if raw.startswith("+++ b/"):
            candidate = raw[6:]
            current_path = "" if ignore.matches_rel(candidate) else candidate
            continue
        if raw.startswith("+++ "):
            # Deleted file or /dev/null: nothing added to scan.
            current_path = ""
            continue
        if raw.startswith("@@"):
            header = raw.split("+", 1)[-1].split(" ", 1)[0]
            start = header.split(",")[0]
            new_line = int(start) if start.isdigit() else 0
            continue
        if raw.startswith("+"):
            line = raw[1:]
            if current_path and line and len(line) <= MAX_LINE_CHARS:
                findings.extend(
                    scan_line(
                        line,
                        current_path,
                        new_line,
                        source="git history",
                        commit=commit,
                        commit_date=date,
                        commit_author=author,
                    )
                )
            new_line += 1
        elif raw.startswith(" "):
            new_line += 1
    return findings


def git_root(path: Path) -> Path | None:
    base = path if path.is_dir() else path.parent
    try:
        result = subprocess.run(
            ["git", "-C", str(base), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip())


def write_json(path: Path, groups: list[Group], meta: dict) -> None:
    payload = {
        "generated_at": meta["generated_at"],
        "paths": meta["paths"],
        "files_scanned": meta["files_scanned"],
        "files_skipped": meta["files_skipped"],
        "git_used": meta["git_used"],
        "rules": meta["rules_count"],
        "unique_secrets": len(groups),
        "groups": [
            {
                "rule": group.rule.id,
                "name": group.rule.name,
                "provider": group.rule.provider,
                "severity": group.severity,
                "masked": group.masked,
                "fingerprint": group.fingerprint,
                "locations": group.locations,
                "found_in_git_history": any(
                    finding.source == "git history" for finding in group.findings
                ),
            }
            for group in groups
        ],
    }
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan for exposed secrets and print a rotation checklist."
    )
    parser.add_argument("paths", nargs="+", help="files or folders to scan")
    parser.add_argument(
        "--git", action="store_true", help="also scan git history of repos found"
    )
    parser.add_argument(
        "--zips",
        action="store_true",
        help="also read text members inside .zip files (Drive / Takeout exports)",
    )
    parser.add_argument(
        "--ignore",
        help="extra .secretsignore file (patterns already in the folder are auto-loaded)",
    )
    parser.add_argument("--out", default="report.md", help="Markdown report path")
    parser.add_argument("--json", help="optional JSON findings path")
    parser.add_argument(
        "--min-severity",
        choices=["Critical", "High", "Medium"],
        default="Medium",
        help="lowest severity to include (default: Medium)",
    )
    parser.add_argument(
        "--max-file-mb",
        type=float,
        default=5.0,
        help="skip files larger than this (default: 5)",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="exit 0 even when critical or high findings exist",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    global MAX_FILE_BYTES
    MAX_FILE_BYTES = int(args.max_file_mb * 1024 * 1024)

    roots = []
    for raw in args.paths:
        path = Path(raw).expanduser()
        if not path.exists():
            print(f"[!] Path not found: {path}", file=sys.stderr)
            return 1
        roots.append(path)

    started = time.time()
    findings: list[Finding] = []
    seen_files: set[Path] = set()
    files_scanned = 0
    files_skipped = 0
    ignore = IgnoreRules.load(roots, args.ignore)
    if ignore.patterns:
        print(f"[*] {len(ignore.patterns)} ignore pattern(s) loaded")

    for root in roots:
        print(f"[*] Scanning {display_path(root)}")
        base = root if root.is_dir() else root.parent
        for path in iter_files(root, ignore):
            resolved = path.resolve()
            if resolved in seen_files:
                continue
            seen_files.add(resolved)
            if path.suffix.lower() == ".zip":
                if not args.zips:
                    files_skipped += 1
                    continue
                zip_findings, zip_read, zip_skipped = scan_zip(path, base, ignore)
                findings.extend(zip_findings)
                files_scanned += zip_read
                files_skipped += zip_skipped
                continue
            if is_binary(path):
                files_skipped += 1
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    files_skipped += 1
                    continue
            except OSError:
                files_skipped += 1
                continue
            files_scanned += 1
            findings.extend(scan_file(path, base))

    git_used = False
    if args.git:
        repos: set[Path] = set()
        for root in roots:
            repo = git_root(root)
            if repo:
                repos.add(repo.resolve())
        for repo in sorted(repos):
            print(f"[*] Scanning git history in {display_path(repo)}")
            git_used = True
            findings.extend(scan_git_history(repo, ignore))

    min_rank = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= min_rank]

    groups = group_findings(findings)
    meta = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "paths": [display_path(root) for root in roots],
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "git_used": git_used,
        "rules_count": len(RULES),
    }

    report_path = Path(args.out)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        render_markdown(groups, meta), encoding="utf-8", newline="\n"
    )
    if args.json:
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(json_path, groups, meta)

    elapsed = time.time() - started
    print(
        f"\n[*] Read {files_scanned} file(s), skipped {files_skipped}, "
        f"in {elapsed:.1f}s"
    )
    if not groups:
        print("[+] No exposed secrets found.")
    else:
        total_locations = sum(len(group.findings) for group in groups)
        print(
            f"[!] {len(groups)} unique secret(s) across {total_locations} "
            f"location(s)"
        )
        for group in groups[:10]:
            print(
                f"    {group.severity:<8} {group.rule.name:<26} "
                f"{group.masked:<20} {plural(len(group.findings), 'location')}"
            )
        if len(groups) > 10:
            print(f"    ...and {len(groups) - 10} more in the report")
    print(f"[+] Report: {report_path}")
    if args.json:
        print(f"[+] JSON: {args.json}")
    print("[i] Deleting the file does not revoke the key. Rotate first.")

    has_urgent = any(
        SEVERITY_ORDER[group.severity] <= SEVERITY_ORDER["High"] for group in groups
    )
    if has_urgent and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
