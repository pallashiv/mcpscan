"""Command-line entrypoint: ``mcpscan scan <path>``."""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace
from typing import List, Optional

from . import __version__
from .models import Finding, Severity
from .html_report import render_html
from .lock import check_lock, load_lock, lock_document
from .report import RENDERERS, render_text
from .scanner import ScanError, scan_file
from .suppress import apply_suppressions, baseline_document, load_baseline, load_ignore

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpscan",
        description="Static security scanner for MCP servers. Reads files only; never runs or connects to a server.",
    )
    parser.add_argument("--version", action="version", version=f"mcpscan {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>", required=True)
    scan = sub.add_parser(
        "scan",
        help="scan a tool manifest or client config",
        description="Scan a tool manifest (tools/list JSON) or a client config (mcpServers JSON).",
        epilog="exit codes: 0 = clean or below --fail-on, 1 = findings at/above --fail-on, 2 = usage or parse error",
    )
    scan.add_argument("path", help="path to a manifest or config JSON file")
    scan.add_argument("--format", choices=["text", "json", "markdown", "sarif", "html"], default="text", help="report format (default: text)")
    scan.add_argument(
        "--fail-on", choices=[s.label for s in Severity], type=str.lower, default="low",
        help="exit 1 if any finding is at or above this severity (default: low, i.e. any finding)",
    )
    scan.add_argument("--output", metavar="FILE", help="write the report to FILE instead of stdout")
    scan.add_argument("--ignore-file", metavar="FILE", help="JSON file of ignore rules; each needs a rule ID and a reason")
    baseline = scan.add_mutually_exclusive_group()
    baseline.add_argument("--baseline", metavar="FILE", help="hide findings already listed in FILE; only new findings count")
    baseline.add_argument("--write-baseline", metavar="FILE", help="save the current findings to FILE and exit 0")
    lock = scan.add_mutually_exclusive_group()
    lock.add_argument("--lock", metavar="FILE", help="flag tools that are new, removed, or changed since FILE was written (rug-pull detection)")
    lock.add_argument("--write-lock", metavar="FILE", help="save a fingerprint of the current tools to FILE and exit 0")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    try:
        result = scan_file(args.path)
        if args.lock or args.write_lock:
            if result.tools_raw is None:
                raise ScanError("--lock and --write-lock need a tool manifest input (this file has no 'tools')")
        if args.write_lock:
            with open(args.write_lock, "w", encoding="utf-8") as fh:
                fh.write(lock_document(result.tools_raw))
            print(f"mcpscan: wrote lock of {len(result.tools_raw)} tool(s) to {args.write_lock}", file=sys.stderr)
            return EXIT_OK
        if args.lock:
            lock_findings = check_lock(result.tools_raw, load_lock(args.lock))
            merged = sorted(set(result.findings) | set(lock_findings), key=Finding.sort_key)
            result = replace(result, findings=merged)
        ignore = load_ignore(args.ignore_file) if args.ignore_file else None
        baseline = load_baseline(args.baseline) if args.baseline else None
        if ignore or baseline is not None:
            result = apply_suppressions(result, ignore, baseline)
    except ScanError as exc:
        print(f"mcpscan: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"mcpscan: error: cannot write {args.write_lock}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.format == "text":
        color = args.output is None and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        report = render_text(result, color=color)
    else:
        report = ({**RENDERERS, "html": render_html})[args.format](result)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
        except OSError as exc:
            print(f"mcpscan: error: cannot write {args.output}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"mcpscan: wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report)

    if args.write_baseline:
        try:
            with open(args.write_baseline, "w", encoding="utf-8") as fh:
                fh.write(baseline_document(result.findings))
        except OSError as exc:
            print(f"mcpscan: error: cannot write {args.write_baseline}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"mcpscan: wrote baseline of {len(result.findings)} finding(s) to {args.write_baseline}", file=sys.stderr)
        return EXIT_OK

    return EXIT_FINDINGS if result.exceeds(Severity.parse(args.fail_on)) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
