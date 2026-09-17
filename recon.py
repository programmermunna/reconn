#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from modules.utils import read_lines, utc_now, write_json

__version__ = "1.0.0"

logger = logging.getLogger("recon")

DEFAULT_ORDER = [
    "subdomain_enum",
    "dns_enum",
    "dns_resolve",
    "whois_lookup",
    "http_probe",
    "tls_enum",
    "url_archive",
    "url_crawl",
    "port_scan",
    "nmap_scan",
    "dir_scan",
    "xss_scan",
    "param_vuln",
    "vuln_scan",
]
RESERVED = {"__init__", "utils"}

BANNER = r"""
  ____  _____ ____ ___  _   _
 |  _ \| ____/ ___/ _ \| \ | |
 | |_) |  _|| |  | | | |  \| |
 |  _ <| |__| |__| |_| | |\  |
 |_| \_\_____\____\___/|_| \_|  v%s

 modular reconnaissance orchestrator
""" % __version__

_COLOR = True
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_STATUS_COLORS = {
    "success": "\033[92m",
    "partial": "\033[93m",
    "failed": "\033[91m",
    "skipped": "\033[90m",
}


def paint(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if _COLOR else text


def normalize_domain(value: str) -> str:
    domain = value.strip().lower()
    for prefix in ("http://", "https://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.strip().strip("/")


def discover_modules() -> list[str]:
    pkg_dir = Path(__file__).resolve().parent / "modules"
    found = {path.stem for path in pkg_dir.glob("*.py") if path.stem not in RESERVED}
    ordered = [name for name in DEFAULT_ORDER if name in found]
    ordered.extend(sorted(found - set(ordered)))
    return ordered


def module_description(name: str) -> str:
    try:
        module = importlib.import_module(f"modules.{name}")
        return str(getattr(module, "DESCRIPTION", ""))
    except Exception:
        return ""


def select_modules(
    requested: str | None, excluded: str | None, available: list[str]
) -> tuple[list[str], list[str]]:
    selected = (
        [name.strip() for name in requested.split(",") if name.strip()]
        if requested
        else list(available)
    )
    unknown = [name for name in selected if name not in available]
    selected = [name for name in selected if name in available]
    if excluded:
        drop = {name.strip() for name in excluded.split(",") if name.strip()}
        selected = [name for name in selected if name not in drop]
    return selected, unknown


def run_module(name: str, domain: str, output_dir: Path) -> dict[str, Any]:
    started = time.monotonic()
    try:
        module = importlib.import_module(f"modules.{name}")
    except Exception as exc:
        logger.error("import failed for modules.%s: %s", name, exc)
        return {"module": name, "status": "failed", "errors": [f"import error: {exc}"]}
    entry = getattr(module, "run", None)
    if not callable(entry):
        logger.error("modules.%s has no run(domain, output_dir) entry point", name)
        return {
            "module": name,
            "status": "failed",
            "errors": ["missing run(domain, output_dir) entry point"],
        }
    try:
        result = entry(domain, str(output_dir))
    except Exception as exc:
        logger.exception("module %s crashed", name)
        return {
            "module": name,
            "status": "failed",
            "errors": [f"unhandled exception: {exc}"],
        }
    if not isinstance(result, dict):
        result = {"module": name, "status": "success", "result": result}
    result.setdefault("duration_seconds", round(time.monotonic() - started, 3))
    return result


def run_domain(
    domain: str, modules: list[str], output_root: Path
) -> tuple[dict[str, Any], Path]:
    domain_dir = output_root / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "domain": domain,
        "started_at": utc_now(),
        "modules": [],
    }
    total = len(modules)
    for index, name in enumerate(modules, 1):
        logger.info("=== [%d/%d] %s ===", index, total, name)
        result = run_module(name, domain, domain_dir)
        manifest["modules"].append(
            {
                "module": name,
                "status": result.get("status"),
                "record_count": result.get("record_count", 0),
                "errors": result.get("errors", []),
                "duration_seconds": result.get("duration_seconds"),
            }
        )
    manifest["finished_at"] = utc_now()
    write_json(domain_dir / "manifest.json", manifest)
    return manifest, domain_dir


def print_summary(manifest: dict[str, Any], manifest_path: Path) -> None:
    entries = manifest.get("modules", [])
    if not entries:
        return
    width = max(len(str(entry.get("module"))) for entry in entries)
    header = f"{'MODULE':<{width}}  {'STATUS':<8}  {'RECORDS':>7}  {'TIME':>8}"
    print()
    print(paint(f"summary — {manifest.get('domain', '?')}", _BOLD))
    print(paint(header, _DIM))
    print(_DIM + "-" * len(header) + _RESET if _COLOR else "-" * len(header))
    counts: dict[str, int] = {}
    for entry in entries:
        status = str(entry.get("status") or "?")
        counts[status] = counts.get(status, 0) + 1
        line = (
            f"{str(entry.get('module')):<{width}}  "
            f"{paint(f'{status:<8}', _STATUS_COLORS.get(status, ''))}  "
            f"{int(entry.get('record_count') or 0):>7}  "
            f"{float(entry.get('duration_seconds') or 0):>7.1f}s"
        )
        print(line)
    totals = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
    print(f"\n{totals}")
    print(paint(f"manifest -> {manifest_path}", _DIM))


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Modular reconnaissance orchestrator — chains recon tools into a structured JSON pipeline.",
        epilog=(
            "examples:\n"
            "  recon -d example.com                        full pipeline\n"
            "  recon -d example.com -m subdomain_enum      single module\n"
            "  recon -l domains.txt -o results/            multi-target\n"
            "  recon -d example.com -x vuln_scan,param_vuln,xss_scan   passive+recon only\n"
            "  recon --list-modules                        show available modules\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_argument_group("target")
    target.add_argument("-d", "--domain", help="single target domain")
    target.add_argument(
        "-l", "--list", dest="domains_file", metavar="FILE",
        help="file with target domains, one per line",
    )
    selection = parser.add_argument_group("module selection")
    selection.add_argument(
        "-m", "--modules", metavar="LIST",
        help="comma-separated modules to run (default: all)",
    )
    selection.add_argument(
        "-x", "--exclude", metavar="LIST",
        help="comma-separated modules to skip",
    )
    selection.add_argument(
        "--list-modules", action="store_true",
        help="list discovered modules and exit",
    )
    output = parser.add_argument_group("output")
    output.add_argument(
        "-o", "--output-root", default="output", metavar="DIR",
        help="output root directory (default: output/)",
    )
    output.add_argument("-silent", "--silent", action="store_true", help="suppress banner and info logs")
    output.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    global _COLOR
    args = parse_args(argv)
    _COLOR = (
        sys.stdout.isatty()
        and not args.no_color
        and not os.environ.get("NO_COLOR")
    )
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else (logging.ERROR if args.silent else logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.silent:
        print(paint(BANNER, _BOLD), flush=True)

    available = discover_modules()
    if args.list_modules:
        width = max(len(name) for name in available) if available else 6
        for name in available:
            print(f"{paint(f'{name:<{width}}', _BOLD)}  {paint(module_description(name), _DIM)}")
        return 0

    targets: list[str] = []
    if args.domain:
        targets.append(normalize_domain(args.domain))
    if args.domains_file:
        domains_path = Path(args.domains_file)
        if not domains_path.is_file():
            logger.error("domain list not found: %s", domains_path)
            return 2
        targets.extend(normalize_domain(line) for line in read_lines(domains_path))
    targets = [t for t in dict.fromkeys(targets) if t]
    if not targets:
        logger.error("no target — use -d example.com or -l domains.txt")
        return 2

    selected, unknown = select_modules(args.modules, args.exclude, available)
    if unknown:
        logger.error("unknown modules: %s (available: %s)", ", ".join(unknown), ", ".join(available))
        return 2
    if not selected:
        logger.error("no modules selected")
        return 2

    output_root = Path(args.output_root)
    exit_code = 0
    try:
        for index, domain in enumerate(targets, 1):
            if len(targets) > 1:
                logger.info("### target %d/%d: %s", index, len(targets), domain)
            manifest, domain_dir = run_domain(domain, selected, output_root)
            if not args.silent:
                print_summary(manifest, domain_dir / "manifest.json")
            else:
                print(f"manifest -> {domain_dir / 'manifest.json'}")
            statuses = {entry.get("status") for entry in manifest.get("modules", [])}
            if "failed" in statuses:
                exit_code = 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
