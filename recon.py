#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import logging
import sys
import time
from pathlib import Path
from typing import Any

from modules.utils import utc_now, write_json

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
    "vuln_scan",
]
RESERVED = {"__init__", "utils"}


def discover_modules() -> list[str]:
    pkg_dir = Path(__file__).resolve().parent / "modules"
    found = {path.stem for path in pkg_dir.glob("*.py") if path.stem not in RESERVED}
    ordered = [name for name in DEFAULT_ORDER if name in found]
    ordered.extend(sorted(found - set(ordered)))
    return ordered


def run_module(name: str, domain: str, output_dir: Path) -> dict[str, Any]:
    started = time.monotonic()
    try:
        module = importlib.import_module(f"modules.{name}")
    except Exception as exc:
        logger.error("import failed for modules.%s: %s", name, exc)
        return {
            "module": name,
            "status": "failed",
            "errors": [f"import error: {exc}"],
        }
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


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Modular recon orchestrator",
    )
    parser.add_argument("-d", "--domain", help="target domain")
    parser.add_argument(
        "-o",
        "--output-root",
        default="output",
        help="root output directory (default: output/)",
    )
    parser.add_argument(
        "-m",
        "--modules",
        default=None,
        help="comma-separated module names (default: all discovered)",
    )
    parser.add_argument("--list", action="store_true", help="list discovered modules")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    available = discover_modules()
    if args.list:
        for name in available:
            print(name)
        return 0
    if not args.domain:
        logger.error("--domain is required")
        return 2

    requested = (
        [name.strip() for name in args.modules.split(",") if name.strip()]
        if args.modules
        else available
    )
    domain_dir = Path(args.output_root) / args.domain
    domain_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "domain": args.domain,
        "started_at": utc_now(),
        "modules": [],
    }
    for name in requested:
        if name not in available:
            logger.error("unknown module %r (available: %s)", name, ", ".join(available))
            manifest["modules"].append(
                {"module": name, "status": "failed", "errors": ["unknown module"]}
            )
            continue
        logger.info("=== module: %s ===", name)
        result = run_module(name, args.domain, domain_dir)
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
    logger.info("manifest written to %s", domain_dir / "manifest.json")
    statuses = {entry["status"] for entry in manifest["modules"]}
    return 1 if "failed" in statuses else 0


if __name__ == "__main__":
    sys.exit(main())
