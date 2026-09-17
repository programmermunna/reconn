from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

try:
    from .utils import (
        build_envelope,
        collect_param_urls,
        command_status,
        ensure_dir,
        iter_json_lines,
        load_json_file,
        missing_tool_envelope,
        run_command,
        tool_path,
        utc_now,
        write_json,
        write_text,
    )
except ImportError:
    from utils import (
        build_envelope,
        collect_param_urls,
        command_status,
        ensure_dir,
        iter_json_lines,
        load_json_file,
        missing_tool_envelope,
        run_command,
        tool_path,
        utc_now,
        write_json,
        write_text,
    )

logger = logging.getLogger(__name__)

MODULE = "xss_scan"
TOOL = "dalfox"
TIMEOUT_SECONDS = 1200
MAX_PARAM_URLS = 300


def _command(targets_path: Path, raw_path: Path) -> list[str]:
    return [
        TOOL,
        "file",
        str(targets_path),
        "--format",
        "json",
        "-o",
        str(raw_path),
        "--silence",
        "--no-spinner",
        "--timeout",
        "10",
        "-w",
        "50",
    ]


def _parse_records(raw_path: Path, stdout: str) -> list[dict[str, Any]]:
    data = load_json_file(raw_path)
    if isinstance(data, list):
        return [entry for entry in data if isinstance(entry, dict)]
    if isinstance(data, dict):
        return [data]
    raw = raw_path.read_text(encoding="utf-8", errors="replace") if raw_path.exists() else stdout
    return list(iter_json_lines(raw))


def run(domain: str, output_dir: str) -> dict[str, Any]:
    out_dir = ensure_dir(Path(output_dir))
    started_at = utc_now()
    raw_path = out_dir / f"{MODULE}.raw.json"
    json_path = out_dir / f"{MODULE}.json"
    targets_path = out_dir / f"{MODULE}.targets.txt"

    targets = collect_param_urls(out_dir, limit=MAX_PARAM_URLS)
    write_text(targets_path, "".join(f"{target}\n" for target in targets))
    command = _command(targets_path, raw_path)

    if tool_path(TOOL) is None:
        return missing_tool_envelope(
            module=MODULE,
            tool=TOOL,
            domain=domain,
            command=command,
            started_at=started_at,
            output_dir=out_dir,
            json_name=json_path.name,
        )
    if not targets:
        envelope = build_envelope(
            module=MODULE,
            tool=TOOL,
            domain=domain,
            command=command,
            started_at=started_at,
            status="skipped",
            records=[],
            raw_files=[],
            errors=["no parameterized URLs discovered — run url_archive/url_crawl first"],
        )
        write_json(json_path, envelope)
        logger.warning("[%s] no parameterized URLs to scan", MODULE)
        return envelope

    logger.info("[%s] running: %s", MODULE, " ".join(command))
    result = run_command(command, timeout=TIMEOUT_SECONDS)

    records = _parse_records(raw_path, result.stdout)

    errors: list[str] = []
    if result.error:
        errors.append(result.error)
    if result.stderr.strip():
        errors.append(result.stderr.strip()[:2000])

    status = command_status(result, bool(records))
    envelope = build_envelope(
        module=MODULE,
        tool=TOOL,
        domain=domain,
        command=command,
        started_at=started_at,
        status=status,
        records=records,
        raw_files=[raw_path.name] if raw_path.exists() else [],
        errors=errors,
        derived_files=[targets_path.name],
        metadata={
            "duration_seconds": result.duration_seconds,
            "returncode": result.returncode,
            "target_count": len(targets),
        },
    )
    write_json(json_path, envelope)
    logger.info("[%s] status=%s records=%d", MODULE, status, len(records))
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser(prog=MODULE)
    parser.add_argument("domain")
    parser.add_argument("-o", "--output-dir", default=None)
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    output_dir = args.output_dir or str(Path("output") / args.domain)
    result = run(args.domain, output_dir)
    return 0 if result.get("status") in {"success", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
