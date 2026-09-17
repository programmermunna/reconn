from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

try:
    from .utils import (
        build_envelope,
        command_status,
        load_json_file,
        missing_tool_envelope,
        output_layout,
        run_command,
        tool_path,
        utc_now,
        write_json,
        write_text,
    )
except ImportError:
    from utils import (
        build_envelope,
        command_status,
        load_json_file,
        missing_tool_envelope,
        output_layout,
        run_command,
        tool_path,
        utc_now,
        write_json,
        write_text,
    )

logger = logging.getLogger(__name__)

MODULE = "dns_enum"
DESCRIPTION = "DNS records, zone transfer and wildcard checks"
TOOL = "dnsrecon"
TIMEOUT_SECONDS = 300


def _command(domain: str, raw_json_path: Path) -> list[str]:
    return [
        TOOL,
        "-d",
        domain,
        "-t",
        "std",
        "--lifetime",
        "10",
        "-j",
        str(raw_json_path),
    ]


def _parse_records(raw_json_path: Path) -> list[dict[str, Any]]:
    data = load_json_file(raw_json_path)
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict)]


def run(domain: str, output_dir: str) -> dict[str, Any]:
    dirs = output_layout(output_dir)
    started_at = utc_now()
    raw_json_path = dirs.raw / f"{MODULE}.raw.json"
    raw_stdout_path = dirs.raw / f"{MODULE}.raw.txt"
    json_path = dirs.json / f"{MODULE}.json"
    command = _command(domain, raw_json_path)

    if tool_path(TOOL) is None:
        return missing_tool_envelope(
            module=MODULE,
            tool=TOOL,
            domain=domain,
            command=command,
            started_at=started_at,
            output_dir=dirs.json,
            json_name=json_path.name,
        )

    logger.info("[%s] running: %s", MODULE, " ".join(command))
    result = run_command(command, timeout=TIMEOUT_SECONDS)

    if result.stdout.strip():
        write_text(raw_stdout_path, result.stdout)

    records = _parse_records(raw_json_path)

    errors: list[str] = []
    if result.error:
        errors.append(result.error)
    if result.stderr.strip():
        errors.append(result.stderr.strip()[:2000])
    if not raw_json_path.exists() and result.returncode == 0:
        errors.append(f"{TOOL} did not produce JSON output at {raw_json_path.name}")

    status = command_status(result, bool(records))
    envelope = build_envelope(
        module=MODULE,
        tool=TOOL,
        domain=domain,
        command=command,
        started_at=started_at,
        status=status,
        records=records,
        raw_files=[
            name
            for name, path in (
                (raw_json_path.name, raw_json_path),
                (raw_stdout_path.name, raw_stdout_path),
            )
            if path.exists()
        ],
        errors=errors,
        metadata={
            "duration_seconds": result.duration_seconds,
            "returncode": result.returncode,
            "scan_types": ["std"],
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
