from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

try:
    from .utils import (
        build_envelope,
        command_status,
        ensure_dir,
        iter_json_lines,
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
        command_status,
        ensure_dir,
        iter_json_lines,
        missing_tool_envelope,
        run_command,
        tool_path,
        utc_now,
        write_json,
        write_text,
    )

logger = logging.getLogger(__name__)

MODULE = "subdomain_enum"
DESCRIPTION = "Passive subdomain enumeration across all sources"
TOOL = "subfinder"
TIMEOUT_SECONDS = 660


def _command(domain: str, raw_path: Path) -> list[str]:
    return [
        TOOL,
        "-d",
        domain,
        "-all",
        "-recursive",
        "-silent",
        "-oJ",
        "-o",
        str(raw_path),
        "-timeout",
        "30",
        "-max-time",
        "10",
    ]


def _parse_records(raw_path: Path, stdout: str) -> list[dict[str, Any]]:
    raw = ""
    if raw_path.exists():
        raw = raw_path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip() and stdout.strip():
        raw = stdout
        write_text(raw_path, raw)
    return [entry for entry in iter_json_lines(raw) if entry.get("host")]


def run(domain: str, output_dir: str) -> dict[str, Any]:
    out_dir = ensure_dir(Path(output_dir))
    started_at = utc_now()
    raw_path = out_dir / f"{MODULE}.raw.jsonl"
    json_path = out_dir / f"{MODULE}.json"
    hosts_path = out_dir / f"{MODULE}.hosts.txt"
    command = _command(domain, raw_path)

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

    logger.info("[%s] running: %s", MODULE, " ".join(command))
    result = run_command(command, timeout=TIMEOUT_SECONDS)

    records = _parse_records(raw_path, result.stdout)
    hosts = sorted({str(record["host"]) for record in records})
    write_text(hosts_path, "".join(f"{host}\n" for host in hosts))

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
        raw_files=[raw_path.name],
        errors=errors,
        derived_files=[hosts_path.name],
        metadata={
            "duration_seconds": result.duration_seconds,
            "returncode": result.returncode,
            "unique_host_count": len(hosts),
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
