from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

try:
    from .utils import (
        build_envelope,
        command_status,
        iter_json_lines,
        missing_tool_envelope,
        output_layout,
        read_lines,
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
        iter_json_lines,
        missing_tool_envelope,
        output_layout,
        read_lines,
        run_command,
        tool_path,
        utc_now,
        write_json,
        write_text,
    )

logger = logging.getLogger(__name__)

MODULE = "url_crawl"
DESCRIPTION = "Web crawling with JS endpoint extraction"
TOOL = "katana"
TIMEOUT_SECONDS = 900
UPSTREAM_URLS_FILE = "http_probe.live_urls.txt"


def _collect_targets(domain: str, txt_dir: Path) -> list[str]:
    targets = {f"https://{domain}", f"http://{domain}"}
    targets.update(read_lines(txt_dir / UPSTREAM_URLS_FILE))
    return sorted(targets)


def _command(targets_path: Path, raw_path: Path) -> list[str]:
    return [
        TOOL,
        "-list",
        str(targets_path),
        "-d",
        "3",
        "-jc",
        "-kf",
        "all",
        "-fs",
        "rdn",
        "-silent",
        "-jsonl",
        "-o",
        str(raw_path),
    ]


def _parse_records(raw_path: Path, stdout: str) -> list[dict[str, Any]]:
    raw = ""
    if raw_path.exists():
        raw = raw_path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip() and stdout.strip():
        raw = stdout
        write_text(raw_path, raw)
    return list(iter_json_lines(raw))


def _endpoint(record: dict[str, Any]) -> str | None:
    for key in ("endpoint", "url"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    request = record.get("request")
    if isinstance(request, dict) and isinstance(request.get("endpoint"), str):
        return request["endpoint"]
    return None


def run(domain: str, output_dir: str) -> dict[str, Any]:
    dirs = output_layout(output_dir)
    started_at = utc_now()
    raw_path = dirs.raw / f"{MODULE}.raw.jsonl"
    json_path = dirs.json / f"{MODULE}.json"
    targets_path = dirs.txt / f"{MODULE}.targets.txt"
    urls_path = dirs.txt / f"{MODULE}.urls.txt"

    targets = _collect_targets(domain, dirs.txt)
    write_text(targets_path, "".join(f"{target}\n" for target in targets))
    command = _command(targets_path, raw_path)

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

    records = _parse_records(raw_path, result.stdout)
    endpoints = sorted(
        {endpoint for record in records if (endpoint := _endpoint(record))}
    )
    write_text(urls_path, "".join(f"{url}\n" for url in endpoints))

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
        derived_files=[targets_path.name, urls_path.name],
        metadata={
            "duration_seconds": result.duration_seconds,
            "returncode": result.returncode,
            "target_count": len(targets),
            "endpoint_count": len(endpoints),
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
