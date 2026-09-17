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
        missing_tool_envelope,
        run_command,
        tool_path,
        utc_now,
        write_json,
        write_text,
    )

logger = logging.getLogger(__name__)

MODULE = "url_archive"
DESCRIPTION = "Historical URLs from Wayback/CommonCrawl/OTX/URLScan"
TOOL = "gau"
TIMEOUT_SECONDS = 300


def _command(domain: str) -> list[str]:
    return [
        TOOL,
        "--subs",
        domain,
        "--providers",
        "wayback,commoncrawl,otx,urlscan",
        "--threads",
        "5",
        "--timeout",
        "60",
    ]


def _parse_urls(raw: str) -> list[str]:
    return sorted({line.strip() for line in raw.splitlines() if line.strip()})


def run(domain: str, output_dir: str) -> dict[str, Any]:
    out_dir = ensure_dir(Path(output_dir))
    started_at = utc_now()
    raw_path = out_dir / f"{MODULE}.raw.txt"
    json_path = out_dir / f"{MODULE}.json"
    urls_path = out_dir / f"{MODULE}.urls.txt"
    command = _command(domain)

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

    urls = _parse_urls(result.stdout)
    write_text(raw_path, result.stdout)
    write_text(urls_path, "".join(f"{url}\n" for url in urls))
    records = [{"url": url, "source": TOOL} for url in urls]

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
        derived_files=[urls_path.name],
        metadata={
            "duration_seconds": result.duration_seconds,
            "returncode": result.returncode,
            "unique_url_count": len(urls),
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
