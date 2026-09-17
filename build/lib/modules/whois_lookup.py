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

MODULE = "whois_lookup"
DESCRIPTION = "Domain registration metadata: registrar, dates, NS"
TOOL = "whois"
TIMEOUT_SECONDS = 60

SINGLE_KEYS = {
    "registrar": "registrar",
    "registrar url": "registrar_url",
    "registrar iana id": "registrar_iana_id",
    "registry domain id": "registry_domain_id",
    "creation date": "created",
    "updated date": "updated",
    "registry expiry date": "expires",
    "registrar registration expiration date": "expires",
    "expiry date": "expires",
    "dnssec": "dnssec",
    "registrant organization": "registrant_org",
    "registrant country": "registrant_country",
    "registrant email": "registrant_email",
}

MULTI_KEYS = {
    "name server": "name_servers",
    "nserver": "name_servers",
    "domain status": "statuses",
    "status": "statuses",
}


def _command(domain: str) -> list[str]:
    return [TOOL, domain]


def _parse_whois(text: str, domain: str) -> dict[str, Any]:
    record: dict[str, Any] = {"domain": domain}
    for line in text.splitlines():
        if ":" not in line or line.startswith((">>", "%", "#")):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key in SINGLE_KEYS:
            record.setdefault(SINGLE_KEYS[key], value)
        elif key in MULTI_KEYS:
            field = MULTI_KEYS[key]
            record.setdefault(field, [])
            if value.lower() not in {v.lower() for v in record[field]}:
                record[field].append(value)
    return record


def run(domain: str, output_dir: str) -> dict[str, Any]:
    out_dir = ensure_dir(Path(output_dir))
    started_at = utc_now()
    raw_path = out_dir / f"{MODULE}.raw.txt"
    json_path = out_dir / f"{MODULE}.json"
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

    if result.stdout.strip():
        write_text(raw_path, result.stdout)

    record = _parse_whois(result.stdout, domain)
    records = [record] if len(record) > 1 else []

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
        metadata={
            "duration_seconds": result.duration_seconds,
            "returncode": result.returncode,
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
