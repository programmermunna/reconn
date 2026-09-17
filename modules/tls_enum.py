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
        ensure_dir,
        iter_json_lines,
        missing_tool_envelope,
        read_lines,
        run_command,
        tool_path,
        utc_now,
        write_json,
        write_text,
    )

logger = logging.getLogger(__name__)

MODULE = "tls_enum"
DESCRIPTION = "TLS certificate metadata, SANs, JARM fingerprint"
TOOL = "tlsx"
TIMEOUT_SECONDS = 600
UPSTREAM_HOSTS_FILE = "subdomain_enum.hosts.txt"


def _collect_targets(domain: str, out_dir: Path) -> list[str]:
    targets = {domain, f"www.{domain}"}
    targets.update(read_lines(out_dir / UPSTREAM_HOSTS_FILE))
    return sorted(targets)


def _command(targets_path: Path, raw_path: Path) -> list[str]:
    return [
        TOOL,
        "-l",
        str(targets_path),
        "-p",
        "443",
        "-san",
        "-cn",
        "-so",
        "-tv",
        "-cipher",
        "-ex",
        "-ss",
        "-mm",
        "-jarm",
        "-json",
        "-silent",
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


def _cert_names(records: list[dict[str, Any]]) -> list[str]:
    names = set()
    for record in records:
        for key in ("subject_cn", "issuer_cn"):
            value = record.get(key)
            if isinstance(value, str) and value:
                names.add(value)
        sans = record.get("subject_an")
        if isinstance(sans, list):
            names.update(str(name) for name in sans if name)
    return sorted(names)


def run(domain: str, output_dir: str) -> dict[str, Any]:
    out_dir = ensure_dir(Path(output_dir))
    started_at = utc_now()
    raw_path = out_dir / f"{MODULE}.raw.jsonl"
    json_path = out_dir / f"{MODULE}.json"
    targets_path = out_dir / f"{MODULE}.targets.txt"
    names_path = out_dir / f"{MODULE}.names.txt"

    targets = _collect_targets(domain, out_dir)
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

    logger.info("[%s] running: %s", MODULE, " ".join(command))
    result = run_command(command, timeout=TIMEOUT_SECONDS)

    records = _parse_records(raw_path, result.stdout)
    names = _cert_names(records)
    write_text(names_path, "".join(f"{name}\n" for name in names))

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
        derived_files=[targets_path.name, names_path.name],
        metadata={
            "duration_seconds": result.duration_seconds,
            "returncode": result.returncode,
            "target_count": len(targets),
            "cert_name_count": len(names),
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
