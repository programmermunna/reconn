from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Any

try:
    from .utils import (
        build_envelope,
        ensure_dir,
        load_json_file,
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
        ensure_dir,
        load_json_file,
        missing_tool_envelope,
        read_lines,
        run_command,
        tool_path,
        utc_now,
        write_json,
        write_text,
    )

logger = logging.getLogger(__name__)

MODULE = "dir_scan"
DESCRIPTION = "Directory/content fuzzing on live web services"
TOOL = "ffuf"
PER_TARGET_TIMEOUT = 120
MAX_TARGETS = 25
UPSTREAM_URLS_FILE = "http_probe.live_urls.txt"
WORDLIST_ENV = "RECON_WORDLIST"
SYSTEM_WORDLISTS = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
)


def _bundled_wordlist() -> Path:
    return Path(__file__).resolve().parent / "wordlists" / "common.txt"


def _find_wordlist() -> Path | None:
    env_path = os.environ.get(WORDLIST_ENV)
    candidates = [env_path, *SYSTEM_WORDLISTS, str(_bundled_wordlist())]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def _collect_targets(domain: str, out_dir: Path) -> list[str]:
    targets = {f"https://{domain}", f"http://{domain}"}
    targets.update(read_lines(out_dir / UPSTREAM_URLS_FILE))
    return sorted(targets)[:MAX_TARGETS]


def _command(target: str, wordlist: Path, raw_path: Path) -> list[str]:
    return [
        TOOL,
        "-u",
        f"{target.rstrip('/')}/FUZZ",
        "-w",
        str(wordlist),
        "-of",
        "json",
        "-o",
        str(raw_path),
        "-mc",
        "all",
        "-ac",
        "-s",
        "-t",
        "50",
        "-timeout",
        "10",
    ]


def _parse_results(raw_path: Path, target: str) -> list[dict[str, Any]]:
    data = load_json_file(raw_path)
    if not isinstance(data, dict):
        return []
    records = []
    for entry in data.get("results") or []:
        if not isinstance(entry, dict):
            continue
        entry["scanned_target"] = target
        records.append(entry)
    return records


def run(domain: str, output_dir: str) -> dict[str, Any]:
    out_dir = ensure_dir(Path(output_dir))
    started_at = utc_now()
    json_path = out_dir / f"{MODULE}.json"
    raw_path = out_dir / f"{MODULE}.raw.jsonl"
    targets_path = out_dir / f"{MODULE}.targets.txt"
    found_path = out_dir / f"{MODULE}.found.txt"

    targets = _collect_targets(domain, out_dir)
    write_text(targets_path, "".join(f"{target}\n" for target in targets))
    wordlist = _find_wordlist()

    probe_command = _command(targets[0], wordlist or Path("wordlist"), Path("ffuf.json"))
    if tool_path(TOOL) is None:
        return missing_tool_envelope(
            module=MODULE,
            tool=TOOL,
            domain=domain,
            command=probe_command,
            started_at=started_at,
            output_dir=out_dir,
            json_name=json_path.name,
        )
    if wordlist is None:
        envelope = build_envelope(
            module=MODULE,
            tool=TOOL,
            domain=domain,
            command=probe_command,
            started_at=started_at,
            status="skipped",
            records=[],
            raw_files=[],
            errors=[f"no wordlist found — set {WORDLIST_ENV} or install seclists"],
        )
        write_json(json_path, envelope)
        logger.error("[%s] no wordlist found", MODULE)
        return envelope

    records: list[dict[str, Any]] = []
    errors: list[str] = []
    raw_lines: list[str] = []
    total_duration = 0.0
    failures = 0

    for target in targets:
        tmp_out = out_dir / f".{MODULE}.{abs(hash(target))}.json"
        command = _command(target, wordlist, tmp_out)
        logger.info("[%s] fuzzing %s", MODULE, target)
        result = run_command(command, timeout=PER_TARGET_TIMEOUT)
        total_duration += result.duration_seconds
        hits = _parse_results(tmp_out, target)
        for hit in hits:
            raw_lines.append(json.dumps(hit))
        records.extend(hits)
        if result.error:
            errors.append(f"{target}: {result.error}")
        if result.returncode != 0:
            failures += 1
            if result.stderr.strip():
                errors.append(f"{target}: {result.stderr.strip()[:500]}")
        if tmp_out.exists():
            tmp_out.unlink()

    if raw_lines:
        write_text(raw_path, "\n".join(raw_lines) + "\n")
    found = sorted(
        {str(record.get("url")) for record in records if record.get("url")}
    )
    write_text(found_path, "".join(f"{url}\n" for url in found))

    if records and not failures:
        status = "success"
    elif records:
        status = "partial"
    elif failures == len(targets):
        status = "failed"
    else:
        status = "success"

    envelope = build_envelope(
        module=MODULE,
        tool=TOOL,
        domain=domain,
        command=_command("<target>", wordlist, Path("ffuf.json")),
        started_at=started_at,
        status=status,
        records=records,
        raw_files=[raw_path.name] if raw_path.exists() else [],
        errors=errors,
        derived_files=[targets_path.name, found_path.name],
        metadata={
            "duration_seconds": round(total_duration, 3),
            "target_count": len(targets),
            "failed_targets": failures,
            "wordlist": str(wordlist),
            "found_count": len(found),
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
