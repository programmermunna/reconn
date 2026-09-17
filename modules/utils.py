from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    error: str | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class OutputLayout:
    root: Path
    json: Path
    raw: Path
    txt: Path


def output_layout(output_dir: str | Path) -> OutputLayout:
    root = ensure_dir(Path(output_dir))
    return OutputLayout(
        root=root,
        json=ensure_dir(root / "json"),
        raw=ensure_dir(root / "raw"),
        txt=ensure_dir(root / "txt"),
    )


def tool_path(name: str) -> str | None:
    return shutil.which(name)


def run_command(command: Sequence[str], timeout: int) -> CommandResult:
    cmd = list(command)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
        )
    except OSError as exc:
        return CommandResult(
            command=cmd,
            returncode=-1,
            stdout="",
            stderr="",
            duration_seconds=round(time.monotonic() - started, 3),
            error=str(exc),
        )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return CommandResult(
            command=cmd,
            returncode=proc.returncode,
            stdout=stdout or "",
            stderr=stderr or "",
            duration_seconds=round(time.monotonic() - started, 3),
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        return CommandResult(
            command=cmd,
            returncode=proc.returncode if proc.returncode is not None else -9,
            stdout=stdout or "",
            stderr=stderr or "",
            duration_seconds=round(time.monotonic() - started, 3),
            timed_out=True,
            error=f"command timed out after {timeout}s",
        )


def write_json(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def write_text(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def load_json_file(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def read_lines(path: Path) -> list[str]:
    try:
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def collect_lines(output_dir: Path, names: Sequence[str], limit: int = 2000) -> list[str]:
    lines: set[str] = set()
    for name in names:
        lines.update(read_lines(output_dir / "txt" / name))
    return sorted(lines)[:limit]


def collect_param_urls(output_dir: Path, limit: int = 500) -> list[str]:
    urls = collect_lines(
        output_dir,
        ("url_archive.urls.txt", "url_crawl.urls.txt", "http_probe.live_urls.txt"),
        limit=limit * 4,
    )
    return [url for url in urls if "=" in url][:limit]


def iter_json_lines(raw: str) -> Iterator[dict[str, Any]]:
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            yield entry


def build_envelope(
    *,
    module: str,
    tool: str,
    domain: str,
    command: Sequence[str],
    started_at: str,
    status: str,
    records: list[dict[str, Any]],
    raw_files: list[str],
    errors: list[str],
    derived_files: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "module": module,
        "tool": tool,
        "domain": domain,
        "command": list(command),
        "started_at": started_at,
        "finished_at": utc_now(),
        "status": status,
        "record_count": len(records),
        "records": records,
        "errors": errors,
        "raw_files": raw_files,
        "derived_files": derived_files or [],
        "metadata": metadata or {},
    }


def command_status(result: CommandResult, has_records: bool) -> str:
    if result.returncode == 0 and not result.timed_out and result.error is None:
        return "success"
    return "partial" if has_records else "failed"


def missing_tool_envelope(
    *,
    module: str,
    tool: str,
    domain: str,
    command: Sequence[str],
    started_at: str,
    output_dir: Path,
    json_name: str,
) -> dict[str, Any]:
    error = f"{tool} binary not found in PATH"
    logger.error("[%s] %s", module, error)
    envelope = build_envelope(
        module=module,
        tool=tool,
        domain=domain,
        command=command,
        started_at=started_at,
        status="skipped",
        records=[],
        raw_files=[],
        errors=[error],
    )
    write_json(output_dir / json_name, envelope)
    return envelope
