from __future__ import annotations

import argparse
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    from .utils import (
        build_envelope,
        command_status,
        ensure_dir,
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
        missing_tool_envelope,
        read_lines,
        run_command,
        tool_path,
        utc_now,
        write_json,
        write_text,
    )

logger = logging.getLogger(__name__)

MODULE = "nmap_scan"
TOOL = "nmap"
TIMEOUT_SECONDS = 1800
UPSTREAM_HOSTS_FILE = "subdomain_enum.hosts.txt"
UPSTREAM_OPEN_FILE = "port_scan.open.txt"
MAX_PORTS = 200


def _collect_hosts(domain: str, out_dir: Path) -> list[str]:
    hosts = {domain}
    hosts.update(read_lines(out_dir / UPSTREAM_HOSTS_FILE))
    return sorted(hosts)


def _collect_ports(out_dir: Path) -> list[int]:
    ports: set[int] = set()
    for line in read_lines(out_dir / UPSTREAM_OPEN_FILE):
        _, _, port = line.rpartition(":")
        if port.isdigit():
            ports.add(int(port))
    return sorted(ports)[:MAX_PORTS]


def _command(targets_path: Path, xml_path: Path, txt_path: Path, ports: list[int]) -> list[str]:
    command = [
        TOOL,
        "-iL",
        str(targets_path),
        "-sV",
        "-sC",
        "-Pn",
        "-T4",
        "--open",
        "-oX",
        str(xml_path),
        "-oN",
        str(txt_path),
    ]
    if ports:
        command += ["-p", ",".join(str(port) for port in ports)]
    else:
        command += ["--top-ports", "1000"]
    return command


def _parse_xml(xml_path: Path) -> list[dict[str, Any]]:
    try:
        root = ET.parse(xml_path).getroot()
    except (OSError, ET.ParseError):
        return []
    records: list[dict[str, Any]] = []
    for host in root.iter("host"):
        address = host.find("address")
        record: dict[str, Any] = {
            "host": address.get("addr") if address is not None else None,
            "hostnames": [
                name.get("name")
                for name in host.iter("hostname")
                if name.get("name")
            ],
            "ports": [],
        }
        os_element = host.find("os")
        if os_element is not None:
            record["os"] = [
                {"name": match.get("name"), "accuracy": match.get("accuracy")}
                for match in os_element.iter("osmatch")
            ]
        for port in host.iter("port"):
            state = port.find("state")
            service = port.find("service")
            record["ports"].append(
                {
                    "port": int(port.get("portid") or 0),
                    "protocol": port.get("protocol"),
                    "state": state.get("state") if state is not None else None,
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "extrainfo": service.get("extrainfo") if service is not None else None,
                    "scripts": [
                        {"id": script.get("id"), "output": script.get("output")}
                        for script in port.iter("script")
                    ],
                }
            )
        if record["ports"] or record.get("os"):
            records.append(record)
    return records


def run(domain: str, output_dir: str) -> dict[str, Any]:
    out_dir = ensure_dir(Path(output_dir))
    started_at = utc_now()
    xml_path = out_dir / f"{MODULE}.raw.xml"
    txt_path = out_dir / f"{MODULE}.raw.txt"
    json_path = out_dir / f"{MODULE}.json"
    targets_path = out_dir / f"{MODULE}.targets.txt"

    hosts = _collect_hosts(domain, out_dir)
    ports = _collect_ports(out_dir)
    write_text(targets_path, "".join(f"{host}\n" for host in hosts))
    command = _command(targets_path, xml_path, txt_path, ports)

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

    records = _parse_xml(xml_path)

    errors: list[str] = []
    if result.error:
        errors.append(result.error)
    if result.stderr.strip():
        errors.append(result.stderr.strip()[:2000])
    if result.returncode == 0 and not xml_path.exists():
        errors.append(f"{TOOL} did not produce XML output at {xml_path.name}")

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
            for name, path in ((xml_path.name, xml_path), (txt_path.name, txt_path))
            if path.exists()
        ],
        errors=errors,
        derived_files=[targets_path.name],
        metadata={
            "duration_seconds": result.duration_seconds,
            "returncode": result.returncode,
            "target_count": len(hosts),
            "ports_scanned": len(ports) if ports else "top-1000",
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
