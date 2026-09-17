# Info — Modular Recon Architecture

An open-source, modular reconnaissance framework in Python. Each recon step lives in
its own isolated module, executes CLI tools with verbose flags, and stores both raw
and normalized JSON output under `output/{domain}/` — designed to scale and to feed
future analytical/graphing modules.

Pure standard library. No Python dependencies.

## Features

- **Isolated modules** — every recon step is a single file exposing `run(domain, output_dir)`
- **Uniform JSON envelope** — every module emits the same schema, so downstream parsers
  never special-case tools
- **Raw + normalized output** — raw tool output is preserved alongside parsed records
- **Pipeline chaining** — `http_probe` and `port_scan` automatically consume hosts
  discovered by `subdomain_enum`
- **Graceful degradation** — missing binaries, timeouts, and non-zero exits are recorded
  in the envelope instead of crashing
- **Run-level manifest** — `manifest.json` aggregates status, record counts, and errors
  for every module in a run

## Modules

| Module            | Tool        | Command highlights                                                        | Key outputs                                        |
|-------------------|-------------|---------------------------------------------------------------------------|----------------------------------------------------|
| `subdomain_enum`  | `subfinder` | `-all -recursive -oJ`                                                     | `subdomain_enum.json`, `subdomain_enum.hosts.txt`  |
| `dns_enum`        | `dnsrecon`  | `-t std --lifetime 10 -j` (SOA/NS/A/AAAA/MX/SRV/TXT, wildcard, AXFR)        | `dns_enum.json`, `dns_enum.raw.txt`                |
| `dns_resolve`     | `dnsx`      | `-a -aaaa -cname -mx -ns -txt -resp -json`                                | `dns_resolve.json`, `dns_resolve.resolved.txt`     |
| `whois_lookup`    | `whois`     | registrar, dates, name servers, statuses parsed to JSON                   | `whois_lookup.json`, `whois_lookup.raw.txt`        |
| `http_probe`      | `httpx`     | `-json -title -tech-detect -tls-grab -cdn -ip -cname -follow-redirects`     | `http_probe.json`, `http_probe.live_urls.txt`      |
| `tls_enum`        | `tlsx`      | `-san -cn -so -tv -cipher -ex -ss -mm -jarm`                              | `tls_enum.json`, `tls_enum.names.txt`              |
| `url_archive`     | `gau`       | `--subs --providers wayback,commoncrawl,otx,urlscan`                      | `url_archive.json`, `url_archive.urls.txt`         |
| `url_crawl`       | `katana`    | `-d 3 -jc -kf all -fs rdn -jsonl`                                         | `url_crawl.json`, `url_crawl.urls.txt`             |
| `port_scan`       | `naabu`     | `-top-ports 1000 -json -verify -rate 3000`                                | `port_scan.json`, `port_scan.open.txt`             |
| `nmap_scan`       | `nmap`      | `-sV -sC -Pn -T4 --open -oX` (reuses naabu open ports when present)       | `nmap_scan.json`, `nmap_scan.raw.xml`              |
| `dir_scan`        | `ffuf`      | `-mc all -ac -of json` per live URL, auto wordlist fallback               | `dir_scan.json`, `dir_scan.found.txt`              |
| `xss_scan`        | `dalfox`    | `file --format json` on parameterized URLs                                | `xss_scan.json`                                    |
| `param_vuln`      | `nuclei`    | `-tags lfi,rce,sqli,ssrf,xss` on parameterized + live URLs                | `param_vuln.json` + severity counts                |
| `vuln_scan`       | `nuclei`    | `-jsonl -severity info..critical -rl 150 -c 50`                           | `vuln_scan.json` + severity counts                 |

## Installation

Python >= 3.10 required. One command installs everything
(Go toolchain if missing, all four recon tools, and `PATH` setup):

```bash
./install.sh
```

Or install the tools manually:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/hahwul/dalfox/v2@latest
pip install dnsrecon    # or: apt install dnsrecon
apt install whois nmap
```

`dir_scan` wordlist priority: `$RECON_WORDLIST` → seclists/dirb system lists →
bundled `wordlists/common.txt`.

> `naabu` needs root or `CAP_NET_RAW` for SYN scanning.

## Usage

```bash
python3 recon.py -d example.com                       # run all modules
python3 recon.py -d example.com -m dns_enum           # run a subset
python3 recon.py -d example.com -o results/ -v        # custom output root, verbose
python3 recon.py --list                               # list discovered modules
python3 modules/http_probe.py example.com             # run a module standalone
```

## Output layout

```
output/example.com/
  manifest.json                  # run summary: per-module status, counts, errors
  subdomain_enum.json            # normalized envelope
  subdomain_enum.raw.jsonl       # raw tool output
  subdomain_enum.hosts.txt       # derived: unique host list
  dns_enum.json
  dns_enum.raw.json
  dns_enum.raw.txt
  http_probe.json
  http_probe.raw.jsonl
  http_probe.targets.txt
  http_probe.live_urls.txt
  port_scan.json
  port_scan.raw.jsonl
  port_scan.targets.txt
  port_scan.open.txt
```

## JSON envelope schema

Every module writes `{module}.json` with this structure:

```json
{
  "module": "http_probe",
  "tool": "httpx",
  "domain": "example.com",
  "command": ["httpx", "-l", "..."],
  "started_at": "2026-09-18T01:00:00+00:00",
  "finished_at": "2026-09-18T01:00:42+00:00",
  "status": "success | partial | failed | skipped",
  "record_count": 3,
  "records": [ { "...": "tool-native fields, verbatim" } ],
  "errors": [],
  "raw_files": ["http_probe.raw.jsonl"],
  "derived_files": ["http_probe.targets.txt", "http_probe.live_urls.txt"],
  "metadata": { "duration_seconds": 41.8, "returncode": 0 }
}
```

## Adding a module

1. Drop `modules/your_module.py` into the package.
2. Expose `run(domain: str, output_dir: str) -> dict` — build the envelope with
   helpers from `modules/utils.py` (`run_command`, `build_envelope`, `command_status`,
   `missing_tool_envelope`, `iter_json_lines`, `write_json`, `write_text`).
3. `recon.py` auto-discovers it on the next run — no registration needed.

## License

MIT — see [LICENSE](LICENSE).

---

## 📞 Contact For Developer

- **Portfolio**: [programmermunna.github.io](https://programmermunna.github.io)
- **GitHub**: [github.com/programmermunna](https://github.com/programmermunna)
- **LinkedIn**: [linkedin.com/in/programmermunna](https://linkedin.com/in/programmermunna)
- **Facebook**: [facebook.com/programmermunna](https://facebook.com/programmermunna)
- **WhatsApp**: [wa.me/+8801938031025](https://wa.me/+8801938031025)

---
