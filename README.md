# CUPS Printer Discovery: Exploitation and Attack Detection with Scapy

University ethical-hacking laboratory investigating **CVE-2024-47176** in the vulnerable `cups-browsed` daemon. The project contains two Python/Scapy tools:

- **`cups_attack.py`** sends a custom legacy CUPS printer-discovery announcement over UDP port 631 and can check whether the victim initiates a TCP connection to the advertised printer.
- **`cups_detector.py`** examines live traffic or saved PCAP/PCAPNG files for suspicious discovery announcements and related TCP connection attempts, and exports alerts to JSON or CSV.

The lab also evaluates three manipulated announcement fields and a network-exposure mitigation. **No remote-code-execution payload is included or required.**

> **Authorized lab use only.** Run these tools only on systems and networks you own or have permission to test. The experiments were designed for an isolated, directly connected lab network.

## Lab environment

| Component | System | Lab IP | Purpose |
| --- | --- | --- | --- |
| Attacker / printer simulator | MacBook Air (macOS) | `10.77.77.1` | Runs Scapy, Wireshark, and `ippeveprinter` |
| Victim host | ThinkPad (Pop!_OS) | `10.77.77.2` | Runs the vulnerable CUPS Docker container |
| Vulnerable service | `cups-browsed` inside Docker | Via host `10.77.77.2:631/udp` (before mitigation) | Receives legacy CUPS announcements |
| IPP printer simulator | `ippeveprinter` on the MacBook | `10.77.77.1:8000/tcp` | Responds to IPP connections |

The machines are connected on an isolated `10.77.77.0/24` Ethernet network. The example commands use the Mac's Ethernet interface `en6`; substitute the correct interface and addresses for your setup.

**Protocol distinction:** Modern printer discovery uses DNS-SD/mDNS on UDP 5353. The attack and detector scripts in this repository specifically target **legacy CUPS browsing on UDP 631**. The detector does not parse mDNS traffic.

## Requirements

- Python **3.10+**
- Scapy **2.8.0**, installed from `requirements.txt`
- macOS or Linux, with permission to capture/send raw packets (typically `sudo`)
- A vulnerable CUPS lab container, configured by the researcher
- Optional: Wireshark for inspecting packet captures; Homebrew CUPS / `ippeveprinter` for the software printer

Python's `argparse`, `csv`, `json`, `logging` and other standard-library modules used by the scripts do not need separate installation.

### Python installation (MacBook)

From the directory containing `cups_attack.py`, `cups_detector.py`, and `requirements.txt`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Check the available options:

```bash
python cups_attack.py --help
python cups_detector.py --help
```

The commands below explicitly select the virtual environment's Python interpreter when using `sudo` so that Scapy remains available.

## Start the software IPP printer

On the MacBook, in a separate terminal:

```bash
"$(brew --prefix cups)/bin/ippeveprinter" -p 8000 -v "Lab Printer"
```

The simulator listens on TCP port 8000. In this lab, `cups-browsed` accepts a legacy advertised path beginning with `/printers/`, such as `/printers/LabPrinter`, while `ippeveprinter` uses its own IPP resource path. Consequently, the simulator may return `client-error-not-found` to a printer-attribute request. **The key observation for this assignment is the victim initiating the connection**, not successful printer registration.

## Tool 1: `cups_attack.py`

### Preview an announcement without sending it

```bash
python cups_attack.py --dry-run
```

### Send and verify a discovery announcement

Run on the MacBook while the victim container is running:

```bash
sudo "$(pwd)/.venv/bin/python" cups_attack.py \
  --target-ip 10.77.77.2 \
  --printer-ip 10.77.77.1 \
  --printer-port 8000 \
  --resource /printers/LabPrinter \
  --verify \
  --iface en6 \
  --pcap pcap_files/scapy_discovery.pcap \
  --capture-pcap pcap_files/scapy_callback.pcap \
  --log-file evidence/scapy_attack.log
```

The program advertises a printer URI similar to:

```text
ipp://10.77.77.1:8000/printers/LabPrinter
```

With `--verify`, Scapy starts a packet capture before sending the UDP announcement. The script then looks for an initial **TCP SYN from the victim to the advertised printer port**. A detected SYN demonstrates a connection attempt; it does not, by itself, demonstrate successful IPP communication or code execution.

**Capture files:** `--pcap` saves the *constructed UDP packet*, not a complete network trace. `--capture-pcap` saves the TCP packets observed during verification. For analysis of both directions together, capture the full exchange with Wireshark as one PCAP/PCAPNG file.

### Packet variations used in the evaluation

Run these separately using the same lab setup (add `--verify --iface en6` to check for callbacks):

```bash
# Change the advertised IPP port: 8000 -> 8001
sudo "$(pwd)/.venv/bin/python" cups_attack.py --printer-port 8001

# Change the advertised resource path
sudo "$(pwd)/.venv/bin/python" cups_attack.py --resource /test_endpoint/test

# Advertise an address with no assigned host in the isolated lab
sudo "$(pwd)/.venv/bin/python" cups_attack.py --printer-ip 10.77.77.99

# Send six announcements one second apart
sudo "$(pwd)/.venv/bin/python" cups_attack.py --count 6 --interval 1
```

Additional options include `--location`, `--info`, `--make-model`, `--state`, `--count`, `--interval`, and `--timeout`. Consult `--help` for the complete list.

## Tool 2: `cups_detector.py`

The detector uses configurable rules to flag:

- **Unauthorized advertisements:** sender address not in `--allow-advertiser` or advertised endpoint not in `--allow-printer`.
- **Unexpected fields:** malformed legacy announcements, invalid or unexpected URI paths, states, and other fields.
- **Unexpected ports:** advertised IPP port not in `--expected-port`.
- **Repeated announcements:** five or more advertisements from one source within ten seconds by default.
- **Suspicious connections:** a TCP SYN from the victim matching a previously observed *suspicious* advertisement within a 30-second window by default.

These are heuristics. An authorized-looking announcement may still be malicious, and a legitimate configuration change may cause an alert.

### Live monitoring

Start the detector **before** transmitting a test announcement:

```bash
sudo "$(pwd)/.venv/bin/python" cups_detector.py \
  --iface en6 \
  --duration 60 \
  --victim-ip 10.77.77.2 \
  --allow-advertiser 10.77.77.1 \
  --allow-printer 10.77.77.1 \
  --expected-port 8000 \
  --json evidence/live_detections.json \
  --csv evidence/live_detections.csv \
  --verbose
```

In another terminal, run one of the `cups_attack.py` commands above. The detector prints any matching events and writes the configured JSON/CSV files when capture finishes.

### Offline PCAP analysis

```bash
python cups_detector.py \
  --pcap pcap_files/full_exchange.pcapng \
  --victim-ip 10.77.77.2 \
  --allow-advertiser 10.77.77.1 \
  --allow-printer 10.77.77.1 \
  --expected-port 8000 \
  --json evidence/offline_detections.json \
  --csv evidence/offline_detections.csv
```

Replace `full_exchange.pcapng` with an existing Wireshark capture that contains the relevant UDP announcements and, if available, subsequent TCP traffic. The detector's output contains event timestamps, severity, categories, addresses, packet numbers, and descriptions.

### Expected detection cases

| Test | Expected alert/event |
| --- | --- |
| Authorized legacy discovery | No security warning; possible informational `discovery_callback` |
| Advertised port `8001` | `unexpected_printer_port`; possibly `suspicious_ipp_connection` |
| Resource `/test_endpoint/test` | `unexpected_discovery_fields` |
| Advertised printer `10.77.77.99` | `unauthorized_printer_endpoint` |
| Six announcements, 1-second intervals | `discovery_burst` |

Actual outcomes depend on the capture, daemon behavior, and detection policy. Not observing a TCP SYN is not proof that the daemon never attempted to process an advertisement.

## Mitigation: stop publishing UDP 631 from Docker

The chosen mitigation is to remove the **UDP 631 port publication** from the vulnerable container's Docker Compose configuration while optionally retaining TCP 631. For example, change:

```yaml
ports:
  - "10.77.77.2:631:631/tcp"
  - "10.77.77.2:631:631/udp"
```

to:

```yaml
ports:
  - "10.77.77.2:631:631/tcp"
```

The YAML above is an **illustrative port-mapping excerpt**, not a complete Compose file. On the ThinkPad, apply the edit with:

```bash
docker compose up -d --force-recreate
docker compose ps
```

Then rerun the **same successful baseline announcement** and compare the result with the pre-mitigation test. The expected outcome is that the remote UDP 631 packet no longer reaches `cups-browsed` through Docker's published host port, so no related TCP callback occurs. Check for other services exposing UDP 631 and confirm the behavior in packet captures and container logs.

This mitigates the exposed network path; **it does not patch the vulnerable daemon**, and it does not prevent communication through other permitted paths (for example, from the Docker host or a container on the same network).

## Evidence and limitations

The project report, Wireshark captures (`.pcap` / `.pcapng`), screenshots, and detector logs (`.json` / `.csv`) document the before/after experiments. See the repository's `pcap_files/` and `evidence/` directories where those artifacts are included.

Known limitations:

- Detection is focused on **IPv4 legacy UDP 631**; mDNS/DNS-SD on UDP 5353 and IPv6 are outside its scope.
- Callback detection correlates initial TCP SYN packets with previously observed valid advertisements; it does not reassemble TCP streams or inspect full IPP transactions.
- Missing packets, allowlist assumptions, and rate thresholds can produce false positives or false negatives.
- The attack tool demonstrates advertisement-triggered network behavior, **not remote code execution**.

All addresses, scripts, and examples are intended for the isolated educational lab described above.
