
#!/usr/bin/env python3

import argparse
from collections import Counter, defaultdict, deque
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import json
import logging
from pathlib import Path
import shlex
from urllib.parse import urlsplit

from scapy.all import sniff

from scapy.layers.inet import IP, UDP, TCP

LOG = logging.getLogger("cups_detector")

def ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc

def port(value: str) -> int:
    try:
        number = int(value)
        if 1 <= number <= 65535:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("port must be between 1 and 65535")

def positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n

def positive_float(value: str) -> float:
    n = float(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return n

def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect unusual legacy CUPS printer discovery and associated IPP connections."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    
    source.add_argument("--pcap", 
                        type=Path, 
                        help="read an existing .pcap or .pcapng file"
    )
    source.add_argument("--iface", 
                        help="sniff live on a network interface, e.g. en6"
    )
    parser.add_argument("--duration", 
                        type=positive_float, 
                        default=60.0,
                        help="live capture duration in seconds (default: 60)"
    )
    parser.add_argument("--victim-ip", 
                        type=ipv4, 
                        default="10.77.77.2",
                        help="IP of the vulnerable CUPS host"
    )
    parser.add_argument("--allow-advertiser", 
                        action="append", 
                        type=ipv4, 
                        default=[],
                        help="authorized announcement source IP (repeat for several)"
    )
    parser.add_argument("--allow-printer", 
                        action="append", 
                        type=ipv4, default=[],
                        help="authorized IPP endpoint IP (repeat for several)"
    )
    parser.add_argument("--expected-port", 
                        action="append", 
                        type=port, 
                        default=[],
                        help="expected advertised IPP TCP port, e.g. 8000 (repeatable)"
    )
    parser.add_argument("--rate-threshold", 
                        type=positive_int, 
                        default=5,
                        help="flag this many advertisements per source within the window (default: 5)"
    )
    parser.add_argument("--rate-window", 
                        type=positive_float, 
                        default=10.0,
                        help="seconds in rate window (default: 10)"
    )
    parser.add_argument("--callback-window", 
                        type=positive_float, 
                        default=30.0,
                        help="seconds to associate TCP SYN with a discovery packet (default: 30)"
    )
    parser.add_argument("--json", 
                        type=Path, 
                        help="export events/alerts to JSON"
    )
    parser.add_argument("--csv", 
                        type=Path, 
                        help="export events/alerts to CSV"
    )
    parser.add_argument("--verbose", 
                        action="store_true", 
                        help="print valid discovery announcements"
    )
    args = parser.parse_args()
    if args.pcap is not None and not args.pcap.is_file():
        parser.error(f"PCAP not found: {args.pcap}")
    return args

@dataclass
class Event:
    time_utc: str
    severity: str
    category: str
    src_ip: str
    dst_ip: str
    packet_number: int
    details: str

@dataclass
class Announcement:
    time: float
    source: str
    host: str
    port: int
    uri: str
    suspicious: bool

class CupsDetector:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.events: list[Event] = []
        self.packet_count = 0
        self.announcement_count = 0
        self.recent_times: dict[str, deque[float]] = defaultdict(deque)
        self.rate_alert_time: dict[str, float] = {}
        self.announcements: deque[Announcement] = deque()
        self.callbacks_seen = 0

    def emit(self, pkt, severity: str, category: str, details: str) -> None:
        ts = datetime.fromtimestamp(float(pkt.time), timezone.utc).isoformat()
        event = Event(
            time_utc=ts,
            severity=severity,
            category=category,
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            packet_number=self.packet_count,
            details=details,
        )
        self.events.append(event)
        LOG.log(logging.WARNING if severity in ("WARNING", "HIGH") else logging.INFO,
                "[%s] %s packet=%d %s -> %s: %s",
                severity, category, event.packet_number,
                event.src_ip, event.dst_ip, details)

    def process(self, pkt) -> None:
        self.packet_count += 1
        if IP not in pkt:
            return  
        if UDP in pkt and int(pkt[UDP].dport) == 631 and pkt[IP].dst == self.args.victim_ip:
            self.inspect_advertisement(pkt)
        if TCP in pkt and pkt[IP].src == self.args.victim_ip:
            flags = int(pkt[TCP].flags)
            if (flags & 0x12) == 0x02:  
                self.inspect_callback(pkt)

    def inspect_advertisement(self, pkt) -> None:
        self.announcement_count += 1
        source = pkt[IP].src
        now = float(pkt.time)
        payload = bytes(pkt[UDP].payload)  

        
        times = self.recent_times[source]
        times.append(now)
        while times and now - times[0] > self.args.rate_window:
            times.popleft()
        if len(times) >= self.args.rate_threshold:
            previous = self.rate_alert_time.get(source, float("-inf"))
            if now - previous >= self.args.rate_window:
                self.emit(pkt, "WARNING", "discovery_burst",
                          f"{len(times)} announcements in {self.args.rate_window:g}s from {source}")
                self.rate_alert_time[source] = now

        if not payload or len(payload) > 2048 or b"\x00" in payload:
            self.emit(pkt, "WARNING", "malformed_discovery",
                      "Empty, oversized (>2048 bytes), or NUL-containing payload")
            return
        try:
            text = payload.decode("utf-8").strip()
            fields = shlex.split(text)
        except (UnicodeDecodeError, ValueError) as exc:
            self.emit(pkt, "WARNING", "malformed_discovery", f"Cannot parse payload: {exc}")
            return
        if not 3 <= len(fields) <= 6:
            self.emit(pkt, "WARNING", "malformed_discovery",
                      f"Expected 3–6 fields; received {len(fields)}")
            return
        try:
            
            def parse_number(value: str) -> int:
                try:
                    return int(value, 0)
                except ValueError:
                    return int(value, 10)

            printer_type, state = parse_number(fields[0]), parse_number(fields[1])
        except ValueError:
            self.emit(pkt, "WARNING", "malformed_discovery",
                      "Printer type and state must be integers")
            return
        if printer_type < 0 or printer_type > 65535 or state not in (3, 4, 5):
            self.emit(pkt, "WARNING", "unexpected_discovery_fields",
                      f"Unexpected printer type={printer_type} or state={state} (expected 3/4/5)")
            return

        uri = fields[2]
        try:
            parsed = urlsplit(uri)
            printer_port = parsed.port if parsed.port is not None else 631
        except ValueError as exc:
            self.emit(pkt, "WARNING", "malformed_discovery", f"Invalid URI port: {exc}")
            return
        if not parsed.hostname or parsed.scheme not in ("ipp", "ipps"):
            self.emit(pkt, "WARNING", "unexpected_discovery_fields",
                      f"Unexpected URI scheme or missing hostname: {uri!r}")
            return
        if not parsed.path.startswith(("/printers/", "/classes/")):
            self.emit(pkt, "WARNING", "unexpected_discovery_fields",
                      f"Resource path not in legacy /printers/ or /classes/: {parsed.path!r}")
            return
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            self.emit(pkt, "WARNING", "unexpected_discovery_fields",
                      "URI contains unexpected credentials, query, or fragment")
            return

        host = parsed.hostname
        suspicious = False
        if self.args.allow_advertiser and source not in self.args.allow_advertiser:
            self.emit(pkt, "HIGH", "unauthorized_advertisement",
                      f"Discovery sender {source} is not on the advertiser allowlist; URI={uri}")
            suspicious = True
        if self.args.allow_printer and host not in self.args.allow_printer:
            self.emit(pkt, "HIGH", "unauthorized_printer_endpoint",
                      f"Advertised endpoint {host} is not on the printer allowlist; URI={uri}")
            suspicious = True
        if self.args.expected_port and printer_port not in self.args.expected_port:
            self.emit(pkt, "WARNING", "unexpected_printer_port",
                      f"Advertised port {printer_port} differs from configured ports {self.args.expected_port}")
            suspicious = True
        if self.args.verbose:
            LOG.info("Discovery packet=%d sender=%s type=%d state=%d uri=%s",
                     self.packet_count, source, printer_type, state, uri)

        self.announcements.append(Announcement(
            time=now, source=source, host=host,
            port=printer_port, uri=uri, suspicious=suspicious,
        ))
        self.prune_announcements(now)

    def prune_announcements(self, current_time: float) -> None:
        while self.announcements and current_time - self.announcements[0].time > self.args.callback_window:
            self.announcements.popleft()

    def inspect_callback(self, pkt) -> None:
        now = float(pkt.time)
        self.prune_announcements(now)
        destination, destination_port = pkt[IP].dst, int(pkt[TCP].dport)
        matches = [a for a in self.announcements
                   if a.host == destination and a.port == destination_port
                   and 0 <= now - a.time <= self.args.callback_window]
        if not matches:
            return  
        ann = matches[-1]
        self.callbacks_seen += 1
        if ann.suspicious:
            self.emit(pkt, "HIGH", "suspicious_ipp_connection",
                      f"Victim initiated TCP to {destination}:{destination_port} after suspicious discovery: {ann.uri}")
        else:
            self.emit(pkt, "INFO", "discovery_callback",
                      f"Victim initiated TCP to advertised printer {destination}:{destination_port}")

    def export(self) -> None:
        records = [asdict(event) for event in self.events]
        if self.args.json:
            self.args.json.parent.mkdir(parents=True, exist_ok=True)
            self.args.json.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
            LOG.info("Wrote %d event(s) to %s", len(records), self.args.json)
        if self.args.csv:
            self.args.csv.parent.mkdir(parents=True, exist_ok=True)
            with self.args.csv.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=list(Event.__dataclass_fields__))
                writer.writeheader()
                writer.writerows(records)
            LOG.info("Wrote %d event(s) to %s", len(records), self.args.csv)

    def summary(self) -> None:
        counts = Counter(event.category for event in self.events)
        LOG.info("Processed %d packets; %d legacy announcements; %d callbacks; %d events",
                 self.packet_count, self.announcement_count,
                 self.callbacks_seen, len(self.events))
        for name, count in sorted(counts.items()):
            LOG.info("  %-31s %d", name, count)


def main() -> int:
    args = arguments()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if not args.allow_advertiser:
        LOG.warning("No --allow-advertiser supplied: cannot classify sender authorization")
    if not args.allow_printer:
        LOG.warning("No --allow-printer supplied: cannot classify advertised endpoint authorization")
    if not args.expected_port:
        LOG.warning("No --expected-port supplied: no unexpected-port alerts")
    detector = CupsDetector(args)
    try:
        if args.pcap:
            LOG.info("Reading offline capture %s", args.pcap)
            sniff(offline=str(args.pcap), prn=detector.process, store=False)
        else:
            LOG.info("Monitoring %s for %.1f seconds", args.iface, args.duration)
            sniff(iface=args.iface,
                  filter=f"(udp and dst port 631) or (tcp and src host {args.victim_ip})",
                  prn=detector.process, store=False, timeout=args.duration)
    except KeyboardInterrupt:
        LOG.info("Interrupted; exporting results collected so far")
    finally:
        detector.summary()
        detector.export()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        LOG.error("Unable to analyze packets: %s", exc)
        raise SystemExit(2) from exc
