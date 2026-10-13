import argparse
import sys
import os
from utils.logger import Logger
from utils.helpers import sanitize_filename
from core.engine import Engine
from core.reporter import Reporter


def banner():
    print(r"""
  ____  _           _                 _____         
 |  _ \| |__   __ _| |_ ___  _ __ __|  ___|   _  ___ 
 | |_) | '_ \ / _` | __/ _ \| '_ ` _ \ |_  | | |/ _ \
 |  __/| | | | (_| | || (_) | | | | | |  _| | |_|  __/
 |_|   |_| |_|\__,_|\__\___/|_| |_| |_|_|   \__, |\___|
                                             |___/      
  👁  PhantomEye — Full OSINT Recon Framework
     by H3M4N1H | For authorized use only
    """)


def parse_args():
    parser = argparse.ArgumentParser(
        description="PhantomEye — Full OSINT recon tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--username", metavar="USERNAME",
                        help="Username to search across 100+ platforms")
    parser.add_argument("-e", "--email", metavar="EMAIL",
                        help="Email address to investigate")
    parser.add_argument("-i", "--ip", metavar="IP",
                        help="IP address to geolocate and analyze")
    parser.add_argument("-d", "--domain", metavar="DOMAIN",
                        help="Domain to enumerate (WHOIS, DNS, subdomains, tech)")
    parser.add_argument("-p", "--phone", metavar="PHONE",
                        help="Phone number to analyze (e.g. +91 9876543210)")
    parser.add_argument("--report", action="store_true",
                        help="Save HTML report after scan")
    parser.add_argument("--output", metavar="PATH", default=None,
                        help="Output path for HTML report (default: reports/<target>.html)")
    parser.add_argument("--threads", type=int, default=20,
                        help="Threads for username scan (default: 20)")

    return parser.parse_args()


def main():
    banner()
    args = parse_args()
    logger = Logger()

    # Check at least one target
    if not any([args.username, args.email, args.ip, args.domain, args.phone]):
        logger.error("No target specified. Use -u, -e, -i, -d, or -p")
        logger.info("Example: python main.py -u h3m4n1h -d github.com")
        sys.exit(1)

    # Determine target summary for report name
    targets = []
    if args.username: targets.append(f"u:{args.username}")
    if args.email:    targets.append(f"e:{args.email}")
    if args.ip:       targets.append(f"ip:{args.ip}")
    if args.domain:   targets.append(f"d:{args.domain}")
    if args.phone:    targets.append(f"p:{args.phone}")
    target_summary = " | ".join(targets)

    logger.info(f"Target(s): {target_summary}")
    logger.info(f"Threads  : {args.threads}")
    print()

    # Run engine
    engine = Engine(logger)
    results = engine.run(
        username=args.username,
        email=args.email,
        ip=args.ip,
        domain=args.domain,
        phone=args.phone,
    )

    # Summary
    print()
    logger.success(f"Scan complete — {len(results)} module(s) ran")

    # Report
    if args.report:
        if args.output:
            out_path = args.output
            if not out_path.endswith(".html"):
                out_path += ".html"
        else:
            os.makedirs("reports", exist_ok=True)
            first_target = sanitize_filename(
                args.username or args.email or args.ip or args.domain or args.phone
            )
            out_path = f"reports/{first_target}.html"

        reporter = Reporter(results, target_summary)
        reporter.to_html(out_path)


if __name__ == "__main__":
    main()
