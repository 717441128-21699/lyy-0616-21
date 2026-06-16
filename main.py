#!/usr/bin/env python3
"""
Main entry point for the DNS server.

Usage:
    python main.py                      # Run on port 53 (default)
    python main.py --port 5353          # Run on custom port
    python main.py --no-recursion       # Authoritative only
    python main.py --test               # Run tests
"""
import argparse
import logging
import sys
import time

from dns_server import DNSServer
from dns_message import (
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_MX,
    DNSMessage,
    DNSQuestion,
    DNSResourceRecord,
)


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def setup_authoritative_records(server):
    """Set up example authoritative zones."""
    local_zone = server.add_authoritative_zone("local", default_ttl=300)
    local_zone.add_record("@", "A", "127.0.0.1")
    local_zone.add_record("localhost", "A", "127.0.0.1")
    local_zone.add_record("localhost", "AAAA", "::1")
    local_zone.add_record("test", "A", "192.168.1.100")
    local_zone.add_record("test", "AAAA", "fd00::1")
    local_zone.add_record("www", "CNAME", "test.local")
    local_zone.add_record("mail", "MX", (10, "mail.local"))
    local_zone.add_record("mail", "A", "192.168.1.50")

    example_zone = server.add_authoritative_zone("example.com", default_ttl=600)
    example_zone.add_record("@", "A", "93.184.216.34")
    example_zone.add_record("@", "MX", (10, "mail.example.com"))
    example_zone.add_record("@", "MX", (20, "mail2.example.com"))
    example_zone.add_record("www", "A", "93.184.216.34")
    example_zone.add_record("api", "CNAME", "www.example.com")
    example_zone.add_record("mail", "A", "10.0.0.1")
    example_zone.add_record("mail2", "A", "10.0.0.2")
    example_zone.add_record("ns1", "A", "10.0.0.53")
    example_zone.add_record("@", "NS", "ns1.example.com")


def main():
    parser = argparse.ArgumentParser(description="DNS Server with caching and recursion")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5353, help="Listen port (default: 5353, use 53 for standard)")
    parser.add_argument(
        "--upstream",
        action="append",
        help="Upstream DNS server (host:port). Can be specified multiple times.",
    )
    parser.add_argument(
        "--no-recursion",
        action="store_true",
        help="Disable recursive resolution (authoritative only)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--test", action="store_true", help="Run built-in tests")
    parser.add_argument("--status-interval", type=int, default=0,
        help="Print status every N seconds while server is running (0 = disable)")
    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.test:
        from test_dns import run_all_tests
        success = run_all_tests()
        sys.exit(0 if success else 1)

    upstream_servers = None
    if args.upstream:
        upstream_servers = []
        for s in args.upstream:
            if ":" in s:
                host, port = s.rsplit(":", 1)
                upstream_servers.append((host, int(port)))
            else:
                upstream_servers.append((s, 53))

    server = DNSServer(
        host=args.host,
        port=args.port,
        upstream_servers=upstream_servers,
        allow_recursion=not args.no_recursion,
    )

    setup_authoritative_records(server)
    server.start()

    print(f"DNS server listening on {args.host}:{args.port} (UDP + TCP)")
    if not args.no_recursion:
        print("Recursive resolution enabled")
    print(f"Authoritative zones: local, example.com")
    print("Press Ctrl+C to stop")

    try:
        if args.status_interval > 0:
            while True:
                time.sleep(args.status_interval)
                server.print_status()
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    main()
