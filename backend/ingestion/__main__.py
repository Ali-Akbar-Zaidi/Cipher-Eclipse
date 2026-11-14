"""
CLI for the ingestion stage, useful for debugging and for the eval scripts.

    python -m ingestion example.com --pretty
    python -m ingestion example.com --out results/example.json
    python -m ingestion example.com --names-only      # just print resolved names
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from .crtsh import CrtShError
from .dns_resolver import MAX_RESOLVED
from .pipeline import run_ingestion


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Passive subdomain ingestion (crt.sh + DNS).")
    p.add_argument("domain")
    p.add_argument("--max-resolved", type=int, default=MAX_RESOLVED)
    p.add_argument("--concurrency", type=int, default=100)
    p.add_argument("--nameserver", action="append", dest="nameservers",
                   help="Resolver IP (repeatable). Default: 1.1.1.1, 8.8.8.8, 9.9.9.9")
    p.add_argument("--exclude-expired", action="store_true")
    p.add_argument("--out", type=Path, help="Write JSON result to this file")
    p.add_argument("--pretty", action="store_true", help="Indent JSON output")
    p.add_argument("--names-only", action="store_true", help="Print resolved names, one per line")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    kwargs = {
        "max_resolved": args.max_resolved,
        "dns_concurrency": args.concurrency,
        "exclude_expired_certs": args.exclude_expired,
    }
    if args.nameservers:
        kwargs["nameservers"] = args.nameservers

    try:
        result = asyncio.run(run_ingestion(args.domain, **kwargs))
    except (CrtShError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.names_only:
        output = "\n".join(result["subdomains"]) + "\n"
    else:
        output = json.dumps(result, indent=2 if args.pretty else None) + "\n"

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
