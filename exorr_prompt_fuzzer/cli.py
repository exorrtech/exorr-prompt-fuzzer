#!/usr/bin/env python3
"""EXORR Prompt Fuzzer — Automated LLM prompt injection testing.

Fuzz LLM endpoints for prompt injection, jailbreak, and safety bypass vulnerabilities.
"""

import argparse
import json
import sys
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from .engine import FuzzEngine
from .report import ReportGenerator
from .payloads import PayloadLoader


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="exorr-prompt-fuzzer",
        description="EXORR Prompt Fuzzer — Automated LLM prompt injection testing for red teams",
        epilog="Walk with the void. ∅ EXORR Security",
    )
    p.add_argument("-t", "--target", required=True, help="Target LLM endpoint URL (e.g. https://api.openai.com/v1/chat/completions)")
    p.add_argument("-k", "--api-key", default="", help="API key for the target endpoint (or set TARGET_API_KEY env var)")
    p.add_argument("-m", "--model", default="gpt-3.5-turbo", help="Model name to target (default: gpt-3.5-turbo)")
    p.add_argument("-p", "--payloads", default=None, help="Path to custom payloads JSON file (default: built-in payloads)")
    p.add_argument("-c", "--categories", default=None, help="Comma-separated categories to test (default: all). Options: injection,jailbreak,extraction,bypass,encoding")
    p.add_argument("-n", "--count", type=int, default=0, help="Max payloads to send (0 = all, default: 0)")
    p.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds (default: 1.0)")
    p.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    p.add_argument("-o", "--output", default=None, help="Output file path (JSON report). Default: ./exorr-fuzz-report-{timestamp}.json")
    p.add_argument("--format", choices=["json", "markdown", "html"], default="json", help="Report format (default: json)")
    p.add_argument("--severity-threshold", choices=["low", "medium", "high", "critical"], default="low", help="Minimum severity to include in report (default: low)")
    p.add_argument("--system-prompt", default=None, help="Custom system prompt to inject before fuzzing")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    p.add_argument("--dry-run", action="store_true", help="Show payloads without sending requests")
    p.add_argument("-v", "--version", action="version", version="%(prog)s 1.0.0")
    return p.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)

    if requests is None:
        print("[!] 'requests' library required. Install: pip install requests", file=sys.stderr)
        return 1

    # Load payloads
    loader = PayloadLoader()
    if args.payloads:
        payloads = loader.load_file(Path(args.payloads))
    else:
        payloads = loader.load_builtin()

    # Filter by category
    if args.categories:
        cats = [c.strip() for c in args.categories.split(",")]
        payloads = [p for p in payloads if p["category"] in cats]

    # Limit count
    if args.count > 0:
        payloads = payloads[:args.count]

    print(f"\n  ∅ EXORR Prompt Fuzzer v1.0.0")
    print(f"  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  Target:   {args.target}")
    print(f"  Model:    {args.model}")
    print(f"  Payloads: {len(payloads)}")
    print(f"  Delay:    {args.delay}s")
    print()

    if args.dry_run:
        for i, p in enumerate(payloads, 1):
            print(f"  [{i}] [{p['category']}] {p['name']}: {p['prompt'][:80]}...")
        print(f"\n  Dry run — {len(payloads)} payloads listed, none sent.")
        return 0

    # Run fuzzer
    engine = FuzzEngine(
        target_url=args.target,
        api_key=args.api_key,
        model=args.model,
        delay=args.delay,
        timeout=args.timeout,
        system_prompt=args.system_prompt,
        verbose=args.verbose,
    )

    results = engine.run(payloads)

    # Generate report
    reporter = ReportGenerator(
        results=results,
        target=args.target,
        model=args.model,
        format=args.format,
        severity_threshold=args.severity_threshold,
    )

    output_path = args.output or f"exorr-fuzz-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.{args.format}"
    reporter.save(output_path)

    # Print summary
    vuln_count = sum(1 for r in results if r.get("vulnerable", False))
    print(f"\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  ✓ Scan complete")
    print(f"    Payloads sent:  {len(results)}")
    print(f"    Vulnerable:     {vuln_count}")
    print(f"    Safe:           {len(results) - vuln_count}")
    print(f"    Report saved:   {output_path}")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
