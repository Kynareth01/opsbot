#!/usr/bin/env python3
"""
Example: Watch a server continuously and alert on issues.

Usage:
    python examples/watch_server.py
    python examples/watch_server.py --interval 10 --dry-run
"""

import argparse
import logging
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from opsbot.config import OpsBotConfig
from opsbot.app import OpsBot


def main():
    parser = argparse.ArgumentParser(description="Watch server and auto-remediate")
    parser.add_argument("--interval", "-i", type=int, default=30, help="Check interval in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually remediate")
    parser.add_argument("--slack", help="Slack webhook URL for alerts")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    config = OpsBotConfig.from_env()
    config.remediation.dry_run = args.dry_run

    if args.slack:
        config.alerts.slack_webhook = args.slack

    bot = OpsBot(config)

    print(f"🤖 OpsBot watching your server (interval: {args.interval}s, dry-run: {args.dry_run})")
    print(f"   Remediation handlers: {len(bot.remediator.get_handler_names())}")
    print()

    if args.once:
        bot.run_once()
    else:
        bot.run(interval=args.interval)


if __name__ == "__main__":
    main()
