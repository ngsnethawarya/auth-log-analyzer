#!/usr/bin/env python3
"""
auth_log_analyzer.py

Small helper script to review Linux authentication logs.
Tested with Ubuntu-style /var/log/auth.log files.
"""

import argparse
from collections import Counter
from pathlib import Path
import re


FAILED_PATTERN = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
SUCCESS_PATTERN = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze SSH login attempts in an auth.log-style file."
    )
    parser.add_argument(
        "logfile",
        help="Path to the log file (e.g. /var/log/auth.log)"
    )
    return parser.parse_args()


def analyze_log(path: Path):
    failed_ips = Counter()
    failed_users = Counter()
    success_users = Counter()
    success_ips = Counter()

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            failed_match = FAILED_PATTERN.search(line)
            if failed_match:
                ip = failed_match.group("ip")
                user = failed_match.group("user")
                failed_ips[ip] += 1
                failed_users[user] += 1
                continue

            success_match = SUCCESS_PATTERN.search(line)
            if success_match:
                ip = success_match.group("ip")
                user = success_match.group("user")
                success_users[user] += 1
                success_ips[ip] += 1

    return {
        "failed_ips": failed_ips,
        "failed_users": failed_users,
        "success_users": success_users,
        "success_ips": success_ips,
    }


def print_top(counter: Counter, title: str, limit: int = 5):
    if not counter:
        print(f"{title}: none")
        return

    print(title)
    for item, count in counter.most_common(limit):
        print(f"  {item:<20} {count}")
    print()


def main():
    args = parse_args()
    log_path = Path(args.logfile)

    if not log_path.is_file():
        raise SystemExit(f"Log file not found: {log_path}")

    results = analyze_log(log_path)

    print(f"\nAnalysis of {log_path}\n" + "-" * 40)
    print_top(results["failed_ips"], "Top source IPs (failed logins)")
    print_top(results["failed_users"], "Usernames targeted (failed logins)")
    print_top(results["success_users"], "Users with successful logins")
    print_top(results["success_ips"], "Source IPs with successful logins")


if __name__ == "__main__":
    main()
