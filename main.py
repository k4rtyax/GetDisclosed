import argparse
import re
import sys
import time
from get_disclosed_reports import run, count_disclosed_reports, fetch_programs


def parse_programs_from_md(filepath):
    programs = []
    current_name = None
    with open(filepath, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            m = re.match(r'###\s+\d+\.\s+\[(.+?)\]\(https://hackerone\.com/.+?\)', line)
            if m:
                current_name = m.group(1).strip()
            m2 = re.match(r'-\s+\*\*Handle:\*\*\s+@(.+)', line)
            if m2 and current_name:
                programs.append((current_name, m2.group(1).strip()))
                current_name = None
    return programs


def cmd_scan(filepath, severity_filter):
    programs = parse_programs_from_md(filepath)
    if not programs:
        print(f"No programs found in '{filepath}'.")
        sys.exit(1)

    print(f"Found {len(programs)} programs. Checking disclosed report counts...\n")

    results = []
    for i, (name, handle) in enumerate(programs, 1):
        print(f"[{i}/{len(programs)}] {name} ...", end=' ', flush=True)
        count = count_disclosed_reports(name, severity_filter)
        if count == 0 and name.lower() != handle.lower():
            count = count_disclosed_reports(handle, severity_filter)
        print(count)
        results.append((name, handle, count))
        time.sleep(0.5)

    results.sort(key=lambda x: x[2], reverse=True)

    print("\n" + "=" * 55)
    print(f"{'#':<5} {'Program':<38} {'Disclosed'}")
    print("-" * 55)
    for rank, (name, handle, count) in enumerate(results, 1):
        if count > 0:
            print(f"{rank:<5} {name:<38} {count}")

    zero = [n for n, h, c in results if c == 0]
    print(f"\n{len(zero)} programs with 0 disclosed reports.")

    out_path = filepath.replace('.md', '_disclosed_counts.md')
    with open(out_path, 'w', encoding='utf-8') as f:
        sev_label = ', '.join(s.capitalize() for s in severity_filter) if severity_filter else "All"
        f.write("# Disclosed Report Counts\n\n")
        f.write(f"> Severity filter: **{sev_label}**  \n")
        f.write(f"> Total programs scanned: **{len(programs)}**\n\n")
        f.write("| # | Program | Handle | Disclosed Reports |\n")
        f.write("|---|---------|--------|------------------|\n")
        for rank, (name, handle, count) in enumerate(results, 1):
            f.write(f"| {rank} | {name} | [@{handle}](https://hackerone.com/{handle}) | {count} |\n")
    print(f"Saved to: {out_path}")


def main():
    parser = argparse.ArgumentParser(
        description="HackerOne disclosed report toolkit.",
        usage="main.py [--fetch-programs] [--scan FILE] [<handle>] [-C] [-H] [-M] [-L] [-N]"
    )
    parser.add_argument("handle", nargs='?', help="Program handle to fetch full reports (e.g. Shopify)")
    parser.add_argument("--fetch-programs", metavar="FILE", nargs='?', const="newest_bounty_programs.md",
                        help="Fetch all HackerOne BBPs and save to FILE (default: newest_bounty_programs.md)")
    parser.add_argument("--scan", metavar="FILE", help="Scan program list from FILE and count disclosed reports")
    parser.add_argument("-C", "--critical", action="store_true", help="Critical severity")
    parser.add_argument("-H", "--high",     action="store_true", help="High severity")
    parser.add_argument("-M", "--medium",   action="store_true", help="Medium severity")
    parser.add_argument("-L", "--low",      action="store_true", help="Low severity")
    parser.add_argument("-N", "--none",     action="store_true", help="None/N/A severity")

    args = parser.parse_args()

    selected = []
    if args.critical: selected.append("critical")
    if args.high:     selected.append("high")
    if args.medium:   selected.append("medium")
    if args.low:      selected.append("low")
    if args.none:     selected.append("none")
    severity_filter = selected if selected else None

    if args.fetch_programs:
        fetch_programs(args.fetch_programs)
    elif args.scan:
        cmd_scan(args.scan, severity_filter)
    elif args.handle:
        sev_label = ', '.join(s.capitalize() for s in severity_filter) if severity_filter else "All"
        print(f"Severity filter: {sev_label}")
        run(args.handle, severity_filter)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
