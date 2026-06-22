import argparse
import re
import sys
import time
from get_disclosed_reports import run, count_disclosed_reports


def parse_programs_from_md(filepath):
    """Returns list of (display_name, url_handle) tuples."""
    programs = []
    current_name = None
    with open(filepath, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # Match: ### N. [Program Name](https://hackerone.com/handle)
            m = re.match(r'###\s+\d+\.\s+\[(.+?)\]\(https://hackerone\.com/.+?\)', line)
            if m:
                current_name = m.group(1).strip()
            # Match: - **Handle:** @slug
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
        # Fallback: try URL handle if display name returned 0
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

    zero = [(n, h) for n, h, c in results if c == 0]
    print(f"\n{len(zero)} programs with 0 disclosed reports.")

    out_path = filepath.replace('.md', '_disclosed_counts.md')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# Disclosed Report Counts\n\n")
        sev_label = ', '.join(s.capitalize() for s in severity_filter) if severity_filter else "All"
        f.write(f"> Severity filter: **{sev_label}**  \n")
        f.write(f"> Total programs scanned: **{len(programs)}**\n\n")
        f.write("| # | Program | Handle | Disclosed Reports |\n")
        f.write("|---|---------|--------|------------------|\n")
        for rank, (name, handle, count) in enumerate(results, 1):
            f.write(f"| {rank} | {name} | [@{handle}](https://hackerone.com/{handle}) | {count} |\n")
    print(f"\nSaved to: {out_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Fetch disclosed HackerOne reports for a program.",
        usage="main.py <handle|--scan FILE> [-C] [-H] [-M] [-L] [-N]"
    )
    parser.add_argument("handle", nargs='?', help="HackerOne program handle (e.g. Shopify)")
    parser.add_argument("--scan", metavar="FILE", help="Scan all handles from a markdown file and count disclosed reports")
    parser.add_argument("-C", "--critical", action="store_true", help="Include Critical severity")
    parser.add_argument("-H", "--high",     action="store_true", help="Include High severity")
    parser.add_argument("-M", "--medium",   action="store_true", help="Include Medium severity")
    parser.add_argument("-L", "--low",      action="store_true", help="Include Low severity")
    parser.add_argument("-N", "--none",     action="store_true", help="Include None/N/A severity")

    args = parser.parse_args()

    selected = []
    if args.critical: selected.append("critical")
    if args.high:     selected.append("high")
    if args.medium:   selected.append("medium")
    if args.low:      selected.append("low")
    if args.none:     selected.append("none")

    severity_filter = selected if selected else None

    if args.scan:
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
