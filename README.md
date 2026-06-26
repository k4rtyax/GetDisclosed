# GetDisclosed

Fetch and extract disclosed HackerOne bug bounty reports into markdown files.

## Setup

Provide credentials via environment variables:

```bash
export HACKERONE_USERNAME=your_username
export HACKERONE_TOKEN=your_api_token
```

…or create a local `creds.json` (gitignored) in the project root:

```json
{
  "username": "your_username",
  "token": "your_api_token"
}
```

## Workflow

**Step 1 — Get list of all Bug Bounty Programs**

```bash
python main.py --fetch-programs
```

Outputs [`newest_bounty_programs.md`](newest_bounty_programs.md) with all public HackerOne BBPs sorted by newest.

---

**Step 2 — Check which programs have disclosed reports**

```bash
python main.py --scan newest_bounty_programs.md
```

Scans every program and outputs a sorted count of disclosed reports.
Outputs `newest_bounty_programs_disclosed_counts.md`.

You can also filter by severity:

```bash
python main.py --scan newest_bounty_programs.md -H       # High only
python main.py --scan newest_bounty_programs.md -H -M    # High + Medium
```

---

**Step 3 — Fetch full reports for a chosen program**

```bash
python main.py <handle>
```

Fetches all disclosed reports and saves them to `Reports/<handle>/`:
- `<handle>_Summary.md` — index table of all reports
- `<report_id>.md` — full report with vulnerability details and timeline

Filter by severity:

```bash
python main.py <handle> -C    # Critical
python main.py <handle> -H    # High
python main.py <handle> -M    # Medium
python main.py <handle> -L    # Low
python main.py <handle> -N    # None
python main.py <handle> -H -M # High + Medium
```

Filter by keyword/query (HackerOne query syntax):

```bash
python main.py <handle> -q 'ssrf'                          # SSRF reports from a program
python main.py <handle> -q 'ssrf' -C -H                    # SSRF + Critical/High only
```

Or search across all programs without specifying a handle:

```bash
python main.py -q 'ssrf AND disclosed:true'
python main.py -q 'ssrf AND substate:("Resolved") AND disclosed:true'
```

Limit the number of reports fetched with `-n`/`--limit`:

```bash
python main.py <handle> -n 20                              # First 20 reports only
python main.py -q 'ssrf AND disclosed:true' -n 50          # Cap a query search at 50
```

Restrict to recently disclosed reports with `-s`/`--since` (no date filter by default):

```bash
python main.py <handle> --since 2025-12-31                 # Only reports disclosed after this date
python main.py --scan newest_bounty_programs.md -s 2025-12-31
```
