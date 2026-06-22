# GetDisclosed

Fetch and extract disclosed HackerOne bug bounty reports into markdown files.

## Setup

```bash
export HACKERONE_USERNAME=your_username
export HACKERONE_TOKEN=your_api_token
```

## Workflow

**Step 1 — Get list of all Bug Bounty Programs**

```bash
python get_newest_programs.py
```

Outputs `newest_bounty_programs.md` with all public HackerOne BBPs sorted by newest.

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
