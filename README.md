# GetDisclosed

Tools to discover and extract disclosed HackerOne bug bounty reports.

## Setup

Set environment variables:

```bash
export HACKERONE_USERNAME=your_username
export HACKERONE_TOKEN=your_api_token
```

## Workflow

### 1. Fetch all Bug Bounty Programs

Generate a list of all public HackerOne BBPs sorted by newest:

```bash
python get_newest_programs.py
```

Output: `newest_bounty_programs.md` — list of all programs with their handles.

---

### 2. Count disclosed reports per program

Scan the generated list to see how many disclosed reports each program has:

```bash
python main.py --scan newest_bounty_programs.md
```

Output: `newest_bounty_programs_disclosed_counts.md` — sorted table by count.

---

### 3. Fetch full disclosed reports for a program

```bash
python main.py <handle>
```

Filter by severity (flags are combinable):

```bash
python main.py <handle> -C   # Critical
python main.py <handle> -H   # High
python main.py <handle> -M   # Medium
python main.py <handle> -L   # Low
python main.py <handle> -N   # None
python main.py <handle> -H -M
```

Output is saved to `Reports/<handle>/`:
- `<handle>_Summary.md` — index table of all fetched reports
- `<report_id>.md` — full report with vulnerability details and timeline
