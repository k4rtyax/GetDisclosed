# GetDisclosed

Fetch and extract disclosed HackerOne reports into markdown files.

## Setup

Set environment variables:

```bash
export HACKERONE_USERNAME=your_username
export HACKERONE_TOKEN=your_api_token
```

## Usage

**Fetch all disclosed reports for a program:**
```bash
python main.py <handle>
```

**Filter by severity (combinable):**
```bash
python main.py <handle> -C   # Critical
python main.py <handle> -H   # High
python main.py <handle> -M   # Medium
python main.py <handle> -L   # Low
python main.py <handle> -N   # None
python main.py <handle> -H -M  # High + Medium
```

**Count disclosed reports from a program list:**
```bash
python main.py --scan programs.md
```

The `--scan` flag reads a markdown file containing HackerOne program handles and outputs a sorted count of disclosed reports per program.

## Output

Reports are saved to `Reports/<handle>/`:
- `<handle>_Summary.md` — index table of all reports
- `<report_id>.md` — full report with details, vulnerability info, and timeline
