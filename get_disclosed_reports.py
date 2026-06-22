import os
import re
import sys
import json
import urllib.request
import urllib.parse
import base64
import time
from datetime import datetime

def _make_auth_header():
    username = os.getenv("HACKERONE_USERNAME")
    token = os.getenv("HACKERONE_TOKEN")
    if not username or not token:
        print("Error: HACKERONE_USERNAME and HACKERONE_TOKEN environment variables must be set.")
        sys.exit(1)
    b64 = base64.b64encode((username + ":" + token).encode('ascii')).decode('ascii')
    return f'Basic {b64}'

def fetch_programs(output_file="newest_bounty_programs.md"):
    print("Fetching programs from HackerOne API...")
    programs = []
    url = "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=100"
    page = 1
    while url:
        print(f"  -> Fetching page {page}...")
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        req.add_header('Authorization', _make_auth_header())
        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode('utf-8'))
                programs.extend(data.get('data', []))
                url = data.get('links', {}).get('next')
                page += 1
        except Exception as e:
            print(f"Error: {e}")
            break

    bbp = [p for p in programs if p.get('attributes', {}).get('offers_bounties')]
    bbp.sort(key=lambda p: p.get('attributes', {}).get('started_accepting_at') or '', reverse=True)

    print(f"\nFound {len(bbp)} Bug Bounty Programs out of {len(programs)} total.")

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Newest Bug Bounty Programs on HackerOne\n\n")
        f.write(f"*Total BBP found: {len(bbp)}*\n\n")
        for i, p in enumerate(bbp, 1):
            attrs = p.get('attributes', {})
            name = attrs.get('name', 'Unknown')
            handle = attrs.get('handle', 'Unknown')
            f.write(f"### {i}. [{name}](https://hackerone.com/{handle})\n")
            f.write(f"- **Handle:** @{handle}\n")
            f.write(f"- **Started Accepting At:** {attrs.get('started_accepting_at', 'Unknown')}\n")
            f.write(f"- **State:** {attrs.get('state', 'Unknown')}\n")
            f.write("---\n")

    print(f"Saved to: {output_file}")
    return output_file

def format_date(date_str):
    if not date_str:
        return ""
    try:
        if '.' in date_str:
            dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        return dt.strftime("%Y-%m-%d %H:%M:%S +0000")
    except Exception:
        return date_str

PAGE_SIZE = 50

def _hacktivity_base_url(query):
    encoded = urllib.parse.quote(query)
    return f"https://api.hackerone.com/v1/hackers/hacktivity?queryString={encoded}&page[size]={PAGE_SIZE}"

def count_disclosed_reports(handle, severity_filter=None):
    query = f'team:("{handle}") AND disclosed:true AND substate:("Resolved") AND disclosed_at:>2025-12-31'
    base = _hacktivity_base_url(query)
    sev_set = {s.lower() for s in severity_filter} if severity_filter else None
    total = 0
    page = 1
    while True:
        url = base + f"&page[number]={page}"
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        req.add_header('Authorization', _make_auth_header())
        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode('utf-8'))
                batch = data.get('data', [])
                if sev_set:
                    batch = [r for r in batch if (r.get('attributes', {}).get('severity_rating') or 'none').lower() in sev_set]
                total += len(batch)
                raw_count = len(data.get('data', []))
                if raw_count < PAGE_SIZE:
                    break
                page += 1
                time.sleep(1)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(10)
                continue
            break
        except Exception:
            break
    return total

def build_included_map(data_auth):
    included = data_auth.get("included", [])
    return {(item["type"], item["id"]): item for item in included}

def fetch_disclosed_reports_list(handle=None, severity_filter=None, extra_query=None, limit=None):
    if handle:
        query = f'team:("{handle}") AND disclosed:true AND substate:("Resolved") AND disclosed_at:>2025-12-31'
        if extra_query:
            query += f' AND {extra_query}'
        label = handle
    else:
        query = extra_query or 'disclosed:true AND substate:("Resolved") AND disclosed_at:>2025-12-31'
        label = "hacktivity"
    print(f"Fetching hacktivity list (query: {query!r})...")
    base = _hacktivity_base_url(query)
    sev_set = {s.lower() for s in severity_filter} if severity_filter else None
    reports = []
    page = 1

    while True:
        print(f"-> Fetching page {page}...")
        url = base + f"&page[number]={page}"
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        req.add_header('Authorization', _make_auth_header())

        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode('utf-8'))
                batch = data.get('data', [])
                if sev_set:
                    batch = [r for r in batch if (r.get('attributes', {}).get('severity_rating') or 'none').lower() in sev_set]
                # Filter out useless substates — keep Resolved & Informative, drop N/A, Duplicate, Spam
                _EXCLUDED = {'not-applicable', 'duplicate', 'spam'}
                batch = [r for r in batch if (r.get('attributes', {}).get('substate') or '').lower().replace(' ', '-') not in _EXCLUDED]
                reports.extend(batch)
                if limit and len(reports) >= limit:
                    reports = reports[:limit]
                    break
                raw_count = len(data.get('data', []))
                if raw_count < PAGE_SIZE:
                    break
                page += 1
                time.sleep(1)

        except urllib.error.HTTPError as e:
            print(f"HTTP Error {e.code}: {e.reason}")
            break
        except Exception as e:
            print(f"Error fetching data: {e}")
            break

    return reports, label

def fetch_full_report_json_authenticated(report_id):
    try:
        url = f"https://api.hackerone.com/v1/hackers/reports/{report_id}"
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        req.add_header('Authorization', _make_auth_header())
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception:
        return None

def fetch_public_info(report_id):
    try:
        url = f"https://hackerone.com/reports/{report_id}.json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception:
        return None

def _extract_program_handle(data_auth, hacktivity_item=None):
    # 1) Best source: hacktivity_item.relationships.program.data.attributes.handle
    #    This is always present per the HackerOne Hacker API docs (hacktivity_item object)
    if hacktivity_item:
        handle = (hacktivity_item.get("relationships", {})
                                 .get("program", {})
                                 .get("data", {})
                                 .get("attributes", {})
                                 .get("handle"))
        if handle:
            return handle

    # 2) Try authenticated report response: relationships.program.data.attributes.handle
    report_data = data_auth.get("data", {}) if data_auth else {}
    prog_data = report_data.get("relationships", {}).get("program", {}).get("data", {})
    handle = prog_data.get("attributes", {}).get("handle")
    if handle:
        return handle

    # 3) Try included list
    for item in (data_auth or {}).get("included", []):
        if item.get("type") == "program":
            handle = item.get("attributes", {}).get("handle")
            if handle:
                return handle

    # 4) Last resort: numeric id
    return str(prog_data.get("id")) if prog_data.get("id") else "unknown"

def write_full_report(report_id, out_path, hacktivity_item):
    data_auth = fetch_full_report_json_authenticated(report_id)

    if not data_auth or "data" not in data_auth:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(f"# Report {report_id}\n\n")
            f.write("> **Note:** Full report details could not be fetched. It might be a limited disclosure.\n\n")
            attr = hacktivity_item.get('attributes', {})
            f.write(f"- **Title:** {attr.get('title')}\n")
            f.write(f"- **URL:** https://hackerone.com/reports/{report_id}\n")
        return None

    program_handle = _extract_program_handle(data_auth, hacktivity_item)
    report_data = data_auth["data"]
    attributes = report_data.get("attributes", {})
    relationships = report_data.get("relationships", {})
    included_map = build_included_map(data_auth)

    title = attributes.get("title", "No Title")

    scope = "None"
    scope_ref = relationships.get("structured_scope", {}).get("data")
    if scope_ref and isinstance(scope_ref, dict):
        scope_obj = included_map.get((scope_ref.get("type"), scope_ref.get("id")), {})
        scope = scope_obj.get("attributes", {}).get("asset_identifier", "None")
        if scope == "None":
            scope = scope_ref.get("attributes", {}).get("asset_identifier", "None")

    weakness = "None"
    weakness_data = relationships.get("weakness", {}).get("data")
    if weakness_data and isinstance(weakness_data, dict):
        weakness = weakness_data.get("attributes", {}).get("name", "None")

    severity_rating = "None"
    severity_data = relationships.get("severity", {}).get("data")
    if severity_data and isinstance(severity_data, dict):
        sev_attrs = severity_data.get("attributes", {})
        rating = sev_attrs.get("rating")
        if rating:
            severity_rating = str(rating).capitalize()
        score = sev_attrs.get("score")
        if score:
            severity_rating = f"{severity_rating} ({score})"

    date_raw = attributes.get("submitted_at") or attributes.get("created_at") or attributes.get("disclosed_at")
    date_formatted = format_date(date_raw)

    reporter = "Unknown"
    reporter_data = relationships.get("reporter", {}).get("data")
    if reporter_data and isinstance(reporter_data, dict):
        reporter = reporter_data.get("attributes", {}).get("username", "Unknown")

    cves = attributes.get("cve_ids") or []
    cves_str = ", ".join(cves) if isinstance(cves, list) and len(cves) > 0 else "None"

    # API REST authenticated tidak menyediakan vulnerability_information,
    # jadi kita harus fallback ke API publik (flat JSON) untuk mengambilnya!
    vuln_info = attributes.get("vulnerability_information")
    if not vuln_info:
        public_data = fetch_public_info(report_id)
        if public_data:
            vuln_info = public_data.get("vulnerability_information")

    if not vuln_info:
        vuln_info = "No Information Provided / Limited Disclosure"

    with open(out_path, 'w', encoding='utf-8') as out_f:
        out_f.write(f"# {title}\n\n")
        out_f.write(f"- **Report ID:** {report_id}\n")
        out_f.write(f"- **URL:** https://hackerone.com/reports/{report_id}\n")
        out_f.write(f"- **Reporter:** @{reporter}\n")
        out_f.write(f"- **Date:** {date_formatted}\n")
        out_f.write(f"- **Severity:** {severity_rating}\n")
        out_f.write(f"- **Weakness:** {weakness}\n")
        out_f.write(f"- **Scope:** {scope}\n")
        out_f.write(f"- **CVE IDs:** {cves_str}\n\n")
        out_f.write("---\n\n## 📝 Vulnerability Details\n\n")
        out_f.write(f"{vuln_info}\n\n")

        activities = relationships.get("activities", {}).get("data", [])
        if isinstance(activities, list) and len(activities) > 0:
            out_f.write("---\n\n## ⏳ Timeline & Comments\n\n")
            for act in activities:
                act_attrs = act.get("attributes", {})
                act_date = format_date(act_attrs.get("created_at") or act_attrs.get("updated_at"))
                act_type = act.get("type", "").replace("activity-", "").replace("-", " ").title()
                
                actor = "Unknown"
                actor_data = act.get("relationships", {}).get("actor", {}).get("data")
                if actor_data and isinstance(actor_data, dict):
                    actor = actor_data.get("attributes", {}).get("username", "Unknown")
                    
                message = act_attrs.get("message", "")
                
                if not act_date:
                    continue
                    
                out_f.write(f"**{act_date}** | `@{actor}` ({act_type})\n")
                if message:
                    formatted_message = "\n".join([f"> {line}" for line in message.split("\n")])
                    out_f.write(f"{formatted_message}\n")
                out_f.write("\n")

    return program_handle

def _bug_type_from_query(query):
    if not query:
        return None
    first = re.split(r'\s+(?:AND|OR)\s+', query, maxsplit=1)[0]
    return re.sub(r'[^\w]', '_', first.strip().lower()) or None

def _write_report_to_dir(out_dir, report_id, item, summary_f):
    attr = item.get('attributes', {})
    rels = item.get('relationships', {})

    title = attr.get('title') or "Limited Disclosure"
    title = title.replace("|", "-").replace("\n", " ").strip()
    severity = attr.get('severity_rating') or "None"
    bounty = attr.get('total_awarded_amount')
    bounty_str = f"${bounty}" if bounty else "-"
    reporter = rels.get('reporter', {}).get('data', {}).get('attributes', {}).get('username') or "Unknown"

    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, f"{report_id}.md")
    if os.path.exists(report_path):
        print(f" [=] Skipped (exists): {report_id}.md")
    else:
        write_full_report(report_id, report_path, item)
    summary_f.write(f"| **{report_id}** | {severity} | {title} | {bounty_str} | `@{reporter}` | [Full Report]({report_id}.md) |\n")
    print(f" [+] Extracted: {report_id}.md ({out_dir})")

def run(handle=None, severity_filter=None, extra_query=None, limit=None):
    reports, label = fetch_disclosed_reports_list(handle, severity_filter, extra_query, limit)

    if not reports:
        target = handle or extra_query or "query"
        print(f"No disclosed reports found for '{target}'.")
        return

    bug_type = _bug_type_from_query(extra_query)
    group_by_program = handle is None

    print(f"\nProcessing {len(reports)} reports...")

    if group_by_program:
        # Route each report to Reports/<program_handle>/<bug_type>/
        # summary_rows: { (out_dir, summary_file, program_handle, sub) -> [row_str, ...] }
        summary_rows = {}

        tmp_dir = os.path.join("Reports", "_tmp")
        os.makedirs(tmp_dir, exist_ok=True)

        for item in reports:
            attr = item.get('attributes', {})
            rels  = item.get('relationships', {})
            url   = attr.get('url')
            report_id = url.split('/')[-1] if url and "hackerone.com/reports/" in url else None
            if not report_id:
                continue

            # Peek handle from hacktivity item first (no API call needed)
            program_handle = (item.get("relationships", {})
                                  .get("program", {})
                                  .get("data", {})
                                  .get("attributes", {})
                                  .get("handle")) or "unknown"

            sub      = bug_type or "disclosed"
            out_dir  = os.path.join("Reports", program_handle, sub)
            os.makedirs(out_dir, exist_ok=True)
            final_path = os.path.join(out_dir, f"{report_id}.md")

            # Skip if already exists — avoid redundant API calls and overwrites
            if os.path.exists(final_path):
                print(f" [=] Skipped (exists): {program_handle}/{sub}/{report_id}.md")
            else:
                tmp_path = os.path.join(tmp_dir, f"{report_id}.md")
                write_full_report(report_id, tmp_path, item)
                os.replace(tmp_path, final_path)

            # Build summary row for this report
            title      = (attr.get('title') or "Limited Disclosure").replace("|", "-").replace("\n", " ").strip()
            severity   = (attr.get('severity_rating') or "None").capitalize()
            bounty     = attr.get('total_awarded_amount')
            bounty_str = f"${bounty}" if bounty else "-"
            reporter   = (rels.get('reporter', {}).get('data', {})
                              .get('attributes', {}).get('username') or "Unknown")
            row = f"| **{report_id}** | {severity} | {title} | {bounty_str} | `@{reporter}` | [Full Report]({report_id}.md) |\n"

            key = (out_dir, os.path.join(out_dir, f"{program_handle}_{sub}_Summary.md"), program_handle, sub)
            summary_rows.setdefault(key, []).append(row)

            print(f" [+] {program_handle}/{sub}/{report_id}.md")
            time.sleep(0.5)

        # Clean up tmp dir if empty
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass

        # Write one summary file per program/bug-type directory
        for (out_dir, summary_file, program_handle, sub), rows in summary_rows.items():
            with open(summary_file, 'w', encoding='utf-8') as sf:
                sf.write(f"# Disclosed Reports — {program_handle} / {sub}\n\n")
                sf.write(f"> **Total Reports:** {len(rows)}\n\n")
                sf.write("## Quick Overview\n\n")
                sf.write("| Report ID | Severity | Title | Bounty | Reporter | Link |\n")
                sf.write("| :---: | :---: | :--- | :---: | :---: | :---: |\n")
                for row in rows:
                    sf.write(row)
            print(f" [+] Summary -> {summary_file}")

        print(f"\nSuccess! Reports grouped by program under Reports/<handle>/{bug_type or 'disclosed'}/")
    else:
        # Single program mode — original behaviour but with optional bug_type subfolder
        if bug_type:
            out_dir = os.path.join("Reports", handle, bug_type)
        else:
            out_dir = os.path.join("Reports", handle)
        os.makedirs(out_dir, exist_ok=True)
        summary_file = os.path.join(out_dir, f"{handle}_Summary.md")

        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"# 📊 Disclosed Reports Summary for: {handle}\n\n")
            f.write(f"> **Total Reports Found:** {len(reports)}\n\n")
            f.write("## 📑 Quick Overview\n\n")
            f.write("| Report ID | Severity | Title | Bounty | Reporter | Link |\n")
            f.write("| :---: | :---: | :--- | :---: | :---: | :---: |\n")

            for item in reports:
                attr = item.get('attributes', {})
                url = attr.get('url')
                report_id = url.split('/')[-1] if url and "hackerone.com/reports/" in url else None
                if report_id:
                    _write_report_to_dir(out_dir, report_id, item, f)
                    time.sleep(0.5)
                else:
                    rels = item.get('relationships', {})
                    title = (attr.get('title') or "Limited Disclosure").replace("|", "-").strip()
                    severity = attr.get('severity_rating') or "None"
                    bounty_str = f"${attr.get('total_awarded_amount')}" if attr.get('total_awarded_amount') else "-"
                    reporter = rels.get('reporter', {}).get('data', {}).get('attributes', {}).get('username') or "Unknown"
                    f.write(f"| - | {severity} | {title} | {bounty_str} | `@{reporter}` | - |\n")

        print(f"\nSuccess! Reports saved to '{out_dir}/'")
        print(f"Summary: {summary_file}")