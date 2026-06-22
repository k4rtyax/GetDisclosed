import json
import sys
import os
import urllib.request
from datetime import datetime

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

def fetch_public_info(report_id):
    try:
        url = f"https://hackerone.com/reports/{report_id}.json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception:
        return None

def extract_report(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        if "data" in data and isinstance(data["data"], dict) and "attributes" in data["data"]:
            report_data = data["data"]
        else:
            report_data = data
            
        attributes = report_data.get("attributes") or {}
        relationships = report_data.get("relationships") or {}
        
        report_id = report_data.get("id", "Unknown")
        title = attributes.get("title", "No Title")
        
        scope = "None"
        structured_scope = relationships.get("structured_scope") or {}
        scope_data = structured_scope.get("data")
        if scope_data and isinstance(scope_data, dict):
            scope_attrs = scope_data.get("attributes") or {}
            scope = scope_attrs.get("asset_identifier", "None")

        weakness = "None"
        weakness_rel = relationships.get("weakness") or {}
        weakness_data = weakness_rel.get("data")
        if weakness_data and isinstance(weakness_data, dict):
            weakness_attrs = weakness_data.get("attributes") or {}
            weakness = weakness_attrs.get("name", "None")

        severity_rating = "None"
        severity_rel = relationships.get("severity") or {}
        severity_data = severity_rel.get("data")
        if severity_data and isinstance(severity_data, dict):
            sev_attrs = severity_data.get("attributes") or {}
            rating = sev_attrs.get("rating")
            if rating:
                severity_rating = str(rating).capitalize()
            score = sev_attrs.get("score")
            if score:
                if severity_rating != "None":
                    severity_rating = f"{severity_rating} ({score})"
                else:
                    severity_rating = f"({score})"

        url = attributes.get("url")
        if url:
            link = url
        else:
            link = f"https://hackerone.com/reports/{report_id}"

        date_raw = attributes.get("submitted_at") or attributes.get("created_at") or attributes.get("disclosed_at")
        date_formatted = format_date(date_raw)

        reporter = "Unknown"
        reporter_rel = relationships.get("reporter") or {}
        reporter_data = reporter_rel.get("data")
        if reporter_data and isinstance(reporter_data, dict):
            reporter_attrs = reporter_data.get("attributes") or {}
            reporter = reporter_attrs.get("username", "Unknown")

        cves = attributes.get("cve_ids") or []
        cves_str = ", ".join(cves) if isinstance(cves, list) else str(cves)

        vuln_info = attributes.get("vulnerability_information")
        
        if not vuln_info and report_id != "Unknown":
            public_data = fetch_public_info(report_id)
            if public_data:
                vuln_info = public_data.get("vulnerability_information")

        if not vuln_info:
            vuln_info = "No Information Provided / Limited Disclosure"

        output_file = f"parsed_report_{report_id}.md"
        
        with open(output_file, 'w', encoding='utf-8') as out_f:
            out_f.write(f"Title:         {title}\n")
            out_f.write(f"Scope:         {scope}\n")
            out_f.write(f"Weakness:      {weakness}\n")
            out_f.write(f"Severity:      {severity_rating}\n")
            out_f.write(f"Link:          {link}\n")
            out_f.write(f"Date:          {date_formatted}\n")
            out_f.write(f"By:            @{reporter}\n")
            out_f.write(f"CVE IDs:       {cves_str}\n")
            out_f.write("Details:\n")
            out_f.write(f"{vuln_info}\n\n")

            activities_rel = relationships.get("activities") or {}
            activities = activities_rel.get("data") or []
            if isinstance(activities, list) and len(activities) > 0:
                out_f.write("Timeline:\n")
                for act in activities:
                    act_attrs = act.get("attributes") or {}
                    act_date = format_date(act_attrs.get("created_at") or act_attrs.get("updated_at"))
                    
                    act_type = act.get("type", "").replace("activity-", "").replace("-", " ")
                    
                    actor = "Unknown"
                    actor_rel = act.get("relationships", {}).get("actor") or {}
                    actor_data = actor_rel.get("data")
                    if actor_data and isinstance(actor_data, dict):
                        actor_attrs = actor_data.get("attributes") or {}
                        actor = actor_attrs.get("username", "Unknown")
                        
                    message = act_attrs.get("message", "")
                    
                    if not act_date:
                        continue
                        
                    out_f.write(f"{act_date}: @{actor} ({act_type})\n")
                    if message:
                        out_f.write(f"{message}\n")
                    out_f.write("---\n")

        print(f"Success! Report saved to -> {output_file}")
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error parsing report '{file_path}': {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_report.py <path_to_report.json>")
        sys.exit(1)

    target_file = sys.argv[1]
    if os.path.exists(target_file):
        extract_report(target_file)
    else:
        print(f"File not found: {target_file}")
