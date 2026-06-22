import json
import urllib.request
import urllib.parse
import base64
import os
import sys

try:
    from extract_report import extract_report
except ImportError:
    print("Error: Could not import extract_report.py. Make sure it is in the same directory.")
    sys.exit(1)

USERNAME = os.getenv("HACKERONE_USERNAME")
TOKEN = os.getenv("HACKERONE_TOKEN")

if not USERNAME or not TOKEN:
    print("Error: Please set HACKERONE_USERNAME and HACKERONE_TOKEN environment variables.")
    sys.exit(1)

def fetch_hacktivity_ids(handle):
    print(f"Fetching disclosed hacktivity IDs for program '{handle}'...")
    
    auth_string = f"{USERNAME}:{TOKEN}"
    auth_bytes = auth_string.encode('ascii')
    base64_bytes = base64.b64encode(auth_bytes)
    base64_string = base64_bytes.decode('ascii')
    
    headers = {
        'Authorization': f'Basic {base64_string}',
        'Accept': 'application/json'
    }
    
    query = f"program:{handle} disclosed:true"
    encoded_query = urllib.parse.quote(query)
    
    url = f"https://api.hackerone.com/v1/hackers/hacktivity?queryString={encoded_query}&page%5Bsize%5D=100"
    
    report_ids = []
    page = 1
    
    while url and page <= 5:
        print(f"  -> Fetching page {page}...")
        req = urllib.request.Request(url, headers=headers)
        
        try:
            with urllib.request.urlopen(req) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                
                data = response_data.get('data', [])
                for item in data:
                    attrs = item.get("attributes", {})
                    if attrs.get("disclosed") == True:
                        report_ids.append(item.get("id"))
                
                links = response_data.get('links', {})
                url = links.get('next')
                page += 1
                
        except Exception as e:
            print(f"Error fetching hacktivity: {e}")
            break
            
    report_ids = list(set(report_ids))
    print(f"Found {len(report_ids)} disclosed reports for '{handle}'.\n")
    return report_ids, headers

def fetch_and_parse_reports(report_ids, headers, handle):
    output_dir = f"reports_{handle}"
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"Downloading and parsing reports into folder '{output_dir}'...")
    
    for rid in report_ids:
        url = f"https://api.hackerone.com/v1/hackers/reports/{rid}"
        req = urllib.request.Request(url, headers=headers)
        
        json_file_path = os.path.join(output_dir, f"report_{rid}.json")
        
        try:
            with urllib.request.urlopen(req) as response:
                report_data = response.read().decode('utf-8')
                with open(json_file_path, 'w', encoding='utf-8') as f:
                    f.write(report_data)
                    
            original_cwd = os.getcwd()
            os.chdir(output_dir)
            try:
                extract_report(f"report_{rid}.json")
            except Exception as e:
                print(f"Error extracting {rid}: {e}")
            finally:
                os.chdir(original_cwd)
                
        except Exception as e:
            print(f"Failed to fetch report {rid}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python get_disclosed_reports.py <program_handle>")
        print("Example: python get_disclosed_reports.py shopify")
        sys.exit(1)

    target_handle = sys.argv[1]
    ids, auth_headers = fetch_hacktivity_ids(target_handle)
    
    if ids:
        fetch_and_parse_reports(ids, auth_headers, target_handle)
        print("\nAll done!")
    else:
        print("No disclosed reports found or error occurred.")
