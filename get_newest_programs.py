import json
import sys
import urllib.request
import base64
from datetime import datetime
import os

USERNAME = os.getenv("HACKERONE_USERNAME")
TOKEN = os.getenv("HACKERONE_TOKEN")

if not USERNAME or not TOKEN:
    print("Error: Please set HACKERONE_USERNAME and HACKERONE_TOKEN environment variables.")
    sys.exit(1)

def fetch_programs():
    print("Fetching programs from HackerOne API. This might take a few moments...")
    
    auth_string = f"{USERNAME}:{TOKEN}"
    auth_bytes = auth_string.encode('ascii')
    base64_bytes = base64.b64encode(auth_bytes)
    base64_string = base64_bytes.decode('ascii')
    
    headers = {
        'Authorization': f'Basic {base64_string}',
        'Accept': 'application/json'
    }
    
    programs = []
    url = "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=100"
    page = 1
    
    while url:
        print(f"  -> Fetching page {page}...")
        req = urllib.request.Request(url, headers=headers)
        
        try:
            with urllib.request.urlopen(req) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                
                data = response_data.get('data', [])
                programs.extend(data)
                
                links = response_data.get('links', {})
                url = links.get('next')
                page += 1
                
        except Exception as e:
            print(f"Error fetching data: {e}")
            break
            
    return programs

def process_and_save(programs):
    bbp_programs = []
    for p in programs:
        attrs = p.get('attributes', {})
        if attrs.get('offers_bounties') == True:
            bbp_programs.append(p)
            
    print(f"\nFound {len(bbp_programs)} Bug Bounty Programs out of {len(programs)} total programs.")
    
    def get_start_date(prog):
        date_str = prog.get('attributes', {}).get('started_accepting_at')
        if not date_str:
            return datetime.min
        try:
            if '.' in date_str:
                return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        except:
            return datetime.min
            
    bbp_programs.sort(key=get_start_date, reverse=True)
    
    output_file = "newest_bounty_programs.md"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Newest Bug Bounty Programs on HackerOne\n\n")
        f.write(f"*Total BBP found: {len(bbp_programs)}*\n\n")
        
        for i, p in enumerate(bbp_programs, 1):
            attrs = p.get('attributes', {})
            name = attrs.get('name', 'Unknown')
            handle = attrs.get('handle', 'Unknown')
            date_str = attrs.get('started_accepting_at', 'Unknown')
            url = f"https://hackerone.com/{handle}"
            
            f.write(f"### {i}. [{name}]({url})\n")
            f.write(f"- **Handle:** @{handle}\n")
            f.write(f"- **Started Accepting At:** {date_str}\n")
            f.write(f"- **State:** {attrs.get('state', 'Unknown')}\n")
            f.write("---\n")
            
    print(f"Success! List saved to -> {output_file}")

if __name__ == "__main__":
    all_programs = fetch_programs()
    if all_programs:
        process_and_save(all_programs)
    else:
        print("No programs were retrieved.")
