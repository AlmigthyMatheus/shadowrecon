import json
import urllib.request
from core.config import BOLD_RED, GRAY, BOLD_WHITE, RESET


def get_dns_records(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Fetching DNS Records (MX, TXT, NS) for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    records_info = {"MX": [], "TXT": [], "NS": []}

    for r_type in ["MX", "TXT", "NS"]:
        try:
            url = f"https://dns.google/resolve?name={domain}&type={r_type}"
            req = urllib.request.Request(url, headers={'User-Agent': 'ShadowRecon-Bot/1.0'})
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode('utf-8'))
                answers = data.get("Answer", [])
                if answers:
                    print(f"{GRAY}    └─ Type {BOLD_WHITE}{r_type}{GRAY}:{RESET}")
                    for ans in answers:
                        val = ans.get("data", "").strip('"')
                        records_info[r_type].append(val)
                        print(f"{GRAY}        [➔] {BOLD_RED}{val}{RESET}")
        except Exception:
            pass

    if not any(records_info.values()):
        print(f"{GRAY}    └─ [-] Could not retrieve DNS records.{RESET}")

    return records_info