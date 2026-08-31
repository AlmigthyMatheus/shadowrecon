import json
import urllib.request
from core.config import BOLD_RED, GRAY, BOLD_WHITE, RESET


def get_whois_info(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Fetching WHOIS/RDAP Information for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    whois_info = {"registrar": "Unknown", "creation_date": "Unknown", "expiration_date": "Unknown", "status": []}

    try:
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(url, headers={'User-Agent': 'ShadowRecon-Bot/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))

                entities = data.get("entities", [])
                for entity in entities:
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    whois_info["registrar"] = item[3]
                                    break

                events = data.get("events", [])
                for event in events:
                    action = event.get("eventAction")
                    date_val = event.get("eventDate", "Unknown")
                    if action == "registration":
                        whois_info["creation_date"] = date_val
                    elif action == "expiration":
                        whois_info["expiration_date"] = date_val

                whois_info["status"] = data.get("status", [])

                print(f"{GRAY}    └─ Registrar: {BOLD_WHITE}{whois_info['registrar']}{RESET}")
                print(f"{GRAY}    └─ Creation Date: {BOLD_WHITE}{whois_info['creation_date']}{RESET}")
                print(f"{GRAY}    └─ Expiration Date: {BOLD_RED}{whois_info['expiration_date']}{RESET}")
                if whois_info["status"]:
                    print(f"{GRAY}    └─ Status: {BOLD_WHITE}{', '.join(whois_info['status'][:3])}{RESET}")
    except Exception:
        print(f"{GRAY}    └─ [-] Could not retrieve WHOIS/RDAP information.{RESET}")

    return whois_info