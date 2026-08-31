import json
import urllib.request
from core.config import BOLD_RED, GRAY, BOLD_WHITE, RESET

def get_ip_geo(ip):
    print(f"{GRAY}    └─ Fetching Geolocation & ASN for {BOLD_WHITE}{ip}{GRAY}...{RESET}")
    geo_info = {}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,as"
        req = urllib.request.Request(url, headers={'User-Agent': 'ShadowRecon-Bot/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("status") == "success":
                country = data.get("country", "Unknown")
                city = data.get("city", "Unknown")
                isp = data.get("isp", "Unknown")
                asn = data.get("as", "Unknown")
                print(f"{GRAY}        [➔] Location: {BOLD_WHITE}{city}, {country}{RESET}")
                print(f"{GRAY}        [➔] ISP / Org: {BOLD_WHITE}{isp}{RESET}")
                print(f"{GRAY}        [➔] ASN: {BOLD_RED}{asn}{RESET}")
                geo_info = {"country": country, "city": city, "isp": isp, "asn": asn}
    except Exception:
        print(f"{GRAY}        [-] Could not retrieve geolocation info.{RESET}")
    return geo_info