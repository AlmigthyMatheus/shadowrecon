import socket
import argparse
import json
import urllib.request
import ssl

BOLD_RED = "\033[1;91m"
RED = "\033[91m"
GRAY = "\033[90m"
BOLD_WHITE = "\033[1;97m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = fr"""{BOLD_RED}
   _____ __            __             ____                   
  / ___// /_  ____ _/ /_  ____  _  / __ \___  _________  ____ 
  \__ \/ __ \/ __ `/ __ \/ __ \| |/ /_/ / _ \/ ___/ __ \/ __ \
 ___/ / / / / /_/ / /_/ / /_/ /|  / _, _/  __/ /__/ /_/ / / / /
/____/_/ /_/\__,_/_.___/\____/ |_/_/ |_|\___/\___/\____/_/ /_/ 

            {BOLD_RED}[ {BOLD_WHITE}ShadowRecon v1.0{BOLD_RED} - Cyber Reconnaissance Tool ]{RESET}
{GRAY}======================================================================={RESET}
"""

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-ALT"
}

COMMON_SUBDOMAINS = [
    "www", "mail", "dev", "api", "admin", "test",
    "vpn", "blog", "portal", "stage", "app", "db"
]


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


def get_ssl_info(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Inspecting SSL/TLS Certificate for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    ssl_info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('organizationName', 'Unknown')
                not_after = cert.get('notAfter', 'Unknown')
                sans = [item[1] for item in cert.get('subjectAltName', []) if item[0] == 'DNS']
                print(f"{GRAY}    └─ Issuer: {BOLD_WHITE}{issuer_name}{RESET}")
                print(f"{GRAY}    └─ Expiration Date: {BOLD_RED}{not_after}{RESET}")
                if sans:
                    displayed_sans = ', '.join(sans[:5])
                    more_tag = f" (+{len(sans) - 5} more)" if len(sans) > 5 else ""
                    print(f"{GRAY}    └─ Alternative Names (SANs): {BOLD_WHITE}{displayed_sans}{more_tag}{RESET}")
                ssl_info = {
                    "issuer": issuer_name,
                    "expiration_date": not_after,
                    "subject_alt_names": sans
                }
    except Exception as e:
        print(f"{GRAY}    └─ [-] Could not retrieve SSL certificate: {e}{RESET}")
    return ssl_info


def get_http_headers(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Fetching HTTP/HTTPS Headers for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    headers_info = {}
    for protocol in ["https", "http"]:
        url = f"{protocol}://{domain}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={'User-Agent': 'ShadowRecon-Bot/1.0'})
            with urllib.request.urlopen(req, timeout=3, context=ctx) as response:
                status = response.status
                server = response.headers.get('Server', 'Unknown')
                powered_by = response.headers.get('X-Powered-By', 'Not specified')
                print(f"{GRAY}    └─ Protocol: {BOLD_WHITE}{protocol.upper()}{RESET}")
                print(f"{GRAY}    └─ Status Code: {BOLD_RED}{status}{RESET}")
                print(f"{GRAY}    └─ Server Header: {BOLD_WHITE}{server}{RESET}")
                if powered_by != 'Not specified':
                    print(f"{GRAY}    └─ X-Powered-By: {BOLD_WHITE}{powered_by}{RESET}")
                headers_info = {
                    "protocol": protocol,
                    "status_code": status,
                    "server": server,
                    "x_powered_by": powered_by,
                    "headers": dict(response.headers)
                }
                break
        except Exception:
            continue
    if not headers_info:
        print(f"{GRAY}    └─ [-] Could not retrieve HTTP/HTTPS headers.{RESET}")
    return headers_info


def enumerate_subdomains(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Starting Subdomain Enumeration on {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    found_subdomains = []
    for sub in COMMON_SUBDOMAINS:
        target_subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(target_subdomain)
            print(f"{GRAY}    └─ {BOLD_WHITE}{target_subdomain}{GRAY} ➔ Resolved IP: {BOLD_RED}{ip}{RESET}")
            found_subdomains.append({"subdomain": target_subdomain, "ip": ip})
        except socket.gaierror:
            pass
    if not found_subdomains:
        print(f"{GRAY}    └─ [-] No active subdomains found from default wordlist.{RESET}")
    return found_subdomains


def check_ports(ip):
    open_ports = []
    print(f"{GRAY}    └─ Scanning common ports on {BOLD_WHITE}{ip}{GRAY}...{RESET}")
    for port, service in COMMON_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"        {BOLD_RED}[!] Port {port} ({service}): OPEN{RESET}")
            open_ports.append({"port": port, "service": service})
        s.close()
    if not open_ports:
        print(f"        {GRAY}[-] No common ports open on {ip}.{RESET}")
    return open_ports


def resolve_domain(domain, scan_ports=False, scan_subdomains=False, fetch_headers=False, inspect_ssl=False,
                   fetch_geo=False, fetch_dns=False, output_file=None):
    scan_data = {
        "target_domain": domain,
        "official_hostname": None,
        "aliases": [],
        "ip_addresses": [],
        "subdomains": [],
        "http_headers": {},
        "ssl_info": {},
        "dns_records": {}
    }

    try:
        hostname, aliases, ips = socket.gethostbyname_ex(domain)
        scan_data["official_hostname"] = hostname
        scan_data["aliases"] = aliases

        print(f"{BOLD_RED}[+]{RESET} {GRAY}Target Domain:{RESET} {BOLD_WHITE}{domain}{RESET}")
        print(f"{BOLD_RED}[+]{RESET} {GRAY}Official Hostname:{RESET} {BOLD_WHITE}{hostname}{RESET}")

        if aliases:
            print(f"{BOLD_RED}[+]{RESET} {GRAY}Aliases:{RESET} {BOLD_WHITE}{', '.join(aliases)}{RESET}")

        print(f"{BOLD_RED}[+]{RESET} {GRAY}IP Addresses Found ({len(ips)}):{RESET}")
        for ip in ips:
            ip_info = {"ip": ip, "reverse_dns": None, "open_ports": [], "geolocation": {}}
            try:
                reverse_host, _, _ = socket.gethostbyaddr(ip)
                ip_info["reverse_dns"] = reverse_host
                print(f"{GRAY}    └─ {BOLD_WHITE}{ip}{GRAY} ➔ Reverse DNS: {BOLD_RED}{reverse_host}{RESET}")
            except socket.herror:
                print(f"{GRAY}    └─ {BOLD_WHITE}{ip}{GRAY} ➔ Reverse DNS: {RED}[No PTR record]{RESET}")

            if fetch_geo:
                ip_info["geolocation"] = get_ip_geo(ip)

            if scan_ports:
                ip_info["open_ports"] = check_ports(ip)

            scan_data["ip_addresses"].append(ip_info)

        if scan_dns:
            scan_data["dns_records"] = get_dns_records(domain)

        if scan_subdomains:
            scan_data["subdomains"] = enumerate_subdomains(domain)

        if fetch_headers:
            scan_data["http_headers"] = get_http_headers(domain)

        if inspect_ssl:
            scan_data["ssl_info"] = get_ssl_info(domain)

        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(scan_data, f, indent=4)
                print(
                    f"\n{BOLD_RED}[+]{RESET} {GRAY}Results successfully exported to:{RESET} {BOLD_WHITE}{output_file}{RESET}")
            except Exception as e:
                print(f"\n{BOLD_RED}[-]{RESET} {GRAY}Failed to write output file: {e}{RESET}")

    except socket.gaierror:
        print(f"{BOLD_RED}[-] Error: Could not resolve domain '{domain}'.{RESET}")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="ShadowRecon - Network & Domain Reconnaissance Tool"
    )

    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain to resolve (e.g., example.com)"
    )

    parser.add_argument(
        "-sp", "--scan-ports",
        action="store_true",
        help="Perform a quick TCP scan on common ports (21, 22, 80, 443, 8080)"
    )

    parser.add_argument(
        "-sub", "--subdomains",
        action="store_true",
        help="Perform wordlist-based subdomain enumeration"
    )

    parser.add_argument(
        "-hb", "--headers",
        action="store_true",
        help="Fetch HTTP/HTTPS web server headers and fingerprint technology"
    )

    parser.add_argument(
        "-ssl", "--ssl-info",
        action="store_true",
        help="Inspect SSL/TLS certificate, expiration date, and SANs"
    )

    parser.add_argument(
        "-geo", "--geolocation",
        action="store_true",
        help="Fetch IP Geolocation, ISP, and ASN information"
    )

    parser.add_argument(
        "-dns", "--dns-records",
        action="store_true",
        help="Fetch MX, TXT, and NS DNS records"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file path to save results in JSON format (e.g., report.json)"
    )

    args = parser.parse_args()
    resolve_domain(
        args.domain,
        scan_ports=args.scan_ports,
        scan_subdomains=args.subdomains,
        fetch_headers=args.headers,
        inspect_ssl=args.ssl_info,
        fetch_geo=args.geolocation,
        fetch_dns=args.dns_records,
        output_file=args.output
    )


if __name__ == "__main__":
    main()