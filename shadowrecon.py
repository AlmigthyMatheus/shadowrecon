import socket
import argparse
import json

from core.config import BANNER, BOLD_RED, RED, GRAY, BOLD_WHITE, RESET
from core.modules.network import check_ports
from core.modules.subdomains import enumerate_subdomains
from core.modules.dns_info import get_dns_records
from core.modules.ssl_info import get_ssl_info
from core.modules.geo import get_ip_geo
from core.modules.whois_info import get_whois_info
from core.modules.web import (
    get_http_headers, check_robots_txt, audit_security_headers,
    detect_waf, check_http_methods, detect_tech, check_cors
)


def resolve_domain(domain, scan_ports=False, scan_subdomains=False, wordlist_file=None, fetch_headers=False,
                   inspect_ssl=False, fetch_geo=False, fetch_dns=False, fetch_robots=False, fetch_whois=False,
                   fetch_sec=False, detect_waf_flag=False, fetch_methods=False, detect_tech_flag=False,
                   check_cors_flag=False, threads=5, output_file=None):
    scan_data = {
        "target_domain": domain,
        "official_hostname": None,
        "aliases": [],
        "ip_addresses": [],
        "subdomains": [],
        "http_headers": {},
        "ssl_info": {},
        "dns_records": {},
        "robots_txt": {},
        "whois_info": {},
        "security_headers": {},
        "waf_protection": [],
        "http_methods": {},
        "detected_technologies": [],
        "cors_policy": {}
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
                ip_info["open_ports"] = check_ports(ip, max_threads=threads)

            scan_data["ip_addresses"].append(ip_info)

        if detect_waf_flag:
            scan_data["waf_protection"] = detect_waf(domain)

        if detect_tech_flag:
            scan_data["detected_technologies"] = detect_tech(domain)

        if check_cors_flag:
            scan_data["cors_policy"] = check_cors(domain)

        if fetch_methods:
            scan_data["http_methods"] = check_http_methods(domain)

        if fetch_whois:
            scan_data["whois_info"] = get_whois_info(domain)

        if fetch_dns:
            scan_data["dns_records"] = get_dns_records(domain)

        if scan_subdomains:
            scan_data["subdomains"] = enumerate_subdomains(domain, wordlist_file=wordlist_file, max_threads=threads)

        if fetch_headers:
            scan_data["http_headers"] = get_http_headers(domain)

        if fetch_sec:
            scan_data["security_headers"] = audit_security_headers(domain)

        if inspect_ssl:
            scan_data["ssl_info"] = get_ssl_info(domain)

        if fetch_robots:
            scan_data["robots_txt"] = check_robots_txt(domain)

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
        help="Perform subdomain enumeration"
    )

    parser.add_argument(
        "-wl", "--wordlist",
        help="Path to custom wordlist text file for subdomain enumeration"
    )

    parser.add_argument(
        "-hb", "--headers",
        action="store_true",
        help="Fetch HTTP/HTTPS web server headers and fingerprint technology"
    )

    parser.add_argument(
        "-sec", "--security-headers",
        action="store_true",
        help="Audit presence and absence of key web security headers (HSTS, CSP, etc.)"
    )

    parser.add_argument(
        "-waf", "--waf-detect",
        action="store_true",
        help="Detect presence of WAF / CDN security protections"
    )

    parser.add_argument(
        "-tech", "--tech-detect",
        action="store_true",
        help="Detect CMS, web frameworks, and frontend libraries"
    )

    parser.add_argument(
        "-cors", "--cors-check",
        action="store_true",
        help="Audit CORS policy for arbitrary origin reflection and credentials allowance"
    )

    parser.add_argument(
        "-m", "--http-methods",
        action="store_true",
        help="Audit allowed HTTP methods (GET, POST, OPTIONS, PUT, DELETE, TRACE)"
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
        "-r", "--robots",
        action="store_true",
        help="Check and extract disallowed paths from robots.txt"
    )

    parser.add_argument(
        "-w", "--whois",
        action="store_true",
        help="Fetch WHOIS domain registration data via RDAP protocol"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=5,
        help="Number of concurrent threads for port scan and subdomain check (Default: 5)"
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
        wordlist_file=args.wordlist,
        fetch_headers=args.headers,
        inspect_ssl=args.ssl_info,
        fetch_geo=args.geolocation,
        fetch_dns=args.dns_records,
        fetch_robots=args.robots,
        fetch_whois=args.whois,
        fetch_sec=args.security_headers,
        detect_waf_flag=args.waf_detect,
        fetch_methods=args.http_methods,
        detect_tech_flag=args.tech_detect,
        check_cors_flag=args.cors_check,
        threads=args.threads,
        output_file=args.output
    )


if __name__ == "__main__":
    main()