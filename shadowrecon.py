import socket
import argparse
import json

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


def resolve_domain(domain, scan_ports=False, scan_subdomains=False, output_file=None):
    scan_data = {
        "target_domain": domain,
        "official_hostname": None,
        "aliases": [],
        "ip_addresses": [],
        "subdomains": []
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
            ip_info = {"ip": ip, "reverse_dns": None, "open_ports": []}
            try:
                reverse_host, _, _ = socket.gethostbyaddr(ip)
                ip_info["reverse_dns"] = reverse_host
                print(f"{GRAY}    └─ {BOLD_WHITE}{ip}{GRAY} ➔ Reverse DNS: {BOLD_RED}{reverse_host}{RESET}")
            except socket.herror:
                print(f"{GRAY}    └─ {BOLD_WHITE}{ip}{GRAY} ➔ Reverse DNS: {RED}[No PTR record]{RESET}")

            if scan_ports:
                ip_info["open_ports"] = check_ports(ip)

            scan_data["ip_addresses"].append(ip_info)

        if scan_subdomains:
            scan_data["subdomains"] = enumerate_subdomains(domain)

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
        "-o", "--output",
        help="Output file path to save results in JSON format (e.g., report.json)"
    )

    args = parser.parse_args()
    resolve_domain(
        args.domain,
        scan_ports=args.scan_ports,
        scan_subdomains=args.subdomains,
        output_file=args.output
    )


if __name__ == "__main__":
    main()