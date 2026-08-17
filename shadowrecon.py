import socket
import argparse

# ANSI Color Codes for Intense Red Theme
BOLD_RED = "\033[1;91m"  # Strong/Intense Bright Red
RED = "\033[91m"  # Bright Red
GRAY = "\033[90m"  # Dimmed Grey
BOLD_WHITE = "\033[1;97m"  # High-contrast White
BOLD = "\033[1m"
RESET = "\033[0m"

# Modern Slant ASCII Art Banner in Intense Red
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


def check_ports(ip):
    open_ports = []
    print(f"{GRAY}    └─ Scanning common ports on {BOLD_WHITE}{ip}{GRAY}...{RESET}")

    for port, service in COMMON_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)

        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"        {BOLD_RED}[!] Port {port} ({service}): OPEN{RESET}")
            open_ports.append(port)
        s.close()

    if not open_ports:
        print(f"        {GRAY}[-] No common ports open on {ip}.{RESET}")


def resolve_domain(domain, scan_ports=False):
    try:
        hostname, aliases, ips = socket.gethostbyname_ex(domain)

        print(f"{BOLD_RED}[+]{RESET} {GRAY}Target Domain:{RESET} {BOLD_WHITE}{domain}{RESET}")
        print(f"{BOLD_RED}[+]{RESET} {GRAY}Official Hostname:{RESET} {BOLD_WHITE}{hostname}{RESET}")

        if aliases:
            print(f"{BOLD_RED}[+]{RESET} {GRAY}Aliases:{RESET} {BOLD_WHITE}{', '.join(aliases)}{RESET}")

        print(f"{BOLD_RED}[+]{RESET} {GRAY}IP Addresses Found ({len(ips)}):{RESET}")
        for ip in ips:
            try:
                reverse_host, _, _ = socket.gethostbyaddr(ip)
                print(f"{GRAY}    └─ {BOLD_WHITE}{ip}{GRAY} ➔ Reverse DNS: {BOLD_RED}{reverse_host}{RESET}")
            except socket.herror:
                print(f"{GRAY}    └─ {BOLD_WHITE}{ip}{GRAY} ➔ Reverse DNS: {RED}[No PTR record]{RESET}")

            if scan_ports:
                check_ports(ip)

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

    args = parser.parse_args()
    resolve_domain(args.domain, scan_ports=args.scan_ports)


if __name__ == "__main__":
    main()