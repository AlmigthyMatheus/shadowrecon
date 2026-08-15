import socket
import argparse


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-ALT"
}


def check_ports(ip):
    open_ports = []
    print(f"    └─ Scanning common ports on {ip}...")

    for port, service in COMMON_PORTS.items():

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)

        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"        [!] Port {port} ({service}): OPEN")
            open_ports.append(port)
        s.close()

    if not open_ports:
        print(f"        [-] No common ports open on {ip}.")


def resolve_domain(domain, scan_ports=False):
    try:
        hostname, aliases, ips = socket.gethostbyname_ex(domain)

        print(f"[+] Target Domain: {domain}")
        print(f"[+] Official Hostname: {hostname}")

        if aliases:
            print(f"[+] Aliases: {', '.join(aliases)}")

        print(f"[+] IP Addresses Found ({len(ips)}):")
        for ip in ips:
            try:
                reverse_host, _, _ = socket.gethostbyaddr(ip)
                print(f"    └─ {ip} ➔ Reverse DNS: {reverse_host}")
            except socket.herror:
                print(f"    └─ {ip} ➔ Reverse DNS: [No PTR record]")

            if scan_ports:
                check_ports(ip)

    except socket.gaierror:
        print(f"[-] Error: Could not resolve domain '{domain}'.")


def main():
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