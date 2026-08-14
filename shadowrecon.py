import socket
import argparse


def resolve_domain(domain):
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

    args = parser.parse_args()
    resolve_domain(args.domain)


if __name__ == "__main__":
    main()