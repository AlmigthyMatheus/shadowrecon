import socket
import ssl
from core.config import BOLD_RED, GRAY, BOLD_WHITE, RESET

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
                    more_tag = f" (+{len(sans)-5} more)" if len(sans) > 5 else ""
                    print(f"{GRAY}    └─ Alternative Names (SANs): {BOLD_WHITE}{displayed_sans}{more_tag}{RESET}")
                ssl_info = {
                    "issuer": issuer_name,
                    "expiration_date": not_after,
                    "subject_alt_names": sans
                }
    except Exception as e:
        print(f"{GRAY}    └─ [-] Could not retrieve SSL certificate: {e}{RESET}")
    return ssl_info