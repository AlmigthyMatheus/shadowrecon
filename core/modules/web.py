import urllib.request
import ssl
import re
from core.config import (
    BOLD_RED, GRAY, BOLD_WHITE, RESET,
    SECURITY_HEADERS_MAP, WAF_SIGNATURES, TECH_SIGNATURES
)


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


def check_robots_txt(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Checking robots.txt for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    robots_info = {"status": False, "disallowed_paths": [], "sitemaps": []}

    for protocol in ["https", "http"]:
        url = f"{protocol}://{domain}/robots.txt"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={'User-Agent': 'ShadowRecon-Bot/1.0'})

            with urllib.request.urlopen(req, timeout=3, context=ctx) as response:
                if response.status == 200:
                    content = response.read().decode('utf-8', errors='ignore')
                    robots_info["status"] = True

                    disallowed = re.findall(r'(?i)Disallow:\s*(.*)', content)
                    sitemaps = re.findall(r'(?i)Sitemap:\s*(.*)', content)

                    clean_disallowed = [p.strip() for p in disallowed if p.strip()]
                    clean_sitemaps = [s.strip() for s in sitemaps if s.strip()]

                    robots_info["disallowed_paths"] = clean_disallowed
                    robots_info["sitemaps"] = clean_sitemaps

                    print(f"{GRAY}    └─ Status: {BOLD_RED}200 OK (Found){RESET}")
                    if clean_disallowed:
                        print(f"{GRAY}    └─ Disallowed Entries Found ({len(clean_disallowed)}):{RESET}")
                        for entry in clean_disallowed[:5]:
                            print(f"{GRAY}        [➔] {BOLD_WHITE}{entry}{RESET}")
                        if len(clean_disallowed) > 5:
                            print(f"{GRAY}        [➔] ... and {len(clean_disallowed) - 5} more{RESET}")
                    if clean_sitemaps:
                        print(f"{GRAY}    └─ Sitemaps Found ({len(clean_sitemaps)}):{RESET}")
                        for sm in clean_sitemaps:
                            print(f"{GRAY}        [➔] {BOLD_RED}{sm}{RESET}")
                    break
        except Exception:
            continue

    if not robots_info["status"]:
        print(f"{GRAY}    └─ [-] Could not retrieve or locate robots.txt.{RESET}")

    return robots_info


def audit_security_headers(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Auditing Web Security Headers for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    audit_data = {"present": {}, "missing": {}}

    for protocol in ["https", "http"]:
        url = f"{protocol}://{domain}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={'User-Agent': 'ShadowRecon-Bot/1.0'})

            with urllib.request.urlopen(req, timeout=4, context=ctx) as response:
                resp_headers = {k.title(): v for k, v in response.headers.items()}

                for header, desc in SECURITY_HEADERS_MAP.items():
                    header_title = header.title()
                    if header_title in resp_headers:
                        val = resp_headers[header_title]
                        audit_data["present"][header] = {"value": val, "description": desc}
                        print(
                            f"{GRAY}    └─ {BOLD_WHITE}[✔] {header}{GRAY}: {BOLD_WHITE}{val[:45]}{'...' if len(val) > 45 else ''}{RESET}")
                    else:
                        audit_data["missing"][header] = desc
                        print(f"{GRAY}    └─ {BOLD_RED}[✘] {header}{GRAY} is MISSING ({desc}){RESET}")
                break
        except Exception:
            continue

    if not audit_data["present"] and not audit_data["missing"]:
        print(f"{GRAY}    └─ [-] Could not connect to target to inspect security headers.{RESET}")

    return audit_data


def detect_waf(domain):
    print(
        f"\n{BOLD_RED}[+]{RESET} {GRAY}Detecting Web Application Firewall (WAF) for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    detected_wafs = []

    for protocol in ["https", "http"]:
        url = f"{protocol}://{domain}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={'User-Agent': 'ShadowRecon-Bot/1.0'})

            with urllib.request.urlopen(req, timeout=4, context=ctx) as response:
                raw_headers = [f"{k.lower()}: {v.lower()}" for k, v in response.headers.items()]
                headers_str = " ".join(raw_headers)

                for waf_name, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if sig in headers_str:
                            if waf_name not in detected_wafs:
                                detected_wafs.append(waf_name)
                                print(
                                    f"{GRAY}    └─ {BOLD_RED}[!] Detected WAF/CDN Protection: {BOLD_WHITE}{waf_name}{GRAY} (Signature: {sig}){RESET}")
                break
        except Exception:
            continue

    if not detected_wafs:
        print(f"{GRAY}    └─ [-] No obvious WAF / CDN protection signatures detected.{RESET}")

    return detected_wafs


def check_http_methods(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Auditing Allowed HTTP Methods for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    methods_data = {"allowed": [], "dangerous": []}

    for protocol in ["https", "http"]:
        url = f"{protocol}://{domain}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={'User-Agent': 'ShadowRecon-Bot/1.0'}, method='OPTIONS')

            with urllib.request.urlopen(req, timeout=4, context=ctx) as response:
                allow_header = response.headers.get("Allow") or response.headers.get("Public")
                if allow_header:
                    methods = [m.strip() for m in allow_header.split(",")]
                    methods_data["allowed"] = methods
                    print(f"{GRAY}    └─ Allowed Methods: {BOLD_WHITE}{', '.join(methods)}{RESET}")

                    dangerous = [m for m in methods if m.upper() in ["PUT", "DELETE", "TRACE", "CONNECT"]]
                    if dangerous:
                        methods_data["dangerous"] = dangerous
                        print(
                            f"{GRAY}    └─ {BOLD_RED}[!] Potentially Dangerous Methods Enabled: {', '.join(dangerous)}{RESET}")
                else:
                    print(f"{GRAY}    └─ [-] Server did not return an 'Allow' header on OPTIONS request.{RESET}")
                break
        except Exception:
            continue

    if not methods_data["allowed"]:
        print(f"{GRAY}    └─ [-] Could not determine allowed HTTP methods.{RESET}")

    return methods_data


def detect_tech(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Detecting CMS & Web Technologies for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    detected_tech = []

    for protocol in ["https", "http"]:
        url = f"{protocol}://{domain}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={'User-Agent': 'ShadowRecon-Bot/1.0'})

            with urllib.request.urlopen(req, timeout=4, context=ctx) as response:
                content = response.read().decode('utf-8', errors='ignore')
                headers_str = " ".join([f"{k}: {v}" for k, v in response.headers.items()])
                full_raw = content + " " + headers_str

                for tech_name, patterns in TECH_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, full_raw, re.IGNORECASE):
                            if tech_name not in detected_tech:
                                detected_tech.append(tech_name)
                                print(f"{GRAY}    └─ {BOLD_RED}[!] Detected Technology: {BOLD_WHITE}{tech_name}{RESET}")
                break
        except Exception:
            continue

    if not detected_tech:
        print(f"{GRAY}    └─ [-] No obvious CMS or framework signatures detected.{RESET}")

    return detected_tech


def check_cors(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Auditing CORS Configuration for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    cors_data = {"allow_origin": None, "allow_credentials": False, "vulnerable": False}

    for protocol in ["https", "http"]:
        url = f"{protocol}://{domain}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            test_origin = "https://evil-shadowrecon.com"
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'ShadowRecon-Bot/1.0',
                    'Origin': test_origin
                }
            )

            with urllib.request.urlopen(req, timeout=4, context=ctx) as response:
                allow_origin = response.headers.get("Access-Control-Allow-Origin")
                allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

                if allow_origin:
                    cors_data["allow_origin"] = allow_origin
                    cors_data["allow_credentials"] = allow_credentials

                    if allow_origin in [test_origin, "*"]:
                        cors_data["vulnerable"] = True
                        print(f"{GRAY}    └─ {BOLD_RED}[!] Misconfiguration Detected!{RESET}")
                        print(f"{GRAY}        [➔] Access-Control-Allow-Origin: {BOLD_WHITE}{allow_origin}{RESET}")
                        print(
                            f"{GRAY}        [➔] Access-Control-Allow-Credentials: {BOLD_WHITE}{allow_credentials}{RESET}")
                    else:
                        print(f"{GRAY}    └─ Access-Control-Allow-Origin: {BOLD_WHITE}{allow_origin}{RESET}")
                else:
                    print(f"{GRAY}    └─ [-] No CORS headers returned for arbitrary origin.{RESET}")
                break
        except Exception:
            continue

    return cors_data


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_redirect_chain(domain):
    print(f"\n{BOLD_RED}[+]{RESET} {GRAY}Tracking HTTP Redirect Chain for {BOLD_WHITE}{domain}{GRAY}...{RESET}")
    chain = []
    current_url = f"http://{domain}"
    max_redirects = 5

    for _ in range(max_redirects):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            opener = urllib.request.build_opener(NoRedirectHandler(), urllib.request.HTTPSHandler(context=ctx))
            req = urllib.request.Request(current_url, headers={'User-Agent': 'ShadowRecon-Bot/1.0'})

            try:
                response = opener.open(req, timeout=4)
                status = response.status
                chain.append({"url": current_url, "status": status})
                print(f"{GRAY}    └─ [{status}] {BOLD_WHITE}{current_url}{RESET} {GRAY}(Final Destination){RESET}")
                break
            except urllib.error.HTTPError as e:
                if e.code in [301, 302, 303, 307, 308]:
                    location = e.headers.get('Location')
                    chain.append({"url": current_url, "status": e.code, "redirect_to": location})
                    print(
                        f"{GRAY}    └─ [{BOLD_RED}{e.code}{GRAY}] {BOLD_WHITE}{current_url}{GRAY} ➔ {BOLD_WHITE}{location}{RESET}")
                    if not location:
                        break
                    if location.startswith('/'):
                        proto = current_url.split("://")[0]
                        host = current_url.split("://")[1].split("/")[0]
                        current_url = f"{proto}://{host}{location}"
                    else:
                        current_url = location
                else:
                    chain.append({"url": current_url, "status": e.code})
                    print(f"{GRAY}    └─ [{e.code}] {BOLD_WHITE}{current_url}{RESET}")
                    break
        except Exception:
            break

    if not chain:
        print(f"{GRAY}    └─ [-] Could not track HTTP redirect chain.{RESET}")

    return chain