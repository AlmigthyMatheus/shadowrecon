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

SECURITY_HEADERS_MAP = {
    "Strict-Transport-Security": "HSTS (Enforces HTTPS connections)",
    "Content-Security-Policy": "CSP (Mitigates XSS and data injection)",
    "X-Frame-Options": "Clickjacking Protection",
    "X-Content-Type-Options": "MIME Sniffing Prevention",
    "Referrer-Policy": "Controls Referrer Information Leakage",
    "Permissions-Policy": "Controls Browser Feature Access"
}

WAF_SIGNATURES = {
    "Cloudflare": ["server: cloudflare", "cf-ray", "__cfduid", "cf_clearance"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-id-2", "awsalb", "awsalbcors"],
    "Akamai": ["x-akamai-transformed", "akamai-origin-hop", "server: akamaighost"],
    "Imperva / Incapsula": ["x-cdn: incapsula", "incap_ses", "visid_incap"],
    "Sucuri": ["x-sucuri-id", "server: sucuri"],
    "ModSecurity": ["server: mod_security", "server: modsecurity"]
}

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"name=[\"']generator[\"']\s+content=[\"']WordPress"],
    "Joomla": [r"name=[\"']generator[\"']\s+content=[\"']Joomla", r"/media/system/js/"],
    "Drupal": [r"name=[\"']generator[\"']\s+content=[\"']Drupal", r"Drupal\.settings"],
    "Next.js": [r"_next/static", r"__NEXT_DATA__"],
    "React": [r"data-reactroot", r"react-dom"],
    "Vue.js": [r"data-v-", r"vue\.js", r"v-app"],
    "Laravel": [r"laravel_session", r"X-SRF-TOKEN"],
    "Django": [r"csrftoken", r"django"]
}