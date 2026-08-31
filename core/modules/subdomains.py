import socket
import os
from concurrent.futures import ThreadPoolExecutor
from core.config import BOLD_RED, GRAY, BOLD_WHITE, RESET, COMMON_SUBDOMAINS


def check_single_subdomain(target_data):
    sub, domain = target_data
    target_subdomain = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(target_subdomain)
        print(f"{GRAY}    └─ {BOLD_WHITE}{target_subdomain}{GRAY} ➔ Resolved IP: {BOLD_RED}{ip}{RESET}")
        return {"subdomain": target_subdomain, "ip": ip}
    except socket.gaierror:
        return None


def enumerate_subdomains(domain, wordlist_file=None, max_threads=5):
    sublist = COMMON_SUBDOMAINS
    if wordlist_file and os.path.exists(wordlist_file):
        try:
            with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
                loaded = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                if loaded:
                    sublist = loaded
                    print(
                        f"\n{BOLD_RED}[+]{RESET} {GRAY}Loaded {len(sublist)} entries from custom wordlist: {BOLD_WHITE}{wordlist_file}{RESET}")
        except Exception as e:
            print(
                f"\n{BOLD_RED}[-]{RESET} {GRAY}Failed to read wordlist file: {e}. Falling back to default list.{RESET}")

    print(
        f"\n{BOLD_RED}[+]{RESET} {GRAY}Starting Subdomain Enumeration on {BOLD_WHITE}{domain}{GRAY} (Entries: {len(sublist)}, Threads: {max_threads})...{RESET}")
    found_subdomains = []
    tasks = [(sub, domain) for sub in sublist]

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = executor.map(check_single_subdomain, tasks)
        for res in results:
            if res:
                found_subdomains.append(res)

    if not found_subdomains:
        print(f"{GRAY}    └─ [-] No active subdomains found.{RESET}")
    return found_subdomains