import socket
from concurrent.futures import ThreadPoolExecutor
from core.config import BOLD_RED, GRAY, BOLD_WHITE, RESET, COMMON_PORTS


def check_single_port(ip_port):
    ip, port, service = ip_port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    result = s.connect_ex((ip, port))
    s.close()
    if result == 0:
        print(f"        {BOLD_RED}[!] Port {port} ({service}): OPEN{RESET}")
        return {"port": port, "service": service}
    return None


def check_ports(ip, max_threads=5):
    open_ports = []
    print(f"{GRAY}    └─ Scanning common ports on {BOLD_WHITE}{ip}{GRAY} (Threads: {max_threads})...{RESET}")
    tasks = [(ip, port, service) for port, service in COMMON_PORTS.items()]

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = executor.map(check_single_port, tasks)
        for res in results:
            if res:
                open_ports.append(res)

    if not open_ports:
        print(f"        {GRAY}[-] No common ports open on {ip}.{RESET}")
    return open_ports