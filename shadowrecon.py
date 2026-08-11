import socket
import sys

def resolver_dominio(dominio):
    try:
        ip = socket.gethostbyname(dominio)
        print(f"[+] O IP de {dominio} é: {ip}")
    except socket.gaierror:
        print(f"[-] Erro: Não foi possível resolver o domínio '{dominio}'.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        alvo = sys.argv[1]
        resolver_dominio(alvo)
    else:
        print("Uso: python shadowrecon.py <dominio>")
        sys.exit(1)