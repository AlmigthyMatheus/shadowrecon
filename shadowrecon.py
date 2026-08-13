import socket
import argparse


def resolver_dominio(dominio):
    try:
        ip = socket.gethostbyname(dominio)
        print(f"[+] O IP de {dominio} é: {ip}")
    except socket.gaierror:
        print(f"[-] Erro: Não foi possível resolver o domínio '{dominio}'.")


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
    resolver_dominio(args.domain)


if __name__ == "__main__":
    main()