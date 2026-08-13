import socket
import argparse


def resolver_dominio(dominio):
    try:
        nome, aliases, ips = socket.gethostbyname_ex(dominio)

        print(f"[+] Domínio Analisado: {dominio}")
        print(f"[+] Hostname Oficial: {nome}")

        if aliases:
            print(f"[+] Apelidos (Aliases): {', '.join(aliases)}")

        print(f"[+] Endereços IP Encontrados ({len(ips)}):")
        for ip in ips:
            print(f"    └─ {ip}")

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