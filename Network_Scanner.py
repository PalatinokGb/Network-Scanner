import sys
from scapy.all import ARP, Ether, srp


def scan_network(ip_range: str) -> list:
    """Envia pacotes ARP Request para descobrir dispositivos ativos na rede.

    Args:
        ip_range (str): O intervalo de IPs da rede (ex: 192.168.1.1/24)

    Returns:
        list: Lista de dicionários contendo IP e MAC dos alvos detetados.
    """
    # Criar pacote ARP Request e pacote Ether de Broadcast
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combinar os pacotes
    packet = broadcast / arp_request

    # Enviar e receber pacotes na Camada 2 (Timeout de 2 segundos)
    answered_list = srp(packet, timeout=2, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def main():
    print("=== Network Scanner (ARP-based) ===")
    # Nota: Requer privilégios de Administrador/Root para executar comandos de rede Scapy
    ip_range = input("Introduza a sub-rede (ex: 192.168.1.1/24): ")

    if not ip_range:
        print("[-] Erro: É necessário especificar um alvo.", file=sys.stderr)
        return

    print(f"\n[+] A mapear a rede ({ip_range})... Por favor, aguarde.")
    try:
        scan_results = scan_network(ip_range)

        print("\nDispositivos detetados na rede:")
        print("-" * 50)
        print("Endereço IP\t\tEndereço MAC")
        print("-" * 50)
        
        for client in scan_results:
            print(f"{client['ip']}\t\t{client['mac']}")
            
    except PermissionError:
        print("[-] Erro: Permissões insuficientes. Execute o script como sudo/administrador.", file=sys.stderr)
    except Exception as e:
        print(f"[-] Ocorreu um erro durante o scan: {e}", file=sys.stderr)
    finally:
        # Mantém a janela aberta até pressionar Enter (se o programa chegar a iniciar)
        input("\nPressione Enter para sair...")


if __name__ == "__main__":
    main()
