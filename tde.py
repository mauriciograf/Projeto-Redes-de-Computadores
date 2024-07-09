import sys
try:
    from scapy.all import sniff, hexdump, IP, TCP, UDP, ICMP
except ImportError:
    print("Scapy não está instalado. Por favor, instale-o executando 'pip install scapy'.")
    sys.exit(1)
count = 0


def callback(packet):
    global count
    count += 1

    if count > 20:
        return

    print(f"Contagem pacote: {count}")
    print(f"Tamanho do pacote recebido: {len(packet)}")

    # Verifica se o pacote tem uma camada IP
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"IP Origem: {ip_layer.src}")
        print(f"IP Destino: {ip_layer.dst}")
        print(f"Protocolo: {ip_layer.proto}")

        # Verifica se o pacote tem uma camada TCP
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"Porta Origem: {tcp_layer.sport}")
            print(f"Porta Destino: {tcp_layer.dport}")
            print("ProtocolO: TCP")

        # Verifica se o pacote tem uma camada UDP
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"Porta Origem: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print("Protocolo: UDP")

        # Verifica se o pacote tem uma camada ICMP
        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            print(f"Tipo: {icmp_layer.type}")
            print(f"Código: {icmp_layer.code}")
            print("Protocolo: ICMP")

    print("Payload:")
    hexdump(packet)
    print("\n")


def main(expression):
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} \"expressao\"")
        return

    # Captura os pacotes
    sniff(filter=expression, prn=callback, store=0)
    return


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} \"expressao\"")
        sys.exit(1)

    main(sys.argv[1])
