import sys
import struct

PCAP_GLOBAL_HEADER_FMT = 'IHHiIII'
PCAP_PACKET_HEADER_FMT = 'IIII'

ETHERNET_HEADER_LEN = 14

# EtherTypes (hex)
ETHERTYPE_IPv4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_RARP = 0x8035

# IPv4 Protocol numbers
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# ICMP types of interest
ICMP_TYPE_NAMES = {
    0: 'Echo Reply',
    3: 'Destination Unreachable',
    4: 'Source Quench',
    5: 'Redirect',
    8: 'Echo Request',
}

def mac_addr(bytes_addr):
    """Converte bytes MAC para string no formato aa:bb:cc:dd:ee:ff"""
    return ':'.join(f'{b:02x}' for b in bytes_addr)

def ipv4_addr(bytes_addr):
    """Converte bytes IPv4 para string decimal."""
    return '.'.join(str(b) for b in bytes_addr)

def parse_ethernet_header(data):
    if len(data) < ETHERNET_HEADER_LEN:
        raise ValueError('Pacote menor que header Ethernet')
    dest_mac = data[0:6]
    src_mac = data[6:12]
    ethertype = struct.unpack('!H', data[12:14])[0]
    return mac_addr(src_mac), mac_addr(dest_mac), ethertype, data[14:]

def parse_arp_packet(data):
    # ARP header total 28 bytes
    if len(data) < 28:
        raise ValueError("ARP packet muito pequeno")
    hardware_type, proto_type, hw_addr_len, proto_addr_len, operation = struct.unpack('!HHBBH', data[0:8])
    sha = data[8:14]   # Sender hw addr (MAC)
    spa = data[14:18]  # Sender proto addr (IPv4)
    tha = data[18:24]  # Target hw addr (MAC)
    tpa = data[24:28]  # Target proto addr (IPv4)
    return {
        "operation": operation,
        "sha": mac_addr(sha),
        "spa": ipv4_addr(spa),
        "tha": mac_addr(tha),
        "tpa": ipv4_addr(tpa)
    }

def parse_ipv4_header(data):
    if len(data) < 20:
        raise ValueError("IPv4 header muito pequeno")
    ver_ihl = data[0]
    ver = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    total_length = struct.unpack('!H', data[2:4])[0]
    protocol = data[9]
    src_ip = ipv4_addr(data[12:16])
    dst_ip = ipv4_addr(data[16:20])
    ttl = data[8]
    flags_frag = struct.unpack('!H', data[6:8])[0]
    tos = data[1]
    identification = struct.unpack('!H', data[4:6])[0]
    header_checksum = struct.unpack('!H', data[10:12])[0]
    return {
        "version": ver,
        "ihl": ihl,
        "total_length": total_length,
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ttl": ttl,
        "flags_frag": flags_frag,
        "tos": tos,
        "identification": identification,
        "header_checksum": header_checksum,
        "payload": data[ihl:total_length]
    }

def parse_icmp_packet(data):
    if len(data) < 8:
        raise ValueError("ICMP header muito pequeno")
    icmp_type, code, checksum = struct.unpack('!BBH', data[0:4])
    identifier = None
    sequence = None
    if icmp_type in (0, 8):  # Echo reply/request
        if len(data) >= 8:
            identifier, sequence = struct.unpack('!HH', data[4:8])
    return {
        "type": icmp_type,
        "code": code,
        "checksum": checksum,
        "identifier": identifier,
        "sequence": sequence
    }

def parse_udp_header(data):
    if len(data) < 8:
        raise ValueError("UDP header muito pequeno")
    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[0:8])
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
        "payload": data[8:]
    }

def parse_tcp_header(data):
    if len(data) < 20:
        raise ValueError("TCP header muito pequeno")
    src_port, dst_port, seq, ack_seq, offset_reserved_flags = struct.unpack('!HHIIH', data[:14])
    data_offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF  # 9 bits flags
    window_size, checksum, urg_pointer = struct.unpack('!HHH', data[14:20])
    payload = data[data_offset:]
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "sequence": seq,
        "acknowledgment": ack_seq,
        "data_offset": data_offset,
        "flags": flags,
        "window_size": window_size,
        "checksum": checksum,
        "urg_pointer": urg_pointer,
        "payload": payload
    }

# Função para interpretar flags TCP
def tcp_flags_str(flags):
    flags_names = [
        ('FIN', 0x001),
        ('SYN', 0x002),
        ('RST', 0x004),
        ('PSH', 0x008),
        ('ACK', 0x010),
        ('URG', 0x020),
        ('ECE', 0x040),
        ('CWR', 0x080),
        ('NS', 0x100)
    ]
    return ', '.join(name for name, bit in flags_names if flags & bit)

def ler_pcap(f):
    # Lê o cabeçalho global pcap (24 bytes)
    global_header = f.read(24)
    if len(global_header) < 24:
        raise ValueError("Arquivo pcap muito pequeno")
    magic_number = struct.unpack('I', global_header[0:4])[0]
    # Poderia verificar magic_number para endianness e versão, omitido para simplicidade.
    # Loop para ler registros de pacotes
    while True:
        packet_header = f.read(16)
        if len(packet_header) < 16:
            break  # fim do arquivo
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)
        packet_data = f.read(incl_len)
        yield packet_data

def main():
    if len(sys.argv) != 2:
        print("Uso: python q1.py <arquivo.pcap>")
        sys.exit(1)

    arquivo = sys.argv[1]
    try:
        f = open(arquivo, 'rb')
    except Exception as e:
        print("Erro ao abrir arquivo:", e)
        sys.exit(1)

    print(f"Lendo arquivo pcap: {arquivo}\n")

    pacote_num = 0
    for packet_data in ler_pcap(f):
        pacote_num += 1
        print(f"--- Pacote {pacote_num} ---")
        try:
            # Parse Ethernet
            src_mac, dst_mac, ethertype, payload = parse_ethernet_header(packet_data)
            print(f"MAC Origem: {src_mac}")
            print(f"MAC Destino: {dst_mac}")

            # ARP ou RARP
            if ethertype == ETHERTYPE_ARP or ethertype == ETHERTYPE_RARP:
                arp_info = parse_arp_packet(payload)
                op_code = arp_info["operation"]
                op_str = "ARP" if ethertype == ETHERTYPE_ARP else "RARP"
                print(f"Código da Operação: {op_str} ({op_code})")
                print(f"MAC Remetente: {arp_info['sha']}")
                print(f"MAC Destinatário: {arp_info['tha']}")
                print(f"IPv4 Remetente: {arp_info['spa']}")
                print(f"IPv4 Destinatário: {arp_info['tpa']}")

            # IPv4
            elif ethertype == ETHERTYPE_IPv4:
                ipv4_info = parse_ipv4_header(payload)
                print(f"IPv4 Origem: {ipv4_info['src_ip']}")
                print(f"IPv4 Destino: {ipv4_info['dst_ip']}")
                # Quatro campos extras escolhidos:
                print(f"TTL: {ipv4_info['ttl']}")
                print(f"Protocolo: {ipv4_info['protocol']}")
                print(f"TOS: {ipv4_info['tos']}")
                print(f"Identificação: {ipv4_info['identification']}")

                # Protocolos internos
                proto = ipv4_info["protocol"]
                ip_payload = ipv4_info["payload"]

                if proto == IPPROTO_ICMP:
                    icmp_info = parse_icmp_packet(ip_payload)
                    icmp_type_name = ICMP_TYPE_NAMES.get(icmp_info["type"], "Outro")
                    print(f"Tipo ICMP: {icmp_type_name} ({icmp_info['type']})")
                    if icmp_type_name in ["Echo Request", "Echo Reply"]:
                        print(f"Número do Identificador: {icmp_info['identifier']}")
                        print(f"Número de Sequência: {icmp_info['sequence']}")

                elif proto == IPPROTO_UDP:
                    udp_info = parse_udp_header(ip_payload)
                    print(f"Porta de Origem: {udp_info['src_port']}")
                    print(f"Porta de Destino: {udp_info['dst_port']}")

                elif proto == IPPROTO_TCP:
                    tcp_info = parse_tcp_header(ip_payload)
                    print(f"Porta de Origem: {tcp_info['src_port']}")
                    print(f"Porta de Destino: {tcp_info['dst_port']}")
                    # Quatro campos extras escolhidos:
                    print(f"Número de Sequência: {tcp_info['sequence']}")
                    print(f"Número de Acknowledgment: {tcp_info['acknowledgment']}")
                    print(f"Bandeiras: {tcp_flags_str(tcp_info['flags'])}")
                    print(f"Tamanho da Janela: {tcp_info['window_size']}")

                    # Para aplicação carregada no TCP, mostrar até 200 bytes após SYN/SYN-ACK
                    # Identificar SYN ou SYN-ACK no pacote pela flags:
                    syn_flag = 0x002
                    ack_flag = 0x010
                    flags = tcp_info['flags']

                    # Se pacote tiver SYN e não ACK = SYN
                    # Se pacote tiver SYN e ACK = SYN-ACK
                    if (flags & syn_flag) != 0:
                        # Mostrar até 200 bytes do payload em cada sentido (contador não realizado, apenas mostra payload)
                        payload_len = len(tcp_info['payload'])
                        to_show = tcp_info['payload'][:200]
                        print(f"Dados da Aplicação TCP (até 200 bytes) [{min(200, payload_len)} bytes]:")
                        # Mostrar hexadecimal legível
                        hex_repr = ' '.join(f"{b:02x}" for b in to_show)
                        print(hex_repr)
        except Exception as e:
            print("Erro ao analisar pacote:", e)

        print()  # Linha em branco entre pacotes

    f.close()

if __name__ == '__main__':
    main()