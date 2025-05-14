def ip_to_binary(ip):
    # Converte o endereço IP em formato string para um número inteiro
    octets = ip.split('.')
    binary_ip = 0
    for octet in octets:
        binary_ip = (binary_ip << 8) + int(octet)
    return binary_ip

def binary_to_ip(binary_ip):
    # Converte um número inteiro de volta para o formato string de um endereço IP
    return f"{(binary_ip >> 24) & 255}.{(binary_ip >> 16) & 255}.{(binary_ip >> 8) & 255}.{binary_ip & 255}"

def calculate_network_broadcast(ip, mask):
    # Converter o IP para binário
    binary_ip = ip_to_binary(ip)
    
    # Para calcular a máscara de sub-rede
    subnet_mask = (1 << 32) - (1 << (32 - mask))
    
    # Para calcula o endereço da rede
    network_address = binary_ip & subnet_mask
    
    # Vai calcular o endereço de broadcast
    broadcast_address = network_address | ~subnet_mask & 0xFFFFFFFF
    
    # Vai calcular o endereço do gateway 'último IP válido'
    gateway_address = broadcast_address - 1
    
    # Vai calcular o número de hosts
    num_hosts = (1 << (32 - mask)) - 2  # -2 para o endereço da rede e o endereço de broadcast
    
    return (binary_to_ip(network_address), 
            binary_to_ip(broadcast_address), 
            binary_to_ip(gateway_address), 
            num_hosts)


ip = "200.17.143.131"
mask = 18

network, broadcast, gateway, hosts = calculate_network_broadcast(ip, mask)

print(f"Endereço da rede: {network}")
print(f"Endereço de broadcast: {broadcast}")
print(f"Endereço do gateway: {gateway}")
print(f"Número de hosts válidos: {hosts}")