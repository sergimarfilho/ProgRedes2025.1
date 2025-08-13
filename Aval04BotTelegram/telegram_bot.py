import socket
import json
import time

# Configurações do bot
TOKEN = '<8451302752:AAEf4YkMDFxD1XBTfrZQXbnfhEl27CZ6-r8>'  
API_URL = f'https://api.telegram.org/bot{TOKEN}/'
OFFSET = 0  # rastreio da última atualização

def get_updates(offset):
    """Obtém a atualizações do bot."""
    url = f'{API_URL}getUpdates?offset={offset}'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('api.telegram.org', 443))
        s.sendall(f'GET {url} HTTP/1.1\r\nHost: api.telegram.org\r\nConnection: close\r\n\r\n'.encode())
        response = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    return json.loads(response.decode().split('\r\n\r\n')[1])

def send_message(chat_id, text):
    """mandar uma mensagem para o chat especificado."""
    url = f'{API_URL}sendMessage?chat_id={chat_id}&text={text}'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('api.telegram.org', 443))
        s.sendall(f'GET {url} HTTP/1.1\r\nHost: api.telegram.org\r\nConnection: close\r\n\r\n'.encode())
        response = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    return json.loads(response.decode().split('\r\n\r\n')[1])

def main():
    global OFFSET
    while True:
        updates = get_updates(OFFSET)
        for update in updates['result']:
            chat_id = update['message']['chat']['id']
            message_text = update['message']['text']
            print(f'Recebido: {message_text} de {chat_id}')

            # Responder a comandos
            if message_text == '/start':
                send_message(chat_id, 'Bemvindo ao bot! Para te ajudar insira /help para ver os comandos disponíveis.')
            elif message_text == '/help':
                send_message(chat_id, 'Comandos disponíveis:\n/start - Iniciar o bot\n/help - Mostrar ajuda')
            else:
                send_message(chat_id, 'Comando não éreconhecido. Use /help para ver os comandos disponíveis.')

            #atualiza o OFFSET para evitar reprocessar denovo a mesma mensagem
            OFFSET = update['update_id'] + 1

        time.sleep(1)  # Espera um poquinho antes de buscar novamente atualizações

if __name__ == '__main__':
    main()
