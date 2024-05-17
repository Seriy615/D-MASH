import socket

def listen_for_broadcast(port=12345):
    # Создаем UDP сокет
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Устанавливаем опцию сокета для многократного использования адреса
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Привязываем сокет к любому доступному адресу и указанному порту
    sock.bind(('', port))
    print(f"Listening for broadcast messages on port {port}...")

    while True:
        data, addr = sock.recvfrom(1024)
        print(f"Received message from {addr}: {data.decode('utf-8')}")

if __name__ == '__main__':
    listen_for_broadcast()
