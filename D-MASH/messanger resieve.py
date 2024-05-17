import socket

def receive_messages():
    # Создаем сокет
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Присваиваем адрес и порт
    sock.bind(('0.0.0.0', 12345))

    while True:
        data, addr = sock.recvfrom(1024)  # Получаем данные
        print(data.decode())  # Выводим сообщение

if __name__ == "__main__":
    receive_messages()
