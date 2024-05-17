import socket

def send_broadcast_message(message, broadcast_address='255.255.255.255', port=12345):
    # Создаем UDP сокет
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Устанавливаем опцию сокета для разрешения широковещания
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Преобразуем сообщение в байты и отправляем
    sock.sendto(message.encode('utf-8'), (broadcast_address, port))
    print(f"Broadcast message sent to {broadcast_address}: {message}")

    # Закрываем сокет
    sock.close()

if __name__ == '__main__':
 
    message = '''

#код для получения сообщений

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

'''
    send_broadcast_message(message, '255.255.255.255')
