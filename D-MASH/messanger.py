import socket

def send_message():
    # Создаем сокет
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Получаем имя пользователя
    username = input("Введите ваше имя: ")

    while True:
        message = input()  # Получаем сообщение от пользователя
        data = f"({username}): {message}"  # Формируем сообщение с указанием отправителя
        sock.sendto(data.encode(), ('<broadcast>', 12345))  # Отправляем данные на все устройства в сети

if __name__ == "__main__":
    send_message()
