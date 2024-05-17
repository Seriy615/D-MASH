import socket

def send_data_to_server(data, server_ip, server_port):
    try:
        # Создаем сокет
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Подключаемся к серверу
        client_socket.connect((server_ip, server_port))
        # Отправляем данные
        client_socket.sendall(data.encode('utf-8'))
        # Закрываем соединение
        client_socket.close()
    except Exception as e:
        print(f"Ошибка при отправке данных: {e}")

if __name__ == "__main__":
    server_ip = "10.10.2.147"  # IP-адрес сервера
    server_port = 12345      # Порт сервера

    while True:
        data = input("Введите данные для отправки на сервер: ")
        send_data_to_server(data, server_ip, server_port)
