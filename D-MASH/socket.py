import socket
import threading

def handle_client(client_socket):
    try:
        while True:
            # Получаем данные от клиента
            data = client_socket.recv(1024)
            if not data:
                break
            print(f"Получены данные: {data.decode('utf-8')}")
    except Exception as e:
        print(f"Ошибка при обработке клиента: {e}")
    finally:
        # Закрываем соединение
        client_socket.close()

def server_loop(server_ip, server_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(5)
    print(f"Сервер запущен на {server_ip}:{server_port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Подключен клиент: {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    server_ip = "0.0.0.0"  # Слушаем на всех интерфейсах
    server_port = 12345    # Порт сервера

    server_loop(server_ip, server_port)
