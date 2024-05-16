import socket

HOST, PORT = "localhost", 12345 

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    while True:
        data = input("Type the message to send:")
        data_bytes = data.encode()  # str to bytes
        sock.sendall(data_bytes)
        data_bytes = sock.recv(1024)
        data = data_bytes.decode()  # bytes to str
        print("Received:", data)
