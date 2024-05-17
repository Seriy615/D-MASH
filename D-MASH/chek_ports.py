import socket
import psutil

def check_port_open(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        return result == 0

def get_open_ports(ip, port_range):
    open_ports = []
    for port in port_range:
        if check_port_open(ip, port):
            open_ports.append(port)
    return open_ports

def get_all_open_ports():
    open_ports = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN:
            open_ports.append(conn.laddr.port)
    return open_ports

if __name__ == "__main__":
    ip = "95.167.221.50"
    port_range = range(1, 65535)  # Диапазон портов для сканирования (1-65535)

    print("Сканирование портов...")
    open_ports = get_open_ports(ip, port_range)
    print(f"Открытые порты (через сканирование): {open_ports}")

    print("\nСписок всех открытых портов (через psutil):")
    all_open_ports = get_all_open_ports()
    print(all_open_ports)
