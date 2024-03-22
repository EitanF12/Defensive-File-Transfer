
import socket
import struct
import threading

def handle_client(client_socket):
    try:
        while True:
            # Receive data from the client
            data = client_socket.recv(1024)
            if not data:
                break
            
            # Unpack the data. Assuming the format is: 1 integer and a 24-char string
            id, message = struct.unpack('I24s', data)
            message = message.decode('utf-8').rstrip('\x00')  # Remove padding
            
            print(f"Received ID: {id}, Message: {message}")
            
            # Echo back the received message
            client_socket.sendall(data)
    except Exception as e:
        print(f"Client connection error: {e}")
    finally:
        client_socket.close()

def start_server(host='127.0.0.1', port=40000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port}")
        
        while True:
            client_socket, _ = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket,))
            thread.start()

if __name__ == "__main__":
    start_server()
