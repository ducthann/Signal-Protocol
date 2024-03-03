import socket
import threading

def receive_messages(client_socket):
    while True:
        try:
            # Receive message from server
            message = client_socket.recv(1024).decode()
            print("Alice:", message)
        except Exception as e:
            print(f"Error: {e}")
            break

def main():
    # Server configuration
    host = '127.0.0.1'
    port = 9999

    # Connect to the server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    # Start receiving thread
    receive_thread = threading.Thread(target=receive_messages, args=(client,))
    receive_thread.start()

    while True:
        # Send message to server
        message = input('')
        client.send(message.encode())

if __name__ == "__main__":
    main()
