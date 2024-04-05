import socket, threading, Elliptic, helpers

class Bob_server(object):
    def __init__(self):
        # generate Bob's keys
        self.IKb, self.IKb_pub = Elliptic.generate()
        self.SPKb, self.SPKb_pub = Elliptic.generate()
        self.OPKb, self.OPKb_pub = Elliptic.generate()

    def x3dh(self, alice):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = Elliptic.exchange(self.SPKb, alice.IKa_pub)
        dh2 = Elliptic.exchange(self.IKb, alice.EKa_pub)
        dh3 = Elliptic.exchange(self.SPKb, alice.EKa_pub)
        dh4 = Elliptic.exchange(self.OPKb, alice.EKa_pub)
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        return helpers.kdf_HMAC(dh1 + dh2 + dh3 + dh4, 32)

class Alice_server(object):
    def __init__(self):
        # generate Alice's keys
        self.IKa, self.IKa_pub = Elliptic.generate()
        self.EKa, self.EKa_pub = Elliptic.generate()

    def x3dh(self, bob):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = Elliptic.exchange(self.IKa, bob.SPKb_pub)
        dh2 = Elliptic.exchange(self.EKa, bob.IKb_pub)
        dh3 = Elliptic.exchange(self.EKa, bob.SPKb_pub)
        dh4 = Elliptic.exchange(self.EKa, bob.OPKb_pub)

        # the shared key is KDF(DH1||DH2||DH3||DH4)
        return helpers.kdf_HMAC(dh1 + dh2 + dh3 + dh4, 32)

############

def handle_client(client_socket, target, client_name):
    while True:
        try:
            # Receive message from client
            data = client_socket.recv(1024)
            if not data:
                break
            # Process message based on the client
            if client_name == "alice":
                msg = data
                if len(msg) == 44:
                    print('-------------------------------------------------------')
                    print("Alice's public key: ", helpers.base64_encode(msg))
                    target.send(msg)
                if len(msg) % 16 == 0: #len(msg) == 16:
                    print("Alice's ciphertext: ", helpers.base64_encode(msg))
                    print('-------------------------------------------------------')
                    target.send(msg)
            elif client_name == "bob":
                msg = data
                if len(msg) == 44:
                    print("Bob's public key: ", helpers.base64_encode(msg))
                    target.send(msg)
                if len(msg) % 16 == 0: #len(msg) == 16:
                    print("Bob's ciphertext: ", helpers.base64_encode(msg))
                    #print('-------------------------------------------------------')
                    target.send(msg)
        except Exception as e:
            print(f"Error: {e}")
            break

def main():

    alice = Alice_server()
    bob = Bob_server()
    
    # Alice performs an X3DH while Bob is offline, using his uploaded keys
    root_key = alice.x3dh(bob)

    # Bob comes online and performs an X3DH using Alice's public keys
    root_key = bob.x3dh(alice)

    print(helpers.Color.BOLD + helpers.Color.RED + 'X3DH shared key: ' + helpers.Color.END + helpers.Color.CYAN + helpers.base64_encode(root_key) + helpers.Color.END)
    print("---------------------------------------------------------------")
    # Server configuration
    host = '127.0.0.1'
    port = 9999

    # Create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Listening on {host}:{port}")

    while True:
        # Accept incoming connections
        client_socket1, addr1 = server.accept()
        print(f"[*] Accepted connection from {addr1[0]}:{addr1[1]}")
        client_socket2, addr2 = server.accept()
        print(f"[*] Accepted connection from {addr2[0]}:{addr2[1]}")

        # sending common key to alice and bob
        client_socket1.sendall(root_key)
        client_socket2.sendall(root_key)
        print("---------------------------------------------------------------")
        # Create threads for handling each client
        client_thread1 = threading.Thread(target=handle_client, args=(client_socket1, client_socket2, "alice"))
        client_thread2 = threading.Thread(target=handle_client, args=(client_socket2, client_socket1, "bob"))

        client_thread1.start()
        client_thread2.start()

if __name__ == "__main__":
    main()
