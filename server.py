import socket
import threading

import base64

import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
import Elliptic

"""
alice_private_key, alice_public_key = Elliptic.make_keypair()
bob_private_key, bob_public_key = Elliptic.make_keypair()
print("Shared secret:", Elliptic.exchange(alice_private_key, bob_public_key))
"""

def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode('utf-8').strip()

def b64_encode(msg):
    # base64 encoding helper function
    return base64.b64encode(msg)

def b64_decode(msg):
	# base64 decoding helper function
	return base64.b64decode(msg)

"""    
def dh_ratchet_rotation_send (self, pbkey: bytes) -> None:
    self.DHratchet = X25519PrivateKey.generate()
    dh_send = self.DHratchet.exchange(pbkey)
    shared_send = self.root_ratchet.next(dh_send)[0]
    self.send_ratchet = SymmRatchet(shared_send)
"""

def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpad(msg):
    # remove pkcs7 padding
    return msg[:-msg[-1]]

def hkdf(inp, length):
    # use HKDF on an input to derive a key
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'',
                info=b'', backend=default_backend())
    return hkdf.derive(inp)

class Bob_server(object):
    def __init__(self):
        # generate Bob's keys
        self.IKb, self.IKb_pub = Elliptic.make_keypair()
        self.SPKb, self.SPKb_pub = Elliptic.make_keypair()
        self.OPKb, self.OPKb_pub = Elliptic.make_keypair()

    def x3dh(self, alice):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = Elliptic.exchange(self.SPKb, alice.IKa_pub)
        dh2 = Elliptic.exchange(self.IKb, alice.EKa_pub)
        dh3 = Elliptic.exchange(self.SPKb, alice.EKa_pub)
        dh4 = Elliptic.exchange(self.OPKb, alice.EKa_pub)
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Bob]\tShared key:', b64(self.sk))
        # self.sk is bytes, and b64(self.sk) is string
        #print('type of self.sk:', type(self.sk))
        return self.sk

class Alice_server(object):
    def __init__(self):
        # generate Alice's keys
        self.IKa, self.IKa_pub = Elliptic.make_keypair()
        self.EKa, self.EKa_pub = Elliptic.make_keypair()

    def x3dh(self, bob):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = Elliptic.exchange(self.IKa, bob.SPKb_pub)
        dh2 = Elliptic.exchange(self.EKa, bob.IKb_pub)
        dh3 = Elliptic.exchange(self.EKa, bob.SPKb_pub)
        dh4 = Elliptic.exchange(self.EKa, bob.OPKb_pub)

        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        #print('[Alice]\tShared key:', b64(self.sk))
        return self.sk



############
# that thing will be in server
alice_server = Alice_server()
bob_server = Bob_server()

# Alice performs an X3DH while Bob is offline, using his uploaded keys
ROOT_KEY = alice_server.x3dh(bob_server)
#print("ROOT_KEY", ROOT_KEY)
# Bob comes online and performs an X3DH using Alice's public keys
#ROOT_KEY = bob_server.x3dh(alice_server)
print("ROOT_KEY", ROOT_KEY)
print("len of ROOT_KEY", len(ROOT_KEY))


def handle_client(client_socket, target, client_name, alice, bob):
    
    while True:
        try:
            # Receive message from client
            data = client_socket.recv(1024)
            if not data:
                break
            # Process message based on the client
            if client_name == "alice":
                #print("data.decode()",data.decode())
                msg = data
                if len(msg) == 44:
                    print("decrypt_msg send to bob: ", msg)
                    target.send(msg)
                if len(msg) % 16 == 0: #len(msg) == 16:
                    #cipher, pk = alice.send(bob, msg)
                    #decrypt_msg = bob.recv(cipher, pk)
                    print("b64_encode of cipher send to alice: ", b64_encode(msg))
                    print("cipher send to bob: ", msg)
                    target.send(msg)
                """
                if data.decode()[0:2] == "b'" or data.decode()[0:2] == 'b"':
                    cipher, pk = alice.send(bob, msg)
                    decrypt_msg = bob.recv(cipher, pk)
                    print("decrypt_msg send to bob: ", decrypt_msg)
                    target.send(decrypt_msg)
                """
                #processed_data = "From Alice " + data.decode()
                #target.send(processed_data.encode())
            elif client_name == "bob":
                msg = data
                if len(msg) == 44:
                    #cipher, pk = alice.send(bob, msg)
                    #decrypt_msg = bob.recv(cipher, pk)
                    print("decrypt_msg send to alice: ", msg)
                    target.send(msg)
                if len(msg) % 16 == 0: #len(msg) == 16:
                    #cipher, pk = alice.send(bob, msg)
                    #decrypt_msg = bob.recv(cipher, pk)
                    print("cipher send to alice: ", msg)
                    print("b64_encode of cipher send to alice: ", b64_encode(msg))
                    target.send(msg)
                #processed_data = "From Bob " + data.decode()
                #target.send(processed_data.encode())
        except Exception as e:
            print(f"Error: {e}")
            break

def main():

    alice = Alice_server()
    bob = Bob_server()
    
    # Alice performs an X3DH while Bob is offline, using his uploaded keys
    ROOT_KEY = alice.x3dh(bob)

    # Bob comes online and performs an X3DH using Alice's public keys
    ROOT_KEY = bob.x3dh(alice)
    #ROOT_KEY = b'\x1b\xb3\x93O\x83\x9d\x12\xf2=O\xde\x82\xe1\xc2\xad4\x14\x0b\x9a,\xe0\xe6\xcd\x8e\xad\xeb\xd1w2-\xf1['

    # Initialize their symmetric ratchets
    #alice.init_ratchets()
    #bob.init_ratchets()
    #bob_ratchet_public = X25519PrivateKey.generate()
    #alice.dh_ratchet(bob.DHratchet.public_key())


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

        # test
        # sending common key to alice and bob
        print("type of ROOT", type(ROOT_KEY))
        client_socket1.sendall(ROOT_KEY)
        client_socket2.sendall(ROOT_KEY)



        # Create threads for handling each client
        client_thread1 = threading.Thread(target=handle_client, args=(client_socket1, client_socket2, "alice", alice, bob))
        client_thread2 = threading.Thread(target=handle_client, args=(client_socket2, client_socket1, "bob", alice, bob))

        client_thread1.start()
        client_thread2.start()

if __name__ == "__main__":
    main()
