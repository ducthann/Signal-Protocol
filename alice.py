import socket
import threading
import base64
import time
import readline
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

class SymmRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv

# Initialize their symmetric ratchets
class Alice(object):
    def __init__(self):
        # generate Alice's keys
        self.DHratchet = None
        self.sk = None
    
    def assign_root_key(self, new_root_key):
        self.sk = new_root_key

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymmRatchet(self.sk)
        # initialise the sending and recving chains
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self, bob_public):
        # perform a DH ratchet rotation using Bob's public key
        if self.DHratchet is not None:
            # the first time we don't have a DH ratchet yet
            dh_recv = self.DHratchet.exchange(bob_public)
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            # use Bob's public and our old private key
            # to get a new recv ratchet
            self.recv_ratchet = SymmRatchet(shared_recv)
            print('[Alice]\tRecv ratchet seed:', b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Bob
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(bob_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Alice]\tSend ratchet seed:', b64(shared_send))

    def enc(self, msg, key, iv):
        #key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        #cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg.encode('utf-8'), AES.block_size))
        print('[Alice]\tSending ciphertext to Bob:', b64(cipher))
        # send ciphertext and current DH public key
        #bob.recv(cipher, self.DHratchet.public_key())
        return cipher, self.DHratchet.public_key()

    def dec(self, cipher):
        # receive Bob's new public key and use it to perform a DH
        #self.dh_ratchet(bob_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        #print('[Alice]\tDecrypted message:', msg)
        return msg


############################################################
alice = Alice()

def receive_messages(client_socket):
    root_key_received = False  # Flag to track whether root key has been received
    while True:
        try:
            # Receive message from server
            #message = client_socket.recv(1024).decode()
            message = client_socket.recv(1024)
            #print("Bob:", message)
            # Check if the length of the received message is 32 bytes (root_key)
            if not root_key_received and len(message) == 32: # receive root_key
                root_key_received = True
                global root_key
                root_key = message
                #print("root_key", root_key)
                #Create that thing in alice.py
                #alice = Alice() 
                alice.assign_root_key(root_key)
                alice.init_ratchets()
            if len(message) == 44: # receive pk of Bob
                global pk_decode
                pk_decode = serialization.load_der_public_key(message, backend=default_backend())
                if (alice.DHratchet is None):
                    alice.dh_ratchet(pk_decode)
                    #print("pk_bob_encode", pk_decode)
                else:
                    alice.dh_ratchet(pk_decode)

            if len(message) % 16 == 0: # receive cipher from Alice
                decrypt_msg = alice.dec(message)
                print("Bob: ", decrypt_msg.decode('utf-8'))
                
            #client_socket.send("abcxyz".encode())
        except Exception as e:
            print(f"Error: {e}")
            break

def get_input(prompt):
    return input(prompt)

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
        #message = input('')
        message = '{}'.format(get_input(''))
        #print(message)
        bytes_data_utf8 = message.encode('utf-8') #convert from string to bytes
        key, iv = alice.send_ratchet.next()
        cipher, pk = alice.enc(bytes_data_utf8, key, iv)
        pk_bob_encode = pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                
        #client.send(message.encode())
        client.send(pk_bob_encode)
        time.sleep(1.2)
        client.send(cipher)

if __name__ == "__main__":
    main()
