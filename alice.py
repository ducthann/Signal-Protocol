import socket, threading, time, helpers
#X25519 is an elliptic curve Diffie-Hellman key exchange using Curve25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from Crypto.Cipher import AES

class Ratchet(object):
    def __init__(self, key):
        self.state = key

    def turn(self, str = b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        kdf_out = helpers.kdf_HMAC(self.state + str, 80)
        # state is from 0 - 31; message_key is from 32 - 63, and iv is from 64 - 79, used for encrypting messages 
        self.state, message_key, iv = kdf_out[slice(32)], kdf_out[slice(32, 64)], kdf_out[slice(64, None)]
        return message_key, iv

# Initialize their symmetric ratchets
class Client(object):
    def __init__(self):
        # generate Alice's keys
        self.dh_ratchet_key = None
        self.root_key = None
    
    def assign_root_key(self, new_root_key):
        self.root_key = new_root_key

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_chain = Ratchet(self.root_key)
        # Alice: initialise send chain and receive chain; Bob should be vice versa
        self.send_chain, self.receive_chain = Ratchet(self.root_chain.turn()[0]), Ratchet(self.root_chain.turn()[0])

    def dh_ratchet(self, bob_public):
        # perform a DH ratchet rotation using Bob's public key
        if self.dh_ratchet_key != None:
            # the first time we don't have a DH ratchet yet
            receive_DH = self.dh_ratchet_key.exchange(bob_public)
            receive_from_bob = self.root_chain.turn(receive_DH)[0]
            # use Bob's public and our old private key
            # to get a new recv ratchet
            self.receive_chain = Ratchet(receive_from_bob)
            print('Receive chain key from Bob: ', helpers.base64_encode(receive_from_bob))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Bob
        self.dh_ratchet_key = X25519PrivateKey.generate()
        send_DH = self.dh_ratchet_key.exchange(bob_public)
        send_to_bob = self.root_chain.turn(send_DH)[0]
        self.send_chain = Ratchet(send_to_bob)
        print('Send chain key to Bob: ', helpers.base64_encode(send_to_bob))

    def enc(self, msg, key, iv):
        cipher_text = AES.new(key, AES.MODE_CFB, iv).encrypt(helpers.padding(msg))
        print('Send ciphertext to Bob:', helpers.base64_encode(cipher_text))
        # send ciphertext and current DH public key
        return cipher_text, self.dh_ratchet_key.public_key()

    def dec(self, cipher_text):
        # receive Bob's new public key and use it to perform a DH
        key, iv = self.receive_chain.turn()
        # decrypt the message using the new recv ratchet
        return helpers.unpadding(AES.new(key, AES.MODE_CFB, iv).decrypt(cipher_text))


############################################################
alice = Client()

def receive_messages(client_socket):
    root_key_received = False  # Flag to track whether root key has been received
    while True:
        try:
            # Receive message from server
            message = client_socket.recv(1024)
            # Check if the length of the received message is 32 bytes (root_key)
            if not root_key_received and len(message) == 32: # receive root_key
                root_key_received = True
                global root_key
                root_key = message
                print("X3DH shared key from server: ", helpers.base64_encode(root_key))
                alice.assign_root_key(root_key)
                alice.init_ratchets()
                continue
            if len(message) == 44: # receive pk of Bob
                global pk_decode
                pk_decode = serialization.load_der_public_key(message, backend=default_backend())
                if alice.dh_ratchet_key is None:
                    alice.dh_ratchet(pk_decode)
                else:
                    alice.dh_ratchet(pk_decode)
            if len(message) % 16 == 0: # receive cipher from Alice
                decrypt_msg = alice.dec(message)
                print("Bob: ", decrypt_msg.decode('utf-8'))
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
        message = '{}'.format(get_input(''))
        #print(message)
        bytes_data_utf8 = message.encode('utf-8') #convert from string to bytes
        key, iv = alice.send_chain.turn()
        cipher, pk = alice.enc(bytes_data_utf8, key, iv)
        pk_bob_encode = pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                
        #client.send(message.encode())
        client.send(pk_bob_encode)
        time.sleep(1.2)
        client.send(cipher)

if __name__ == "__main__":
    main()
