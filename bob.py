import socket, threading, time, helpers
#X25519 is an elliptic curve Diffie-Hellman key exchange using Curve25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from Crypto.Cipher import AES

class Ratchet(object):
    def __init__(self, key):
        self.state = key

    # str has type of bytes
    def turn(self, str = b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        kdf_out = helpers.kdf_HMAC(self.state + str, 80)
        # 80 will ensure the message_key is 16 
        # state is from 0 - 31; chain_key is from 32 - 63, and iv is from 64 - 79, used for encrypting messages 
        self.state, chain_key, message_key = kdf_out[slice(32)], kdf_out[slice(32, 64)], kdf_out[slice(64, None)]
        return chain_key, message_key

class Client(object):
    def __init__(self):
        # generate Bob's keys
        self.dh_ratchet_key = X25519PrivateKey.generate()
        self.root_key = None
    
    def assign_root_key(self, new_root_key):
        self.root_key = new_root_key

    def init_ratchets(self):
        # initialize root chain
        self.root_chain = Ratchet(self.root_key)
        # Bob: initialise receive chain and send chain; Alice should be vice versa
        self.receive_chain, self.send_chain = Ratchet(self.root_chain.turn()[0]), Ratchet(self.root_chain.turn()[0])

    def dh_ratchet(self, alice_public):
        # compute a DH with the current key of Bob using Alice's public key
        receive_DH = self.dh_ratchet_key.exchange(alice_public)
        # using receive_DH to turn the root chain once to get a new receiving chain 
        receive_from_alice = self.root_chain.turn(receive_DH)[0]
        self.receive_chain = Ratchet(receive_from_alice)
        print(helpers.Color.BOLD + helpers.Color.BLUE + 'Receiving chain: ' + helpers.Color.END + helpers.Color.CYAN + helpers.base64_encode(receive_from_alice) + helpers.Color.END)

        # Bob generates a new key pair
        self.dh_ratchet_key = X25519PrivateKey.generate()
        # Bob computes DH key exchange using Alice's public key
        send_DH = self.dh_ratchet_key.exchange(alice_public)
        # send_DH is an input to Bob's root chain to obtain a new key for initializing Bob's sending chain
        send_to_bob = self.root_chain.turn(send_DH)[0]
        self.send_chain = Ratchet(send_to_bob)
        print(helpers.Color.BOLD + helpers.Color.BRIGHT_MAGENTA + 'Sending chain: ' + helpers.Color.END + helpers.Color.CYAN + helpers.base64_encode(send_to_bob) + helpers.Color.END)

    def enc(self, msg, key, iv):
        cipher_text = AES.new(key, AES.MODE_CFB, iv).encrypt(helpers.padding(msg))
        #print('Send ciphertext to Alice: ', helpers.base64_encode(cipher_text))
        # send ciphertext and the current DH public key
        return cipher_text, self.dh_ratchet_key.public_key()

    def dec(self, cipher_text):
        # receive Alice's new public key and use it to perform a DH
        # the receiving chain that comes from self.receive_chain = Ratchet(receive_from_alice)
        chain_key, message_key = self.receive_chain.turn()
        # decrypt the message using the new recv ratchet
        return helpers.unpadding(AES.new(chain_key, AES.MODE_CFB, message_key).decrypt(cipher_text))

bob = Client()

#######################################################################
def receive_messages(client_socket):
    root_key_received = False  # Flag to track whether root key has been received
    while True:
        try:
            # Receive message from server
            message = client_socket.recv(1024)
            #this condition check root_key sent from server, and its length is 32
            #since we just need root_key once, so after root key received, we no longer need 
            #care of this condition
            if not root_key_received and len(message) == 32: # receive root_key
                root_key_received = True
                global root_key
                root_key = message
                print(helpers.Color.BOLD + helpers.Color.RED + 'X3DH shared key from server: ' + helpers.Color.END + helpers.Color.CYAN + helpers.base64_encode(root_key) + helpers.Color.END)
                print("---------------------------------------------------------------")
                #Create that thing in alice.py
                bob.assign_root_key(root_key)
                bob.init_ratchets()
                # via socket, we need to send bytes using public_bytes
                pk_bob_encode = bob.dh_ratchet_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                #send public key of bob encoded via socket
                print(helpers.Color.BOLD + helpers.Color.YELLOW + 'Send public key to Alice: ' + helpers.Color.END + helpers.Color.CYAN + helpers.base64_encode(pk_bob_encode) + helpers.Color.END)
                client_socket.send(pk_bob_encode)
                continue
            # the length of public key received from Alice is 44    
            if len(message) == 44: # receive pk of Bob
                global pk_decode
                pk_decode = serialization.load_der_public_key(message, backend=default_backend())
                print(helpers.Color.BOLD + helpers.Color.GREEN + 'Receive public key from Alice: ' + helpers.Color.END + helpers.Color.CYAN + helpers.base64_encode(pk_decode.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)) + helpers.Color.END)
                bob.dh_ratchet(pk_decode)
            # the length of ciphertext received from Alice is 16, 32, ...
            if len(message) % 16 == 0: #len(message) == 16: # receive cipher from Alice
                decrypt_msg = bob.dec(message)
                print(helpers.Color.BOLD + helpers.Color.GREEN + 'Receive ciphertext from Alice: ' + helpers.Color.END + helpers.Color.CYAN + helpers.base64_encode(message) + helpers.Color.END)
                print("Alice: ", decrypt_msg.decode('utf-8'))
                print("---------------------------------------------------------------")
                print(helpers.Color.BOLD + helpers.Color.CYAN + "Type a message" + helpers.Color.END)
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
        chain_key, message_key = bob.send_chain.turn()
        cipher, pk = bob.enc(bytes_data_utf8, chain_key, message_key)
        pk_bob_encode = pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                
        #send pubic key first, then send cipher 
        client.send(pk_bob_encode)
        time.sleep(0.5)
        client.send(cipher)
        print(helpers.Color.BOLD + helpers.Color.YELLOW + 'Send public key to Alice: ' + helpers.Color.END + helpers.Color.CYAN + helpers.base64_encode(pk_bob_encode) + helpers.Color.END)
        print(helpers.Color.BOLD + helpers.Color.YELLOW + 'Send ciphertext to Alice: ' + helpers.Color.END + helpers.Color.CYAN + helpers.base64_encode(cipher) + helpers.Color.END)

if __name__ == "__main__":
    main()
