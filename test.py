import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES


def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode('utf-8').strip()
    
def dh_ratchet_rotation_send (self, pbkey: bytes) -> None:
    self.DHratchet = X25519PrivateKey.generate()
    dh_send = self.DHratchet.exchange(pbkey)
    shared_send = self.root_ratchet.next(dh_send)[0]
    self.send_ratchet = SymmRatchet(shared_send)

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

class Bob_server(object):
    def __init__(self):
        # generate Bob's keys
        self.IKb = X25519PrivateKey.generate()
        self.SPKb = X25519PrivateKey.generate()
        self.OPKb = X25519PrivateKey.generate()

    def x3dh(self, alice):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.SPKb.exchange(alice.IKa.public_key())
        dh2 = self.IKb.exchange(alice.EKa.public_key())
        dh3 = self.SPKb.exchange(alice.EKa.public_key())
        dh4 = self.OPKb.exchange(alice.EKa.public_key())
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Bob]\tShared key:', b64(self.sk))
        # self.sk is bytes, and b64(self.sk) is string
        print('type of self.sk:', type(self.sk))
        return self.sk

class Alice_server(object):
    def __init__(self):
        # generate Alice's keys
        self.IKa = X25519PrivateKey.generate()
        self.EKa = X25519PrivateKey.generate()

    def x3dh(self, bob):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.IKa.exchange(bob.SPKb.public_key())
        dh2 = self.EKa.exchange(bob.IKb.public_key())
        dh3 = self.EKa.exchange(bob.SPKb.public_key())
        dh4 = self.EKa.exchange(bob.OPKb.public_key())
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Alice]\tShared key:', b64(self.sk))
        return self.sk


class Bob(object):
    def __init__(self):
        # generate Bob's keys
        self.DHratchet = X25519PrivateKey.generate()
        self.sk = ROOT_KEY

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymmRatchet(self.sk)
        # initialise the sending and recving chains
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self, alice_public):
        # perform a DH ratchet rotation using Alice's public key
        dh_recv = self.DHratchet.exchange(alice_public)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        # use Alice's public and our old private key
        # to get a new recv ratchet
        self.recv_ratchet = SymmRatchet(shared_recv)
        print('[Bob]\tRecv ratchet seed:', b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Alice
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(alice_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Bob]\tSend ratchet seed:', b64(shared_send))

    def send(self, msg, key, iv):
        #key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Bob]\tSending ciphertext to Alice:', b64(cipher))
        # send ciphertext and current DH public key
        #alice.recv(cipher, self.DHratchet.public_key())
        return cipher, self.DHratchet.public_key()

    def recv(self, cipher):
        # receive Alice's new public key and use it to perform a DH
        #self.dh_ratchet(alice_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        #print('[Bob]\tDecrypted message:', msg)
        return msg

class Alice(object):
    def __init__(self):
        # generate Alice's keys
        self.DHratchet = None
        self.sk = ROOT_KEY

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

    def send(self, msg, key, iv):
        #key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        #cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg.encode('utf-8'), AES.block_size))
        print('[Alice]\tSending ciphertext to Bob:', b64(cipher))
        # send ciphertext and current DH public key
        #bob.recv(cipher, self.DHratchet.public_key())
        return cipher, self.DHratchet.public_key()

    def recv(self, cipher):
        # receive Bob's new public key and use it to perform a DH
        #self.dh_ratchet(bob_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        #print('[Alice]\tDecrypted message:', msg)
        return msg


############
# that thing will be in server
alice_server = Alice_server()
bob_server = Bob_server()

# Alice performs an X3DH while Bob is offline, using his uploaded keys
ROOT_KEY = alice_server.x3dh(bob_server)

# Bob comes online and performs an X3DH using Alice's public keys
ROOT_KEY = bob_server.x3dh(alice_server)
#when we have root_key, we send it to alice and bob

####################################################
#root_key sent from server will be a global variable, then when 
#we create Object Alice or Bob, we will assign root_key to self.sk

##########################
# Initialize their symmetric ratchets

#Create that thing in alice.py
alice = Alice() 
alice.init_ratchets()

#Create that thing in alice.py
bob = Bob()
bob.init_ratchets()
#########################

#In alice.py, when receive Bob's DHratchet.public_key()
# run alice.dh_ratchet(bob.DHratchet.public_key()) 
# in alice.py
if (alice.DHratchet is None):
    alice.dh_ratchet(bob.DHratchet.public_key())

#we don't need to create that thing in bob.py 

# in network, we send byte
# Alice sends Bob a message and her new DH ratchet public key
msg = b'Hello Bob!' 
key, iv = alice.send_ratchet.next()
cipher, pk = alice.send(msg, key, iv) # send from Alice to server with cipher, pk
print("cipher: ", cipher)
print("pk: ", pk)
# Encoding the public key
pk_encode = pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
print("pk_encode: ", pk_encode)

# we use pk_encode to send to server, and server send to Bob
# Decoding the encoded bytes back into a public key object
pk_decode = serialization.load_der_public_key(pk_encode, backend=default_backend())
print("pk_decode: ", pk_decode)

#now we can use pk_decode and pk for the same purpose
# then server forward it to bob 

#Bob run dh_ratchet with pk of Alice already sent, and decrypt "cipher"
bob.dh_ratchet(pk)
decrypt_msg = bob.recv(cipher)
print("decrypt_msg", decrypt_msg)

# Bob sends Alice 
msg = b'Hello to you too, Alice!'
key, iv = bob.send_ratchet.next()
cipher, pk = bob.send(msg, key, iv)

alice.dh_ratchet(pk)
decrypt_msg = alice.recv(cipher)
print("decrypt_msg", decrypt_msg)

# Bob uses that information to sync with Alice and send her a message
#cipher, pk = bob.send(alice, b'Hello to you too, Alice!')
#decrypt_msg = alice.recv(cipher, pk)
#print("decrypt_msg", decrypt_msg)

"""
alice.send(bob, b'Halo Bob!')
bob.send(alice, b'Halo Alice!')

alice.send(bob, b'1')
bob.send(alice, b'2')

#alice.send(bob, b'1')
#bob.send(alice, b'2')

#alice.send(bob, b'Halo Bob!')

# Print out the matching pairs
#print('[Alice]\tsend ratchet:', list(map(b64, alice.send_ratchet.next())))
#print('[Bob]\trecv ratchet:', list(map(b64, bob.recv_ratchet.next())))
#print('[Alice]\trecv ratchet:', list(map(b64, alice.recv_ratchet.next())))
#print('[Bob]\tsend ratchet:', list(map(b64, bob.send_ratchet.next())))
"""