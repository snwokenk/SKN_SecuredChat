from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

import os, json

# TODO: turn AES to Mode_EAX


class SKNEncryption:
    """
    Used For AES symmetic key encryption and decryption
    view: https://pycryptodome.readthedocs.io/en/stable/src/cipher/modern.html#eax-mode
    for instructions
    """
    def __init__(self, key=None, iv=None, nonce=None):
        self.key = os.urandom(32) if key is None else key
        self.iv = Random.new().read(AES.block_size) if iv is None else iv
        self.cipher = AES.new(self.key, mode=AES.MODE_EAX)
        self.nonce = self.cipher.nonce

        # print("This is key and nonce", self.key,'this is nonce', self.nonce)

    def encrypt_msg(self, msg, in_hex=False):

        try:
            msg = msg.encode()
        except AttributeError:
            pass

        ciphertext, tag = self.cipher.encrypt_and_digest(plaintext=msg)

        cipher_text = [ciphertext.hex(), tag.hex(), self.nonce.hex()]
        # if in_hex is True, encode string then turn to hex
        return json.dumps(cipher_text).encode().hex() if in_hex else cipher_text

    def decrypt_msg(self, cipher_msg):
        try:
            cipher_msg = bytes.fromhex(cipher_msg)
        except ValueError as e:
            return b''
        except TypeError as f:
            if isinstance(cipher_msg, int):
                return b''

        # decode bytes
        cipher_msg = cipher_msg.decode()

        # turn to python object
        cipher_msg = json.loads(cipher_msg)
        cipher_text, tag, nonce = [bytes.fromhex(msg) for msg in cipher_msg]


        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)

        try:
            return cipher.decrypt_and_verify(cipher_text, tag)
        except (ValueError, KeyError) as e:
            print(e)
            print("Incorrect decryption")

    # def decrypt_msg(self, cipher_msg):
    #     try:
    #         cipher_msg = bytes.fromhex(cipher_msg)
    #     except ValueError as e:
    #         print(e)
    #         return b''
    #     except TypeError as f:
    #         print(f)
    #         if isinstance(cipher_msg, int):
    #             return b''
    #
    #     # decode bytes
    #     cipher_msg = cipher_msg.decode()
    #
    #     # turn to python object
    #     cipher_msg = json.loads(cipher_msg)
    #     cipher_text, tag, nonce = [bytes.fromhex(msg) for msg in cipher_msg]
    #     print(cipher_msg)
    #
    #     cipher = AES.new(self.key, AES.MODE_CFB, self.iv)
    #     return cipher.decrypt(cipher_msg)[len(self.iv):]

    def get_key_iv(self, in_hex=False, in_json=False):

        if in_hex:
            if in_json:
                return json.dumps([self.key.hex(), self.iv.hex()])
            return [self.key.hex(), self.iv.hex()]
        else:
            return [self.key, self.iv]

    def get_key_and_nonce(self, in_hex=False, in_json=False):
        """
        gets key and nonce
        :param in_hex: should be in hex
        :param in_json: should be in json
        :return:
        """
        if in_hex:
            if in_json:
                return json.dumps([self.key.hex(), self.nonce.hex()])
            return [self.key.hex(), self.nonce.hex()]
        else:
            return [self.key, self.nonce]



class SKNPKI:
    def __init__(self):
        self.privateKey = None
        self.publicKey = None

    def generate_keys(self):
        """
        run this once connection is made,
        these keys will be used to encrypt AES key for conversation
        :return:
        """
        print("begin generating public/private key pair")
        # generate RSA 4096 Key Pair
        key = RSA.generate(4096)


        # store RSA private key in
        self.privateKey = key.exportKey("DER")
        self.publicKey = key.publickey().exportKey("DER")
        print('private/pubkey generated and loaded')

    @staticmethod
    def encrypt_with_pubkey(pubkey_in_bytes, message, is_hex=False, in_json=False):
        message = message.encode()
        pub_key = RSA.importKey(pubkey_in_bytes)
        sha256_cipher = PKCS1_v1_5.new(pub_key)
        h = SHA256.new(message).digest()

        cipher_text = sha256_cipher.encrypt(message + h)

        if is_hex:
            if in_json:
                return json.dumps(cipher_text.hex())
            return cipher_text.hex()
        else:
            return cipher_text

    @staticmethod
    def decrypt_with_privkey(privkey_in_bytes, cipher_text, is_hex_and_json):

        if is_hex_and_json:
            cipher_text = json.loads(cipher_text)
            cipher_text = bytes.fromhex(cipher_text)

        dsize = SHA256.digest_size

        priv_key = RSA.importKey(privkey_in_bytes)

        cipher = PKCS1_v1_5.new(priv_key)
        sentinel = Random.new().read(32)
        message = cipher.decrypt(cipher_text, sentinel)
        h_digest = SHA256.new(message[:-dsize]).digest()

        if h_digest == message[-dsize:]:

            return message[:-dsize].decode()



def turn_hex_bytes(hex_msg, toHex=False):
    if toHex and isinstance(hex_msg, bytes):
        return hex_msg.hex()
    elif toHex and not isinstance(hex_msg, bytes):
        return "0"
    try:
        byte_text = bytes.fromhex(hex_msg)
    except TypeError:
        byte_text = b''

    return byte_text


if __name__ == '__main__':

    # t = SKNPKI()
    # t.generate_keys()
    #
    # cipher_text = SKNPKI.encrypt_with_pubkey(t.publicKey, "Samuel")
    # print(cipher_text)
    # plain_text = SKNPKI.decrypt_with_privkey(t.privateKey, cipher_text, is_hex_and_json=False)
    # print(plain_text)


    l = turn_hex_bytes("samuel", toHex=True)
    print(l)
    p = SKNEncryption()
    p1 = p.encrypt_msg(b"samuel", in_hex=True)
    b = SKNEncryption(key=p.key, iv=p.iv).decrypt_msg(p1)

    p2 = p.encrypt_msg(b'Hello', in_hex=True)

    # print(type(p1), p1)
    # print(b)
    # print(p1)
    # print(b)
    # print()
    # print(p.iv, p.key)
    # print()
    # print(p.iv, p.key)