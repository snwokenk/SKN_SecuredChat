from twisted.internet.protocol import Protocol, ReconnectingClientFactory, connectionDone
from twisted.internet import reactor
from twisted.internet.defer import Deferred

from SKN_Crypto import SKNPKI, SKNEncryption

import json, time

from multiprocessing import Process


class ChatClient(Protocol):
    def __init__(self, factory):
        super().__init__()
        self.pki = SKNPKI()
        self.pki.generate_keys()
        self.aes_key_iv_list = None  # list [AES_KEY, IV] both in hexadecimal format
        self.message_state = list()
        self.chatEnabled = False
        self.enc_instance = None

    def connectionMade(self):
        peer = self.transport.getPeer()
        pubkey1 = self.pki.publicKey.hex().encode()
        self.transport.write(pubkey1)

    def dataReceived(self, data):
        data = data.decode()
        if self.chatEnabled:
            data = self.enc_instance.decrypt_msg(data).decode()
            print("\nother: ", data)
            print(">>> ", end="")
        else:
            if self.message_state:
                self.chatEnabled = True
                data = self.enc_instance.decrypt_msg(data).decode()
                print(data)
                reactor.callInThread(self.sendMsg, self.enc_instance)

            else:
                # if message state is empty then message expected is encrypted list of AES KEY/IV
                self.message_state.append(len(self.message_state))
                self.aes_key_iv_list = json.loads(SKNPKI.decrypt_with_privkey(self.pki.privateKey,
                                                                              cipher_text=data,
                                                                              is_hex_and_json=True))

                self.enc_instance = SKNEncryption(key=bytes.fromhex(self.aes_key_iv_list[0]),
                                                  iv=bytes.fromhex(self.aes_key_iv_list[1]))
                msg = self.enc_instance.encrypt_msg("Message Now Encrypted", in_hex=True).encode()
                self.transport.write(msg)

    def sendMsg(self,  encryption_instance):
        while True:
            print(">>> ", end="")
            msg = input()
            print("\nYou: {}".format(msg))
            enc_msg = encryption_instance.encrypt_msg(msg, in_hex=True).encode()
            self.transport.write(enc_msg)

    def connectionLost(self, reason=connectionDone):
        print(reason)
        reactor.stop()


class ChatClientFactory(ReconnectingClientFactory):

    def __init__(self):
        super().__init__()
        self.EncryptClass = SKNEncryption

    def buildProtocol(self, addr):
        return ChatClient(factory=self)




if __name__ == '__main__':
    reactor.connectTCP("127.0.0.1", 55500, ChatClientFactory())

    reactor.run()