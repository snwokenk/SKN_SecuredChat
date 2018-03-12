from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor

from SKN_Crypto import SKNPKI, SKNEncryption
from ChatClient import ChatClientFactory
from threading import Timer


class ChatServer(Protocol):
    def __init__(self, factory, chat_client_factory_instance):
        super().__init__()
        self.factory = factory
        self.pubkey_of_peer_hex = None
        self.message_state = list()
        self.chatclientfactory = chat_client_factory_instance
        self.enc_instance = SKNEncryption()  # using instance method get_key_iv can get iv and key
        self.chatEnabled = False

    def connectionMade(self):
        self.chatclientfactory.stopTrying()

    def dataReceived(self, data):
        data = data.decode()
        if self.chatEnabled:
            data = self.enc_instance.decrypt_msg(data).decode()
            print("\nother: ", data)
            print(">>> ", end="")
        else:
            if self.message_state:
                # self.chatEnabled is set to true and a separate thread for writing creating. Now any message sent
                # to you is decoded and printed, without blocking reactor, allowing for simulate
                first_data = self.enc_instance.decrypt_msg(data).decode()
                print(first_data)
                self.chatEnabled = True
                self.transport.write(data.encode())
                reactor.callInThread(self.sendMsg, self.enc_instance)

            else:  # This part is first executed on connection. self.message_state is empty

                # add to message_state list make self.medsage_state truthy. could use a variable and set to true
                self.message_state.append(len(self.message_state))

                # set pubkey_of_peer_hex to received data (which should be pubkey)
                self.pubkey_of_peer_hex = data

                # turn to bytes to be used to encrypt AES symmetric keys. This will be used for communication
                pubkey = bytes.fromhex(self.pubkey_of_peer_hex)

                # encrypt AES symmetric key and iv with pubkey
                aes_key_iv = SKNPKI.encrypt_with_pubkey(pubkey_in_bytes=pubkey,
                                                        message=self.enc_instance.get_key_iv(in_hex=True, in_json=True),
                                                        in_json=True, is_hex=True)

                # send encrypted AES symmetric key to peer. This key will be used in communication
                self.transport.write(aes_key_iv.encode())

    def sendMsg(self, encryption_instance):
        while True:
            print(">>> ", end="")
            msg = input()
            print("\nYou: {}".format(msg))
            enc_msg = encryption_instance.encrypt_msg(msg, in_hex=True).encode()
            self.transport.write(enc_msg)


class ChatServerFactory(Factory):

    def __init__(self):
        super().__init__()
        self.PKIClass = SKNPKI
        self.EncryptClass = SKNEncryption

    def buildProtocol(self, addr):
        return ChatServer(factory=self, chat_client_factory_instance=ChatClientFactory())

if __name__ == '__main__':
    reactor.listenTCP(55500, ChatServerFactory())
    reactor.run()