from twisted.internet.protocol import Protocol, ReconnectingClientFactory, connectionDone
from twisted.internet import reactor
from twisted.internet.defer import Deferred

from SKN_Crypto import SKNPKI, SKNEncryption

import json, time


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
        """
        public/private key pair created on connection and public key sent to listening side

        :return:
        """
        peer = self.transport.getPeer()
        pubkey1 = self.pki.publicKey.hex().encode()
        self.transport.write(pubkey1)

    def dataReceived(self, data):
        data = data.decode()

        if self.chatEnabled:  # This is executed at the 3rd message and greater

            # decrypt data with AES key received in the first message
            data = self.enc_instance.decrypt_msg(data).decode()

            # display the text
            print("\nother: ", data)
            print(">>> ", end="")

        else:

            if self.message_state:  # This executes on the second message

                # enable chat, any messages sent after second will just be printed out.
                self.chatEnabled = True

                # decrypt text with AES key provided by peer
                data = self.enc_instance.decrypt_msg(data).decode()

                # display text
                print(data)

                # create a separate thread, using callinThread (not callFromThread), for replying without blocking
                reactor.callInThread(self.sendMsg, self.enc_instance)

            else:  # executed first. self.message_state empty. Expecting hex of AES key/iv encrypted with own pubkey

                # add to message_state list make self.medsage_state truthy. could use a variable and set to true
                self.message_state.append(len(self.message_state))

                # SKNPKI turns hex into json string and string into list. Then decrypts key/;iv with private key
                self.aes_key_iv_list = json.loads(SKNPKI.decrypt_with_privkey(self.pki.privateKey,
                                                                              cipher_text=data,
                                                                              is_hex_and_json=True))

                # using the AES key and IV, instantiate an SKNEncryption class.
                self.enc_instance = SKNEncryption(key=bytes.fromhex(self.aes_key_iv_list[0]),
                                                  iv=bytes.fromhex(self.aes_key_iv_list[1]))

                # instance of SKNEncryption now used to encrypt a test message "Message Now Encrypted"
                msg = self.enc_instance.encrypt_msg("Message Now Encrypted", in_hex=True).encode()

                # send encrypted test message to peer
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