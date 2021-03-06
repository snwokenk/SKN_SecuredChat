from twisted.internet.protocol import Protocol, ReconnectingClientFactory, connectionDone
from twisted.internet.error import ReactorNotRunning
from twisted.internet import reactor
from twisted.internet.defer import Deferred

from SKN_Crypto import SKNPKI, SKNEncryption

import json, time


class ChatClient(Protocol):
    """
    When connection is made, ChatClient sends public key to chat server
    and receives public key encrypted
    """
    def __init__(self, factory):
        super().__init__()
        self.pki = SKNPKI()
        self.pki.generate_keys()
        self.aes_key_nonce_list = None  # list [AES_KEY, IV] both in hexadecimal format
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

                # display test text "Message Now Encrypted"
                print(data)

                # create a separate thread, using callinThread (not callFromThread), for replying without blocking
                reactor.callInThread(self.sendMsg, bytes.fromhex(self.aes_key_nonce_list[0]))

            else:  # executed first. self.message_state empty. Expecting hex of AES key/iv encrypted with own pubkey

                # add to message_state list make self.medsage_state truthy. could use a variable and set to true
                self.message_state.append(len(self.message_state))

                # SKNPKI turns hex into json string and string into list. Then decrypts key/;iv with private key
                self.aes_key_nonce_list = json.loads(SKNPKI.decrypt_with_privkey(self.pki.privateKey,
                                                                                 cipher_text=data,
                                                                                 is_hex_and_json=True))

                # using the AES key and IV, instantiate an SKNEncryption class.
                self.enc_instance = SKNEncryption(key=bytes.fromhex(self.aes_key_nonce_list[0]),
                                                  nonce=bytes.fromhex(self.aes_key_nonce_list[1]))


                # instance of SKNEncryption now used to encrypt a test message "Message Now Encrypted"
                msg = self.enc_instance.encrypt_msg("Message Now Encrypted", in_hex=True).encode()

                # send encrypted test message to peer
                self.transport.write(msg)

    def sendMsg(self, key):

        while True:
            print(">>> ", end="")
            msg = input()
            if msg and not msg == "exit":
                print("\nYou: {}".format(msg))
                encryption_instance = SKNEncryption(
                    key=key)
                enc_msg = encryption_instance.encrypt_msg(msg, in_hex=True).encode()
                self.transport.write(enc_msg)
            elif msg == "exit":
                break
            else:
                continue

        self.transport.loseConnection()

    def connectionLost(self, reason=connectionDone):
        try:
            reactor.stop()
        except ReactorNotRunning:
            print("\nreactor not running")
        else:
            print("\nConnection Lost: Press Enter To Exit")


class ChatClientFactory(ReconnectingClientFactory):

    def __init__(self):
        super().__init__()
        self.EncryptClass = SKNEncryption

    def buildProtocol(self, addr):
        return ChatClient(factory=self)

def runThisClient():
    reactor.connectTCP("127.0.0.1", 55507, ChatClientFactory())
    reactor.run()

if __name__ == '__main__':
    try:
        runThisClient()

    except KeyboardInterrupt:
        try:
            reactor.stop()
        except ReactorNotRunning:
            pass
        finally:
            print("SKNChat Stopped")
    except SystemExit:
        print("SKNChat Stopped")

    else:
        print("SKNChat Exited")