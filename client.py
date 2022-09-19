
import socket
from crypto import KeyManager, DES


class Client:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.addr, self.port))

    def send(self, msg_bytes: bytes):
        self.s.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.s.recv(self.buffer_size)

        return msg_bytes

    def close(self):
        self.s.close()


if __name__ == '__main__':
    client = Client('localhost', 9999)
    key = KeyManager().read_key('key.txt')
    des = DES(key)

    while True:
        msg = input('> ')
        if msg == 'exit':
            break
        cipher_text= des.encrypt(msg)
        print("transmitting cipher: %s\n" % cipher_text)
        client.send(cipher_text)

        cipher_text = client.recv()
        print("From server: %s" % cipher_text)
        msg = des.decrypt(cipher_text)
        print("decrypted msg: %s\n" % msg)
        
    client.close()
