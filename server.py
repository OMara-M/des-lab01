
import socket

from crypto import KeyManager, DES

class Server:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.addr, self.port))
        self.s.listen(1)
        self.conn, self.addr = self.s.accept()
        print("server running")

    def send(self, msg_bytes: bytes):
        self.conn.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.conn.recv(buffer_size)

        return msg_bytes

    def close(self):
        self.conn.close()


if __name__ == '__main__':
    server = Server('localhost', 9999)
    key = KeyManager.read_key('key.txt')
    des = DES(key)

    while True:
        print("waiting for transmission")
        cipher_text = server.recv()
        print("From client: %s" % cipher_text)
        msg = des.decrypt(cipher_text)
        print("decrypted msg: %s\n" % msg)

        msg = input('> ')
        if msg == 'exit':
            break
        cipher_text = des.encrypt(msg)
        print("Transmitting cipher: %s\n" % cipher_text)
        server.send(cipher_text)

    server.close()
