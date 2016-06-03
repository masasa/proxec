import socket
import select


class Client(object):
    def __init__(self, server, sock, addr, dest_host, dest_port):
        self.server = server
        self.sock = sock
        self.addr = addr
        self._dest_host = dest_host
        self._dest_port = dest_port
        self._connect_dest()

        server.register(sock, self)
        server.register(self.sock_pop3, self)

    def _connect_dest(self):
        sock_pop3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_pop3.connect((self._dest_host, self._dest_port))
        self.sock_pop3 = sock_pop3

    def handle_closed(self):
        self.server.unregister(self.sock)
        self.server.unregister(self.sock_pop3)

    def handle_ready(self, sock):
        data = sock.recv(10000)

        # Connection closed
        if len(data) == 0:
            self.handle_closed()

        # Data came from client
        if sock == self.sock:
            self.sock_pop3.send(data)
        # Data came from POP3 Server
        else:
            self.sock.send(data)


class POP3Proxy(object):
    def __init__(self, host, port, dest_host, dest_port):
        self._dest_host = dest_host
        self._dest_port = dest_port

        # Start server
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))

        # Amount of users that can wait in line
        self.server.listen(200)

        self.clients = {}

    def register(self, sock, client):
        self.clients[sock] = client

    def unregister(self, sock):
        del self.clients[sock]

    def loop(self):
        while True:
            input_ready, output_ready, except_ready = select.select([self.server] + self.clients.keys(), [], [])

            # For each input socket
            for sock in input_ready:

                # Case: Accept
                if sock is self.server:
                    self.handle_accept()
                    continue

                # Case: Socket related
                self.handle_ready(sock)

    def handle_accept(self):
        sock, addr = self.server.accept()
        print '>> New connection from: %s:%d' % addr
        Client(self, sock, addr, self._dest_host, self._dest_port)

    def handle_ready(self, sock):
        self.clients[sock].handle_ready(sock)


def main():
    server = POP3Proxy('0.0.0.0', 20020, "127.0.0.1", 9999) #"#"mail.webfaction.com", 110)

    try:
        server.loop()
    except KeyboardInterrupt:
        print "Ctrl C - Stopping server. Bye Bye"


if __name__ == '__main__':
    main()

