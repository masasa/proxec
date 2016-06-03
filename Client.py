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
            print "[Client -> Server] " + data
            self.sock_pop3.send(data)
        # Data came from POP3 Server
        else:
            print "[Server -> Client] " + data
            self.sock.send(data)