import socket
import select
import argparse
from client import Client


# Amount of users that can wait in line
LISTEN_BACKLOG = 200


class POP3Proxy(object):
    """
    Main POP3 Proxy server.
    This server utilizes Reactor design pattern to handle multiple clients in a single process.
    """
    def __init__(self, host, port, dest_host, dest_port):
        self._dest_host = dest_host
        self._dest_port = dest_port

        # Start server
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(LISTEN_BACKLOG)

        # Connected clients dictionary
        self.clients = {}

    def register(self, sock, client):
        """
        Register a new client
        Args:
            sock: client socket
            client: Client() object that represents the client
        """
        self.clients[sock] = client

    def unregister(self, sock):
        """
        Unregister a client socket
        Args:
            sock: client socket
        """
        del self.clients[sock]

    def loop(self):
        """
        Server main loop (handle new clients and handle traffic)
        """
        while True:
            input_ready, output_ready, except_ready = select.select([self.server] + self.clients.keys(), [], [])

            # For each input socket
            for sock in input_ready:

                # Case: Accept
                if sock is self.server:
                    self._handle_accept()
                    continue

                # Case: Socket related
                self._handle_ready(sock)

    def _handle_accept(self):
        sock, addr = self.server.accept()
        print '>> New connection from: %s:%d' % addr
        # client will register itself
        Client(self, sock, addr, self._dest_host, self._dest_port)

    def _handle_ready(self, sock):
        """
        Data is ready to be read from socket
        """
        self.clients[sock].handle_ready(sock)


def run_server(listen_ip, listen_port, dest, dest_port):
    print ">> Starting Proxy security layer"
    print ">>      listening on: %s:%d   forwarding traffic to: %s:%d" % (listen_ip, listen_port, dest, dest_port)

    server = POP3Proxy(listen_ip, listen_port, dest, dest_port)

    try:
        server.loop()
    except KeyboardInterrupt:
        print "Ctrl C - Stopping server. Bye Bye"


def main():
    parser = argparse.ArgumentParser(description='POP3 Security Layer proxy')
    parser.add_argument('destination', help='destination to forward packets (pop3 server)')
    parser.add_argument('--port', help='destination port (default: 110)', type=int, default=110)
    parser.add_argument('--listen', help='listening ip', default="0.0.0.0")
    parser.add_argument('--listen-port', help='listening port', default=20020, type=int)

    args = parser.parse_args()
    run_server(args.listen, args.listen_port, args.destination, args.port)

if __name__ == '__main__':
    main()

