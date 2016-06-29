import socket
import email
from settings import DETECTORS


class ClientState(object):
    Ignore, Retrieve = range(2)


class Client(object):
    def __init__(self, server, sock, addr, dest_host, dest_port):
        self.server = server
        self.sock = sock
        self.addr = addr
        self._dest_host = dest_host
        self._dest_port = dest_port
        self._connect_dest()

        # State defines when we should extract an .eml file
        self.state = ClientState.Ignore

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
            self.handle_command(sock, data)
        # Data came from POP3 Server
        else:
            self.handle_response(sock, data)

    def handle_response(self, sock, data):
        print "[Server -> Client] " + repr(data)
        # Incoming response
        if not data.startswith("+OK"):
            self.sock.send(data)
            return

        if self.state != ClientState.Retrieve:
            self.sock.send(data)
            return

        # Make sure we received all data (read until '.')
        while not data.endswith(".\r\n"):
            data = data + sock.recv(1000)

        # Extract header and mail
        header, eml_data = data.split("\r\n", 1)
        eml_data = eml_data[:eml_data.rfind(".\r\n")]

        print "[Server -> Client] Searching for attachments.... "

        msg = email.message_from_string(eml_data)

        payload = msg.get_payload()
        if len(payload) > 0:
            print "[Server -> Client] %d payloads found" % (len(payload),)
            msg.set_payload(self.process_payload(payload))

        # Send data
        new_data = msg.as_string(unixfrom=True)
        self.sock.send("+OK %d octets\r\n%s.\r\n" % (len(new_data), new_data))
        # self.sock.send(data)
        self.state = ClientState.Ignore

    def process_payload(self, payloads):
        new_payloads = []
        for attachment in payloads:
            file_content = attachment.get_payload(decode=True)

            # If payload is an email or not a file
            if file_content is None:
                new_payloads.append(attachment)
                continue

            print '>>> Applying detectors (%r)' % (attachment.get_content_type(),)
            # Apply detectors
            if any(detector.is_malicious(file_content) for detector in DETECTORS):
                continue
            new_payloads.append(attachment)

        return new_payloads

    def handle_command(self, sock, data):
        print "[Client -> Server] " + data
        self.sock_pop3.send(data)
        # If retrieve message
        if data.startswith("RETR"):
            print "[Client -> Server] ## RETR ##"
            self.state = ClientState.Retrieve

