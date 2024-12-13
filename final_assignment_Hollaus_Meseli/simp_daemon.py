import socket
import sys
import simp_check_functions as check
from simp_protocol import *
from simp_check_functions import *

class SimpDaemon:
    def __init__(self, daemon_ip):
        """
        Initialize the daemon with the given IP and port.
        """
        self.daemon_ip = daemon_ip
        self.port_to_daemon = 7777  # Port for communication with other daemons
        self.port_to_client = 7778  # Port for communication with clients

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
        self.client_socket.bind((self.daemon_ip, self.port_to_client))

        self.running = True  # Track whether the daemon is running or stopped
        self.available = True  # Track whether the daemon is busy or available (client_ip)
        self.chat_partner = None  # IP and port of the current chat partner (if any)
        self.current_user = None  # Username of the current user (if any)

    def start(self):
        """
        Start the daemon and wait for incoming connections.
        """
        print(f"Starting daemon at {self.daemon_ip}...")
        self.handle_client()

    def handle_client(self):
        """
        Handles communication with one client on port 7778.
            - Build and run the client connection
        """

        print(f"Waiting for client connection at {self.daemon_ip}:{self.port_to_client}...")

        while self.running:  # Loop until the daemon is stopped
            data, addr = self.client_socket.recvfrom(1024)  # wait for client message
            self.handle_message_client(data, addr)  # process the incoming message





    def handle_message_client(self, data, addr):
        """
        Process incoming messages from the client and respond accordingly.
        """
        message = data.decode('ascii').split('|')  # Format: OPERATION|PAYLOAD
        operation = message[0]
        payload = message[1] if len(message) > 1 else None  # Extract the payload if it exists

        if operation == "PING":
            if not self.available:
                response = "ERROR|Daemon is busy with another user."
            else:
                self.available = False
                response = "PONG|Daemon is running."
            self._send_message_client(response, addr)

        elif operation == "CONNECT":
            self.current_user = payload
            response = f"CONNECTED|Welcome, {self.current_user}!"
            self._send_message_client(response, addr)

        elif operation == "CHAT":
            pass

        elif operation == "QUIT":
            self.available = True
            self.current_user = None
            response = "QUIT|You have been disconnected."
            self._send_message_client(response, addr)

        else:
            response = "ERROR|Unknown operation."
            self._send_message_client(response, addr)

    def _send_message_client(self, message, addr):
        """
        Send a message to the client.
        """
        self.client_socket.sendto(message.encode('ascii'), addr)






    def handle_daemon(self):
        """
        Handles communication with other daemons on port 7777.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((self.daemon_ip, self.port_to_daemon))
            while self.running:
                data, addr = sock.recvfrom(1024)
        # build and run daemon connection







    def handle_message(self, data, addr):
        """
        Process incoming messages and respond accordingly.
        """
        # Placeholder: Parse the SIMP datagram (type, operation, etc.)
        # Example: datagram_type, operation, user, payload = parse_datagram(data)

        # Logic for handling chat requests, errors, or termination
        if self.state == "available":
            print(f"Received chat request from {addr}")
            # Example: Respond with SYN+ACK
        elif self.state == "busy":
            print(f"Busy; rejecting request from {addr}")
            # Example: Respond with ERR + FIN

    def send_response(self, addr, datagram):
        """
        Send a response datagram to the specified address.
        """
        self.socket.sendto(datagram, addr)

    def stop(self):
        """
        Stop the daemon gracefully.
        """
        print("Shutting down daemon...")
        self.socket.close()



# callable from command line: python simp_daemon.py 192.168.1.1
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python simp_daemon.py <IP address>")
        exit(1)

    daemon_ip = sys.argv[1]
    # validate IP address format
    check = check.is_valid_ip(daemon_ip)
    if not check:
        print(f"Error: {daemon_ip} is not a valid IP address.")
        exit(1)

    daemon = SimpDaemon(daemon_ip)  # Initialize the daemon
    daemon.start()  # wait for connection to client
