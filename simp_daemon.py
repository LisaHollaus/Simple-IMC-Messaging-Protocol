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

        # Initialize the socket for communication with a client
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
        self.client_socket.bind((self.daemon_ip, self.port_to_client))

        self.running = True  # Track whether the daemon is running or stopped
        self.available = True  # Track whether the daemon is busy or available (client_ip)
        self.chat_partner = None  # IP and port of the current chat partner (if any)
        self.current_user = None  # Username of the current user (if any)

        self.chat_requests = {} # Track pending chat requests (client_ip: username)

    def start(self):
        """
        Main loop for the daemon.

        """
        print(f"Starting daemon at {self.daemon_ip}...")

        # connection to client
        self.connection_to_client()

        while self.running:  # Loop until the daemon is stopped
            data, addr = self.client_socket.recvfrom(1024)  # wait for client message
            self.handle_message_client(data, addr)  # process the incoming message

            # check if there any chat requests
            # if there are chat requests, handle them and forward to the client

            # if there are no chat requests, tell the client that there are no chat requests



    def connection_to_client(self):
        """
        Build the connection to the client before asking for the username.
            1. Receive a connection request from the client (PING)
            2. Respond to the client (PONG)
            3. If the response is positive, proceed with the client setup
            4. Receive the username from the client (CONNECT)
            5. Respond to the client with a welcome message and check for pending chat requests
        """
        print(f"Waiting for client connection at {self.daemon_ip}:{self.port_to_client}...")

        try:
            while True:
                data, addr = self.client_socket.recvfrom(1024) # wait for client message
                self.handle_message_client(data, addr)  # process the incoming message and send






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

        elif operation == "CONNECT":
            self.current_user = payload

            # check if there are any pending chat requests
            if len(self.chat_requests) > 0:
                response = self.get_requests()
            else:
                response = f"CONNECT|Welcome, {self.current_user}! You currently have no pending chat requests.

        elif operation == "CHAT":
            pass

        elif operation == "QUIT":
            self.available = True
            self.current_user = None
            response = "QUIT|You have been disconnected."
        else:
            response = "ERROR|Unknown operation."

        self._send_message_client(response, addr)

    def _send_message_client(self, message, addr):
        """
        Send a message to the client.
        """
        self.client_socket.sendto(message.encode('ascii'), addr)


    def get_requests(self, addr):
        """
        Get the list of pending chat requests.
        """
        requests = f"CONNECT|Welcome, {self.current_user}! You have pending chat requests from:\n"
        for client_ip, username in self.chat_requests.items():
            requests += f"IP: {client_ip} | Username: {username}\n"

        # send the list of pending chat requests to the client
        requests += "Would you like to chat with any of these users? \nEnter username or 'NO'."
        self._send_message_client(requests, addr)

        # receive the response from the client (CHAT|username) or (CHAT|NO)
        while True:
            data, addr = self.client_socket.recvfrom(1024)
            response = data.decode('ascii').split('|')

            if response[0] == "CONNECT":
                if response[1].upper() == "NO":
                    return "CONNECT|" # continue with the client setup
                elif response[1] in self.chat_requests.values():
                    # connect to the chat partner
                    # skip forward to the chat setup
                    # remove the chat request from the list
                    # return?
                    # get out of this loop and into the chat partner setup
                    pass # placeholder
            response = "ERROR|Invalid response. Please enter a valid username or 'NO'."







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
