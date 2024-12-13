import socket
import sys
import simp_check_functions as check
import threading
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

        self.current_user = None  # Username of the current user (if any)
        self.chat_partner = {}  # IP and username of the current chat partner (if any) {client_ip: username}
        self.chat_requests = {}  # Track pending chat requests {client_ip: username}

    def start(self):
        """
        Main loop for the daemon.

        Start the daemon and run separate threads for listening to new connections
        and handling the current chat.

        """
        print(f"Starting daemon at {self.daemon_ip}...")

        # Create threads
        listener_thread = threading.Thread(target=self.listen_for_client_connections, daemon=True)
        chat_thread = threading.Thread(target=self.handle_current_chat, daemon=True)

        # Start threads
        listener_thread.start()
        chat_thread.start()

        # Keep the main thread running
       # try:
        #    while self.running:
         #       pass
        #except KeyboardInterrupt:
         #   print("\nShutting down daemon...")
          #  self.running = False


    def listen_for_client_connections(self):
        """
            Listen for new connection requests on the client socket.

            Build the connection to the client before asking for the username.
            1. Receive a connection request from the client (PING)
            2. Respond to the client (PONG)
            3. If the response is positive, proceed with the client setup
            4. Receive the username from the client (CONNECT)
            5. Respond to the client with a welcome message and check for pending chat requests

        """
        print("Listening for new connections...")
        while self.running:
            try:
                data, addr = self.client_socket.recvfrom(1024)
                self.handle_message_client(data, addr)
            except Exception as e:
                print(f"Error in listening for connections: {e}")

    def handle_current_chat(self):
        """
        Handle the current chat session with the client.
        """
        while self.running:
            if self.chat_partner:
                try:
                    # Receive and forward chat messages

                    # Forward message to chat partner
                    pass

                except Exception as e:
                    print(f"Error in chat handling: {e}")
            else:
                # No active chat; yield CPU
                threading.Event().wait(0.5)  # Sleep for 0.5 seconds




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
            print("User connected: ", self.current_user)

            # check if there are any pending chat requests
            if len(self.chat_requests) > 0:
                response = self._get_requests(addr)
            else:
                response = f"CONNECT|Welcome, {self.current_user}! You currently have no pending chat requests."

        elif operation == "CHAT":
            if not payload:  # empty payload = waiting for chat partner
                self.wait_for_chat_partner(addr)
            else:
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


    def _get_requests(self, addr):
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
                    return "CONNECTING|"  # continue with the client setup
                elif response[1] in self.chat_requests.values():
                    # connect to the chat partner
                    ip = [ip for ip, user in self.chat_requests.items() if user == response[1]][0]  # get the IP
                    self.chat_partner = {ip: response[1]}  # set the chat partner

                    # remove the chat request from the list
                    self.chat_requests.pop(ip)
                    return f"CONNECTING|connecting to user:{response[1]}... "

            response = "ERROR|Invalid response. Please enter a valid username or 'NO'."


    def wait_for_chat_partner(self, addr):
        """
        Wait for incoming chat requests from other users.
        """
        pass
        # wait for SYN datagram from the other daemon
        # if received, send a SYN+ACK datagram to the other daemon
        # if the other daemon responds with ACK, start the chat




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

    #def stop(self):
        """
        Stop the daemon gracefully.
        """
     #   print("Shutting down daemon...")
      #  self.socket.close()




def show_usage():
    print("Usage: python simp_daemon.py <IP address>")


# callable from command line example: python simp_daemon.py 127.0.0.1 (or any other IP address)
if __name__ == "__main__":
    if len(sys.argv) != 2:
        show_usage()
        exit(1)

    daemon_ip = sys.argv[1]
    # validate IP address format
    check = check.is_valid_ip(daemon_ip)
    if not check:
        print(f"Error: {daemon_ip} is not a valid IP address.")
        exit(1)

    daemon = SimpDaemon(daemon_ip)  # Initialize the daemon
    daemon.start()  # wait for connection to client
