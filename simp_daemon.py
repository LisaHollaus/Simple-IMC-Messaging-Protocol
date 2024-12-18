import socket
import sys
import simp_check_functions as check
import threading
from threading import Lock
#from simp_protocol import *
from simp_check_functions import *

class SimpDaemon:
    protocol = SimpProtocol()  # Creating an instance of SimpProtocol to make use of the class methods

    def __init__(self, daemon_ip):
        """
        Initialize the daemon with the given IP and port.
        """
        self.lock = Lock() # lock to serialize access to shared resources
        self.daemon_ip = daemon_ip
        self.port_to_daemon = 7777  # Port for communication with other daemons
        self.port_to_client = 7778  # Port for communication with clients

        # Initialize the socket for communication with a client
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
        self.client_socket.bind((self.daemon_ip, self.port_to_client))

        self.daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
        self.daemon_socket.bind((self.daemon_ip, self.port_to_daemon))

        self.running = True  # Track whether the daemon is running or stopped
        self.available = True  # Track whether the daemon is busy or available (client_ip)

        self.current_user = None  # Username of the current user (if any)
        self.chat_partner = {}  # IP and username of the current chat partner (if any) {client_ip: username}
        self.chat_requests = {}  # Track pending chat requests {client_ip: username}
        self.sequence_tracker = {}  # Track expected sequence numbers for chat partners {addr: expected_sequence_number}


    def set_chat_partner(self, addr, user):
        with self.lock:
            self.chat_partner[addr] = user


    def get_chat_partner(self):
        with self.lock:
            return self.chat_partner



    def start(self):
        """
        Main loop for the daemon.

        Start the daemon and run separate threads for listening to new connections
        and handling the current chat.

        """
        print(f"Starting daemon at {self.daemon_ip}...")

        # Create threads
        client_thread = threading.Thread(target=self.listen_for_client_connections, daemon=True)  # Listen for new connections
        chat_thread = threading.Thread(target=self.listen_for_client_connections, daemon=True)  # Handle the current chat session
        daemon_thread = threading.Thread(target=self.listen_to_daemons, daemon=True)  # Listen to other daemons and handle chat requests

        # Start threads
        client_thread.start()
        chat_thread.start()
        daemon_thread.start()

        # Keep the main thread running
        try:
            while self.running:
                pass
        except KeyboardInterrupt:
            self.stop()  # shutting down the daemon


    def listen_for_client_connections(self):
        """
            Listen for new connection requests on the client socket.

            Build the connection to the client before asking for the username.
            1. Receive a connection request from the client (PING)
            2. Respond to the client (PONG)
            3. If the response is positive, proceed with the client setup
            4. Receive the username from the client (CONNECT)
            5. Respond to the client with a welcome message and check for pending chat requests
            6. If there are pending chat requests, ask the client if they want to chat
            7. If the client accepts, connect to the chat partner
            8. Stop and wait for chat messages from the client until chat ends (QUIT)
        """

        while self.running:
            try:
                data, addr = self.client_socket.recvfrom(1024)
                self.handle_message_client(data, addr)
            except Exception as e:
                print(f"Error in listening for connections: {e}")

    def handle_message_client(self, data, addr):
        """
        Process incoming messages from the client and respond accordingly.
        """

        message = data.decode('ascii').split('|')  # Format: OPERATION|PAYLOAD
        operation = message[0]
        payload = message[1] if len(message) > 1 else None  # Extract the payload if it exists
        response = None

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

        elif operation == "CONNECTING":
            if not payload:
                # empty payload = waiting for chat partner
                self.wait_for_chat_partner(addr)

            else:
                # send chat request to the chat partner
                target_ip = payload.split(":")[1].strip()  # "request: {target_ip}"

                # try to connect to the chat partner
                connected, msg = self.three_way_handshake(target_ip)  # return two values (bool, error/username)

                if connected:
                    response = f"CONNECTING|Connected to user: {msg}"
                else:
                    response = f"ERROR| {msg}"

        elif operation == "CHAT":
            if self.chat_partner:
                # forward the message to the chat partner and vise versa
                self.forward_chat_messages(payload, addr)
            else:
                response = "ERROR|No chat partner available."

        elif operation == "QUIT":
            self.available = True
            self.current_user = None
            response = "QUIT|You have been disconnected."

        else:
            response = "ERROR|Unknown operation."

        self._send_message_client(response, addr)


    def forward_chat_messages(self, message, client_addr):
        """
        Forward a chat message to the chat partner.
        Create chat datagram and send it to the chat partner
        Receive answer and send it back to the client
        """

        chat_partner_addr = list(self.chat_partner.keys())[0]
        # Initial sequence number (alternate between 0 and 1 for retransmissions)
        sequence_number = self.sequence_tracker.get(chat_partner_addr, 1)  # Default is 1

        # create chat datagram
        response = protocol.create_datagram(
                HeaderType.CHAT,
                Operation.CONST,
                sequence_number,
                f"{self.current_user}",
                message
            )

        # send datagram and wait for ACK from the chat partner
        while True:
            try:
                self.daemon_socket.settimeout(5)  # Set a timeout for the response
                self.daemon_socket.sendto(response, chat_partner_addr)
                print(f"Message sent to chat partner {chat_partner_addr}.")

                header_info, data, addr = self.receive_datagram()  # Attempt to receive an ACK

                if addr == chat_partner_addr and header_info.operation == Operation.ACK and header_info.sequence_number == sequence_number:
                    print(f"ACK received.")
                    self.sequence_tracker[chat_partner_addr] = 1 - sequence_number # Toggle between 0 and 1
                    break
                else:
                    print(f"Unexpected response received: {header_info}, {data}")

            except socket.timeout:
                print(f"Timeout: No ACK received from {chat_partner_addr}. Retrying...")
                self.forward_chat_messages(message, client_addr)
                # Retransmit the same datagram (recursive call)

        # wait for the response from the chat partner (stop and wait)
        header_info, data, addr = self.receive_datagram()
        if header_info.type == HeaderType.CHAT and header_info.operation == Operation.CONST:
            # forward the message to the client
            response = f"CHAT| {data['payload']}"

        elif header_info.operation == Operation.FIN:
            # close the connection
            self.closing_connection(addr)
            response = f"QUIT|Chat partner has disconnected."

        else:
            # forward the error message to the client
            response = f"ERROR| {data['payload']}"
        self.client_socket.sendto(response, client_addr)



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

            #response = "ERROR|Invalid response. Please enter a valid username or 'NO'."



    def wait_for_chat_partner(self, addr):
        """
        Wait for incoming chat requests (SYN) from other users (daemon).
        Periodically check with the user if they want to keep waiting.
        """
        #global header_info
        while True:
            try:
                self.daemon_socket.settimeout(30)  # Set a timeout for the incoming chat requests
                # Wait to receive a datagram from another daemon
                header_info, data, daemon_addr = self.receive_datagram()

            except socket.timeout:
                print("No chat requests received.")
                # ask the user if they want to keep waiting
                message = "ERROR|No chat requests received. Do you want to keep waiting? (YES/NO)"
                self._send_message_client(message, addr)

                # receive the response from the client
                data, addr = self.client_socket.recvfrom(1024)
                response = data.decode('ascii').split('|')

                if response[0] == "CONNECTING":
                    # recall the function to wait for chat partner
                    self.wait_for_chat_partner(addr)

                elif response[0] == "QUIT":
                    break

            # Check if the received datagram is a SYN
            if header_info and header_info.operation == Operation.SYN:
                print(f"Received SYN from {daemon_addr}.")

                # Respond with a SYN+ACK
                syn_ack_datagram = protocol.create_datagram(
                    HeaderType.CONTROL,
                    Operation.SYN.value | Operation.ACK.value,
                    1,  # Sequence number
                    f"{self.current_user}",
                    ""  # Empty payload
                )
                self.daemon_socket.sendto(syn_ack_datagram, daemon_addr)
                print(f"Sent SYN+ACK to {daemon_addr}.")

                # Wait for ACK from the sender to complete the handshake
                self.daemon_socket.settimeout(5)  # Set timeout for the response
                try:
                    ack_header_info, ack_data, ack_addr = self.receive_datagram()
                    if ack_header_info.operation == Operation.ACK and ack_addr == daemon_addr:
                        print(f"ACK received from {daemon_addr}. Handshake complete.")

                        # Set the chat partner and break the loop
                        self.chat_partner = {daemon_addr[0]: data['user']}
                        return  # Exit the function after a successful handshake

                except socket.timeout:
                    print(f"Timeout waiting for ACK from {daemon_addr}. Restarting wait.")

            else:
                print(f"Unexpected datagram from {daemon_addr}. Ignoring...")



    def receive_datagram(self):
        """
        Receive a datagram from the client.
        Check if the datagram is valid and the sequence number is correct.
        Return datagram if valid, False otherwise
        """
        # wait for incoming datagrams
        data, addr = self.daemon_socket.recvfrom(1024)

        # check if the datagram is valid
        header_info = check_header(data)

        if not header_info.is_ok:
            print(f"Error parsing datagram from {addr}: {header_info.code}")
            error_response = protocol.create_datagram(
                HeaderType.CONTROL,
                Operation.ERR,
                0,  # Sequence number
                f"{self.current_user}",  # User
                header_info.code  # Error message
            )
            self.daemon_socket.sendto(error_response, addr)
            return False

        # Parse the datagram to extract the data and header info into a dictionary
        data = protocol.parse_datagram(data)

        # Check if the sequence number is correct
        expected_sequence = self.sequence_tracker.get(addr, 1)  # Default expected sequence is 1
        if header_info.sequence_number != expected_sequence:
            print(f"Unexpected sequence number from {addr}. Expected {expected_sequence}, got {header_info.sequence_number}.")
            error_response = protocol.create_datagram(
                HeaderType.CONTROL,
                Operation.ERR,
                0,
                f"{self.current_user}",
                "Invalid sequence number."
            )
            self.daemon_socket.sendto(error_response, addr)
            return False

        # Update the expected sequence number
        self.sequence_tracker[addr] = 1 - expected_sequence  # Toggle between 0 and 1

        return header_info, data, addr




    def handle_message(self,header_info, data, addr):
        """
        Process incoming messages and respond accordingly.
        """

        # Logic for handling chat requests from other daemons , when client is not busy (SYN)
        if self.available and header_info.operation == Operation.SYN:
            print(f"Received chat request from {addr}")

            # Save the chat request for later (handled by client loop)
            self.chat_requests[addr[0]] = data['user']  # Save the chat request {client_ip: username}

        else:
            print(f"Busy; automatically rejecting request from {addr}")
            # Respond with ERR followed by FIN datagram (close connection)
            response = protocol.create_datagram(
                HeaderType.CONTROL,
                Operation.ERR.value,
                1,  # Sequence number
                f"Daemon {daemon_ip}",  # User
                ErrorCode.BUSY_DAEMON
            )
            self.daemon_socket.sendto(response, addr)

            # send FIN datagram and close the connection
            self.closing_connection(addr)




    def three_way_handshake(self, addr):
        """
        Perform the three-way handshake with the other daemon.
        """
        # 1. Prepare the SYN datagram
        print(f"Starting three-way handshake with {addr}...")
        sequence_number = 1  # Initial sequence number

        syn_datagram = protocol.create_datagram(
            HeaderType.CONTROL,
            Operation.SYN,
            sequence_number,
            f"{self.current_user}",
            ""  # Empty payload
        )

        # 2. Send SYN and wait for SYN + ACK from the receiver (try only 3 times to avoid infinite loop)
        tries = 3
        while tries > 0:
            try:
                self.daemon_socket.sendto(syn_datagram, addr)
                print(f"SYN sent to {addr} with sequence {sequence_number}.")

                self.daemon_socket.settimeout(5)  # Set a timeout for the response
                header_info, data, addr = self.receive_datagram()

                # If the received operation is SYN + ACK
                if header_info and header_info.operation == (Operation.SYN.value | Operation.ACK.value) and header_info.sequence_number == sequence_number:
                    print(f"SYN+ACK received from {addr}.")
                    break
                elif header_info and header_info.operation == Operation.ERR:
                    print(f"Error received from {addr}: {data}")
                    return False, data
                else:
                    print(f"Unexpected datagram received from {addr}, resending SYN.")
                    self.daemon_socket.sendto(syn_datagram, addr)

            except socket.timeout:
                print(f"Timeout waiting for SYN+ACK from {addr}. resending SYN.")
                # resend SYN
                tries -= 1

        if tries == 0:
            print(f"Failed to establish connection with {addr}.")
            return False, "Connection failed."

        # 3. Sender replies with ACK
        ack_datagram = protocol.create_datagram(
            HeaderType.CONTROL,
            Operation.ACK,
            sequence_number,  # Sequence number
            f"{self.current_user}",  # User
            ""  # Empty payload
        )
        self.daemon_socket.sendto(ack_datagram, addr)
        print(f"ACK sent to {addr}. Handshake complete.")
        self.sequence_tracker[addr] = 1 - sequence_number  # Initialize expected sequence number for chat partner

        # set the chat partner
        self.chat_partner = {addr: data['user']}
        return True, data['user']  # return the chat partner's username

    def closing_connection(self, addr):
        """
        Send a FIN datagram to the client
        Wait for the client to respond with ACK
        Close the connection.
        """
        # create FIN datagram
        response = protocol.create_datagram(
            HeaderType.CONTROL,
            Operation.FIN,
            1,  # Sequence number
            f"Daemon {daemon_ip}",  # User
            ""  # Empty payload
        )

        self.daemon_socket.settimeout(5)  # Set timeout to 5 seconds for receiving
        while True:
            try:
                self.daemon_socket.sendto(response, addr)

                # wait for ACK from the client
                header_info, data, addr = self.receive_datagram()

                # check if the received datagram is an ACK
                if header_info and header_info.operation == Operation.ACK:
                    print(f"ACK received from {addr}")
                    break
                else:
                    print(f"Resending FIN to {addr}")

            except socket.timeout:
                # Timeout occurred, resend FIN
                print(f"Timeout waiting for ACK from {addr}, resending FIN")

        # self.available = True # in case of successful connection before




    def listen_to_daemons(self):
        """
        Handles communication with other daemons on port 7777.
        """
        protocol = SimpProtocol()  # Create an instance of SimpProtocol

        print(f"Listening for daemon communication on {self.port_to_daemon}...")

        # build and run daemon connection
        while self.running:
            header_info, data, addr = self.receive_datagram()

            if header_info:  # check if the datagram is valid (False if not)
                try:
                    # handle the message
                    self.handle_message(header_info, data, addr)

                except Exception as e:
                    print(f"Error handling message from {addr}: {e}")
                    error_response = protocol.create_datagram(
                            #header_info,  # Header info
                            HeaderType.CONTROL,
                            Operation.ERR,
                            0,  # Sequence number
                            f"Daemon {daemon_ip}",  # User
                            header_info.code  # Error message
                        )
                    self.daemon_socket.sendto(error_response, addr)


    def stop(self):
        """
        Stop the daemon gracefully.
        """
        print("Shutting down daemon...")
        self.running = False
        self.client_socket.close()
        self.daemon_socket.close()


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
