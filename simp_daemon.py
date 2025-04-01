import socket
import sys
import threading
from threading import Lock
from typing import Optional, Tuple, Dict, Any  # lib added for type hinting in methods

from simp_check_functions import *


class SimpDaemon:
    SOCKET_TIMEOUT = 5
    MAX_RETRIES = 3

    def __init__(self, daemon_ip: str) -> None:
        """
        Initialize the daemon with the given IP and port.
        """
        self.protocol = SimpProtocol()  # Creating an instance of SimpProtocol to make use of the class methods
        self.lock = Lock()  # lock to serialize access to shared resources
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

    def set_chat_partner(self, addr: str, user: str) -> None:
        with self.lock:
            self.chat_partner[addr] = user

    def get_chat_partner(self) -> Dict[str, str]:
        with self.lock:
            return self.chat_partner

    def start(self) -> None:
        """
        Main loop for the daemon.

        Start the daemon and run separate threads for listening to new connections
        and handling the current chat.
        """
        print(f"Starting daemon at {self.daemon_ip}...")

        # Create threads
        client_thread = threading.Thread(target=self.listen_for_client_connections, daemon=True)  # Listen for new connections
        daemon_thread = threading.Thread(target=self.listen_to_daemons, daemon=True)  # Listen to other daemons and handle chat requests

        # Start threads
        client_thread.start()
        daemon_thread.start()

        # Keep the main thread running
        try:
            while self.running:
                pass
        except KeyboardInterrupt:
            self.stop()  # shutting down the daemon

    def listen_for_client_connections(self) -> None:
        """
            Listen for new connection requests on the client socket.

            Build the connection to the client before asking for the username.
            1. Receive a connection request from the client (PING)
            2. Respond to the client (PONG)
            3. If the response is positive, proceed with the client setup
            4. Receive the username from the client (CONNECT)
            5. Respond to the client with a welcome message and check for pending chat requests
                - If there are pending chat requests, ask the client if they want to chat
                - Else proceed and start a chat or wait for the chat partner to connect
            6. Stop and wait for chat messages from the client until chat ends (QUIT)
        """
        while self.running:
            try:
                self.client_socket.settimeout(None)  # Remove any previous timeout for listening

                # wait for incoming messages from the client
                data, addr = self.client_socket.recvfrom(1024)

                # handle the message from the client
                new_response = self.handle_message_client(data, addr)

                # send the response to the client, if any
                if new_response:
                    self._send_message_client(new_response, addr)

            except Exception as e:
                print(f"Error in listening for connections: {e}")
                continue  # continue with the loop

    def handle_message_client(self, data: bytes, addr: Tuple[str, int]) -> Optional[str]:
        """
        Process incoming messages from the client and respond accordingly.
        """
        # Parse the received message
        message = data.decode('ascii').split('|')  # Format: OPERATION|PAYLOAD
        operation = message[0]
        payload = message[1] if len(message) > 1 else None  # Extract the payload if it exists

        # send ACK to the client if the message is not an ACK itself
        if operation != "ACK":
            # send ACK to the client
            self._send_message_client("ACK", addr)
        else:
            return

        # Handle the operation
        if operation == "PING":
            if not self.available:
                return "ERROR|Daemon is busy with another user."            
            self.available = False
            return "PONG|Daemon is running."

        elif operation == "CONNECT":
            self.current_user = payload
            print("User connected: ", self.current_user)

            # check if there are any pending chat requests
            if len(self.chat_requests) > 0:
                return self._get_requests(addr)
            else:
                return f"CONNECT|Welcome, {self.current_user}! \nYou currently have no pending chat requests."

        elif operation == "CONNECTING":
            if not payload:
                print("waiting for chat partner")

                while not self.chat_partner:  # wait for the chat partner to connect (handled by other running thread)
                    pass

                print("chat partner connected")

                chat_partner_ip = list(self.chat_partner.keys())[0]
                chat_partner_username = self.chat_partner[chat_partner_ip]
                return f"CONNECTING|Connected to user: {chat_partner_username}"

            else:
                # send chat request to the chat partner
                target_ip = payload.split(":")[1].strip()  # "request: {target_ip}"

                # try to connect to the chat partner
                self.three_way_handshake(target_ip)

                # wait for three-way-handshake to finish (handled by other running thread)
                while not self.chat_partner:
                    pass

                return f"CONNECTING|Connected to user: {self.chat_partner[target_ip]}"  # username

        elif operation == "CHAT":
            if self.get_chat_partner():
                # forward the message to the chat partner and vise versa
                self._forward_chat_messages(payload, addr)
                return
            else:
                return "ERROR|No chat partner available."

        elif operation == "QUIT":
            self.available = True
            self.current_user = None
            return "QUIT|You have been disconnected."

        else:
            return "ERROR|Unknown operation."

    def _forward_chat_messages(self, message: str, client_addr: Tuple[str, int]) -> None:
        """
        Forward a chat message to the chat partner.
        Create chat datagram and send it to the chat partner
        Receive answer and send it back to the client
        """
        chat_partner = self.get_chat_partner()
        chat_partner_ip = list(chat_partner.keys())[0]
        chat_partner_addr = (chat_partner_ip, self.port_to_daemon)  # Create proper address tuple
        
        sequence_number = self.sequence_tracker.get(chat_partner_addr, 0)  # should be 0, Default is 0

        # create chat datagram
        response = self.protocol.create_datagram(
                HeaderType.CHAT,
                Operation.CONST,
                sequence_number,
                self.current_user,
                message
            )

        self.daemon_socket.sendto(response, chat_partner_addr)
        print(f"Message sent to chat partner {chat_partner_addr}.")

    def _send_message_client(self, message: str, addr: Tuple[str, int]) -> None:
        """
        Send a message to the client
        """
        max_retries = self.MAX_RETRIES
        retries = 0
        while retries < max_retries:
            try:
                self.client_socket.sendto(message.encode('ascii'), addr)

                # wait for ACK if the message is not an ACK
                if message != "ACK":
                    self.client_socket.settimeout(self.SOCKET_TIMEOUT)  # Set timeout for receiving
                    try:
                        data, addr = self.client_socket.recvfrom(1024)
                        message_ack = data.decode('ascii').split('|')  # Format: OPERATION|PAYLOAD

                        if message_ack[0] == "ACK":
                            self.client_socket.settimeout(None)  # Reset timeout
                            return
                        
                    except socket.timeout:
                        retries += 1
                        print(f"Timeout waiting for ACK from {addr}. Retry {retries}/{max_retries}")
                        continue
                else:
                    return  # No need to wait for ACK if sending an ACK

            except Exception as e:
                print(f"Error sending message to client: {e}")
                retries += 1

            finally:
                self.client_socket.settimeout(None)

        print(f"Failed to send message after {max_retries} attempts")
        self.client_socket.settimeout(None)  # Reset timeout

    def _get_requests(self, addr: Tuple[str, int]) -> Optional[str]:
        """
        Get the list of pending chat requests.
        """
        requests = f"CONNECT|Welcome, {self.current_user}! \nYou have pending chat requests from:\n"
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
                    self.set_chat_partner(ip, response[1])

                    # remove the chat request from the list
                    self.chat_requests.pop(ip)
                    return f"CONNECTING|connecting to user:{response[1]}... "

    def receive_datagram(self) -> tuple[HeaderInfo, Any, Any] | tuple[HeaderInfo, bytes, tuple | Any] | tuple[
            HeaderInfo, Any, tuple | Any] | tuple[HeaderInfo | None, bytes | None | Any, tuple | None | Any]:
        """
        Receive a datagram from another daemon.
        Check if the datagram is valid and the sequence number is correct.
        Send ACK for valid messages and ERR for invalid messages.
        Return datagram if valid, False otherwise
        """
        header_info = None
        data = None
        addr = None
        try:
            # wait for incoming datagrams
            data, addr = self.daemon_socket.recvfrom(1024)
            print(f"Received datagram from {addr}: {data}")

            # check if the datagram is valid
            header_info = check_header(data)

            # Skip sequence checking for error messages
            if header_info.operation == Operation.ERR and header_info.type == HeaderType.CONTROL:
                print(f"Received error message: {self.protocol.parse_datagram(data)['payload']}")
                return header_info, self.protocol.parse_datagram(data), addr
            
            ip = addr[0] if isinstance(addr, tuple) else addr
            expected_sequence = self.sequence_tracker.get(ip, 0)  # Default expected sequence is 0

            if not header_info.is_ok:
                print(f"Error parsing datagram from {addr}: {header_info.code}")
                error_response = self.protocol.create_datagram(
                    HeaderType.CONTROL,
                    Operation.ERR,
                    header_info.sequence_number,  # Use the same sequence number
                    self.current_user,  # User
                    header_info.code  # Error message
                )
                self.daemon_socket.sendto(error_response, addr)
                return header_info, data, addr

            # Check if the sequence number is correct
            if header_info.sequence_number != expected_sequence:
                print(f"Unexpected sequence number from {ip}. Expected {expected_sequence}, got {header_info.sequence_number}.")
                    
                # send ERR message
                error_response = self.protocol.create_datagram(
                        HeaderType.CONTROL,
                        Operation.ERR,
                        expected_sequence,  # Use the expected sequence number
                        self.current_user,
                        ErrorCode.WRONG_SEQUENCE
                )
                self.daemon_socket.sendto(error_response, addr)
                return header_info, data, addr

            # Update the expected sequence number
            self.sequence_tracker[ip] = 1 - expected_sequence  # Toggle between 0 and 1

            # Parse the datagram to extract the data and header info into a dictionary
            data = self.protocol.parse_datagram(data)

            # Send ACK for chat messages (not for ACKs or other control messages)
            if header_info.type == HeaderType.CHAT:
                ack_datagram = self.protocol.create_datagram(
                    HeaderType.CONTROL,
                    Operation.ACK,
                    header_info.sequence_number,  # Use same sequence number
                    self.current_user,
                    ""  # Empty payload
                )
                self.daemon_socket.sendto(ack_datagram, addr)
                print(f"ACK sent for message with sequence: {header_info.sequence_number}")

            return header_info, data, addr

        except Exception as e:
            print(f"Error receiving datagram: {e}")
            return header_info, data, addr

    def handle_message_daemons(self, header_info: Any, data: Dict[str, Any], addr: Tuple[str, int]) -> None:
        """
        Process incoming messages and respond accordingly.
        """
        # skip if the header_info is None
        if not header_info or not data or not addr:
            print(f"Invalid datagram received!")
            return
        
        ip = addr[0] if isinstance(addr, tuple) else addr

        # Handle chat messages
        if header_info.type == HeaderType.CHAT:
            if data is None:
                print(f"Error: Received None data from {addr}")
                return

            print(f"Received chat message from {addr}: {data['payload']}")
             
            # First send ACK back to the sending daemon
            ack = self.protocol.create_datagram(
                    HeaderType.CONTROL,
                    Operation.ACK,
                    header_info.sequence_number,
                    self.current_user,
                    ""
                )
            
            self.daemon_socket.sendto(ack, addr)
            print(f"ACK sent for message {data['payload']}")

            # forward the chat message to the client
            client_addr = (self.daemon_ip, self.port_to_client)
            response = f"CHAT|{data['payload']}"
            self._send_message_client(response, client_addr)
            return

        # Don't process ACKs here as they're handled in receive_datagram
        if header_info.operation == Operation.ACK:
            print(f"ACK received from {addr} in handle_message_daemons")

            # update the sequence number for tracking lost messages
            self.sequence_tracker[ip] = 1 - header_info.sequence_number  # Toggle between 0 and 1

            # start the chat if the handshake is complete
            if not self.chat_partner: 
                self.chat_partner[ip] = data['user']
                print(f"Chat started with {data['user']}")
            return
        
        # Logic for handling chat requests from other daemons , when client is not busy (SYN)
        if header_info.operation == Operation.SYN:
            print(f"Received chat request from {addr}")

            # Save the chat request 
            self.chat_requests[ip] = data['user']  # Save the chat request {client_ip: username}
            print(f"Chat request saved for {ip}: {data['user']}")

            # send SYN+ACK to the client if the client is not in a chat already
            if not self.chat_partner:
                syn_ack = self.protocol.create_datagram(
                    HeaderType.CONTROL,
                    Operation.SYN_ACK,
                    header_info.sequence_number + 1,  # 1
                    self.current_user,
                    ""
                )
                self.daemon_socket.sendto(syn_ack, addr)
                print(f"SYN+ACK sent to from handle_message_daemons: {addr}")

            return
        
        if header_info.operation == Operation.SYN_ACK:
            print(f"SYN+ACK received from handle_message_daemons: {addr}")
            self.chat_requests.pop(ip, None)  # None is the default value if the key is not found
            print(f"Chat request removed for {ip}")

            # Send final ACK without incremented sequence number
            ack_datagram = self.protocol.create_datagram(
                HeaderType.CONTROL,
                Operation.ACK,
                header_info.sequence_number,  # use the same sequence number for ACK (1)
                self.current_user,
                ""
            )
            self.daemon_socket.sendto(ack_datagram, addr)
            print(f"Final ACK sent to {addr}. Handshake complete.")

            # set the chat partner
            self.set_chat_partner(ip, data['user'])
            print(f"Chat partner set to {data['user']}")

            # update the sequence number
            self.sequence_tracker[ip] = 1 - header_info.sequence_number

            return 

        # For error messages, just log and return
        if header_info.operation == Operation.ERR:
            print(f"Received error: {data['payload']}")
            return

        else:
            print(f"Busy; automatically rejecting request from {addr}")
            # Respond with ERR followed by FIN datagram (close connection)
            response = self.protocol.create_datagram(
                HeaderType.CONTROL,
                Operation.ERR,
                header_info.sequence_number,  # using the same sequence number
                self.current_user,  # User
                ErrorCode.BUSY_DAEMON
            )
            self.daemon_socket.sendto(response, addr)

            # send FIN datagram and close the connection
            self.closing_connection(addr, header_info)

    def three_way_handshake(self, addr: str) -> None:
        """
        Perform the three-way handshake with the other daemon.
        """
        # Convert string address to tuple with port, if not already a tuple
        target_addr = (addr, self.port_to_daemon) if isinstance(addr, str) else addr
        ip = target_addr[0] if isinstance(target_addr, tuple) else target_addr

        print(f"Starting three-way handshake with {addr}...")

        # Initialize sequence tracking
        self.sequence_tracker[ip] = 0
        sequence_number = self.sequence_tracker[ip]
        
        # Prepare the SYN datagram
        syn_datagram = self.protocol.create_datagram(
            HeaderType.CONTROL,
            Operation.SYN,
            sequence_number,  # 0 for the first SYN
            self.current_user,
            ""  # Empty payload
        )

        print(f"Sending SYN datagram to {ip}.")
        self.daemon_socket.sendto(syn_datagram, target_addr)                      

        # increment the sequence number
        self.sequence_tracker[ip] = 1 - sequence_number  # 1 - 0 = 1

        # the rest of the handshake is handled in handle_message_daemons
        return

    def closing_connection(self, addr: Tuple[str, int], header_info:Any) -> None:
        """
        Send a FIN datagram to the client
        Wait for the client to respond with ACK
        Close the connection.
        """
        # create FIN datagram
        response = self.protocol.create_datagram(
            HeaderType.CONTROL,
            Operation.FIN,
            header_info.sequence_number,  # using the same sequence number
            self.current_user,  # User
            ""  # Empty payload
        )

        self.daemon_socket.settimeout(self.SOCKET_TIMEOUT)  # Set timeout to 5 seconds for receiving
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

            finally:
                self.daemon_socket.settimeout(None)

    def listen_to_daemons(self) -> None:
        """
        Handles communication with other daemons on port 7777.
        """
        global addr
        print(f"Listening for daemon communication on {self.port_to_daemon}...")

        # build and run daemon connection
        while self.running:
            try:
                header_info, data, addr = self.receive_datagram()
            
                # Skip if we received None (invalid datagram)
                if header_info is None:
                    continue

                # handle the message
                self.handle_message_daemons(header_info, data, addr)

            except Exception as e:
                print(f"Error handling message: {e}")
                if addr:
                    error_response = self.protocol.create_datagram(
                                HeaderType.CONTROL,
                                Operation.ERR,
                                self.sequence_tracker[addr[0]],  # Use the current sequence number
                                self.current_user,
                                e  # Error message
                            )

                    # let the other daemon know about the error
                    self.daemon_socket.sendto(error_response, addr)
                continue  # keep the daemon running

    def stop(self) -> None:
        """
        Stop the daemon gracefully.
        """
        print("Shutting down daemon...")
        self.current_user = None
        self.chat_partner = {}
        self.chat_requests = {}
        self.running = False
        self.client_socket.close()
        self.daemon_socket.close()


def show_usage() -> None:
    print("Usage: python simp_daemon.py <IP address>")


# callable from command line example: python simp_daemon.py 127.0.0.1 (or any other IP address)
if __name__ == "__main__":
    if len(sys.argv) != 2:
        show_usage()
        exit(1)

    daemon_ip = sys.argv[1]
    # validate IP address format
    check = is_valid_ip(daemon_ip)
    if not check:
        print(f"Error: {daemon_ip} is not a valid IP address.")
        exit(1)

    daemon = SimpDaemon(daemon_ip)  # Initialize the daemon
    daemon.start()  # wait for connection to client
