import socket
import sys
import threading
from threading import Lock
from simp_check_functions import *


class SimpDaemon:
    SOCKET_TIMEOUT = 5
    MAX_RETRIES = 3

    def __init__(self, daemon_ip):
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
        and handling the acurrent chat.

        """
        print(f"Starting daemon at {self.daemon_ip}...")

        # Create threads
        client_thread = threading.Thread(target=self.listen_for_client_connections, daemon=True)  # Listen for new connections
        # chat_thread = threading.Thread(target=self.listen_for_client_connections, daemon=True)  # Handle the current chat session
        daemon_thread = threading.Thread(target=self.listen_to_daemons, daemon=True)  # Listen to other daemons and handle chat requests

        # Start threads
        client_thread.start()
        # chat_thread.start()
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
                self.client_socket.settimeout(None)  # Remove timeout for listening

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

    def handle_message_client(self, data, addr):
        """
        Process incoming messages from the client and respond accordingly.
        """

        # Parse the received message
        message = data.decode('ascii').split('|')  # Format: OPERATION|PAYLOAD
        operation = message[0]
        payload = message[1] if len(message) > 1 else None  # Extract the payload if it exists

        # send ACK to the client if the message is not an ACK itself
        if operation != "ACK":
            print(f"Received message from {addr}: {operation} | {payload}\n"
                  f"sending ACK to {addr}...")
            # send ACK to the client
            self._send_message_client("ACK", addr)
        else:
            print(f"Received ACK from {addr}.")
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
                print("sending CONNECT")
                return f"CONNECT|Welcome, {self.current_user}! \nYou currently have no pending chat requests."

        elif operation == "CONNECTING":
            if not payload:
                # empty payload = waiting for chat partner
                response = self.wait_for_chat_partner(addr)
                if response:
                    return response
                else:
                    return "ERROR|Something went wrong, please try again."

            else:
                # send chat request to the chat partner
                target_ip = payload.split(":")[1].strip()  # "request: {target_ip}"

                # try to connect to the chat partner
                connected, msg = self.three_way_handshake(target_ip)  # return two values (bool, error/username)

                if connected:
                    return f"CONNECTING|Connected to user: {msg}"
                else:
                    return f"ERROR| {msg}"

        elif operation == "CHAT":
            if self.get_chat_partner():
                # forward the message to the chat partner and vise versa
                self.forward_chat_messages(payload, addr)
            else:
                return "ERROR|No chat partner available."

        elif operation == "QUIT":
            self.available = True
            self.current_user = None
            return "QUIT|You have been disconnected."

        else:
            return "ERROR|Unknown operation."


    def forward_chat_messages(self, message, client_addr):
        """
        Forward a chat message to the chat partner.
        Create chat datagram and send it to the chat partner
        Receive answer and send it back to the client
        """
        chat_partner = self.get_chat_partner()
        chat_partner_addr = list(chat_partner.keys())[0]
        # Initial sequence number (alternate between 0 and 1 for retransmissions)
        sequence_number = self.sequence_tracker.get(chat_partner_addr, 0)  # Default is 0

        # create chat datagram
        response = self.protocol.create_datagram(
                HeaderType.CHAT,
                Operation.CONST,
                sequence_number,
                self.current_user,
                message
            )

        # send datagram and wait for ACK from the chat partner
        # try up to 3 times to send the message to avoid infinite loop for unreachable chat partner
        max_retries = self.MAX_RETRIES
        retry_count = 0
        while retry_count < max_retries:
            try:
                self.daemon_socket.settimeout(self.SOCKET_TIMEOUT)  # Set a timeout for the response
                self.daemon_socket.sendto(response, chat_partner_addr)
                print(f"Message sent to chat partner {chat_partner_addr}.")

                # wait for ACK
                header_info, data, addr = self.receive_datagram()

                if (addr == chat_partner_addr and 
                    header_info.operation == Operation.ACK and 
                    header_info.sequence_number == sequence_number):

                    print(f"ACK received, next sequence number is {1 - sequence_number}.")
                    self.sequence_tracker[chat_partner_addr] = 1 - sequence_number  # Toggle between 0 and 1
                    break
                else:
                    print(f"Unexpected response received: {header_info}, {data}")
                    retry_count += 1
                    continue

            except socket.timeout:
                print(f"Timeout: No ACK received from {chat_partner_addr}. Retrying... {retry_count + 1} of {max_retries}")
                retry_count += 1
                # Retransmit the same datagram
            
            finally:
                self.daemon_socket.settimeout(None)

        if retry_count == max_retries:
            response = "ERROR|Failed to deliver message after maximum retries"
            self._send_message_client(response, client_addr)
            return

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
                            print("ACK received.")
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




    def _get_requests(self, addr):
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

            #response = "ERROR|Invalid response. Please enter a valid username or 'NO'."

    def wait_for_chat_partner(self, addr):
        """
        Wait for incoming chat requests (SYN) from other users (daemon).
        Periodically check with the user if they want to keep waiting.
        """
        while True:
            print(f"Waiting for chat partner...")
            try:
                self.daemon_socket.settimeout(30)  # Set a timeout for the incoming chat requests
                # Wait to receive a datagram from another daemon
                header_info, data, daemon_addr = self.receive_datagram()

                print(f"datagram received: {header_info}")

                if not header_info:  # Handle None case from receive_datagram
                    continue

                # Check if the received datagram is a SYN
                if header_info and header_info.operation == Operation.SYN:
                    print(f"Received SYN from {daemon_addr}.")

                    # Respond with a SYN+ACK
                    syn_ack_datagram = self.protocol.create_datagram(
                        HeaderType.CONTROL,
                        Operation.SYN_ACK,
                        header_info.sequence_number,
                        self.current_user,
                        ""
                    )
                    self.daemon_socket.sendto(syn_ack_datagram, daemon_addr)
                    print(f"Sent SYN+ACK to {daemon_addr}.")

                    # Wait for ACK from the sender
                    try:
                        self.daemon_socket.settimeout(self.SOCKET_TIMEOUT)  # 5 seconds timeout
                        ack_header_info, ack_data, ack_addr = self.receive_datagram()
                        if ack_header_info and ack_header_info.operation == Operation.ACK and ack_addr == daemon_addr:
                            print(f"ACK received from {daemon_addr}. Handshake complete.")
                            # Set the chat partner and exit
                            self.set_chat_partner(daemon_addr[0], data['user'])
                            return f"CONNECTING|Connected to user: {data['user']}"
                        
                    except socket.timeout:
                        print(f"Timeout waiting for ACK from {daemon_addr}.")
                        continue 
                
                else:
                    print(f"Unexpected datagram received from {daemon_addr}: {header_info}")
                    continue

            except socket.timeout:
                print("No chat requests received.")
                # Ask the user if they want to keep waiting
                message = "ERROR|No chat requests received. Do you want to keep waiting? (YES/NO)"
                self._send_message_client(message, addr)

                # Receive the response from the client
                try:
                    self.client_socket.settimeout(30)
                    data, client_addr = self.client_socket.recvfrom(1024)
                    response = data.decode('ascii').split('|')

                    if response[0] == "CONNECTING":
                        # Continue waiting
                        continue
                    elif response[0] == "QUIT":
                        return
                    
                except socket.timeout:
                    print("No response from client, stopping wait.")
                    return

            except Exception as e:
                print(f"Error in wait_for_chat_partner: {e}")
                return

            finally:
                self.daemon_socket.settimeout(None)
                self.client_socket.settimeout(None)



    def receive_datagram(self):
        """
        Receive a datagram from the client.
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
            print(f"Header info: {header_info.type, header_info.operation, header_info.sequence_number, header_info.is_ok, header_info.code}")

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

            
            # Send ACK for non-control messages or messages that aren't already ACKs
            if (header_info.type != HeaderType.CONTROL and header_info.operation != Operation.ACK):
                ack_datagram = self.protocol.create_datagram(
                    HeaderType.CONTROL,
                    Operation.ACK,
                    header_info.sequence_number,  # Use same sequence number
                    self.current_user,
                    ""  # Empty payload
                )
                self.daemon_socket.sendto(ack_datagram, addr)
                print(f"ACK sent for message {header_info.sequence_number}")

            return header_info, data, addr

        except Exception as e:
            print(f"Error receiving datagram: {e}")
            return header_info, data, addr

        

    def handle_message_daemons(self, header_info, data, addr):
        """
        Process incoming messages and respond accordingly.
        """
        # skip if the header_info is None
        if not header_info or not data or not addr:
            return
        
        # Don't process ACKs here as they're handled in receive_datagram
        if header_info.operation == Operation.ACK or header_info.operation == Operation.SYN_ACK:
            return
        
        # For error messages, just log and return
        if header_info.operation == Operation.ERR:
            print(f"Received error: {data['payload']}")
            return

        # Logic for handling chat requests from other daemons , when client is not busy (SYN)
        if header_info.operation == Operation.SYN:
            print(f"Received chat request from {addr}")

            # Save the chat request 
            self.chat_requests[addr[0]] = data['user']  # Save the chat request {client_ip: username}
            print(f"Chat request saved for {addr[0]}: {data['user']}")

            # send SYN+ACK to the client if the client is not in a chat already
            if not self.chat_partner:
                syn_ack = self.protocol.create_datagram(
                    HeaderType.CONTROL,
                    Operation.SYN_ACK,
                    header_info.sequence_number,
                    self.current_user,
                    ""
                )
            self.daemon_socket.sendto(syn_ack, addr)
            print(f"SYN+ACK sent to {addr}")

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
            self.closing_connection(addr)

    def three_way_handshake(self, addr):
        """
        Perform the three-way handshake with the other daemon.
        """
        # Convert string address to tuple with port, if not already a tuple
        target_addr = (addr, self.port_to_daemon) if isinstance(addr, str) else addr
        print(f"Starting three-way handshake with {addr}...")

        # Initialize sequence tracking
        ip = target_addr[0] if isinstance(target_addr, tuple) else target_addr
        self.sequence_tracker[ip] = 0
        sequence_number = self.sequence_tracker[ip]
        
        # 1. Prepare the SYN datagram
        syn_datagram = self.protocol.create_datagram(
            HeaderType.CONTROL,
            Operation.SYN,
            sequence_number,  # 0 for the first SYN
            self.current_user,
            ""  # Empty payload
        )

        # 2. Send SYN and wait for SYN + ACK from the receiver (try only 3 times to avoid infinite loop)
        tries = self.MAX_RETRIES
        while tries > 0:
            try:
                print(f"Sending SYN datagram to {ip}.")
                self.daemon_socket.sendto(syn_datagram, target_addr)
                print(f"SYN sent to {ip}.")

                self.daemon_socket.settimeout(self.SOCKET_TIMEOUT)  # Set a timeout for the response
                header_info, data, received_addr = self.receive_datagram()

                print(f"Does this equal? {received_addr} = {target_addr}")

                # If the received operation is SYN + ACK with the same sequence number as the sent SYN
                if header_info.operation == (Operation.SYN.value | Operation.ACK.value) and header_info.sequence_number == sequence_number:
                    print(f"SYN+ACK received from {received_addr}.")
                    
                    # 3. Send final ACK with incremented sequence number
                    ack_datagram = self.protocol.create_datagram(
                        HeaderType.CONTROL,
                        Operation.ACK,
                        sequence_number + 1,  # use the same sequence number for ACK
                        self.current_user,
                        ""
                    )
                    self.daemon_socket.sendto(ack_datagram, target_addr)
                    print(f"ACK sent to {target_addr}. Handshake complete.")

                    self.set_chat_partner(ip, data['user'])
                    return True, data['user']  # return the chat partner's username

                elif header_info and header_info.operation == Operation.ERR:
                    print(f"Error received from {received_addr}: {data}")
                    return False, data
                
                else:
                    print(f"Unexpected datagram received from {target_addr}, resending SYN.")
                    tries -= 1
                    continue # resend SYN

            except socket.timeout:
                print(f"Timeout waiting for SYN+ACK from {target_addr}. resending SYN.")
                # resend SYN
                tries -= 1
                continue

            finally:
                self.daemon_socket.settimeout(None)

        if tries == 0:
            print(f"Failed to establish connection with {target_addr}.")
            return False, "Connection failed."

    

    def closing_connection(self, addr):
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

        # self.available = True # in case of successful connection before

    def listen_to_daemons(self):
        """
        Handles communication with other daemons on port 7777.
        """

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
                print(f"Error handling message from {addr}: {e}")
                error_response = self.protocol.create_datagram(
                            HeaderType.CONTROL,
                            Operation.ERR,
                            header_info.sequence_number,  # Sequence number
                            self.current_user, 
                            header_info.code  # Error message
                        )
                self.daemon_socket.sendto(error_response, addr)
                continue


    def stop(self):
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


def show_usage():
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
