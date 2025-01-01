import socket
import sys
from simp_check_functions import *


class Client:
    SOCKET_TIMEOUT = 5
    MAX_RETRIES = 3

    def __init__(self, daemon_ip):
        """
        Initialize the client to communicate with a specific daemon.
        """
        self.daemon_ip = daemon_ip
        self.daemon_port = 7778  # Default port for the daemon
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
        self.username = None  # Set during user login or setup
        self.chat_partner = None  # Set during chat setup

    def connect_to_daemon(self):
        """
        Build the connection to the daemon before asking for the username.
            1. Send a connection request to the daemon (PING)
            2. Receive a response from the daemon (PONG)
            3. If the response is positive, proceed with the client setup
        """
        # 1. Send a connection request to the daemon (PING)
        try:
            print(f"Connecting to daemon at {self.daemon_ip}...")
            message = "PING|"  # to check if the daemon is running/available
            self._send_message(message)

            # 2. Receive a response from the daemon (PONG)
            response = self._receive_chat()

            if response[0] == "PONG":
                print(f"Connected to daemon {self.daemon_ip}!")
            else:
                print(f"Error in connecting: {response[1]}")
                exit(1)

            # 3. If the response is positive, proceed with the client setup
            self.username = input("Enter your username: ")
            message = f"CONNECT|{self.username}"
            self._send_message(message)

            response = self._receive_chat()  # Wait for the welcome message

            print("received", response)
            print(response[1])  # Print welcome message and pending chat requests
            if response[1] == f"Welcome, {self.username}! \nYou currently have no pending chat requests.":
                return response
            else:
                while response[0] != "CONNECTING":
                    response = self._receive_chat()
                    print(response[1])  # Print welcome message and pending chat requests
            return response

        except Exception as e:
            print(f"Error in connect_to_daemon: {e}")
            exit(1)

    def _send_message(self, message):
        """
        Send a message and wait for an ACK from the daemon.
        If no ACK is received within the timeout, retry sending the message.
        """
        max_retries = 3
        retries = 0
        while retries < max_retries:
            try:

                self.socket.sendto(message.encode('ascii'), (self.daemon_ip, self.daemon_port))
                print(f"Message sent: {message}")

                # Wait for ACK
                self.socket.settimeout(5)  # Set timeout for receiving
                response_ack = self._receive_chat()

                # Check if the response is an ACK
                if response_ack[0] == "ACK":
                    print("ACK received.")
                    return  # Message sent successfully and ACK received
                else:
                    print(f"Unexpected response: {response_ack[1]}")
                    retries += 1

            except socket.timeout:
                retries += 1
                print(f"Timeout waiting for ACK. Retrying... ({retries} of {max_retries})")

            except Exception as e:
                raise e
            
            finally:
                self.socket.settimeout(None)

        raise Exception("Max retries exceeded. Message not acknowledged. Daemon not reachable. Exiting.")

    def start(self):
        """
        Entry point for the client to interact with the user.
        """
        response = self.connect_to_daemon()  # Connect to the daemon before starting

        if response[1] == f"Welcome, {self.username}! \nYou currently have no pending chat requests." or response == "CONNECTING|":  # not accepted requests
            self.options()
        else:
            self.start_chat()




    def options(self):
        """
        Provide the user with options to start a chat, wait for a chat, or quit.
        """
        while True:
            print("\nWhat now? \n(1) Start Chat \n(2) Wait for Chat \n(q) Quit")
            choice = input("Choose an option: ")
            if choice == '1':
                self.start_chat()
            elif choice == '2':
                self.wait_for_chat()
            elif choice == 'q':
                self.quit()
            else:
                print("Invalid choice. Try again.")

    def start_chat(self):
        """
        Initiate a chat request with another user.
        """
        while True:
            target_ip = input("Enter the target user's daemon IP address: ").strip()
            check = is_valid_ip(target_ip)
            if check is True: # check if the IP address is valid
                break
            else:
                print("Invalid IP address. Try again.")

        print(f"Chat request sent to {target_ip}.")
        self._send_message(f"CONNECTING|request: {target_ip}")  # Send a chat request to the daemon

        print(f"Chat request sent!\n"
              f"Waiting for response from {target_ip}...")

        
        response = self._receive_chat()
        if response[0] == "ERROR":
            print(f"Error: {response[1]}")
            return
        
        self.main_chat_loop(response)


    def main_chat_loop(self, response):
        # set the chat partner
        self.chat_partner = response[1].split(": ")[1]
        print(response[1])

        print("Start chatting! Type 'q' to end the chat.")
        
        # Chat loop
        while True:
            message = input(f"{self.username}: ")
            if message.upper() == 'Q':
                self._send_message("QUIT|")
                break
                
            self._send_message(f"CHAT|{message}")
            
            response = self._receive_chat()
            if response[0] == "ERROR":
                print(f"Error: {response[1]}")
                break
            elif response[0] == "QUIT":
                print("Chat partner has disconnected.")
                break
            elif response[0] == "CHAT":
                print(f"{self.chat_partner}: {response[1]}")
                continue

        print("Chat ended.")
        self.options()

    def wait_for_chat(self):
        """
        Wait for incoming chat requests from other users.
        """
        print("Waiting for incoming chat requests...")
        # let the daemon handle the chat request
        self._send_message("CONNECTING|")

        while True:

            response = self._receive_chat()
            if response[0] == "CONNECTING":
                print(f"Incoming chat request..")

                user_request = response[1].split(": ")[1]

                # ask the user if he wants to accept the chat request
                print(f"Do you want to accept the chat request from {user_request}? (y/n)")
                choice = input("Choose an option: ")

                if choice.upper() == 'Y' or choice.upper() == 'YES':
                    print(f"Chat request accepted from {user_request}.")

                    # no need to send a message to the daemon, as the daemon will assume that the chat request is accepted after the three way handshake
                    # wait for the first message from the chat partner
                    response = self._receive_chat()
                    if response[0] == "CHAT":
                        print(f"Chat partner connected! Start chatting!")
                        print(f"{user_request}: {response[1]}")

                        # continue the chat in the main chat loop (async to the other chat partner = stop-and-wait)
                        self.main_chat_loop(response)
                    elif response[0] == "QUIT":
                        print("Chat partner disconnected.")
                        return
                    else:
                        print("Error: Chat partner did not send a message.")
                        return
                    
                else:
                    self._send_message("QUIT|") # send a QUIT message to the daemon, so the daemon will know that the chat request is denied
                    print("Chat request denied.")
                    return

            elif response[0] == "ERROR":
                print(f"Error: {response[1]}")
                return
            else:
                print(response[1])
                print("Still waiting for incoming chat requests...")

    def _receive_chat(self):
        """
        Receive chat messages from the daemon and format it to a list.
        Automatically send an ACK for every valid message received.
        Handle invalid or unexpected message formats and return an error message.
        """
            # timeout needed?
            # should the user be asked again if he doesn't respond within the timeout?
        try:

            data, addr = self.socket.recvfrom(1024)

            if not data:  # Check if data is empty
                return ["ERROR", "Received empty message"]

            response = data.decode('ascii').split('|')
            if len(response) < 1:  # check if the message is too short (at least operation needed!)
                return ["Error", "Invalid message format!"]

            # If the message is not an ACK, send an ACK response
            if response[0] != "ACK":
                print("sending ACK")
                self._send_ack(addr)
            #elif response[0] == "ACK":
             #   print("ACK received.")
              #  self._receive_chat()  # Wait for the next message (skip ACK)

            return response  # [operation, payload]

        except Exception as e:  # catch all exceptions
            print(f"Error: {e}")
            return ["ERROR", str(e)]


    def _send_ack(self, addr):
        """
        Send an automatic ACK to the daemon after receiving a message.
        """
        try:
            ack_message = "ACK|"
            self.socket.sendto(ack_message.encode('ascii'), addr)
            print("ACK sent.")
        except Exception as e:
            print(f"Error while sending ACK: {e}")

    def quit(self):
        """
        Disconnect from the daemon and exit.
        """
        print("Disconnecting from the daemon...")
        try:
            self._send_message("QUIT|")
            response = self._receive_chat()
            if response[0] == "DISCONNECTED":
                print(response[1])  # Print the disconnect message
        except Exception as e:
            print(f"Error while disconnecting: {e}")
        finally:
            self.socket.close()
            print("Disconnected. Exiting...")
            exit(0)


def show_usage():
    print("Usage: python simp_client.py <daemon IP>")


# callable from command line example: python simp_client.py 127.0.0.1 (or any other IP address)
if __name__ == "__main__":
    if len(sys.argv) != 2:
        show_usage()
        exit(1)

    daemon_ip = sys.argv[1]

    # Validate IP address format
    check = is_valid_ip(daemon_ip)
    if not check:
        print(check)
        exit(1)

    client = Client(daemon_ip)
    client.start()




