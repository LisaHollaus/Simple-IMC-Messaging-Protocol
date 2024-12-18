import socket
import sys
from simp_check_functions import *

class Client:
    def __init__(self, daemon_ip):
        """
        Initialize the client to communicate with a specific daemon.
        """
        self.daemon_ip = daemon_ip
        self.daemon_port = 7778  # Default port for the daemon
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
        self.username = None  # Set during user login or setup
        self.chat_partner = None # Set during chat setup

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
                print(f"Connected to daemon at {self.daemon_ip}.")
            else:
                print(f"Error: {response[1]}")
                exit(1)

            # 3. If the response is positive, proceed with the client setup
            self.username = input("Enter your username: ")
            message = f"CONNECT|{self.username}"
            self._send_message(message)

            response = self._receive_chat()  # Wait for the welcome message
            print(response[1])  # Print welcome message and pending chat requests
            if response[1] == f"Welcome, {self.username}! You currently have no pending chat requests.":
                return response
            else:
                while response[0] != "CONNECTING":
                    response = self._receive_chat()
                    print(response[1])  # Print welcome message and pending chat requests
            return response

        except Exception as e:
            print(f"Error: {e}")
            exit(1)


    def _send_message(self, message):
        """
        Send a message to the daemon, also calculate the checksum
        and append it to the message.
        """
        checksum = calculate_checksum16(message.encode('ascii'))
        message_with_checksum = f"{message}|{checksum:04X}" # add checksum to the message in the format: message|checksum (4 hex digits)
        self.socket.sendto(message_with_checksum.encode('ascii'), (self.daemon_ip, self.daemon_port))


    def start(self):
        """
        Entry point for the client to interact with the user.
        """
        response = self.connect_to_daemon()  # Connect to the daemon before starting

        if response[0] == "WELCOME":
            print(response[1])  # Welcome message
            self.options()
        elif response[0] == "CONNECTING":
            print("A chat request is pending. Waiting for the connection to be established...")
            while response[0] != "CONNECTING":
                response = self._receive_chat()
                if response[0] == "ERROR":
                    print(f"Error: {response[1]}")
                    self.options()
                    return
            self.start_chat()
        else:
            print("Unexpected response from daemon. Exiting.")
            exit(1)


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

        print(f"Chat request sent!"
              f"Waiting for response from {target_ip}...")

        response = self._receive_chat()
        self.chat_partner = response[1].split(": ")[1]
        print(response[1])

        print("Start chatting! Type 'q' to end the chat.")
        message = input("Enter your message: ")
        # Chat loop
        while response[0].upper() != "QUIT" or message.upper() != "Q":
            message = input(f"{self.username}: ")
            response = self._receive_chat()
            if response[0].upper() == "ERROR":
                print(f"Error: {response[1]}")
                break
            print(f"{self.chat_partner}: {response[1]}")

        print("Chat ended.")
        self.options()




    def wait_for_chat(self):
        """
        Wait for incoming chat requests from other users.
        """
        # inform daemon that client is waiting for chat requests
        print("Informing daemon that you are waiting for chat requests...")
        self._send_message("WAIT|")


        while True:
            response = self._receive_chat()
            if response[0] == "CONNECTING":
                print(f"Incoming chat request from {response[1]}")
                self.chat_partner = response[1]
                self.start_chat()
                break
            elif response[0] == "ERROR":
                print(f"Error: {response[1]}")
                return
            else:
                print("Still waiting for incoming chat requests...")


    def _receive_chat(self, timeout=5):
        """
        Receive chat messages from the daemon and format it to a list.
        Handle invalid or unexpected message formats and return an error message.
        """
        try:
            self.socket.settimeout(timeout) # setting timeout for receiving --> preventing infinite waiting
            data, addr = self.socket.recvfrom(1024)
            response = data.decode('ascii').split('|')
            if len(response) < 2: # check if the message is too short (at least op and payload needed!)
                raise ValueError("Error: Invalid message format!")
            #print(response[1])  # Print the chat message
            return response
        except socket.timeout:
            return ["ERROR", "Timeout while waiting for the response"]
        except Exception as e:
            print(f"Error: {e}")
            return ["ERROR", str(e)]


    def quit(self):
        """
        Disconnect from the daemon and exit.
        """
        print("Disconnecting from the daemon...")
        try:
            self._send_message("QUIT|")
            response = self._receive_chat()
            if response[0] == "DISCONNECTED":
                print(response[1]) # Print the disconnect message
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




