import socket
import sys
import simp_check_functions as check

class Client:
    def __init__(self, daemon_ip):
        """
        Initialize the client to communicate with a specific daemon.
        """
        self.daemon_ip = daemon_ip
        self.daemon_port = 7778  # Default port for the daemon
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
        self.username = None  # Set during user login or setup

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
            data, addr = self.socket.recvfrom(1024)
            response = data.decode('ascii').split('|')
            if response[0] == "PONG":
                print(f"Connected to daemon at {self.daemon_ip}.")
            else:
                print(f"Error: {response[1]}")
                exit(1)

            # 3. If the response is positive, proceed with the client setup
            self.username = input("Enter your username: ")
            message = f"CONNECT|{self.username}"
            self._send_message(message)
            data, addr = self.socket.recvfrom(1024)
            response = data.decode('ascii').split('|')
            print(response[1])  # Print welcome message

        except Exception as e:
            print(f"Error: {e}")
            exit(1)



    def _send_message(self, message):
        """
        Send a message to the daemon.
        """
        self.socket.sendto(message.encode('ascii'), (self.daemon_ip, self.daemon_port))





    def start(self):
        """
        Entry point for the client to interact with the user.
        """
        self.connect_to_daemon()  # Connect to the daemon before starting

        # Daemon response:
        # info about pending chat requests
        # if no requests are pending, the client can choose to start a chat or wait for a chat request

        while True:
            print("\nWhat now? \n(1) Start Chat \n(2) Wait for Chat \n(q) Quit")
            choice = input("Choose an option: ")
            if choice == '1':
                self.start_chat()
            elif choice == '2':
                self.wait_for_chat()
            elif choice == 'q':
                self.quit()
                break







    def start_chat(self):
        """
        Initiate a chat request with another user.
        """
        target_ip = input("Enter the target user's IP address: ")
        # Placeholder: Logic to send a chat request to the target user

        # Example: Send a SYN datagram to the daemon
        # datagram = create_datagram(0x01, 0x02, self.username, "")
        # self.socket.sendto(datagram, (target_ip, 7777))
        print(f"Chat request sent to {target_ip}.")

    def wait_for_chat(self):
        """
        Wait for incoming chat requests from other users.
        """
        print("Waiting for incoming chat requests...")
        # Placeholder: Logic to receive and process incoming requests
        # Example: Receive SYN, respond with SYN+ACK

    def quit(self):
        """
        Disconnect from the daemon and exit.
        """
        print("Disconnecting from the daemon...")
        # Notify daemon of client disconnect
        self.socket.close()



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python simp_client.py <daemon IP>")
        exit(1)

    daemon_ip = sys.argv[1]

    # Validate IP address format
    check = check.is_valid_ip(daemon_ip)
    if not check:
        print(check)
        exit(1)

    client = Client(daemon_ip)
    client.start()




