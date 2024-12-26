# Final Assignment 
#### Authors: Hollaus, Meseli

## How to run the application
### Preparations:
- activate the virtual environment

### Start the daemon:
In order to start the daemon, run the following command in the terminal:
python simp_daemon.py <IP address>

Example:
```bash
python simp_daemon.py 127.0.0.1
```
### Start the client:
In order to start the client, run the following command in the terminal:
python simp_client.py <daemon IP>

Example:
```bash
python simp_client.py 127.0.0.1
```

### Connect to another client:

1. Input the username of the client
2. Create another daemon - client pair (example using 127.0.0.2)
3. If there are other users you can connect to them, otherwise you have to wait for another user to connect to you
4. The other user can accept or decline the connection request 
5. If the connection request is accepted you can start chatting with the other user 
6. quit the chat by typing q in the message field


### Protocol between client and daemon:
We implemented a simple protocol between the client and the daemon, based on a simple text-based format.

The protocol defines following operations:

- Ping: Check if the daemon is alive. 
- Connect: Establish a connection between the client and the daemon.
- Connecting: The daemon is connecting to another daemon (chat partner).
- Chat: Send chat messages from the client to the daemon. 
- Quit: Disconnect the client from the daemon. 
- ERROR: Send an error message from the daemon to the client.

Each message will have a simple format: OPERATION|PAYLOAD

- Operation: A short string to define the type of request (CONNECT, CHAT, QUIT).
- Payload: Optional additional data (e.g., username, chat message).

### Additional Notes on our implementation approach:
- We added a checksum to the protocol to ensure the integrity of the messages between daemon and daemon.
- We assumed the client knows the IP address of the users daemon he wants to connect to, so we did not implement a discovery mechanism (example: Database).
- We added a timeout of 30 seconds for the chat partner to respond until the client gets asked again if he wants to keep on waiting or quit, to give the client the option to quit 
