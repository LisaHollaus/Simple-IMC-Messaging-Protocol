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

### Notes
- We added a checksum to the protocol to ensure the integrity of the messages between daemon and daemon.
- 