### Protocol between client and daemon:

The protocol defines three operations:

Ping: Check if the daemon is alive.
Connect: Establish a connection between the client and the daemon.
Chat: Send chat messages from the client to the daemon.
Quit: Disconnect the client from the daemon.
Each message will have a simple format:

Simple format: Format: OPERATION|PAYLOAD
Operation: A short string to define the type of request (CONNECT, CHAT, QUIT).
Payload: Optional additional data (e.g., username, chat message).