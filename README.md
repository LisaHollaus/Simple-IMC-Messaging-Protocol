# Final Assignment 
#### Authors: Hollaus, Meseli

A UDP based client-daemon communication Protocol.
Detailed description of the project can be found in the [Documentation.docx](Documentation.docx) file.

But here is a short overview on how to run the project:

### Preparations
- activate the virtual environment
- install requirements.txt

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
6. quit the chat by typing "q" in the message field


### Additional note from the authors:
The project is not fully functional yet. The connection between the clients is established, but the chat messages in the end seem to be echoing and therefore resulting in an invalid sequence number. 
Sadly, we were not able to fix this issue in time, but we are still working on it for our own learning purposes and hope to fix it soon.
