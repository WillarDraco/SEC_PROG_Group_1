import json
import socket
import time

msg = {
    "type": "USER_ADVERTISE",
    "from": "fake_server",
    "to": "*",
    "ts": int(time.time() * 1000),
    "payload": {
        "user_id": "hacker123",
        "server_id": "fake_server",
        "meta": {
            "pubkey": "FAKE_PUBLIC_KEY"
        }
    },
    "visited_servers": ["fake_server"],
    "sig": "INVALID_SIGNATURE"
}

# Convert to a single-line JSON string
msg_str = json.dumps(msg)

# Send to server (Change port and ip to match the server)
with socket.create_connection(("127.0.0.1", 34797)) as sock:
    sock.sendall((msg_str + "\n").encode())
