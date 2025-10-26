"""
Group 1
Name                        ID              Discord
Benjamin Signorelli         a1861126        dracomaleficus
Willard Gorman              a1863235        nihili
Gia Thanh Nguyen            a1876555        g.l.toys
"""
# # {
#   "type": "STRING",
#   "from": "STRING",          // "server_uuid" or "user_uuid"
#   "to":   "STRING",          // "server_uuid", "user_uuid", or "*"
#   "ts":   "INT",             // unix ms
#   "payload": { },            // object, type-specific
#   "sig": "BASE64URL"         // signature over canonical payload (see §10)
# # }

# The purpose of this file is to select the correct json message to send


def messageSelect(msg_type, payload):
    match msg_type:
        case "SERVER_HELLO_JOIN":
            return {
                "type": "SERVER_HELLO_JOIN",
                "from": server_id,
                "to": payload.get("to", "A.B.C.D:12345"),
                "ts": ts,
                "payload": {
                    "host": payload.get("host", "A.B.C.D"),
                    "port": payload.get("port", 12345),
                    "pubkey": payload.get("pubkey", "BASE64URL(RSA-4096-PUB)")
                },
                "sig": payload.get("sig", "...")
            }
        case "SERVER_ANNOUNCE":
            return {
                "type": "SERVER_ANNOUNCE",
                "from": server_id,
                "to": "*",  # Broadcast to all servers on the network
                "ts": ts,
                "payload": {
                    "host": payload.get("host", "A.B.C.D"),  # The Server's IP
                    # The Server's WS port
                    "port": payload.get("port", 12345),
                    "pubkey": payload.get("pubkey", "BASE64URL(RSA-4096-PUB)")
                },
                "sig": payload.get("sig", "...")
            }
        case "USER_ADVERTISE":
            return {
                "type": "USER_ADVERTISE",
                "from": "server_id",
                "to": "*",  # Broadcast to all servers, which relays to all clients
                "ts": 1700000100000,
                "payload": {"user_id": "the_user_id", "server_id": "server_id", "meta": {}},
                "sig": "..."
            }
        case "SERVER_DELIVER":
            return {
                "type": "SERVER_DELIVER",
                "from": "sender_server_id",
                "to": "recipient_server_id",
                "ts": 1700000300000,
                "payload": {
                    "user_id": "recipient_user_id",
                    "ciphertext": "<b64url RSA-OAEP(SHA-256)>",
                    "sender": "Bob",
                    "sender_pub": "<b64url RSA-4096 pub>",
                    "content_sig": "<b64url RSASSA-PSS(SHA-256)>"
                },
                "sig": "<server_2 signature over payload>"
            }
        case "HEARTBEAT":
            return {
                "type": "HEARTBEAT",
                "from": "server_1",
                "to": "server_2",
                "ts": 1700000002000,
                "payload": {},
                "sig": "..."
            }
        case "USER_HELLO":
            return {
                "type": "USER_HELLO",
                "from": "user_id",  # User's ID
                "to": "server_id",  # Local Server ID
                "ts": 1700000003000,
                "payload": {
                    "client": "cli-v1",
                    "pubkey": "<b64url RSA-4096 pub>",  # for signature verification by clients
                    # if using separate keys; else duplicate pubkey
                    "enc_pubkey": "<b64url RSA-4096 pub>"
                },
                "sig": ""  # optional on first frame
            }
        case "MSG_DIRECT":
            return {
                "type": "MSG_DIRECT",
                "from": "sender_user_id",  # UUID of sender
                "to": "recipent_user_id",  # UUID of recipient
                "ts": 1700000400000,
                "payload": {
                    "ciphertext": "<b64url RSA-OAEP(SHA-256) ciphertext over plaintext>",
                    "sender_pub": "<b64url RSA-4096 pub of sender>",
                    "content_sig": "<b64url RSASSA-PSS(SHA-256) over ciphertext|from|to|ts>"
                },
                "sig": "<optional client->server link sig; not required if TLS/Noise used>"
            }
        case "USER_DELIVER":
            return {
                "type": "USER_DELIVER",
                "from": "server_1",
                "to": "recipient_user_id",
                "ts": 1700000400100,
                "payload": {
                    "ciphertext": "<b64url RSA-OAEP(SHA-256)>",
                    "sender": "Bob",
                    "sender_pub": "<b64url RSA-4096 pub>",
                    "content_sig": "<b64url RSASSA-PSS(SHA-256)>"
                },
                "sig": "<server_1 signature over payload>"  # transport integrity
            }
        case "PUBLIC_CHANNEL_ADD":
            return {
                "type": "PUBLIC_CHANNEL_ADD",
                "from": "server_id",
                "to": "*",  # Broadcast to all Servers
                "ts": 0,
                "payload": {"add": ["Dave"], "if_version": 1},
                "sig": "..."
            }
        case "PUBLIC_CHANNEL_UPDATED":
            return {
                "type": "PUBLIC_CHANNEL_UPDATED",
                "from": payload.get("from", "server_id"),
                "to": payload.get("to", "*"),  # Broadcast to all servers
                "ts": payload.get("ts", 0),
                "payload": {
                    # Bumped every time a user is added or changed
                    "version": payload.get("version", 2),
                    "wraps": payload.get("wraps", [
                        {"member_id": "id", "wrapped_key": "..."},
                        {"member_id": "id", "wrapped_key": "..."},
                        {"member_id": "id", "wrapped_key": "..."},
                        {"member_id": "id", "wrapped_key": "..."}
                    ])
                },
                "sig": payload.get("sig", "...")
            }
        case "PUBLIC_CHANNEL_KEY_SHARE":
            return {
                "type": "PUBLIC_CHANNEL_KEY_SHARE",
                "from": payload.get("from", "sender_server_id"),
                "to": payload.get("to", "*"),  # Broadcast to all servers
                "ts": payload.get("ts", 1700000500000),
                "payload": {
                    "shares": payload.get("shares", [
                        {"member": "user_id", "wrapped_public_channel_key":
                            "<b64url RSA-OAEP(SHA-256) under user_id.pub>"},
                        {"member": "user_id",
                            "wrapped_public_channel_key": "<b64url ...>"}
                    ]),
                    "creator_pub": payload.get("creator_pub", "<b64url RSA-4096 pub>"),
                    "content_sig": payload.get("content_sig", "<b64url RSASSA-PSS over SHA-256(shares|creator_pub)>")
                },
                "sig": payload.get("sig", "")
            }
        case "MSG_PUBLIC_CHANNEL":
            return {
                "type": "MSG_PUBLIC_CHANNEL",
                "from": "user_id",
                "to": "g123",
                "ts": 1700000600000,
                "payload": {
                    "ciphertext": "<b64url RSA-OAEP(SHA-256) ciphertext>",
                    "sender_pub": "<b64url RSA-4096 pub>",
                    "content_sig": "<b64url RSASSA-PSS(SHA-256) over ciphertext|from|ts>"
                },
                "sig": ""
            }
        case "FILE_START":
            return {
                "type": "FILE_START",
                "from": "user_id",
                "to": "user_id",
                "ts": 1700000700000,
                "payload": {
                    "file_id": "uuid",
                    "name": "report.pdf",
                    "size": 1234567,
                    "sha256": "<hex>",
                    "mode": "dm"
                },
                "sig": "<optional>"
            }
        case "FILE_CHUNK":
            return {
                "type": "FILE_CHUNK",
                "from": "user_id",
                "to": "user_id",
                "ts": 1700000700500,
                "payload": {
                    "file_id": "uuid",
                    "index": 0,
                    "ciphertext": "<b64url>",
                },
                "sig": ""
            }
        case "FILE_END":
            return {
                "type": "FILE_END",
                "from": "user_id",
                "to": "user_id",
                "ts": 1700000701000,
                "payload": {"file_id": "uuid"},
                "sig": ""
            }
        case "ERROR":
            return {
                "type": "ERROR",
                "from": "server_id",
                "to": "server_id",
                "ts": 1700000900000,
                "payload": {"code": "USER_NOT_FOUND", "detail": "Bob not registered"},
                "sig": "..."
            }
