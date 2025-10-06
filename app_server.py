# app_server.py
import asyncio
import json
import uuid
import time
import hashlib
import json

from server.transport_sig import server_sign_payload, server_verify_payload


class Server:
    def __init__(self, host="127.0.0.1", port=0, introducer_host="127.0.0.1", introducer_port=8000):
        self.server_id = str(uuid.uuid4())
        self.host = host
        self.port = port
        self.introducer_host = introducer_host
        self.introducer_port = introducer_port

        self.user_pubkeys = {}   # user_id -> pubkey_b64u
        self.peers = {}                 # server_id -> {"host":..., "port":...}
        self.active_peer_writers = {}   # server_id -> writer
        self.active_clients = {}        # client_id -> writer
        self.user_locations = {}        # client_id -> server_id
        self.active_files = {}          # file_id -> metadata
        self.seen_msgs = set()   # remembers broadcast ids we've processed

    # Helper to compute a sstable id
    def _broadcast_id(self, msg: dict) -> str:
        core = {
            "type": msg.get("type"),
            "from": msg.get("from"),
            "ts":   msg.get("ts"),
        }
        payload = msg.get("payload", {})
        try:
            payload_bytes = json.dumps(
                payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except Exception:
            payload_bytes = str(payload).encode("utf-8")
        head_bytes = json.dumps(core, sort_keys=True,
                                separators=(",", ":")).encode("utf-8")
        h = hashlib.sha256()
        h.update(head_bytes)
        h.update(payload_bytes)
        return h.hexdigest()

    # -------------------- Introducer registration --------------------

    async def register_with_introducer(self):
        try:
            reader, writer = await asyncio.open_connection(self.introducer_host, self.introducer_port)
            join_message = {
                "type": "SERVER_JOIN",
                "payload": {
                    "server_id": self.server_id,
                    "host": self.host,
                    "port": self.port,
                    "pubkey": "FAKE_PUBLIC_KEY"
                }
            }
            writer.write((json.dumps(join_message) + "\n").encode("utf-8"))
            await writer.drain()

            line = await reader.readline()
            if not line:
                print("[Error] No response from introducer")
            else:
                response = json.loads(line.decode().strip())
                print(f"[Introducer] Server list received: {response}")
                payload = response.get("payload", {})
                self.peers = payload.get("servers", {}) or {}
                clients = payload.get("clients", []) or []
                for c in clients:
                    uid = c.get("user_id")
                    host = c.get("host")
                    port = c.get("port")
                    sid = None
                    for s_id, s_info in self.peers.items():
                        if s_info.get("host") == host and s_info.get("port") == port:
                            sid = s_id
                            break
                    if uid and sid:
                        self.user_locations[uid] = sid
                print(
                    f"[User Locations] Initialized from introducer: {self.user_locations}")
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"[Error] Failed to register with introducer: {e}")

    # -------------------- Send advertise to introducer --------------------
    async def send_advertise_to_introducer(self, advertise_msg):
        try:
            r, w = await asyncio.open_connection(self.introducer_host, self.introducer_port)
            w.write((json.dumps(advertise_msg) + "\n").encode("utf-8"))
            await w.drain()
            try:
                ack = await asyncio.wait_for(r.readline(), timeout=0.5)
                if ack:
                    pass
            except asyncio.TimeoutError:
                pass
            w.close()
            await w.wait_closed()
            print("[Advertise] Sent USER_ADVERTISE to introducer")
        except Exception as e:
            print(f"[Error] Failed to advertise to introducer: {e}")

    # -------------------- Connection handler --------------------
    async def handle_connection(self, reader, writer):
        peer_name = writer.get_extra_info('peername')
        print(f"[Connection] New connection from {peer_name}")

        while True:
            try:
                line = await reader.readline()
                if not line:
                    print(f"[Connection] {peer_name} disconnected")
                    break

                message = json.loads(line.decode().strip())
                msg_type = message.get("type", "")
                sender = message.get("from")
                recipient = message.get("to")
                visited = set(message.get("visited_servers", []))

                # -------------------- USER_HELLO --------------------
                if msg_type == "USER_HELLO":
                    self.active_clients[sender] = writer
                    self.user_locations[sender] = self.server_id
                    pub = message.get("payload", {}).get("pubkey", "")
                    if pub:
                        self.user_pubkeys[sender] = pub
                    ack = {"type": "USER_HELLO_ACK",
                           "from": self.server_id, "to": sender, "payload": {}}
                    writer.write((json.dumps(ack) + "\n").encode("utf-8"))
                    await writer.drain()
                    print(f"[Hello] Registered client {sender}")
                    print("[User Locations] Current mapping:")
                    for uid, sid in self.user_locations.items():
                        print(f"  {uid} -> {sid}")

                    advertise_msg = {
                        "type": "USER_ADVERTISE",
                        "from": self.server_id,
                        "to": "*",
                        "ts": int(time.time() * 1000),
                        "payload": {
                            "user_id": sender,
                            "server_id": self.server_id,
                            "meta": {
                                "client": message.get("payload", {}).get("client", "cli-v1"),
                                "pubkey": message.get("payload", {}).get("pubkey", ""),
                                "enc_pubkey": message.get("payload", {}).get("enc_pubkey", "")
                            }
                        },
                        "sig": ""
                    }

                    for peer_id, peer_writer in list(self.active_peer_writers.items()):
                        try:
                            peer_writer.write(
                                (json.dumps(advertise_msg) + "\n").encode("utf-8"))
                            await peer_writer.drain()
                            print(
                                f"[Advertise] Sent USER_ADVERTISE for {sender} to peer {peer_id}")
                        except Exception as e:
                            print(
                                f"[Error] Failed to advertise user {sender} to peer {peer_id}: {e}")

                    asyncio.create_task(
                        self.send_advertise_to_introducer(advertise_msg))

                # -------------------- USER_ADVERTISE --------------------
                elif msg_type == "USER_ADVERTISE":
                    payload = message.get("payload", {})
                    user_id = payload.get("user_id")
                    server_id = payload.get("server_id")
                    if user_id and server_id:
                        self.user_locations[user_id] = server_id
                        pub = payload.get("meta", {}).get("pubkey", "")
                        if pub:
                            self.user_pubkeys[user_id] = pub
                        print(
                            f"[User Locations] Updated from peer: {user_id} -> {server_id}")

                # -------------------- MSG_DIRECT --------------------
                elif msg_type == "MSG_DIRECT":
                    if recipient in self.active_clients:
                        recipient_writer = self.active_clients[recipient]
                        recipient_writer.write(
                            (json.dumps(message) + "\n").encode("utf-8"))
                        await recipient_writer.drain()
                        print(
                            f"[Delivered] Direct message from {sender} delivered locally to {recipient}")
                    elif recipient in self.user_locations:
                        target_server_id = self.user_locations[recipient]
                        if target_server_id == self.server_id:
                            print(
                                f"[Routing] Recipient {recipient} expected local but not found")
                            error_msg = {"type": "USER_NOT_FOUND", "from": self.server_id, "to": sender, "payload": {
                                "missing_user": recipient}}
                            if sender in self.active_clients:
                                self.active_clients[sender].write(
                                    (json.dumps(error_msg) + "\n").encode("utf-8"))
                                await self.active_clients[sender].drain()
                        else:
                            peer_writer = self.active_peer_writers.get(
                                target_server_id)
                            if peer_writer:
                                message["visited_servers"] = list(
                                    visited | {self.server_id})
                                peer_writer.write(
                                    (json.dumps(message) + "\n").encode("utf-8"))
                                await peer_writer.drain()
                                print(
                                    f"[Forwarded] Direct message from {sender} forwarded to server {target_server_id}")
                            else:
                                print(
                                    f"[Routing] Target server {target_server_id} for {recipient} not connected")
                    else:
                        error_msg = {"type": "USER_NOT_FOUND", "from": self.server_id,
                                     "to": sender, "payload": {"missing_user": recipient}}
                        if sender in self.active_clients:
                            self.active_clients[sender].write(
                                (json.dumps(error_msg) + "\n").encode("utf-8"))
                            await self.active_clients[sender].drain()
                        print(
                            f"[Error] USER_NOT_FOUND for recipient {recipient}")

                # -------------------- USER_LIST_REQUEST --------------------
                elif msg_type == "USER_LIST_REQUEST":
                    # send current sorted list back to requester
                    users_sorted = [
                        {"user_id": uid, "server_id": sid,
                            "pubkey": self.user_pubkeys.get(uid, "")}
                        for uid, sid in sorted(self.user_locations.items())
                    ]
                    resp = {
                        "type": "USER_LIST",
                        "from": self.server_id,
                        "to": sender,
                        # "ts": int(time.time() * 1000),
                        "payload": {"users": users_sorted},
                        "sig": ""
                    }
                    writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                    await writer.drain()
                    print(f"[User List] Sent USER_LIST to {sender} on request")

                # -------------------- MSG_BROADCAST --------------------
                elif msg_type == "MSG_BROADCAST":
                    try:
                        mid = self._broadcast_id(message)
                    except Exception as e:
                        print(
                            f"[Broadcast] could not compute id: {e}; message={message}")
                        mid = None

                    if mid is not None:
                        if mid in self.seen_msgs:
                            # already processed — no local delivery, no forwarding
                            continue
                        self.seen_msgs.add(mid)

                    # ---- local delivery (except to sender) ----
                    try:
                        sender_id = message.get("from")
                        for client_id, client_writer in list(self.active_clients.items()):
                            if client_id != sender_id:
                                client_writer.write(
                                    (json.dumps(message) + "\n").encode("utf-8"))
                                await client_writer.drain()
                    except Exception as e:
                        print(f"[Broadcast] local delivery error: {e}")

                    # ---- forwarding to peers that haven't seen it ----
                    try:
                        visited = set(message.get("visited_servers", []))
                        visited.add(self.server_id)
                        message["visited_servers"] = list(visited)

                        for peer_id, peer_writer in list(self.active_peer_writers.items()):
                            if peer_id not in visited:
                                try:
                                    peer_writer.write(
                                        (json.dumps(message) + "\n").encode("utf-8"))
                                    await peer_writer.drain()
                                except Exception as e:
                                    print(
                                        f"[Broadcast] forward error to {peer_id}: {e}")
                    except Exception as e:
                        print(f"[Broadcast] forwarding block error: {e}")

                # -------------------- SERVER_ANNOUNCE --------------------
                elif msg_type == "SERVER_ANNOUNCE":
                    peer_id = sender
                    if peer_id not in self.active_peer_writers and peer_id != self.server_id:
                        try:
                            peer_host = message["payload"]["host"]
                            peer_port = message["payload"]["port"]
                            peer_reader, peer_writer = await asyncio.open_connection(peer_host, peer_port)
                            self.active_peer_writers[peer_id] = peer_writer
                            print(
                                f"[Peer] Connected back to announcing server {peer_id}")
                        except Exception as e:
                            print(
                                f"[Error] Failed to connect back to announcing server {peer_id}: {e}")

                # -------------------- FILE HANDLING --------------------
                elif msg_type in ["FILE_START", "FILE_CHUNK", "FILE_END"]:
                    payload = message.get("payload", {})
                    file_id = payload.get("file_id")
                    recipient = message.get("to")

                    if msg_type == "FILE_START" and file_id:
                        self.active_files[file_id] = {
                            "sender": sender,
                            "recipient": recipient,
                            "name": payload.get("name"),
                            "size": payload.get("size"),
                            "sha256": payload.get("sha256"),
                            "mode": payload.get("mode", "dm")
                        }
                        print(
                            f"[File] FILE_START {file_id} from {sender} to {recipient}")

                    if not recipient and file_id in self.active_files:
                        recipient = self.active_files[file_id]["recipient"]

                    if not recipient:
                        print(
                            f"[File] Missing recipient for {msg_type}, ignoring.")
                        continue

                    if recipient in self.active_clients:
                        rec_writer = self.active_clients[recipient]
                        rec_writer.write(
                            (json.dumps(message) + "\n").encode("utf-8"))
                        await rec_writer.drain()
                        print(
                            f"[File] Delivered {msg_type} locally to {recipient}")
                    elif recipient in self.user_locations:
                        target_server_id = self.user_locations[recipient]
                        if target_server_id != self.server_id and target_server_id in self.active_peer_writers:
                            peer_writer = self.active_peer_writers[target_server_id]
                            message["visited_servers"] = list(
                                visited | {self.server_id})
                            peer_writer.write(
                                (json.dumps(message) + "\n").encode("utf-8"))
                            await peer_writer.drain()
                            print(
                                f"[File] Forwarded {msg_type} for {recipient} to server {target_server_id}")
                        else:
                            print(
                                f"[File Routing] Target server {target_server_id} not connected for {recipient}")
                    else:
                        err = {"type": "USER_NOT_FOUND", "from": self.server_id,
                               "to": sender, "payload": {"missing_user": recipient}}
                        if sender in self.active_clients:
                            self.active_clients[sender].write(
                                (json.dumps(err) + "\n").encode("utf-8"))
                            await self.active_clients[sender].drain()
                        print(
                            f"[File Error] USER_NOT_FOUND for recipient {recipient}")

                    if msg_type == "FILE_END" and file_id in self.active_files:
                        print(f"[File] Transfer complete for {file_id}")
                        del self.active_files[file_id]

                else:
                    print(f"[Warning] Unknown message type: {msg_type}")

            except Exception as e:
                print(f"[Error] Connection error with {peer_name}: {e}")
                break

        for cid, w in list(self.active_clients.items()):
            if w == writer:
                del self.active_clients[cid]
                if cid in self.user_locations:
                    del self.user_locations[cid]
                print(f"[Cleanup] Removed client {cid}")
        writer.close()
        await writer.wait_closed()

    # -------------------- Peer Management --------------------
    async def send_announce(self, writer):
        announce_msg = {
            "type": "SERVER_ANNOUNCE",
            "from": self.server_id,
            "to": "*",
            "payload": {"host": self.host, "port": self.port, "pubkey": "FAKE_PUBLIC_KEY"},
            "sig": "..."
        }
        writer.write((json.dumps(announce_msg) + "\n").encode("utf-8"))
        await writer.drain()
        print("[Announce] Sent SERVER_ANNOUNCE to peer")

    async def connect_to_peers(self):
        for sid, info in self.peers.items():
            if sid == self.server_id:
                continue
            if sid not in self.active_peer_writers:
                try:
                    reader, writer = await asyncio.open_connection(info['host'], info['port'])
                    self.active_peer_writers[sid] = writer
                    print(f"[Peer] Connected to peer {sid}")
                    await self.send_announce(writer)
                except Exception as e:
                    print(f"[Error] Failed to connect to peer {sid}: {e}")

    # -------------------- Server Lifecycle --------------------
    async def run_server(self):
        server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        addr = server.sockets[0].getsockname()
        self.host, self.port = addr[0], addr[1]
        print(f"[Server] Running on {self.host}:{self.port}")
        return server

    async def run(self):
        server = await self.run_server()
        await self.register_with_introducer()
        await self.connect_to_peers()
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    srv = Server()
    asyncio.run(srv.run())
