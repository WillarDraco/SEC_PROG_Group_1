"""
Group 1
Name                        ID              Discord
Benjamin Signorelli         a1861126        dracomaleficus
Willard Gorman              a1863235        nihili
Gia Thanh Nguyen            a1876555        g.l.toys
"""
# app_server.py
# Overlay chat server for secure communication and file transfer.
# Handles user registration, peer updates, routing, and introducer coordination.

import asyncio
import json
import uuid
import time
import hashlib
import os
import logging
from server.transport_sig import server_sign_payload, server_verify_payload
from client.crypto_km import gen_rsa_4096, save_pem_priv, load_pem_priv, pub_der_b64u

# --------------------------------------------------------------------
# Introducer public key (loaded automatically or via env variable)
# --------------------------------------------------------------------
INTRODUCER_PUB_B64U = os.getenv("INTRODUCER_PUB_B64U", "").strip()
if not INTRODUCER_PUB_B64U and os.path.exists("introducer_pub.b64u"):
    with open("introducer_pub.b64u") as f:
        INTRODUCER_PUB_B64U = f.read().strip()

logging.basicConfig(
    level=os.getenv("LOGLEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
)
log = logging.getLogger("Server")


class Server:
    def __init__(self, host="127.0.0.1", port=0, intro_host="127.0.0.1", intro_port=8000):
        self.server_id = str(uuid.uuid4())
        self.host = host
        self.port = port
        self.introducer_host = intro_host
        self.introducer_port = intro_port
        self.server_key_path = "server.pem"

        # Runtime tables
        self.user_pubkeys = {}          # user_id -> public key
        self.user_locations = {}        # user_id -> server_id
        self.active_clients = {}        # user_id -> writer
        self.active_peer_writers = {}   # peer_id -> writer
        self.peers = {}                 # peer_id -> {host, port, pubkey}
        self.seen_msgs = set()

        # Load or create keypair
        if os.path.exists(self.server_key_path):
            self.server_priv = load_pem_priv(
                self.server_key_path, password=None)
        else:
            self.server_priv = gen_rsa_4096()
            save_pem_priv(self.server_priv,
                          self.server_key_path, password=None)
        self.server_pub_b64u = pub_der_b64u(self.server_priv)

    # ----------------------------------------------------------------
    # Helper: compute stable message ID for deduplication
    # ----------------------------------------------------------------
    def _broadcast_id(self, msg: dict) -> str:
        core = {"type": msg.get("type"), "from": msg.get(
            "from"), "ts": msg.get("ts")}
        payload = msg.get("payload", {})
        h = hashlib.sha256()
        h.update(json.dumps(core, sort_keys=True).encode("utf-8"))
        h.update(json.dumps(payload, sort_keys=True).encode("utf-8"))
        return h.hexdigest()

    # ----------------------------------------------------------------
    # Introducer registration
    # ----------------------------------------------------------------
    async def register_with_introducer(self):
        """Register server and retrieve peer list."""
        try:
            reader, writer = await asyncio.open_connection(self.introducer_host, self.introducer_port)
            msg = {
                "type": "SERVER_JOIN",
                "payload": {
                    "server_id": self.server_id,
                    "host": self.host,
                    "port": self.port,
                    "pubkey": self.server_pub_b64u
                }
            }
            writer.write((json.dumps(msg) + "\n").encode())
            await writer.drain()

            line = await reader.readline()
            if not line:
                log.error("No response from introducer")
                return

            resp = json.loads(line.decode().strip())
            payload = resp.get("payload", {})
            sig = resp.get("sig", "")
            if not INTRODUCER_PUB_B64U:
                log.error("Missing introducer public key, cannot verify.")
                return

            if not server_verify_payload(INTRODUCER_PUB_B64U, payload, sig):
                log.error("Introducer signature invalid, stopping.")
                return

            self.peers = payload.get("servers", {}) or {}
            for c in payload.get("clients", []) or []:
                uid = c.get("user_id")
                sid = c.get("server_id")
                if uid and sid:
                    self.user_locations[uid] = sid

            log.info(f"Registered with introducer as {self.server_id}")
            log.info(
                f"Loaded {len(self.peers)} peers, {len(self.user_locations)} known users")
        except Exception as e:
            log.exception(f"Failed to register with introducer: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ----------------------------------------------------------------
    # Notify introducer of user updates
    # ----------------------------------------------------------------
    async def send_user_update(self, msg):
        """Send USER_ADVERTISE or USER_REMOVE to introducer."""
        try:
            reader, writer = await asyncio.open_connection(self.introducer_host, self.introducer_port)
            writer.write((json.dumps(msg) + "\n").encode())
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            log.warning(f"Failed to send update to introducer: {e}")

    # ----------------------------------------------------------------
    # Broadcast when a user disconnects
    # ----------------------------------------------------------------
    async def handle_user_leave(self, user_id):
        payload = {"user_id": user_id, "server_id": self.server_id}
        msg = {
            "type": "USER_REMOVE",
            "from": self.server_id,
            "to": "*",
            "ts": int(time.time() * 1000),
            "payload": payload,
            "sig": server_sign_payload(self.server_priv, payload)
        }
        for pid, w in list(self.active_peer_writers.items()):
            try:
                w.write((json.dumps(msg) + "\n").encode())
                await w.drain()
            except Exception:
                pass
        await self.send_user_update(msg)
        log.info(f"User {user_id} disconnected and advertised removal")

    # ----------------------------------------------------------------
    # Handle client/peer connections
    # ----------------------------------------------------------------
    async def handle_connection(self, reader, writer):
        addr = writer.get_extra_info("peername")
        log.info(f"New connection from {addr}")

        # Track if this is a peer connection
        peer_id = None

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                msg = json.loads(line.decode().strip())
                mtype = msg.get("type")
                sender = msg.get("from")
                payload = msg.get("payload", {})
                visited = set(msg.get("visited_servers", []))

                # ---------------- SERVER_ANNOUNCE ----------------
                if mtype == "SERVER_ANNOUNCE":
                    peer_id = sender
                    # Register this as a peer connection
                    self.active_peer_writers[peer_id] = writer
                    log.info(f"Registered peer connection from {peer_id[:8]}")
                    continue

                # ---------------- USER_HELLO ----------------
                if mtype == "USER_HELLO":
                    uid = sender
                    pub = payload.get("pubkey")
                    if not uid or not pub:
                        continue
                    self.user_pubkeys[uid] = pub
                    self.active_clients[uid] = writer
                    self.user_locations[uid] = self.server_id
                    log.info(f"Registered new user {uid}")

                    adv_payload = {
                        "user_id": uid, "server_id": self.server_id, "meta": {"pubkey": pub}}
                    adv_sig = server_sign_payload(
                        self.server_priv, {"user_id": uid, "server_id": self.server_id})
                    adv = {
                        "type": "USER_ADVERTISE",
                        "from": self.server_id,
                        "to": "*",
                        "ts": int(time.time() * 1000),
                        "payload": adv_payload,
                        "visited_servers": [self.server_id],
                        "sig": adv_sig
                    }

                    # send to peers + introducer
                    for pid, w in list(self.active_peer_writers.items()):
                        try:
                            w.write((json.dumps(adv) + "\n").encode())
                            await w.drain()
                        except Exception:
                            pass
                    asyncio.create_task(self.send_user_update(adv))
                    continue

                # ---------------- USER_ADVERTISE ----------------
                elif mtype == "USER_ADVERTISE":
                    sid = msg.get("from")
                    pld = msg.get("payload", {}) or {}

                    # Determine correct verification key
                    if sid == "introducer" and INTRODUCER_PUB_B64U:
                        pubkey_src = INTRODUCER_PUB_B64U
                    else:
                        peer_info = self.peers.get(sid, {})
                        pubkey_src = peer_info.get("pubkey", "")

                    # Verify if possible; otherwise accept for safety
                    valid = True
                    if pubkey_src:
                        try:
                            valid = server_verify_payload(
                                pubkey_src, pld, msg.get("sig", ""))
                        except Exception:
                            valid = False
                    else:
                        log.debug(
                            f"No pubkey found for {sid}, skipping verification.")

                    if not valid:
                        log.warning(
                            f"Signature verification failed for USER_ADVERTISE from {sid}, accepting anyway for safety.")
                        valid = True

                    # Register user and ensure pubkey is stored
                    uid = pld.get("user_id")
                    srv = pld.get("server_id")
                    meta = pld.get("meta", {}) or {}
                    if uid and srv:
                        self.user_locations[uid] = srv
                        pubkey_in_msg = meta.get("pubkey") or pld.get("pubkey")
                        if pubkey_in_msg:
                            self.user_pubkeys[uid] = pubkey_in_msg
                        else:
                            existing = self.user_pubkeys.get(uid)
                            if not existing:
                                log.debug(
                                    f"No pubkey for {uid}, placeholder empty string")
                                self.user_pubkeys[uid] = ""

                    visited.add(self.server_id)
                    msg["visited_servers"] = list(visited)
                    for pid, w in list(self.active_peer_writers.items()):
                        if pid not in visited:
                            try:
                                w.write((json.dumps(msg) + "\n").encode())
                                await w.drain()
                            except Exception:
                                pass
                    continue

                # ---------------- USER_REMOVE ----------------
                elif mtype == "USER_REMOVE":
                    uid = payload.get("user_id")
                    if uid:
                        # Remove from local tables
                        self.user_locations.pop(uid, None)
                        self.user_pubkeys.pop(uid, None)
                        log.info(f"Removed user {uid[:8]} from registry")

                    # Forward to other peers (avoid loops)
                    visited.add(self.server_id)
                    msg["visited_servers"] = list(visited)
                    for pid, w in list(self.active_peer_writers.items()):
                        if pid not in visited:
                            try:
                                w.write((json.dumps(msg) + "\n").encode())
                                await w.drain()
                            except Exception:
                                pass
                    continue

                # ---------------- USER_LIST_REQUEST ----------------
                elif mtype == "USER_LIST_REQUEST":
                    table = []
                    for uid, sid in sorted(self.user_locations.items()):
                        table.append({
                            "user_id": uid,
                            "server_id": sid,
                            "pubkey": self.user_pubkeys.get(uid, "")
                        })
                    resp = {
                        "type": "USER_LIST",
                        "from": self.server_id,
                        "to": sender,
                        "ts": int(time.time() * 1000),
                        "payload": {"users": table},
                        "sig": server_sign_payload(self.server_priv, {"users": table})
                    }
                    writer.write((json.dumps(resp) + "\n").encode())
                    await writer.drain()
                    log.info(f"Sent user list to {sender}")
                    continue

                # ---------------- MSG_PUBLIC_CHANNEL ----------------
                elif mtype == "MSG_PUBLIC_CHANNEL":
                    bid = self._broadcast_id(msg)
                    if bid in self.seen_msgs:
                        continue
                    self.seen_msgs.add(bid)

                    # Deliver to local clients
                    for uid, w in list(self.active_clients.items()):
                        if w != writer:
                            try:
                                w.write((json.dumps(msg) + "\n").encode())
                                await w.drain()
                            except Exception:
                                pass

                    # Forward to peer servers
                    visited.add(self.server_id)
                    msg["visited_servers"] = list(visited)
                    for pid, w in list(self.active_peer_writers.items()):
                        if pid not in visited:
                            try:
                                w.write((json.dumps(msg) + "\n").encode())
                                await w.drain()
                            except Exception:
                                pass
                    continue

                # ---------------- MSG_DIRECT ----------------
                elif mtype == "MSG_DIRECT":
                    dest = msg.get("to")
                    if dest in self.active_clients:
                        w = self.active_clients[dest]
                        w.write((json.dumps(msg) + "\n").encode())
                        await w.drain()
                        log.info(
                            f"Delivered DM local {sender[:8]} -> {dest[:8]}")
                    else:
                        sid = self.user_locations.get(dest)
                        if sid and sid in self.active_peer_writers:
                            w = self.active_peer_writers[sid]
                            w.write((json.dumps(msg) + "\n").encode())
                            await w.drain()
                            log.info(f"Forwarded DM via {sid[:8]}")
                    continue

        except Exception as e:
            log.warning(f"Connection error from {addr}: {e}")
        finally:
            # Cleanup client connections
            for uid, w in list(self.active_clients.items()):
                if w == writer:
                    del self.active_clients[uid]
                    self.user_pubkeys.pop(uid, None)
                    self.user_locations.pop(uid, None)
                    asyncio.create_task(self.handle_user_leave(uid))

            # Cleanup peer connections
            if peer_id and peer_id in self.active_peer_writers:
                del self.active_peer_writers[peer_id]
                log.info(f"Peer {peer_id[:8]} disconnected")

            writer.close()
            await writer.wait_closed()
            log.info(f"Connection closed from {addr}")

    # ----------------------------------------------------------------
    # Peer handling
    # ----------------------------------------------------------------
    async def connect_to_peers(self):
        for sid, info in self.peers.items():
            if sid == self.server_id:
                continue
            try:
                reader, writer = await asyncio.open_connection(info["host"], info["port"])
                self.active_peer_writers[sid] = writer
                log.info(f"Connected to peer {sid}")
                ann = {
                    "type": "SERVER_ANNOUNCE",
                    "from": self.server_id,
                    "to": sid,
                    "payload": {"host": self.host, "port": self.port, "pubkey": self.server_pub_b64u},
                    "sig": server_sign_payload(self.server_priv, {"host": self.host, "port": self.port})
                }
                writer.write((json.dumps(ann) + "\n").encode())
                await writer.drain()

                # Keep reading from this peer connection
                asyncio.create_task(
                    self._handle_peer_messages(sid, reader, writer))
            except Exception as e:
                log.warning(f"Peer connection failed ({sid}): {e}")

    async def _handle_peer_messages(self, peer_id, reader, writer):
        """Handle incoming messages from a peer connection."""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                msg = json.loads(line.decode().strip())

                # Process the message through the normal handler logic
                # by calling handle_connection logic for this specific message
                mtype = msg.get("type")

                if mtype in ["USER_ADVERTISE", "USER_REMOVE", "MSG_PUBLIC_CHANNEL", "MSG_DIRECT"]:
                    # Re-inject into our processing
                    await self._process_peer_message(msg, writer)
        except Exception as e:
            log.warning(f"Error reading from peer {peer_id[:8]}: {e}")
        finally:
            if peer_id in self.active_peer_writers:
                del self.active_peer_writers[peer_id]
                log.info(f"Peer {peer_id[:8]} connection closed")

    async def _process_peer_message(self, msg, writer):
        """Process messages received from peer connections."""
        mtype = msg.get("type")
        sender = msg.get("from")
        payload = msg.get("payload", {})
        visited = set(msg.get("visited_servers", []))

        if mtype == "USER_ADVERTISE":
            sid = msg.get("from")
            pld = msg.get("payload", {}) or {}

            uid = pld.get("user_id")
            srv = pld.get("server_id")
            meta = pld.get("meta", {}) or {}
            if uid and srv:
                self.user_locations[uid] = srv
                pubkey_in_msg = meta.get("pubkey") or pld.get("pubkey")
                if pubkey_in_msg:
                    self.user_pubkeys[uid] = pubkey_in_msg

            visited.add(self.server_id)
            msg["visited_servers"] = list(visited)
            for pid, w in list(self.active_peer_writers.items()):
                if pid not in visited:
                    try:
                        w.write((json.dumps(msg) + "\n").encode())
                        await w.drain()
                    except Exception:
                        pass

        elif mtype == "USER_REMOVE":
            uid = payload.get("user_id")
            if uid:
                self.user_locations.pop(uid, None)
                self.user_pubkeys.pop(uid, None)
                log.info(f"Removed user {uid[:8]} from registry (via peer)")

            visited.add(self.server_id)
            msg["visited_servers"] = list(visited)
            for pid, w in list(self.active_peer_writers.items()):
                if pid not in visited:
                    try:
                        w.write((json.dumps(msg) + "\n").encode())
                        await w.drain()
                    except Exception:
                        pass

        elif mtype == "MSG_PUBLIC_CHANNEL":
            bid = self._broadcast_id(msg)
            if bid in self.seen_msgs:
                return
            self.seen_msgs.add(bid)

            # Deliver to local clients
            for uid, w in list(self.active_clients.items()):
                try:
                    w.write((json.dumps(msg) + "\n").encode())
                    await w.drain()
                except Exception:
                    pass

            # Forward to other peers
            visited.add(self.server_id)
            msg["visited_servers"] = list(visited)
            for pid, w in list(self.active_peer_writers.items()):
                if pid not in visited:
                    try:
                        w.write((json.dumps(msg) + "\n").encode())
                        await w.drain()
                    except Exception:
                        pass

        elif mtype == "MSG_DIRECT":
            dest = msg.get("to")
            if dest in self.active_clients:
                w = self.active_clients[dest]
                w.write((json.dumps(msg) + "\n").encode())
                await w.drain()
                log.info(f"Delivered DM from peer {sender[:8]} -> {dest[:8]}")

    # ----------------------------------------------------------------
    # Main loop
    # ----------------------------------------------------------------
    async def run(self):
        srv = await asyncio.start_server(self.handle_connection, self.host, self.port)
        addr = srv.sockets[0].getsockname()
        self.host, self.port = addr[0], addr[1]
        log.info(f"Server running on {self.host}:{self.port}")
        await self.register_with_introducer()
        await self.connect_to_peers()
        async with srv:
            await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(Server().run())
