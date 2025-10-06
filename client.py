import asyncio
import json
import uuid
import time
import os
import hashlib

# --- CRYPTO IMPORTS ---
from client.crypto_km import gen_rsa_4096, save_pem_priv, load_pem_priv, pub_der_b64u
from client.crypto_dm import make_dm_payload, open_dm_payload
from client.crypto_file import make_file_chunk_payload, open_file_chunk_payload

# Max RSA-OAEP plaintext size (bytes) for 4096-bit key, SHA-256
RSA_MOD_BYTES = 512
HASH_LEN = 32  # SHA-256
RSA_OAEP_MAX = RSA_MOD_BYTES - 2*HASH_LEN - 2  # = 446


class Client:
    def __init__(self, server_host="127.0.0.1", server_port=9000, key_path="me.pem", key_password=b"pwd"):
        self.client_id = str(uuid.uuid4())
        self.server_host = server_host
        self.server_port = server_port

        # presence + key directories
        self.users = {}          # user_id -> server_id
        self.user_pub = {}       # user_id -> pub_der_b64u (for E2E)
        self.seen_broadcasts = set()

        # files
        self.active_files = {}   # file_id -> {"name": str, "chunks": []}
        # file_id -> {"name": str, "size": int, "sha": str, "chunks": []}
        self.incoming_files = {}

        # key management
        self.key_path = key_path
        self.key_password = key_password
        if os.path.exists(self.key_path):
            self.priv = load_pem_priv(
                self.key_path, password=self.key_password)
        else:
            self.priv = gen_rsa_4096()
            save_pem_priv(self.priv, self.key_path, password=self.key_password)
        self.pub_b64u = pub_der_b64u(self.priv)

    # -------------------- SERVER LISTENER --------------------
    async def listen_server(self, reader):
        while True:
            try:
                line = await reader.readline()
                if not line:
                    print("[Connection] Server disconnected.")
                    break

                message = json.loads(line.decode().strip())
                mtype = message.get("type", "")
                sender = message.get("from", "")
                payload = message.get("payload", {})

                # --- USERS / KEYS SYNC ---
                if mtype == "USER_ADVERTISE":
                    user_id = payload["user_id"]
                    server_id = payload["server_id"]
                    self.users[user_id] = server_id
                    pubkey = payload.get("pubkey", "")
                    if pubkey:
                        self.user_pub[user_id] = pubkey
                    print(f"\n[Network] {user_id} on {server_id}")

                elif mtype == "USER_LIST":
                    # payload.users: [{user_id, server_id, (optional) pubkey}]
                    users = payload.get("users", [])
                    self.users = {u["user_id"]: u.get(
                        "server_id") for u in users}
                    # capture pubkeys if provided by introducer path
                    for u in users:
                        if "pubkey" in u and u["pubkey"]:
                            self.user_pub[u["user_id"]] = u["pubkey"]
                    print("\n[User List]")
                    for uid in sorted(self.users.keys()):
                        print(f"  {uid} -> {self.users[uid]}")
                    continue

                # --- DM (E2E) RECEIVE ---
                elif mtype == "MSG_DIRECT":
                    pld = message.get("payload", {})
                    if all(k in pld for k in ("ciphertext", "sender_pub", "content_sig")):
                        try:
                            pt, sender_pub = open_dm_payload(
                                self.priv,
                                pld,
                                message["from"],
                                message["to"],
                                message["ts"],
                            )
                            print(
                                f"\n[DM from {sender}]: {pt.decode('utf-8', 'ignore')} 🔒 (E2E)")
                            # cache sender pub
                            if "sender_pub" in pld:
                                self.user_pub[sender] = pld["sender_pub"]
                        except Exception as e:
                            print(f"\n[DM] decrypt/verify failed: {e}")
                    else:
                        # plaintext fallback (old format)
                        text = pld.get("text", "")
                        print(f"\n[DM from {sender}]: {text} (plaintext)")

                # --- FILE TRANSFER (E2E on CHUNKS) ---
                elif mtype == "FILE_START":
                    file_id = payload["file_id"]
                    filename = payload["name"]
                    filesize = payload.get("size", 0)
                    filehash = payload.get("sha256", "")
                    self.incoming_files[file_id] = {
                        "name": filename, "size": filesize, "sha": filehash, "chunks": []
                    }
                    print(
                        f"\n[File] Incoming '{filename}' ({filesize} bytes) from {sender}")

                elif mtype == "FILE_CHUNK":
                    file_id = payload["file_id"]
                    idx = payload["index"]
                    if file_id not in self.incoming_files:
                        # ignore if we never saw the start
                        continue
                    try:
                        chunk_data = open_file_chunk_payload(
                            self.priv, payload)
                        self.incoming_files[file_id]["chunks"].append(
                            (idx, chunk_data))
                        print(f"[File] Received chunk {idx} for {file_id}")
                    except Exception as e:
                        print(f"[File] chunk decrypt failed idx={idx}: {e}")

                elif mtype == "FILE_END":
                    file_id = payload["file_id"]
                    if file_id not in self.incoming_files:
                        continue
                    info = self.incoming_files[file_id]
                    ordered = [c for _, c in sorted(
                        info["chunks"], key=lambda x: x[0])]
                    data = b"".join(ordered)
                    dest = f"received_{info['name']}"
                    with open(dest, "wb") as f:
                        f.write(data)
                    sha = hashlib.sha256(data).hexdigest()
                    if info["sha"] and sha != info["sha"]:
                        print(
                            f"[File] ⚠️ Hash mismatch for {dest} (expected {info['sha']}, got {sha})")
                    else:
                        print(f"[File] ✅ Received {dest} ({len(data)} bytes)")
                    del self.incoming_files[file_id]

                elif mtype == "MSG_PUBLIC_CHANNEL":
                    bid = f"{message.get('from')}|{message.get('ts')}"
                    if bid in self.seen_broadcasts:
                        continue
                    self.seen_broadcasts.add(bid)

                    text = payload.get("text", "")
                    print(f"\n[Broadcast from {sender}]: {text}")

                else:
                    print(f"\n[Server message]: {message}")

            except Exception as e:
                print(f"[Error] Reading from server: {e}")
                break

    # -------------------- HELLO MESSAGE --------------------
    async def send_hello(self, writer):
        hello_message = {
            "type": "USER_HELLO",
            "from": self.client_id,
            "to": "*",
            "ts": int(time.time() * 1000),
            "payload": {
                "client": "cli-v1",
                "pubkey": self.pub_b64u,   # real RSA-4096 pub
                "enc_pubkey": self.pub_b64u
            },
            "sig": ""
        }
        writer.write((json.dumps(hello_message) + "\n").encode("utf-8"))
        await writer.drain()
        print(f"[Hello] Sent USER_HELLO (pubkey attached)")

    # -------------------- FILE SEND (RSA-OAEP per chunk) --------------------
    async def send_file(self, writer, recipient_id, file_path):
        if not os.path.exists(file_path):
            print("[File] Error: File not found.")
            return
        # need recipient pubkey
        rec_pub = self.user_pub.get(recipient_id)
        if not rec_pub:
            print(
                "[File] No recipient pubkey known yet; ask them to /tell you once or wait for advertise/list.")
            return

        file_id = str(uuid.uuid4())
        filesize = os.path.getsize(file_path)
        sha256_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()

        # FILE_START
        start_msg = {
            "type": "FILE_START",
            "from": self.client_id,
            "to": recipient_id,
            "ts": int(time.time() * 1000),
            "payload": {
                "file_id": file_id,
                "name": os.path.basename(file_path),
                "size": filesize,
                "sha256": sha256_hash,
                "mode": "dm"
            },
            "sig": ""
        }
        writer.write((json.dumps(start_msg) + "\n").encode("utf-8"))
        await writer.drain()
        print(
            f"[File] Starting file transfer '{file_path}' ({filesize} bytes)")

        CHUNK_SIZE = 400
        with open(file_path, "rb") as f:
            index = 0
            sent = 0
            while chunk := f.read(CHUNK_SIZE):
                # RSA encrypt the chunk for recipient
                chunk_payload = make_file_chunk_payload(
                    rec_pub, file_id, index, chunk)
                chunk_msg = {
                    "type": "FILE_CHUNK",
                    "from": self.client_id,
                    "to": recipient_id,
                    "ts": int(time.time() * 1000),
                    "payload": chunk_payload,
                    "sig": ""
                }
                writer.write((json.dumps(chunk_msg) + "\n").encode("utf-8"))
                await writer.drain()
                index += 1
                sent += len(chunk)
                percent = (sent / filesize) * 100
                print(f"[File] Sent chunk {index} ({percent:.1f}%)", end="\r")
        print()

        end_msg = {
            "type": "FILE_END",
            "from": self.client_id,
            "to": recipient_id,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": file_id},
            "sig": ""
        }
        writer.write((json.dumps(end_msg) + "\n").encode("utf-8"))
        await writer.drain()
        print(f"[File] ✅ Finished sending {file_path}")

    # -------------------- CHAT LOOP --------------------
    async def chat_loop(self, writer):
        while True:
            cmd = await asyncio.to_thread(input, "Enter command (/list, /tell, /all, /file): ")

            if cmd.strip() == "/list":
                req = {"type": "USER_LIST_REQUEST", "from": self.client_id,
                       "to": "*", "ts": int(time.time()*1000), "payload": {}, "sig": ""}
                writer.write((json.dumps(req) + "\n").encode("utf-8"))
                await writer.drain()
                print("[List] Requested user list from server...")
                continue

            if cmd.startswith("/tell "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    print("[Input] Usage: /tell <user_id> <message>")
                    continue

                to_id = parts[1].strip()      # normalise once
                text = parts[2]
                rec_pub = self.user_pub.get(to_id)
                if not rec_pub:
                    print(
                        "[DM] No recipient pubkey yet. Ask them to be online or run /list.")
                    continue

                # single timestamp reused everywhere
                ts_ms = int(time.time() * 1000)

                pt = text.encode("utf-8")
                if len(pt) > RSA_OAEP_MAX:
                    print(f"[DM] Message too long for RSA-OAEP ({len(pt)} bytes). "
                          f"Limit is {RSA_OAEP_MAX} bytes. Please shorten your message.")
                    continue

                # build RSA-only DM payload (signature covers ciphertext|from|to|ts)
                payload = make_dm_payload(
                    self.priv,
                    rec_pub,
                    text.encode("utf-8"),
                    self.client_id,
                    to_id,
                    ts_ms,
                )

                env = {
                    "type": "MSG_DIRECT",
                    "from": self.client_id,
                    "to": to_id,             # same string as above, no extra .strip()
                    "ts": ts_ms,             # reuse the same timestamp
                    "payload": payload,      # contains sender_pub + content_sig
                    "sig": "",
                    "visited_servers": []
                }

                writer.write((json.dumps(env) + "\n").encode("utf-8"))
                await writer.drain()
                print(f"[Sent] DM to {to_id} (E2E)")
                continue

            if cmd.startswith("/all "):
                text = cmd[len("/all "):].strip()
                if not text:
                    print("[Input] Usage: /all <message>")
                    continue
                # NOTE: public channel encryption not wired here; this is plaintext broadcast for now.
                # If needed, you can do per-recipient RSA like DM fan-out at client or leave as is.
                env = {"type": "MSG_PUBLIC_CHANNEL", "from": self.client_id, "to": "*", "ts": int(time.time()*1000),
                       "payload": {"text": text}, "sig": "", "visited_servers": []}
                writer.write((json.dumps(env) + "\n").encode("utf-8"))
                await writer.drain()
                print(f"[Broadcast] {text}")
                continue

            if cmd.startswith("/file "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    print("[Input] Usage: /file <user_id> <path>")
                    continue
                to_id, path = parts[1].strip(), parts[2].strip()
                await self.send_file(writer, to_id, path)
                continue

            print("[Input] Unknown command. Use /list, /tell, /all, or /file.")

    # -------------------- MAIN RUN LOOP --------------------
    async def run(self):
        reader, writer = await asyncio.open_connection(self.server_host, self.server_port)
        asyncio.create_task(self.listen_server(reader))
        await self.send_hello(writer)
        print(f"[Me] user_id = {self.client_id}")
        await self.chat_loop(writer)


if __name__ == "__main__":
    port = int(input("Server port: "))
    client = Client(server_host="127.0.0.1", server_port=port)
    asyncio.run(client.run())
