"""
Group 1
Name                        ID              Discord
Benjamin Signorelli         a1861126        dracomaleficus
Willard Gorman              a1863235        nihili
Gia Thanh Nguyen            a1876555        g.l.toys
"""
# client.py
# Secure overlay chat client for encrypted messaging and file transfer.
# Communicates directly with a single server node.

import asyncio
import json
import uuid
import time
import os
import sys
import hashlib
import getpass
import re
from pathlib import Path

from client.crypto_km import gen_rsa_4096, save_pem_priv, load_pem_priv, pub_der_b64u
from client.crypto_dm import make_dm_payload, open_dm_payload
from client.crypto_file import make_file_chunk_payload, open_file_chunk_payload

RSA_MOD_BYTES = 512
HASH_LEN = 32
RSA_OAEP_MAX = RSA_MOD_BYTES - 2 * HASH_LEN - 2  # ~446 bytes

PROMPT = "Enter command (/list, /tell, /all, /file): "

# Security: Define download directory
DOWNLOAD_DIR = "received_files"


def sanitize_filename(filename):
    """
    Sanitize filename to prevent path traversal attacks.
    - Removes path separators (/, \)
    - Removes null bytes
    - Removes parent directory references (..)
    - Limits to alphanumeric, dash, underscore, dot
    - Truncates to reasonable length
    """
    if not filename:
        return "unnamed_file"

    # Get just the basename (no directory components)
    filename = os.path.basename(filename)

    # Remove any remaining path traversal attempts
    filename = filename.replace("..", "")
    filename = filename.replace("/", "")
    filename = filename.replace("\\", "")
    filename = filename.replace("\x00", "")

    # Only allow safe characters: alphanumeric, dash, underscore, dot
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

    # Prevent hidden files
    if filename.startswith('.'):
        filename = '_' + filename

    # Truncate to reasonable length
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:190] + ext[:10]

    # Ensure we have a valid filename
    if not filename or filename in ('.', '..'):
        filename = "unnamed_file"

    return filename


def get_unique_filepath(directory, filename):
    """
    Get a unique filepath by adding numbers if file exists.
    e.g., file.txt -> file_1.txt -> file_2.txt
    """
    filepath = os.path.join(directory, filename)
    if not os.path.exists(filepath):
        return filepath

    name, ext = os.path.splitext(filename)
    counter = 1
    while True:
        new_filename = f"{name}_{counter}{ext}"
        filepath = os.path.join(directory, new_filename)
        if not os.path.exists(filepath):
            return filepath
        counter += 1


def show_prompt():
    """Repaint the prompt only if using a real terminal."""
    if sys.stdin and sys.stdin.isatty():
        print(PROMPT, end="", flush=True)


class Client:
    def __init__(self, server_host="127.0.0.1", server_port=9000, key_path="me.pem"):
        self.client_id = str(uuid.uuid4())
        self.server_host = server_host
        self.server_port = server_port
        self.key_path = key_path

        # Local tables
        self.users = {}       # user_id -> server_id
        self.user_pub = {}    # user_id -> pubkey
        self.seen_broadcasts = set()

        # File tracking
        self.active_files = {}
        self.incoming_files = {}

        # Create download directory if it doesn't exist
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)

        # Load or create keypair
        pwd = os.getenv("CHAT_KEY_PASSWORD")
        if pwd is None and sys.stdin.isatty():
            try:
                pwd = getpass.getpass("Key password (leave blank for none): ")
            except Exception:
                pwd = None
        self.key_password = (pwd.encode() if pwd else None)

        if os.path.exists(self.key_path):
            self.priv = load_pem_priv(
                self.key_path, password=self.key_password)
        else:
            self.priv = gen_rsa_4096()
            save_pem_priv(self.priv, self.key_path, password=self.key_password)
        self.pub_b64u = pub_der_b64u(self.priv)

    # ----------------------------------------------------------------
    # Listen for server messages
    # ----------------------------------------------------------------
    async def listen_server(self, reader):
        while True:
            try:
                line = await reader.readline()
                if not line:
                    print("\n[Connection] Server closed connection.")
                    break

                msg = json.loads(line.decode().strip())
                mtype = msg.get("type")
                sender = msg.get("from")
                payload = msg.get("payload", {}) or {}

                # User updates
                if mtype == "USER_ADVERTISE":
                    uid = payload.get("user_id")
                    sid = payload.get("server_id")
                    if uid and sid:
                        self.users[uid] = sid
                    pub = (payload.get("meta", {}) or {}).get(
                        "pubkey") or payload.get("pubkey", "")
                    if uid and pub:
                        self.user_pub[uid] = pub
                    print(f"\n[Network] User {uid} joined via {sid}")
                    show_prompt()
                    continue

                elif mtype == "USER_REMOVE":
                    uid = (payload or {}).get("user_id")
                    if uid:
                        self.users.pop(uid, None)
                        self.user_pub.pop(uid, None)
                        print(f"\n[Network] User {uid} went offline")
                    show_prompt()
                    continue

                elif mtype == "USER_LIST":
                    users = payload.get("users", []) or []
                    self.users = {u["user_id"]: u.get(
                        "server_id") for u in users}
                    for u in users:
                        if "pubkey" in u:
                            self.user_pub[u["user_id"]] = u["pubkey"]
                    print("\n[User List]")
                    for uid in sorted(self.users.keys()):
                        print(f"  {uid} -> {self.users[uid]}")
                    show_prompt()
                    continue

                # Direct messages (E2E)
                elif mtype == "MSG_DIRECT":
                    pld = payload
                    if all(k in pld for k in ("ciphertext", "sender_pub", "content_sig")):
                        try:
                            pt, sender_pub = open_dm_payload(
                                self.priv, pld, msg.get(
                                    "from"), msg.get("to"), msg.get("ts")
                            )
                            text = pt.decode("utf-8", "ignore")
                            print(f"\n[DM from {sender[:8]}]: {text}")
                            if "sender_pub" in pld and sender:
                                self.user_pub[sender] = pld["sender_pub"]
                        except Exception as e:
                            print(f"\n[DM] Failed to decrypt: {e}")
                    else:
                        print(
                            f"\n[DM from {sender[:8]}]: {pld.get('text', '')}")
                    show_prompt()
                    continue

                # Broadcast channel
                elif mtype == "MSG_PUBLIC_CHANNEL":
                    msg_id = f"{msg.get('from')}|{msg.get('ts')}"
                    if msg_id not in self.seen_broadcasts:
                        self.seen_broadcasts.add(msg_id)
                        text = (payload or {}).get("text", "")
                        print(f"\n[Broadcast from {sender[:8]}]: {text}")
                    show_prompt()
                    continue

                # File start notice
                elif mtype == "FILE_START":
                    fid = payload.get("file_id")
                    fname = payload.get("name", "")
                    size = payload.get("size", 0)
                    sha = payload.get("sha256", "")

                    # Sanitize filename immediately
                    safe_fname = sanitize_filename(fname)

                    if fid and safe_fname:
                        self.incoming_files[fid] = {
                            "name": safe_fname,  # Store sanitized name
                            "original_name": fname,  # Keep original for display
                            "size": size,
                            "sha": sha,
                            "chunks": []
                        }
                        print(
                            f"\n[File] Receiving '{fname}' as '{safe_fname}' ({size} bytes) from {sender[:8]}")
                    show_prompt()
                    continue

                elif mtype == "FILE_CHUNK":
                    fid = payload.get("file_id")
                    idx = payload.get("index")
                    if not fid or fid not in self.incoming_files:
                        continue
                    try:
                        chunk_data = open_file_chunk_payload(
                            self.priv, payload)
                        self.incoming_files[fid]["chunks"].append(
                            (idx, chunk_data))
                    except Exception as e:
                        print(f"[File] Chunk {idx} decrypt failed: {e}")
                    show_prompt()
                    continue

                elif mtype == "FILE_END":
                    fid = payload.get("file_id")
                    if not fid or fid not in self.incoming_files:
                        continue
                    info = self.incoming_files[fid]
                    data = b"".join([c for _, c in sorted(info["chunks"])])

                    # Use sanitized filename and ensure unique path
                    safe_fname = info["name"]
                    filepath = get_unique_filepath(DOWNLOAD_DIR, safe_fname)

                    try:
                        with open(filepath, "wb") as f:
                            f.write(data)

                        sha = hashlib.sha256(data).hexdigest()
                        if info["sha"] and sha != info["sha"]:
                            print(f"\n[File] ⚠️ Hash mismatch for {filepath}")
                            print(f"  Expected: {info['sha']}")
                            print(f"  Got:      {sha}")
                        else:
                            print(
                                f"\n[File] ✓ Received {filepath} ({len(data)} bytes)")
                    except Exception as e:
                        print(f"\n[File] ✗ Failed to save file: {e}")

                    del self.incoming_files[fid]
                    show_prompt()
                    continue

                else:
                    print(f"\n[Server msg]: {msg}")
                    show_prompt()
                    continue

            except Exception as e:
                print(f"\n[Error] Reading from server: {e}")
                break

    # ----------------------------------------------------------------
    # Send USER_HELLO to announce this client
    # ----------------------------------------------------------------
    async def send_hello(self, writer):
        hello = {
            "type": "USER_HELLO",
            "from": self.client_id,
            "to": "*",
            "ts": int(time.time() * 1000),
            "payload": {
                "user_id": self.client_id,
                "client": "cli-v1",
                "pubkey": self.pub_b64u,
                "enc_pubkey": self.pub_b64u
            },
            "sig": ""
        }
        writer.write((json.dumps(hello) + "\n").encode())
        await writer.drain()
        print(f"[Hello] USER_HELLO sent (pubkey attached)")

    # ----------------------------------------------------------------
    # File transfer (RSA-OAEP chunks)
    # ----------------------------------------------------------------
    async def send_file(self, writer, to_uid, path):
        if not os.path.exists(path):
            print("[File] Path not found.")
            return

        # Security check: ensure path is not attempting traversal
        try:
            real_path = os.path.realpath(path)
            if not os.path.isfile(real_path):
                print("[File] Path is not a regular file.")
                return
        except Exception as e:
            print(f"[File] Invalid path: {e}")
            return

        rec_pub = self.user_pub.get(to_uid)
        if not rec_pub:
            print("[File] No recipient pubkey known.")
            return

        fid = str(uuid.uuid4())
        size = os.path.getsize(real_path)

        # Check file size limit (e.g., 100MB)
        MAX_FILE_SIZE = 100 * 1024 * 1024
        if size > MAX_FILE_SIZE:
            print(
                f"[File] File too large ({size} bytes). Maximum is {MAX_FILE_SIZE} bytes.")
            return

        with open(real_path, "rb") as f:
            data = f.read()
        sha = hashlib.sha256(data).hexdigest()

        # Send only the basename, not the full path
        filename = os.path.basename(real_path)

        start_msg = {
            "type": "FILE_START",
            "from": self.client_id,
            "to": to_uid,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": fid, "name": filename, "size": size, "sha256": sha},
            "sig": ""
        }
        writer.write((json.dumps(start_msg) + "\n").encode())
        await writer.drain()
        print(f"[File] Starting '{filename}' ({size} bytes)")

        CHUNK = 400
        idx = 0
        sent = 0
        with open(real_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                chunk_payload = make_file_chunk_payload(
                    rec_pub, fid, idx, chunk)
                chunk_msg = {
                    "type": "FILE_CHUNK",
                    "from": self.client_id,
                    "to": to_uid,
                    "ts": int(time.time() * 1000),
                    "payload": chunk_payload,
                    "sig": ""
                }
                writer.write((json.dumps(chunk_msg) + "\n").encode())
                await writer.drain()
                idx += 1
                sent += len(chunk)
                print(
                    f"[File] Sent chunk {idx} ({(sent/size)*100:.1f}%)", end="\r")
        print()

        end_msg = {
            "type": "FILE_END",
            "from": self.client_id,
            "to": to_uid,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": fid},
            "sig": ""
        }
        writer.write((json.dumps(end_msg) + "\n").encode())
        await writer.drain()
        print(f"[File] Completed '{filename}'")

    # ----------------------------------------------------------------
    # Input handler
    # ----------------------------------------------------------------
    async def chat_loop(self, writer):
        while True:
            show_prompt()
            cmd = await asyncio.to_thread(input, "")

            if cmd.strip() == "/list":
                req = {
                    "type": "USER_LIST_REQUEST",
                    "from": self.client_id,
                    "to": "*",
                    "ts": int(time.time() * 1000),
                    "payload": {},
                    "sig": ""
                }
                writer.write((json.dumps(req) + "\n").encode())
                await writer.drain()
                print("[List] Requested user list.")
                continue

            if cmd.startswith("/tell "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    print("[Usage] /tell <user_id> <message>")
                    continue
                to_uid, text = parts[1], parts[2]
                rec_pub = self.user_pub.get(to_uid)
                if not rec_pub:
                    print("[DM] Unknown recipient pubkey.")
                    continue

                msg_bytes = text.encode()
                if len(msg_bytes) > RSA_OAEP_MAX:
                    print(
                        f"[DM] Message too long ({len(msg_bytes)} bytes). Limit {RSA_OAEP_MAX}.")
                    continue

                ts = int(time.time() * 1000)
                payload = make_dm_payload(
                    self.priv, rec_pub, msg_bytes, self.client_id, to_uid, ts)
                msg = {
                    "type": "MSG_DIRECT",
                    "from": self.client_id,
                    "to": to_uid,
                    "ts": ts,
                    "payload": payload,
                    "sig": "",
                    "visited_servers": []
                }
                writer.write((json.dumps(msg) + "\n").encode())
                await writer.drain()
                print(f"[DM] Sent to {to_uid[:8]}")
                continue

            if cmd.startswith("/all "):
                text = cmd[len("/all "):].strip()
                if not text:
                    print("[Usage] /all <message>")
                    continue
                msg = {
                    "type": "MSG_PUBLIC_CHANNEL",
                    "from": self.client_id,
                    "to": "*",
                    "ts": int(time.time() * 1000),
                    "payload": {"text": text},
                    "sig": "",
                    "visited_servers": []
                }
                writer.write((json.dumps(msg) + "\n").encode())
                await writer.drain()
                print(f"[Broadcast] {text}")
                continue

            if cmd.startswith("/file "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    print("[Usage] /file <user_id> <path>")
                    continue
                to_uid, path = parts[1], parts[2]
                await self.send_file(writer, to_uid, path)
                continue

            print("[Input] Unknown command. Use /list, /tell, /all, or /file.")

    # ----------------------------------------------------------------
    # Entry point
    # ----------------------------------------------------------------
    async def run(self):
        reader, writer = await asyncio.open_connection(self.server_host, self.server_port)
        asyncio.create_task(self.listen_server(reader))
        await self.send_hello(writer)
        print(f"[Me] user_id = {self.client_id}")
        print(
            f"[Security] Files will be saved to: {os.path.abspath(DOWNLOAD_DIR)}")
        await self.chat_loop(writer)


if __name__ == "__main__":
    port = int(input("Server port: "))
    client = Client(server_host="127.0.0.1", server_port=port)
    asyncio.run(client.run())
