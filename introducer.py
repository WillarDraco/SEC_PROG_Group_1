"""
Group 1
Name                        ID              Discord
Benjamin Signorelli         a1861126        dracomaleficus
Willard Gorman              a1863235        nihili
Gia Thanh Nguyen            a1876555        g.l.toys
"""
# introducer.py
# Central registry node that links servers together.
# Tracks which users belong to which server and distributes user updates.

import asyncio
import json
import time
import os
import logging
from server.transport_sig import server_sign_payload
from client.crypto_km import gen_rsa_4096, save_pem_priv, load_pem_priv, pub_der_b64u

logging.basicConfig(
    level=os.getenv("LOGLEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [Introducer] %(message)s"
)

KEY_PATH = "introducer.pem"
PUB_PATH = "introducer_pub.b64u"

# --------------------------------------------------------------------
# Load or create introducer RSA key
# --------------------------------------------------------------------
if os.path.exists(KEY_PATH):
    introducer_priv = load_pem_priv(KEY_PATH, password=None)
else:
    introducer_priv = gen_rsa_4096()
    save_pem_priv(introducer_priv, KEY_PATH, password=None)

introducer_pub_b64u = pub_der_b64u(introducer_priv)
with open(PUB_PATH, "w") as f:
    f.write(introducer_pub_b64u)

logging.info(f"Public key exported to {PUB_PATH}")
logging.info(f"Tip: export INTRODUCER_PUB_B64U=$(cat {PUB_PATH})")

# --------------------------------------------------------------------
# State tables
# --------------------------------------------------------------------
servers = {}   # server_id -> {host, port, pubkey}
clients = {}   # user_id -> {"server": id, "pubkey": key}


async def handle_server(reader, writer):
    """Handle all server-side requests (join, advertise, remove)."""
    peer = writer.get_extra_info("peername")
    logging.info(f"Connection from {peer}")

    try:
        line = await reader.readline()
        if not line:
            logging.warning("Empty message from server, skipping")
            return

        msg = json.loads(line.decode().strip())
        mtype = msg.get("type")
        payload = msg.get("payload", {}) or {}

        # ---------------------------------------------------------------
        # SERVER_JOIN — server registration
        # ---------------------------------------------------------------
        if mtype == "SERVER_JOIN":
            sid = payload.get("server_id")
            host = payload.get("host")
            port = payload.get("port")
            pubkey = payload.get("pubkey")

            if not all([sid, host, port, pubkey]):
                logging.warning("Incomplete SERVER_JOIN payload")
                return

            servers[sid] = {"host": host, "port": port, "pubkey": pubkey}

            welcome_payload = {
                "assigned_id": sid,
                "servers": servers,
                "clients": [
                    {"user_id": uid, "server_id": info["server"], "meta": {
                        "pubkey": info.get("pubkey", "")}}
                    for uid, info in clients.items()
                ],
                "introducer_pub": introducer_pub_b64u
            }

            sig = server_sign_payload(introducer_priv, welcome_payload)
            response = {
                "type": "SERVER_WELCOME",
                "from": "introducer",
                "to": sid,
                "ts": int(time.time() * 1000),
                "payload": welcome_payload,
                "sig": sig
            }

            writer.write((json.dumps(response) + "\n").encode())
            await writer.drain()

            logging.info(f"Registered server {sid[:8]} at {host}:{port}")
            logging.info(f"Total servers: {len(servers)}")

            # Send all known clients to this new server
            for uid, info in clients.items():
                adv_payload = {
                    "user_id": uid,
                    "server_id": info["server"],
                    "meta": {"pubkey": info.get("pubkey", "")}
                }
                sig_adv = server_sign_payload(introducer_priv, adv_payload)
                adv = {
                    "type": "USER_ADVERTISE",
                    "from": "introducer",
                    "to": sid,
                    "ts": int(time.time() * 1000),
                    "payload": adv_payload,
                    "sig": sig_adv
                }
                try:
                    r, w = await asyncio.open_connection(host, port)
                    w.write((json.dumps(adv) + "\n").encode())
                    await w.drain()
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass

        # ---------------------------------------------------------------
        # USER_ADVERTISE — new user joined
        # ---------------------------------------------------------------
        elif mtype == "USER_ADVERTISE":
            user_id = payload.get("user_id")
            server_id = payload.get("server_id")
            meta = payload.get("meta", {}) or {}

            if not user_id or not server_id:
                logging.warning("Invalid USER_ADVERTISE payload")
                return

            pub = meta.get("pubkey", "")
            clients[user_id] = {"server": server_id, "pubkey": pub}
            logging.info(
                f"User {user_id[:8]} joined via {server_id[:8]} (pubkey={'yes' if pub else 'no'})")
            logging.info(f"Total clients: {len(clients)}")

            adv_payload = {"user_id": user_id,
                           "server_id": server_id, "meta": {"pubkey": pub}}
            # Sign the full payload including meta.pubkey
            sig = server_sign_payload(introducer_priv, adv_payload)
            adv_msg = {
                "type": "USER_ADVERTISE",
                "from": "introducer",
                "to": "*",
                "ts": int(time.time() * 1000),
                "payload": adv_payload,
                "sig": sig
            }

            # Broadcast new user to all servers
            for sid, info in servers.items():
                try:
                    r, w = await asyncio.open_connection(info["host"], info["port"])
                    w.write((json.dumps(adv_msg) + "\n").encode())
                    await w.drain()
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass

        # ---------------------------------------------------------------
        # USER_REMOVE — user disconnected
        # ---------------------------------------------------------------
        elif mtype == "USER_REMOVE":
            user_id = payload.get("user_id")
            server_id = payload.get("server_id")

            if user_id in clients:
                del clients[user_id]
                logging.info(f"User {user_id[:8]} removed from registry")

            # Inform all servers
            rm_payload = {"user_id": user_id, "server_id": server_id}
            sig = server_sign_payload(introducer_priv, rm_payload)
            rm_msg = {
                "type": "USER_REMOVE",
                "from": "introducer",
                "to": "*",
                "ts": int(time.time() * 1000),
                "payload": rm_payload,
                "sig": sig
            }

            for sid, info in servers.items():
                try:
                    r, w = await asyncio.open_connection(info["host"], info["port"])
                    w.write((json.dumps(rm_msg) + "\n").encode())
                    await w.drain()
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass

        else:
            logging.warning(f"Unknown message type: {mtype}")

    except Exception as e:
        logging.exception(f"Error handling message: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


# --------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------
async def main():
    server = await asyncio.start_server(handle_server, "127.0.0.1", 8000)
    addr = server.sockets[0].getsockname()
    logging.info(f"Running on {addr[0]}:{addr[1]}")
    logging.info(f"Public key (first 30 chars): {introducer_pub_b64u[:30]}...")
    logging.info("Waiting for servers to connect...\n")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
