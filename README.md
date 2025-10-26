# Secure Chat Application (SOCP v1.3)

This project implements a secure peer-to-peer chat system with:
End-to-end encrypted direct messages (RSA-4096 + PSS)
Plaintext broadcast messages
Secure file transfer (RSA-OAEP per chunk)
Multi-server routing and introducer registration

## Contact

```
Group 1
Name                        ID              Discord
Benjamin Signorelli         a1861126        dracomaleficus
Willard Gorman              a1863235        nihili
Gia Thanh Nguyen            a1876555        g.l.toys
```

## Requirements

Make sure you have Python 3.10+ installed.
Then install dependencies:

```
pip install cryptography
```

## Project Structure

```
SecureProgramming/
│
├── app_server.py # Main server app (Thanh + Will + Ben)
├── client.py # Main client app (Thanh + Will + Ben)
├── introducer.py (Thanh + Will)
├── protocol.py (Ben + Will)
├── README (Thanh)
│
├── server/ (Thanh)
│ ├── __init__.py
│ └── transport_sig.py
│
├── client/ (Thanh)
│ ├── __init__.py
│ ├── crypto_km.py
│ ├── crypto_dm.py
│ ├── crypto_file.py
│ ├── crypto_api.py
│
└── common/ (Thanh)
├── __init__.py
├── b64url.py
└── canon.py

```

Each folder must contain an empty `__init__.py` to make imports work.

## How to Run the System

### 1 Start the Introducer

The introducer is the first server that other servers register to.
In one terminal, run:

```
python3 introducer.py
```

You’ll see something like:

```
[Introducer] Public key exported to introducer_pub.b64u
```

Leave this running.

### 2️ Start Additional Servers

Open two more terminals, and run each with a different port:

```
export SERVER_KEY_PASS= "Your Password"
python3 app_server.py
```

Each server will auto-register with the introducer and print something like:

```
[Server] Server running on 127.0.x.x:abcde
[Server] Registered with introducer as
```

### 3 Start Clients

Open another terminal for each client.
Run the client, and when asked for Server port, enter one of the ports printed by a server.
Example:

```
python3 client.py
Server port: abcde
```

It then will prompt for password, just press "Enter" (leave the password empty)
Note: client keys are unencrypted for ease of testing

Output:

```
[Hello] Sent USER_HELLO (pubkey attached)
[Me] user_id = e08d3983-64ac-40c9-ad99-9f3a836dfe2f
```

## Commands

Once connected, you can use the following commands in the client terminal:

/list: Request the user list (shows IDs + which server they’re on) (must do once for each client after enter port)

/ tell <user_id> <message>: Send an end-to-end encrypted DM

/all <message>: Broadcast a plaintext message to everyone

/file <user_id> <path>: Send a file (RSA-OAEP encrypted per chunk)

Example:

```
/tell 39a3ba6f-80d9-423b-99a6-1172f9ab1a71 hey userX!
/all hello everyone
/file 39a3ba6f-80d9-423b-99a6-1172f9ab1a71 test.txt
```
