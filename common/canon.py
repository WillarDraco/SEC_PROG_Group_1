"""
Group 1
Name                        ID              Discord
Benjamin Signorelli         a1861126        dracomaleficus
Willard Gorman              a1863235        nihili
Gia Thanh Nguyen            a1876555        g.l.toys
"""
import json
import hashlib


# ---- Convert data to JSON format and compute its SHA-256 hash for signing or verification ---- #
def canon(obj) -> bytes:
    # return (sorted key, no whitespace) JSON-encoded bytes
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')


def sha256_bytes(*chunks: bytes) -> bytes:
    # compute SHA-256 hassh of concatenated byte chunks and return raw 32 bytes digest
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()
