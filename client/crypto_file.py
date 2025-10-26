"""
Group 1
Name                        ID              Discord
Benjamin Signorelli         a1861126        dracomaleficus
Willard Gorman              a1863235        nihili
Gia Thanh Nguyen            a1876555        g.l.toys
"""
from common.b64url import b64u, ub64u
from client.crypto_km import pub_from_der
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# ---- RSA-OAEP ciphertext ---- #
def make_file_chunk_payload(receiver_pub_der_b64u: str, file_id: str, index: int, plaintext_chunk: bytes) -> dict:
    rpk = pub_from_der(ub64u(receiver_pub_der_b64u))

    ct = rpk.encrypt(
        plaintext_chunk,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    return {"file_id": file_id, "index": index, "ciphertext": b64u(ct)}


def open_file_chunk_payload(receiver_priv, payload: dict) -> bytes:
    ct = ub64u(payload["ciphertext"])
    return receiver_priv.decrypt(
        ct,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
