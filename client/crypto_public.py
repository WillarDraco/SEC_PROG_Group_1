from common.b64url import b64u, ub64u
from common.canon import canon, sha256_bytes
from client.crypto_api import sign_pss, verify_pss
from client.crypto_km import pub_from_der, pub_der_b64u
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def public_content_hash(cipher_b64u: str, from_id: str, ts_ms: int) -> bytes:
    obj = {"ciphertext": cipher_b64u, "from": from_id, "ts": ts_ms}
    return sha256_bytes(canon(obj))


def make_public_payload(sender_priv, receiver_pub_der_b64u: str, plaintext: bytes, from_id: str, ts_ms: int) -> dict:
    rpk = pub_from_der(ub64u(receiver_pub_der_b64u))
    ct = rpk.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    ctb = b64u(ct)
    h = public_content_hash(ctb, from_id, ts_ms)
    sig = sign_pss(sender_priv, h)
    return {"ciphertext": ctb, "sender_pub": pub_der_b64u(sender_priv), "content_sig": b64u(sig)}


def open_public_payload(receiver_priv, payload: dict, from_id: str, ts_ms: int):
    ctb = payload["ciphertext"]
    sigb = payload["content_sig"]
    spub_b64u = payload["sender_pub"]
    h = public_content_hash(ctb, from_id, ts_ms)
    spk = pub_from_der(ub64u(spub_b64u))
    if not verify_pss(spk, ub64u(sigb), h):
        raise ValueError("INVALID_SIG")
    pt = receiver_priv.decrypt(
        ub64u(ctb),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    return pt, spk
