from common.b64url import b64u, ub64u
from common.canon import canon, sha256_bytes
from client.crypto_api import sign_pss, verify_pss
from client.crypto_km import pub_from_der
from cryptography.hazmat.primitives.asymmetric import rsa


def server_sign_payload(server_priv: rsa.RSAPrivateKey, payload_obj: dict) -> str:
    msg = canon(payload_obj)            # sorted keys, no spaces, UTF-8 bytes
    digest = sha256_bytes(msg)          # stable input to PSS
    return b64u(sign_pss(server_priv, digest))


def server_verify_payload(server_pub_der_b64u: str, payload_obj: dict, sig_b64u: str) -> bool:
    # Verify the signature
    pk = pub_from_der(ub64u(server_pub_der_b64u))
    msg = canon(payload_obj)
    digest = sha256_bytes(msg)
    return verify_pss(pk, ub64u(sig_b64u), digest)
