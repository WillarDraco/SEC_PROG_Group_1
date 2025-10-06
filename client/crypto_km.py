from __future__ import annotations
import os
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from common.b64url import b64u


# ---- RSAA-4096 generation ---- #
def gen_rsa_4096() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def assert_rsa4096_key(key) -> None:
    size = getattr(key, "key_size", None)
    if size != 4096:
        raise ValueError("RSA key must be 4096 bits")

# ---- Save/ Load private key (PKCS#8 PEM) ---- #


def save_pem_priv(sk: rsa.RSAPrivateKey, path: str, password: Optional[bytes] = None) -> None:
    assert_rsa4096_key(sk)  # check key length
    # if password is provided
    if password:
        # applies ssymmetric cipher (AES-256-CBC)
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()  # stored as plain text
    pem = sk.private_bytes(encoding=serialization.Encoding.PEM,
                           format=serialization.PrivateFormat.PKCS8, encryption_algorithm=enc,)
    # write then chmod 600 on *nix to avoid leaky perms
    with open(path, "wb") as f:
        f.write(pem)
    try:
        os.chmod(path, 0o600)  # only owner can access
    except Exception:
        pass    # ignore


def load_pem_priv(path: str, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    with open(path, "rb") as f:
        sk = serialization.load_pem_private_key(f.read(), password=password)
    assert_rsa4096_key(sk)
    return sk

# ---- Public key export/ import (DER SubjectPublicKeyInfo) ---- #


def pub_der(sk: rsa.RSAPrivateKey) -> bytes:
    assert_rsa4096_key(sk)
    # return a byte string containing the public key in DER format
    return sk.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo,)


def pub_from_der(der: bytes) -> rsa.RSAPublicKey:
    pk = serialization.load_der_public_key(der)
    assert_rsa4096_key(pk)
    # return the public key
    return pk


# ---- Convenience for wire format ---- #
def pub_der_b64u(sk: rsa.RSAPrivateKey) -> str:
    return b64u(pub_der(sk))
