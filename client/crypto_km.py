# crypto_km.py
# encryption helpers

from __future__ import annotations
import os
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from common.b64url import b64u, ub64u


# ---- RSA-4096 generation ---- #
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
        # applies symmetric cipher (AES-256-CBC)
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


# ---- Digital Signature Functions (RSA-PSS with SHA-256) ---- #
def sign_data(private_key: rsa.RSAPrivateKey, data: bytes) -> str:
    """
    Sign data using RSA-PSS with SHA-256.

    Args:
        private_key: RSA private key object
        data: Bytes to sign

    Returns:
        Base64url-encoded signature
    """
    assert_rsa4096_key(private_key)

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Return base64url encoded signature
    return b64u(signature)


def verify_signature(public_key_b64u: str, data: bytes, signature_b64u: str) -> bool:
    """
    Verify RSA-PSS signature.

    Args:
        public_key_b64u: Base64url-encoded DER public key
        data: Original data that was signed
        signature_b64u: Base64url-encoded signature

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Decode public key
        pub_der_bytes = ub64u(public_key_b64u)
        public_key = serialization.load_der_public_key(
            pub_der_bytes, backend=default_backend())

        # Verify it's RSA-4096
        assert_rsa4096_key(public_key)

        # Decode signature
        signature = ub64u(signature_b64u)

        # Verify
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
