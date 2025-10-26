"""
Group 1
Name                        ID              Discord
Benjamin Signorelli         a1861126        dracomaleficus
Willard Gorman              a1863235        nihili
Gia Thanh Nguyen            a1876555        g.l.toys
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ---- Sign/ Verify with RSA-PSS ---- #
def sign_pss(sk: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return sk.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256(),)


def verify_pss(pk: rsa.RSAPublicKey, sig: bytes, data: bytes) -> bool:
    try:
        pk.verify(sig, data, padding.PSS(mgf=padding.MGF1(
            hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256(),)
        return True
    except Exception:
        return False
