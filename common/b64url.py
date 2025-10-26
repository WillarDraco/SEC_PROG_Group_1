"""
Group 1
Name                        ID              Discord
Benjamin Signorelli         a1861126        dracomaleficus
Willard Gorman              a1863235        nihili
Gia Thanh Nguyen            a1876555        g.l.toys
"""
import base64
import re

# ---- BASE64URL helpers ---- #

# make sure string only has legal Bae64URL characters
_B64URL_RE = re.compile(r'^[A-Za-z0-9_-]+$')


def b64u(b: bytes) -> str:
    # encode byte and decode to string and strip "="
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def ub64u(s: str) -> bytes:
    # calculate how much padding needed to make length multiple of 4
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())


def is_b64u(s: str) -> bool:
    # check if characters and length are legal for base64url
    return bool(_B64URL_RE.match(s)) and (len(s) % 4 != 1)
