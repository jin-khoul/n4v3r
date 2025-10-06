from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
from io import *
import sqlite3
from pathlib import Path
import xml.etree.ElementTree as ET
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from ppadb.client import Client as AdbClient
import os, shutil
import tarfile
import time
import tempfile
import requests
import hashlib
from io import FileIO, BytesIO
from typing import Optional
from struct import Struct
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import hashlib
import asyncio
import argparse

parser = argparse.ArgumentParser(description="Extract naver series.")
parser.add_argument("--output", default="out", help="Output directory (default: out)")
parser.add_argument("--run-with-sudo", action="store_true", help="Run adb commands with sudo (default: False)")
parser.add_argument("--host", default="127.0.0.1", help="ADB host (default: 127.0.0.1)")
parser.add_argument("--port", type=int, default=5037, help="ADB port (default: 5037)")
args = parser.parse_args()

output = args.output
run_with_sudo = args.run_with_sudo
host = args.host
port = args.port

su_prefix = ""
su_suffix = ""

if run_with_sudo:
    su_prefix = "su -c '"
    su_suffix = "'"

def a(a_1):
    a1 = ET.fromstring(a_1)
    a2 = a1.find("CryptographyInformation")
    a3 = a2.find("ID").text.strip()
    a4 = base64.b64decode(a3)
    return a4.hex(), a2.find("EncryptionMethod").text.strip()

def b(b_1):
    b1 = f"{b_1}/com.nhn.android.nbooks/shared_prefs/series_android.xml"
    b2 = None
    with open(b1, "r", encoding="utf-8") as f:
        b2 = f.read()
    b3 = ET.fromstring(b2)
    return b3.find(".//string[@name='device_id']").text.encode()

def c(c_1, c_2, c_3):
    c1 = c_1.h_c().decode("utf-8")
    c2 = f"n.{c1}.{c_2}.prk"
    c3 = f"{c_3}/com.nhn.android.nbooks/files/" + c2
    with open(c3, "rb") as f:
        c4 = f.read()
    return base64.b64encode(c4).decode("utf-8")

def d(d_1, d_2):
    return requests.get(
        f"https://comic-dn.pstatic.net/drm/{d_1['contentsNo']}/{d_1['volumeNo']}/{d_2}".rsplit(
            ".", 1
        )[0],
        headers={
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive",
            "Host": "comic-dn.pstatic.net",
            "User-Agent": "okhttp/4.12.0",
        },
    ).content

def e(e_1, e_2, e_3):
    e1 = e_2.h_b().decode("utf-8")
    e2 = e1.replace(":", "_")
    e3 = e_1["userId"]
    e4 = (
        f"{e_3}/com.nhn.android.nbooks/files/"
        + e3
        + "_"
        + e2
        + ".xml"
    )
    e5 = None
    with open(e4, "r", encoding="utf-8") as f:
        e5 = f.read()
    return e5

def g(g_1):
    g1 = f"/sdcard/nbooks_backup_{int(time.time())}.tar"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tar") as g2:
        g3 = g2.name
    g4 = tempfile.mkdtemp(prefix="nbooks_backup_")
    g_1.shell(
        f"{su_prefix}tar -cf {g1} -C /data/data com.nhn.android.nbooks{su_suffix}"
    )
    g_1.pull(g1, g3)
    g_1.shell(f"rm {g1}")
    with tarfile.open(g3) as tar:
        for g5 in tar.getmembers():
            g5.name = g5.name.replace(":", "_")
            tar.extract(g5, path=g4)
    return g3, g4

a__1 = Struct(">4sBIBBBB2HQ6H")
class h:
    h__1: Optional[bytes] = None
    h__2: Optional[int] = None
    h__3: Optional[int] = None
    h__4: Optional[int] = None
    h__5: Optional[int] = None
    h__6: Optional[int] = None
    h__7: Optional[bytes] = None
    h__8: Optional[bytes] = None
    h__9: Optional[bytes] = None
    h__10: Optional[int] = None
    h__11: Optional[bytes] = None
    h__12: Optional[bytes] = None
    h__13: Optional[bytes] = None
    h__14: Optional[str] = None
    h__15: Optional[str] = None
    h__16: Optional[str] = None
    h__17: Optional[bytes] = None
    h__18: Optional[bytes] = None
    h__19: Optional[str] = None

    def __init__(self, h_1) -> None:
        if isinstance(h_1, str):
            h_1 = FileIO(h_1, "rb")
        elif isinstance(h_1, (bytes, bytearray)):
            h_1 = BytesIO(h_1)
        h0 = h_1.read(a__1.size)
        (
            self.h__1,
            self.h__2,
            self.h__3,
            self.h__4,
            self.h__5,
            self.h__6,
            h1,
            h2,
            h3,
            self.h__10,
            h4,
            h5,
            h6,
            h7,
            h8,
            h9,
        ) = a__1.unpack(h0)
        if self.h__1 != b"fmdr":
            raise ValueError("invalid drm file")
        if self.h__2 != 2:
            raise ValueError(f"version mismatch 2 != {self.h__2}")
        self.h__7 = h_1.read(h1)
        self.h__8 = h_1.read(h2)
        self.h__9 = h_1.read(h3)
        self.h__11 = h_1.read(h4)
        self.h__12 = h_1.read(h5)
        self.h__13 = h_1.read(h6)
        self.h__14 = (
            h_1.read(h7).decode("utf-8", errors="replace")
            if h7 > 0
            else None
        )
        self.h__15 = (
            h_1.read(h8).decode("utf-8", errors="replace")
            if h8 > 0
            else None
        )
        self.h__16 = (
            h_1.read(h9).decode("utf-8", errors="replace")
            if h9 > 0
            else None
        )
        h10 = (
            a__1.size
            + h1
            + h2
            + h3
            + h4
            + h5
            + h6
            + h7
            + h8
            + h9
        )
        if self.h__3 is None:
            raise ValueError(
                "header_length is None, cannot read header for SHA1 digest."
            )
        h11 = self.h__3 - h10
        self.h__17 = h_1.read(h11) if h11 > 0 else None
        self.h__18 = h_1.read()
        h_1.seek(0)
        header = h_1.read(self.h__3 if self.h__3 is not None else 0)
        self.h__19 = hashlib.sha1(header).hexdigest()

    def h_a(self, ha_1: bytes) -> bytes:
        if not self.h__9:
            raise ValueError("IV is missing.")
        if self.h__18 is None:
            raise ValueError("drmfile is missing.")
        ha1 = Counter.new(128, initial_value=int.from_bytes(self.h__9, byteorder="big"))
        ha2 = AES.new(ha_1, AES.MODE_CTR, counter=ha1)
        return ha2.decrypt(self.h__18)

    def h_b(self):
        return self.h__13

    def h_c(self):
        return self.h__11

async def j():
    os.makedirs(output, exist_ok=True)
    j1 = AdbClient(host=host, port=port)
    j2 = j1.devices()[0]
    print(j2)
    j3, j4 = g(j2)
    j5 = Path(f"{j4}/com.nhn.android.nbooks/databases/series").resolve()
    if not j5.exists():
        raise FileNotFoundError(f"Database not found at: {j5}")
    j6 = sqlite3.connect(str(j5))
    j7 = j6.cursor()
    try:
        j7.execute("SELECT * FROM download")
        ja1 = j7.fetchall()
        ja2 = [jaa1[0] for jaa1 in j7.description]
        j8 = [dict(zip(ja2, jab1)) for jab1 in ja1]
    except sqlite3.Error as ea:
        print(ea)
    finally:
        j7.close()
    j9 = b(j4)
    for j10 in j8:
        jb1 = j10["path"].split("/")[-1]
        if j10["status"] != "COMPLETE":
            continue
        jb2 = d(j10, jb1)
        jb3 = h(BytesIO(jb2))
        jb4 = e(j10, jb3, j4)
        jb5, jb6 = a(jb4)
        jb7 = c(jb3, jb5, j4)
        jb8 = base64.b64decode(jb7)
        jb9 = serialization.load_der_private_key(
            jb8, password=j9, backend=default_backend()
        )
        jb10 = jb9.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        jb11 = RSA.import_key(jb10, passphrase=None)
        jb12 = base64.b64decode(jb6)
        jb13 = PKCS1_v1_5.new(jb11).decrypt(jb12, None)
        open(f"{output}/{jb1}.zip", "wb").write(
            jb3.h_a(jb13)
        )
    j6.close()
    if os.path.exists(j3):
        os.remove(j3)
    if j4 == None:
        return
    if os.path.exists(j4):
        shutil.rmtree(j4)

if __name__ == "__main__":
    asyncio.run(j())
