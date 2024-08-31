from json import loads, dumps
from json.decoder import JSONDecodeError
from random import randint

from Crypto.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CFB

SkinManagerWrapContent3D_Bytes: bytes = b"+\xc0s\xa3)\xc5\x93\xd7~\x9eMR\xfd\xeb\xfcz\xcb\x9fZ[\xdel\x81\xe8&|\xf7\xfbv\xd3\x11\xac"
BackSystemRawTexture2D_Bytes: bytes = b"r\x94\x84\xb1\xd3\xc3\xea\xdb\xc4\xac\x9d\x86w^Y\xef\xd6\xd1\xd3\xef\xb2\xd3\xef\xb2\x83\xa7{\xa7\xcb\x9f\xb6\xd8"


def websocket_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    d = Cipher(AES(key), CFB(iv)).decryptor()
    d = d.update(ct) + d.finalize()
    return d[:-d[-1]] if 0 < d[-1] <= 16 and not len(d) % 16 and d[-d[-1]:] == bytes([d[-1]] * d[-1]) else d


def websocket_encrypt(key: bytes, iv: bytes, pt: bytes) -> bytes:
    e = Cipher(AES(key), CFB(iv)).encryptor()
    pad = 16 - len(pt) % 16
    return e.update(pt + bytes([pad] * pad)) + e.finalize()


def https_decrypt(ct: bytes) -> dict:
    j, shift, i = dict(), ct[-2], 0
    ct = bytes([(l - shift) % 256 for l in ct[:-2:2]])
    while i < len(ct):
        k_len, v_len = [(l + shift) % 256 >> 1 for l in ct[i:i + 2]]
        if ct[i + 2:i + 2 + k_len] == b"token" and v_len % 32 == 0:
            n = i + 2 + k_len
            for n in range(i + 2 + k_len, len(ct)):
                if (97 > ct[n] or ct[n] > 102) and (48 > ct[n] or ct[n] > 57):
                    break
            v_len = ((n - i - 2 - k_len + (n + 1 == len(ct))) >> 5) << 5
        j[ct[i + 2:i + 2 + k_len].decode()] = ct[i + 2 + k_len:i + 2 + k_len + v_len].decode()
        i += 2 + k_len + v_len
    return j


def https_encrypt(pt: dict) -> bytes:
    ct, shift = b'', randint(1, 255)
    for k, v in pt.items():
        ct += bytes([(len(k) << 1) % 256, (len(v) << 1) % 256] + [(l + shift) % 256 for l in (k.encode() + v.encode())])
    return b'\x00'.join(bytes((i,)) for i in ct) + b'\x00' + bytes((shift,)) + b'\x00'


def packet_decrypt(key: bytes, iv: bytes, ct: list[bytes]) -> list:
    pkt = loads(ct[0][9 * ct[0].startswith(b"452-/sio,"):])
    del ct[0]
    for i in range(len(pkt)):
        if "_placeholder" in pkt[i] and pkt[i]["_placeholder"] and "num" in pkt[i] and isinstance(pkt[i]["num"], int):
            pkt[i] = websocket_decrypt(key, iv, ct[pkt[i]["num"]][ct[pkt[i]["num"]].startswith(b'\x04'):])
            try:
                pkt[i] = loads(pkt[i])
            except (JSONDecodeError, UnicodeDecodeError):
                continue
    return pkt


def packet_encrypt(key: bytes, iv: bytes, pt: list, from_client: bool) -> list[bytes]:
    ckt = [b"452-/sio," +
           dumps([{"_placeholder": True, "num": i} for i in range(len(pt))], separators=(', ', ':')).encode()]
    for i in pt:
        if isinstance(i, dict):
            i = dumps(i).encode()
        else:
            if isinstance(i, str):
                i = i.encode()
            if isinstance(i, bytes):
                try:
                    i = (loads if from_client else dumps)(i)
                except (JSONDecodeError, UnicodeDecodeError):
                    pass
        ckt.append(b'\x04' + websocket_encrypt(key, iv, i))
    return ckt


def device_changer(ct: bytes, device: str) -> bytes:
    ct, shift = ct[::2], ct[-2]
    pos = ct.index(bytes([18, 64] + [(i + shift) % 256 for i in b"device_id"])) + 11
    ct = ct[:pos] + bytes([(i + shift) % 256 for i in device[:32].encode().rjust(32, b'0')]) + ct[pos + 32:]
    return b'\x00'.join(bytes((i,)) for i in ct) + b'\x00'


def websocket_password(pwd: str) -> tuple[bytes, bytes]:
    kv: bytes = PBKDF2(
        password=pwd,
        salt=b"L\x82\xa1\x18$d\x15\x96",
        dkLen=0x30,
        count=1
    )
    return kv[:0x20], kv[0x20:0x30]


def xor_bytes(byte1: bytes, byte2: bytes, inverse: bool = False) -> bytes:
    if len(byte1) == len(byte2):
        if inverse:
            byte2: bytes = bytes((~i) & 0xFF for i in byte2)
        return bytes(byte1[i] ^ byte2[i] for i in range(len(byte1)))
    raise ValueError(f"Cannot XOR Both Byte Arrays of Different Length(s): {len(byte1)} & {len(byte2)} Byte(s).")


def websocket_sid(sid: str) -> bytes:
    return bytes(
        (i - (
            0x57 if i >= 0x3A else 0x30
        )) & 0xFF for i in sid[:0x20].encode(
            encoding="utf8"
        )).ljust(
        0x20, b'\x00'
    )


def websocket_key_iv(sid: str) -> tuple[bytes, bytes]:
    return websocket_password(
        pwd=xor_bytes(
            byte1=SkinManagerWrapContent3D_Bytes,
            byte2=xor_bytes(
                byte1=websocket_sid(
                    sid=sid
                ),
                byte2=BackSystemRawTexture2D_Bytes,
                inverse=True
            ),
            inverse=False
        ).decode(
            encoding="unicode_escape"
        )
    )
