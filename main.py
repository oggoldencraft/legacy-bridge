import socket
import struct
import threading
import json
import os
import zlib
import traceback

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB8
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import CFB8

# ─────────────────────────────────────────────────────────────
# PROXY CONFIGURATION
# ─────────────────────────────────────────────────────────────
LISTEN_PORT = 25564
LISTEN_HOST = "0.0.0.0"
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 25565

DEBUG = True
DEBUG_MOVEMENT = False
DEBUG_FORGE = True

# Generate proxy RSA-1024 Keypair for 1.6.4 authentication handshake
_RSA_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,
    backend=default_backend()
)
_RSA_PUB_DER = _RSA_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
print(f"[*] RSA-1024 pubkey ready ({len(_RSA_PUB_DER)} bytes)")


# ─────────────────────────────────────────────────────────────
# PURE PYTHON STANDALONE NBT ENGINE
# ─────────────────────────────────────────────────────────────
class NBTTag:
    TAG_END = 0
    TAG_BYTE = 1
    TAG_SHORT = 2
    TAG_INT = 3
    TAG_LONG = 4
    TAG_FLOAT = 5
    TAG_DOUBLE = 6
    TAG_BYTE_ARRAY = 7
    TAG_STRING = 8
    TAG_LIST = 9
    TAG_COMPOUND = 10
    TAG_INT_ARRAY = 11


def nbt_decompress(raw_bytes):
    """Safely decompresses GZIP or Zlib NBT payloads."""
    if not raw_bytes:
        return b""
    try:
        return zlib.decompress(raw_bytes, 16 + zlib.MAX_WBITS)
    except Exception:
        try:
            return zlib.decompress(raw_bytes)
        except Exception:
            return raw_bytes


def nbt_compress(raw_bytes):
    """Compresses NBT payloads into GZIP format."""
    if not raw_bytes:
        return b""
    co = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    return co.compress(raw_bytes) + co.flush()


def nbt_read_payload(tag_type, data, offset):
    if tag_type == NBTTag.TAG_BYTE:
        return struct.unpack('>b', data[offset:offset + 1])[0], offset + 1
    elif tag_type == NBTTag.TAG_SHORT:
        return struct.unpack('>h', data[offset:offset + 2])[0], offset + 2
    elif tag_type == NBTTag.TAG_INT:
        return struct.unpack('>i', data[offset:offset + 4])[0], offset + 4
    elif tag_type == NBTTag.TAG_LONG:
        return struct.unpack('>q', data[offset:offset + 8])[0], offset + 8
    elif tag_type == NBTTag.TAG_FLOAT:
        return struct.unpack('>f', data[offset:offset + 4])[0], offset + 4
    elif tag_type == NBTTag.TAG_DOUBLE:
        return struct.unpack('>d', data[offset:offset + 8])[0], offset + 8
    elif tag_type == NBTTag.TAG_BYTE_ARRAY:
        length = struct.unpack('>i', data[offset:offset + 4])[0]
        offset += 4
        return data[offset:offset + length], offset + length
    elif tag_type == NBTTag.TAG_STRING:
        length = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 2
        s = data[offset:offset + length].decode('utf-8', 'replace')
        return s, offset + length
    elif tag_type == NBTTag.TAG_LIST:
        elem_type = data[offset]
        offset += 1
        length = struct.unpack('>i', data[offset:offset + 4])[0]
        offset += 4
        lst = []
        for _ in range(length):
            elem_val, offset = nbt_read_payload(elem_type, data, offset)
            lst.append(elem_val)
        return (elem_type, lst), offset
    elif tag_type == NBTTag.TAG_COMPOUND:
        compound = {}
        while offset < len(data):
            t = data[offset]
            offset += 1
            if t == NBTTag.TAG_END:
                break
            nlen = struct.unpack('>H', data[offset:offset + 2])[0]
            offset += 2
            name = data[offset:offset + nlen].decode('utf-8', 'replace')
            offset += nlen
            v, offset = nbt_read_payload(t, data, offset)
            compound[name] = (t, v)
        return compound, offset
    elif tag_type == NBTTag.TAG_INT_ARRAY:
        length = struct.unpack('>i', data[offset:offset + 4])[0]
        offset += 4
        ints = []
        for _ in range(length):
            ints.append(struct.unpack('>i', data[offset:offset + 4])[0])
            offset += 4
        return ints, offset
    return None, offset


def nbt_write_payload(tag_type, val):
    out = bytearray()
    if tag_type == NBTTag.TAG_BYTE:
        out.extend(struct.pack('>b', val))
    elif tag_type == NBTTag.TAG_SHORT:
        out.extend(struct.pack('>h', val))
    elif tag_type == NBTTag.TAG_INT:
        out.extend(struct.pack('>i', val))
    elif tag_type == NBTTag.TAG_LONG:
        out.extend(struct.pack('>q', val))
    elif tag_type == NBTTag.TAG_FLOAT:
        out.extend(struct.pack('>f', val))
    elif tag_type == NBTTag.TAG_DOUBLE:
        out.extend(struct.pack('>d', val))
    elif tag_type == NBTTag.TAG_BYTE_ARRAY:
        out.extend(struct.pack('>i', len(val)))
        out.extend(val)
    elif tag_type == NBTTag.TAG_STRING:
        sb = val.encode('utf-8')
        out.extend(struct.pack('>H', len(sb)))
        out.extend(sb)
    elif tag_type == NBTTag.TAG_LIST:
        elem_type, lst = val
        out.append(elem_type)
        out.extend(struct.pack('>i', len(lst)))
        for elem in lst:
            out.extend(nbt_write_payload(elem_type, elem))
    elif tag_type == NBTTag.TAG_COMPOUND:
        for k, (t, v) in val.items():
            out.append(t)
            kb = k.encode('utf-8')
            out.extend(struct.pack('>H', len(kb)))
            out.extend(kb)
            out.extend(nbt_write_payload(t, v))
        out.append(NBTTag.TAG_END)
    elif tag_type == NBTTag.TAG_INT_ARRAY:
        out.extend(struct.pack('>i', len(val)))
        for item in val:
            out.extend(struct.pack('>i', item))
    return bytes(out)


# ─────────────────────────────────────────────────────────────
# BLOCK, ITEM & BIOME REMAPPING (1.7.2 -> 1.6.4)
# ─────────────────────────────────────────────────────────────
_BLOCK_REMAP = {}

def _add(src_id, src_meta, dst_id, dst_meta):
    _BLOCK_REMAP[(src_id, src_meta)] = (dst_id, dst_meta)

# Stained Glass (95:*) -> Glass (20:0)
for _m in range(16):
    _add(95, _m, 20, 0)

# Stained Glass Pane (160:*) -> Glass Pane (102:0)
for _m in range(16):
    _add(160, _m, 102, 0)

# Planks: Acacia (5:4) and Dark Oak (5:5) -> Oak Planks (5:0)
_add(5, 4, 5, 0)
_add(5, 5, 5, 0)

# Logs: Acacia (17:4) and Dark Oak (17:5) -> Oak Log (17:0)
_add(17, 4, 17, 0)
_add(17, 5, 17, 0)

# Leaves: Acacia (18:4) and Dark Oak (18:5) -> Oak Leaves (18:0)
_add(18, 4, 18, 0)
_add(18, 5, 18, 0)

# leaves2 / logs2 (161/162) — don't exist in 1.6.4
for _m in range(16):
    _add(161, _m, 18, 0)   # Leaves2 -> Oak Leaves
    _add(162, _m, 17, 0)   # Log2    -> Oak Log

# Saplings
_add(6, 4, 6, 0)
_add(6, 5, 6, 0)

# Podzol (3:2) -> Dirt (3:0)
_add(3, 2, 3, 0)

# Red Sand (12:1) -> Sand (12:0)
_add(12, 1, 12, 0)

# Packed Ice (174) -> Ice (79)
for _m in range(16):
    _add(174, _m, 79, 0)

# New small flowers (id 38, metas 1-9) -> Rose (id 37)
for _m in range(1, 10):
    _add(38, _m, 37, 0)

# Double-plants (id 175) -> Tallgrass (31:1)
for _m in range(16):
    _add(175, _m, 31, 1)

# Fern (31:2) -> Grass (31:1)
_add(31, 2, 31, 1)

# Acacia Stairs (163) -> Oak Stairs (53)
for _m in range(8):
    _add(163, _m, 53, _m)

# Dark Oak Stairs (164) -> Oak Stairs (53)
for _m in range(8):
    _add(164, _m, 53, _m)

# Wooden Slabs (126) for Acacia (metadata 4) and Dark Oak (metadata 5) -> Oak Slab (126:0)
for _m in range(16):
    is_top = _m & 8
    wood_type = _m & 7
    if wood_type in (4, 5):
        _add(126, _m, 126, is_top | 0)

# Double Wooden Slabs (125) for Acacia (4) and Dark Oak (5) -> Oak Double Slab (125)
for _m in range(16):
    wood_type = _m & 7
    if wood_type in (4, 5):
        _add(125, _m, 125, 0)

# Fast flat lookup table for chunk rewriting
_REMAP_FLAT = [-1] * (4096 * 16)
for (_sid, _smeta), (_did, _dmeta) in _BLOCK_REMAP.items():
    _REMAP_FLAT[(_sid << 4) | (_smeta & 0x0F)] = (_did << 4) | (_dmeta & 0x0F)

_REMAP_LOW_BYTES = set()
for (_sid, _sm) in _BLOCK_REMAP.keys():
    _REMAP_LOW_BYTES.add(_sid & 0xFF)


def remap_block(bid, meta):
    """O(1) block remap lookup function. Returns (new_id, new_meta)."""
    if bid < 0 or bid >= 4096:
        return bid, meta
    v = _REMAP_FLAT[(bid << 4) | (meta & 0x0F)]
    if v < 0:
        return bid, meta
    return v >> 4, v & 0x0F


def remap_item(item_id, damage):
    """Remaps 1.7.2 items and blocks to safe 1.6.4 counterparts."""
    if item_id == -1 or item_id is None:
        return -1, 0
    if item_id < 256:
        return remap_block(item_id, damage)
    # Acacia Boat -> Oak Boat
    if item_id == 424:
        return 333, 0
    # Fish variants (Salmon, Clownfish, Pufferfish) -> Raw Fish
    if item_id == 349:
        return 349, 0
    # Cooked Salmon -> Cooked Fish
    if item_id == 350:
        return 350, 0
    # Fallback for out-of-range 1.7 items
    if item_id > 422:
        return 280, 0  # Stick fallback
    return item_id, damage


def remap_nbt_compound(tag):
    """Recursively walks an NBT tag payload to deep-translate item mappings."""
    if not isinstance(tag, dict):
        return
    if 'id' in tag and 'Damage' in tag:
        t_id, val_id = tag['id']
        t_dmg, val_dmg = tag['Damage']
        if t_id in (NBTTag.TAG_SHORT, NBTTag.TAG_INT) and t_dmg in (NBTTag.TAG_SHORT, NBTTag.TAG_INT):
            nid, ndmg = remap_item(val_id, val_dmg)
            tag['id'] = (t_id, nid)
            tag['Damage'] = (t_dmg, ndmg)

    # Recurse compound elements and list of compounds
    for k, (t, v) in tag.items():
        if t == NBTTag.TAG_COMPOUND:
            remap_nbt_compound(v)
        elif t == NBTTag.TAG_LIST:
            elem_type, lst = v
            if elem_type == NBTTag.TAG_COMPOUND:
                for item in lst:
                    remap_nbt_compound(item)


def _rewrite_chunk_blocks(raw, prim_mask, add_mask, has_biomes):
    """Rewrites Chunk Block IDs, Metadata, and prevents NPE Biome client crashes."""
    section_count = bin(prim_mask).count('1')
    add_count = bin(add_mask).count('1')

    if section_count == 0:
        if has_biomes and len(raw) == 256:
            buf = bytearray(raw)
            for i in range(256):
                if buf[i] > 22:
                    buf[i] = 1 # Map to Plains to avoid client-side crash
            return bytes(buf)
        return raw

    per_light_with_sky = 2048 + 2048 + 2048
    per_light_no_sky = 2048 + 2048
    expected_with_sky = (
        section_count * (4096 + per_light_with_sky)
        + add_count * 2048
        + (256 if has_biomes else 0)
    )
    expected_no_sky = (
        section_count * (4096 + per_light_no_sky)
        + add_count * 2048
        + (256 if has_biomes else 0)
    )

    if len(raw) == expected_with_sky:
        per_light = per_light_with_sky
    elif len(raw) == expected_no_sky:
        per_light = per_light_no_sky
    else:
        return raw

    buf = bytearray(raw)
    dirty = False

    # Prevent Biome NPE Crash: 1.6.4 clients crash instantly on Biome IDs > 22
    if has_biomes and len(buf) >= 256:
        biome_start = len(buf) - 256
        for i in range(biome_start, len(buf)):
            if buf[i] > 22:
                buf[i] = 1 # Plains fallback
                dirty = True

    meta_off_base = section_count * 4096
    add_base = section_count * (4096 + per_light)

    sections = [i for i in range(16) if (prim_mask >> i) & 1]
    add_sections = [i for i in range(16) if (add_mask >> i) & 1]

    for s_idx, sec in enumerate(sections):
        id_start = s_idx * 4096
        meta_start = meta_off_base + s_idx * 2048
        add_slot = None
        if sec in add_sections:
            add_slot = add_base + add_sections.index(sec) * 2048

        section_ids = buf[id_start:id_start + 4096]
        interesting = False
        for b in section_ids:
            if b in _REMAP_LOW_BYTES:
                interesting = True
                break
        if not interesting and add_slot is None:
            continue

        for i in range(4096):
            low = buf[id_start + i]
            high = 0
            if add_slot is not None:
                a = buf[add_slot + (i >> 1)]
                if i & 1:
                    high = a >> 4
                else:
                    high = a & 0x0F
            bid = (high << 8) | low

            mbyte = buf[meta_start + (i >> 1)]
            if i & 1:
                meta = mbyte >> 4
            else:
                meta = mbyte & 0x0F

            new_id, new_meta = remap_block(bid, meta)
            if new_id == bid and new_meta == meta:
                continue

            dirty = True

            buf[id_start + i] = new_id & 0xFF
            if add_slot is not None and high != 0:
                a = buf[add_slot + (i >> 1)]
                if i & 1:
                    a = a & 0x0F
                else:
                    a = a & 0xF0
                buf[add_slot + (i >> 1)] = a

            if new_meta != meta:
                mb = buf[meta_start + (i >> 1)]
                if i & 1:
                    mb = (mb & 0x0F) | ((new_meta & 0x0F) << 4)
                else:
                    mb = (mb & 0xF0) | (new_meta & 0x0F)
                buf[meta_start + (i >> 1)] = mb

    if not dirty:
        return raw
    return bytes(buf)


# ─────────────────────────────────────────────────────────────
# SOCKET & ENCRYPTION WRAPPERS
# ─────────────────────────────────────────────────────────────
class EncryptedSocket:
    def __init__(self, sock, ss):
        b = default_backend()
        self.sock = sock
        self._enc = Cipher(algorithms.AES(ss), CFB8(ss), backend=b).encryptor()
        self._dec = Cipher(algorithms.AES(ss), CFB8(ss), backend=b).decryptor()
        self._lk = threading.Lock()

    def sendall(self, d):
        with self._lk:
            self.sock.sendall(self._enc.update(bytes(d)))

    def recv(self, n):
        r = self.sock.recv(n)
        if r:
            return self._dec.update(r)
        return r

    def shutdown(self, how):
        try:
            self.sock.shutdown(how)
        except OSError:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class LockedSocket:
    def __init__(self, sock):
        self.sock = sock
        self._lk = threading.Lock()

    def sendall(self, d):
        with self._lk:
            self.sock.sendall(d)

    def recv(self, n):
        return self.sock.recv(n)

    def shutdown(self, how):
        try:
            self.sock.shutdown(how)
        except OSError:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class SocketBuffer:
    def __init__(self, sock):
        self.sock = sock
        self.buf = bytearray()

    def upgrade(self, ns):
        self.sock = ns

    def read_exact(self, n):
        if n == 0:
            return b""
        while len(self.buf) < n:
            try:
                chunk = self.sock.recv(65536)
            except OSError:
                return None
            if not chunk:
                return None
            self.buf.extend(chunk)
        r = bytes(self.buf[:n])
        del self.buf[:n]
        return r

    def peek(self, n):
        while len(self.buf) < n:
            try:
                chunk = self.sock.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            self.buf.extend(chunk)
        return bytes(self.buf[:n])

    def read_byte(self):
        r = self.read_exact(1)
        return r[0] if r else None

    def read_sbyte(self):
        r = self.read_exact(1)
        return struct.unpack('>b', r)[0] if r else None

    def read_short(self):
        r = self.read_exact(2)
        return struct.unpack('>h', r)[0] if r else None

    def read_ushort(self):
        r = self.read_exact(2)
        return struct.unpack('>H', r)[0] if r else None

    def read_int(self):
        r = self.read_exact(4)
        return struct.unpack('>i', r)[0] if r else None

    def read_long(self):
        r = self.read_exact(8)
        return struct.unpack('>q', r)[0] if r else None

    def read_float(self):
        r = self.read_exact(4)
        return struct.unpack('>f', r)[0] if r else None

    def read_double(self):
        r = self.read_exact(8)
        return struct.unpack('>d', r)[0] if r else None

    def read_bool(self):
        b = self.read_byte()
        return bool(b) if b is not None else None

    def read_164_string(self):
        n = self.read_ushort()
        if n is None:
            return None
        if n == 0:
            return ""
        r = self.read_exact(n * 2)
        return r.decode('utf-16-be', 'replace') if r else None

    def read_slot(self):
        item_id = self.read_short()
        if item_id is None or item_id == -1:
            return {"id": -1, "count": 0, "damage": 0, "nbt": b""}
        count = self.read_byte()
        damage = self.read_short()
        nbt_len = self.read_short()
        nbt = b""
        if nbt_len is not None and nbt_len > 0:
            nbt = self.read_exact(nbt_len) or b""
        return {
            "id": item_id,
            "count": count if count is not None else 1,
            "damage": damage if damage is not None else 0,
            "nbt": nbt
        }

    def read_varint(self):
        v = 0
        s = 0
        while True:
            b = self.read_byte()
            if b is None:
                return None
            v |= (b & 0x7F) << s
            if not (b & 0x80):
                break
            s += 7
        return v


class BR:
    """Byte Reader helper for 1.7.2 packet parsing."""
    def __init__(self, data):
        self.d = data
        self.o = 0

    def rem(self):
        return len(self.d) - self.o

    def take(self, n):
        r = self.d[self.o:self.o + n]
        self.o += n
        return r

    def u8(self):
        v = self.d[self.o]
        self.o += 1
        return v

    def i8(self):
        v = struct.unpack('>b', self.d[self.o:self.o + 1])[0]
        self.o += 1
        return v

    def u16(self):
        v = struct.unpack('>H', self.d[self.o:self.o + 2])[0]
        self.o += 2
        return v

    def i16(self):
        v = struct.unpack('>h', self.d[self.o:self.o + 2])[0]
        self.o += 2
        return v

    def i32(self):
        v = struct.unpack('>i', self.d[self.o:self.o + 4])[0]
        self.o += 4
        return v

    def i64(self):
        v = struct.unpack('>q', self.d[self.o:self.o + 8])[0]
        self.o += 8
        return v

    def f32(self):
        v = struct.unpack('>f', self.d[self.o:self.o + 4])[0]
        self.o += 4
        return v

    def f64(self):
        v = struct.unpack('>d', self.d[self.o:self.o + 8])[0]
        self.o += 8
        return v

    def bool(self):
        return bool(self.u8())

    def varint(self):
        v = 0
        s = 0
        while True:
            b = self.d[self.o]
            self.o += 1
            v |= (b & 0x7F) << s
            if not (b & 0x80):
                break
            s += 7
        return v

    def string(self):
        n = self.varint()
        r = self.d[self.o:self.o + n]
        self.o += n
        return r.decode('utf-8', 'replace')

    def metadata_raw(self):
        start = self.o
        while self.o < len(self.d):
            item = self.u8()
            if item == 0x7F:
                break
            t = (item >> 5) & 0x07
            if t == 0:
                self.o += 1
            elif t == 1:
                self.o += 2
            elif t == 2:
                self.o += 4
            elif t == 3:
                self.o += 4
            elif t == 4:
                sl = self.varint()
                self.o += sl
            elif t == 5:
                if self.o + 2 > len(self.d):
                    break
                iid = struct.unpack('>h', self.d[self.o:self.o + 2])[0]
                self.o += 2
                if iid != -1:
                    self.o += 1
                    self.o += 2
                    if self.o + 2 > len(self.d):
                        break
                    nl = struct.unpack('>h', self.d[self.o:self.o + 2])[0]
                    self.o += 2
                    if nl > 0:
                        self.o += nl
            elif t == 6:
                self.o += 12
            else:
                break
        return self.d[start:self.o]


# ─────────────────────────────────────────────────────────────
# COMPLETE DATAWATCHER TRANSLATOR (1.7.2 -> 1.6.4)
# ─────────────────────────────────────────────────────────────
def translate_datawatcher(meta_raw):
    """
    Translates DataWatcher metadata stream from 1.7.2 to 1.6.4.
    Preserves item slots, entity states, custom names, and animations.
    """
    if not meta_raw or meta_raw == b'\x7F':
        return bytes([0x7F])

    out = bytearray()
    i = 0
    n = len(meta_raw)
    while i < n:
        header = meta_raw[i]
        if header == 0x7F:
            break
        t = (header >> 5) & 0x07
        i += 1

        if t == 0:  # Byte
            if i >= n:
                break
            b = meta_raw[i]
            i += 1
            out.append(header)
            out.append(b)
        elif t == 1:  # Short
            if i + 2 > n:
                break
            s = meta_raw[i:i + 2]
            i += 2
            out.append(header)
            out.extend(s)
        elif t == 2:  # Int
            if i + 4 > n:
                break
            iv = meta_raw[i:i + 4]
            i += 4
            out.append(header)
            out.extend(iv)
        elif t == 3:  # Float
            if i + 4 > n:
                break
            fv = meta_raw[i:i + 4]
            i += 4
            out.append(header)
            out.extend(fv)
        elif t == 4:  # String
            slen = 0
            sh = 0
            while True:
                if i >= n:
                    break
                b = meta_raw[i]
                i += 1
                slen |= (b & 0x7F) << sh
                if not (b & 0x80):
                    break
                sh += 7
            if i + slen > n:
                break
            s = meta_raw[i:i + slen].decode('utf-8', 'replace')
            i += slen
            out.append(header)
            out.extend(enc_164_str(s[:64]))
        elif t == 5:  # Slot with Deep NBT Remapping
            if i + 2 > n:
                break
            iid = struct.unpack('>h', meta_raw[i:i + 2])[0]
            i += 2
            if iid == -1:
                out.append(header)
                out.extend(struct.pack('>h', -1))
                continue
            if i + 5 > n:
                break
            cnt = meta_raw[i]
            i += 1
            dmg = struct.unpack('>h', meta_raw[i:i + 2])[0]
            i += 2
            nl = struct.unpack('>h', meta_raw[i:i + 2])[0]
            i += 2
            nbt = b""
            if nl > 0:
                if i + nl > n:
                    break
                nbt = meta_raw[i:i + nl]
                i += nl
            new_id, new_dmg = remap_item(iid, dmg)

            # Deep translate NBT inside the metadata slot
            if nbt:
                try:
                    if nbt[0] == 10:
                        nlen = struct.unpack('>H', nbt[1:3])[0]
                        offset = 3 + nlen
                        compound, _ = nbt_read_payload(NBTTag.TAG_COMPOUND, nbt, offset)
                        remap_nbt_compound(compound)
                        new_payload = nbt_write_payload(NBTTag.TAG_COMPOUND, compound)
                        nbt = nbt[:3+nlen] + new_payload
                except Exception:
                    pass

            out.append(header)
            out.extend(struct.pack('>hBhh', new_id, cnt, new_dmg, len(nbt) if len(nbt) > 0 else -1))
            if nbt:
                out.extend(nbt)
        elif t == 6:  # Chunk coordinates (3 ints)
            if i + 12 > n:
                break
            coords = meta_raw[i:i + 12]
            i += 12
            out.append(header)
            out.extend(coords)
        else:
            break

    out.append(0x7F)
    return bytes(out)


def write_varint(v):
    v &= 0xFFFFFFFF
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def enc_164_str(s):
    if s is None:
        s = ""
    e = s.encode('utf-16-be')
    return struct.pack('>H', len(s)) + e


def enc_172_str(s):
    if s is None:
        s = ""
    e = s.encode('utf-8')
    return write_varint(len(e)) + e


class ConnState:
    def __init__(self):
        self.last_feet_y = 0.0
        self.last_head_y = 0.0
        self.on_ground = True
        self.spawn_x = 0.0
        self.spawn_y = 0.0
        self.spawn_z = 0.0
        self.spawn_yaw = 0.0
        self.spawn_pitch = 0.0
        self.ssock = None
        self.csock = None
        self.compression_threshold = -1
        self.client_ip = "127.0.0.1"
        self.is_forge = False
        self.handshake_host = TARGET_HOST
        self.in_game = False


def pack_172(cs, pid, payload):
    body = write_varint(pid) + bytes(payload)
    threshold = cs.compression_threshold if cs else -1
    if threshold < 0:
        return write_varint(len(body)) + body

    if len(body) >= threshold:
        compressed = zlib.compress(body)
        data_len_field = write_varint(len(body))
        packet_data = data_len_field + compressed
    else:
        data_len_field = write_varint(0)
        packet_data = data_len_field + body

    return write_varint(len(packet_data)) + packet_data


def read_172_packet(sb, cs):
    packet_len = sb.read_varint()
    if packet_len is None:
        return None
    if packet_len == 0:
        return b""

    raw = sb.read_exact(packet_len)
    if raw is None:
        return None

    threshold = cs.compression_threshold if cs else -1
    if threshold < 0:
        return raw

    val = 0
    shift = 0
    idx = 0
    while True:
        if idx >= len(raw):
            return None
        b = raw[idx]
        idx += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift >= 35:
            return None

    data_length = val
    rest = raw[idx:]

    if data_length == 0:
        return rest
    else:
        try:
            decompressed = zlib.decompress(rest)
        except zlib.error:
            return None
        return decompressed


TRANSLATIONS = {
    "chat.type.text":                       "<%s> %s",
    "chat.type.announcement":               "[%s] %s",
    "chat.type.emote":                      "* %s %s",
    "chat.type.admin":                      "[%s: %s]",
    "chat.type.achievement":                "%s has just earned the achievement %s",
    "multiplayer.player.joined":            "%s joined the game",
    "multiplayer.player.left":              "%s left the game",
    "multiplayer.player.joined.renamed":    "%s (formerly known as %s) joined the game",
    "commands.message.display.incoming":    "%s whispers to you: %s",
    "commands.message.display.outgoing":    "You whisper to %s: %s",
    "death.attack.player":                  "%s was slain by %s",
    "death.attack.mob":                     "%s was slain by %s",
    "death.attack.arrow":                   "%s was shot by %s",
    "death.attack.arrow.item":              "%s was shot by %s using %s",
    "death.attack.fall":                    "%s fell from a high place",
    "death.attack.outOfWorld":              "%s fell out of the world",
    "death.attack.drown":                   "%s drowned",
    "death.attack.drown.player":            "%s drowned whilst trying to escape %s",
    "death.attack.lava":                    "%s tried to swim in lava",
    "death.attack.inFire":                  "%s went up in flames",
    "death.attack.onFire":                  "%s burned to death",
    "death.attack.inWall":                  "%s suffocated in a wall",
    "death.attack.explosion":               "%s blew up",
    "death.attack.explosion.player":        "%s was blown up by %s",
    "death.attack.magic":                   "%s was killed by magic",
    "death.attack.wither":                  "%s withered away",
    "death.attack.starve":                  "%s starved to death",
    "death.attack.cactus":                  "%s was pricked to death",
    "death.attack.cactus.player":           "%s walked into a cactus whilst trying to escape %s",
    "death.attack.generic":                 "%s died",
    "death.attack.anvil":                   "%s was squashed by a falling anvil",
    "death.attack.fallingBlock":            "%s was squashed by a falling block",
    "death.fell.accident.generic":          "%s fell from a high place",
    "tile.bed.notValid":                    "Your home bed was missing or obstructed",
    "tile.bed.noSleep":                     "You can only sleep at night",
    "tile.bed.notSafe":                     "You may not rest now; there are monsters nearby",
    "tile.bed.occupied":                    "This bed is occupied",
}

COLOR = {
    "black": "0", "dark_blue": "1", "dark_green": "2", "dark_aqua": "3", "dark_red": "4",
    "dark_purple": "5", "gold": "6", "gray": "7", "dark_gray": "8", "blue": "9", "green": "a",
    "aqua": "b", "red": "c", "light_purple": "d", "yellow": "e", "white": "f"
}

_SOUND_MAP = {
    "game.player.hurt": "damage.hit",
    "game.player.die": "damage.hit",
    "game.generic.explode": "random.explode",
    "game.player.swim": "liquid.swim",
    "game.player.swim.splash": "liquid.splash",
    "entity.player.splash": "liquid.splash",
    "random.anvil_land": "random.anvil_land",
    "random.anvil_break": "random.anvil_break",
    "random.anvil_use": "random.anvil_use",
    "mob.zombie.say": "mob.zombie.say",
    "mob.zombie.hurt": "mob.zombie.hurt",
    "mob.zombie.death": "mob.zombie.death",
    "entity.ghast.shoot": "mob.ghast.fireball",
    "entity.arrow.shoot": "random.bow",
    "entity.click": "random.click",
    "entity.pop": "random.pop",
}


def translate_sound_name(name):
    """Maps modern 1.7.2 namespace sound names into legal 1.6.4 names."""
    if name in _SOUND_MAP:
        return _SOUND_MAP[name]
    name = name.lower()
    if name.startswith("game."):
        name = name.replace("game.", "random.", 1)
    if name.startswith("entity."):
        name = name.replace("entity.", "random.", 1)
    return name[:63]


def resolve_chat_to_legacy(obj):
    if isinstance(obj, str):
        return obj
    if isinstance(obj, list):
        return "".join(resolve_chat_to_legacy(x) for x in obj)
    if not isinstance(obj, dict):
        return str(obj)

    prefix = ""
    color = obj.get("color")
    if color in COLOR:
        prefix += "§" + COLOR[color]
    if obj.get("bold"):
        prefix += "§l"
    if obj.get("italic"):
        prefix += "§o"
    if obj.get("underlined"):
        prefix += "§n"
    if obj.get("strikethrough"):
        prefix += "§m"
    if obj.get("obfuscated"):
        prefix += "§k"

    body = ""
    if "text" in obj:
        body = obj["text"]
    elif "translate" in obj:
        key = obj["translate"]
        args = obj.get("with", [])
        resolved_args = [resolve_chat_to_legacy(a) for a in args]
        template = TRANSLATIONS.get(key)
        if template:
            try:
                body = template % tuple(resolved_args)
            except Exception:
                body = template + " " + " ".join(resolved_args)
        else:
            body = " ".join(resolved_args) if resolved_args else key

    result = prefix + body
    for extra in obj.get("extra", []):
        result += resolve_chat_to_legacy(extra)
    return result


def chat_json_to_164_json(js):
    try:
        obj = json.loads(js)
    except Exception:
        return json.dumps({"text": str(js)}, ensure_ascii=False)

    if isinstance(obj, str):
        return json.dumps({"text": obj}, ensure_ascii=False)

    plain = resolve_chat_to_legacy(obj)
    return json.dumps({"text": plain}, ensure_ascii=False)


def strip_json_to_plain(js):
    try:
        obj = json.loads(js)
    except Exception:
        return js
    return resolve_chat_to_legacy(obj)


def check_proxy_protocol(sb):
    head = sb.peek(12)
    if not head:
        return None

    if head.startswith(b"PROXY "):
        line = bytearray()
        while True:
            b = sb.read_byte()
            if b is None:
                return None
            line.append(b)
            if len(line) >= 2 and line[-2:] == b"\r\n":
                break
            if len(line) > 200:
                return None
        parts = line.decode("ascii", "ignore").strip().split()
        if len(parts) >= 6 and parts[1] in ("TCP4", "TCP6"):
            try:
                return parts[2], int(parts[4])
            except Exception:
                return None
        return None

    if head == b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a":
        hdr = sb.read_exact(16)
        if not hdr or len(hdr) < 16:
            return None
        ver_cmd = hdr[12]
        fam_proto = hdr[13]
        addr_len = struct.unpack(">H", hdr[14:16])[0]
        addr = sb.read_exact(addr_len) if addr_len else b""
        if addr is None:
            return None
        if (ver_cmd & 0x0F) != 0x01:
            return None
        fam = (fam_proto >> 4) & 0x0F
        try:
            if fam == 0x1 and len(addr) >= 12:
                ip = socket.inet_ntoa(addr[0:4])
                port = struct.unpack(">H", addr[8:10])[0]
                return ip, port
            if fam == 0x2 and len(addr) >= 36:
                ip = socket.inet_ntop(socket.AF_INET6, addr[0:16])
                port = struct.unpack(">H", addr[32:34])[0]
                return ip, port
        except Exception:
            return None
    return None


def query_172_status(host, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        sb = SocketBuffer(s)
        hb = host.encode("utf-8")
        hs = write_varint(4) + write_varint(len(hb)) + hb + struct.pack(">H", port) + write_varint(1)
        body = write_varint(0x00) + hs
        s.sendall(write_varint(len(body)) + body)
        body = write_varint(0x00)
        s.sendall(write_varint(len(body)) + body)
        resp = read_172_packet(sb, None)
        try:
            s.close()
        except Exception:
            pass
        if not resp:
            return None
        r = BR(resp)
        if r.varint() != 0x00:
            return None
        data = json.loads(r.string())
        motd = resolve_chat_to_legacy(data.get("description", "Minecraft Server"))
        players = data.get("players", {}) or {}
        online = int(players.get("online", 0))
        max_p = int(players.get("max", 20))
        return motd.replace("\x00", ""), online, max_p
    except Exception as e:
        if DEBUG:
            print(f"[.] status query failed: {e!r}")
        return None


# ─────────────────────────────────────────────────────────────
# SERVER TO CLIENT PACKET DISPATCHER (1.7.2 -> 1.6.4)
# ─────────────────────────────────────────────────────────────
def handle_s2c(sb, csock, state_box, done, cs):
    try:
        while not done.is_set():
            packet_body = read_172_packet(sb, cs)
            if packet_body is None:
                break
            if len(packet_body) == 0:
                continue

            r = BR(packet_body)
            pid = r.varint()
            st = state_box[0]

            if st == "LOGIN":
                if pid == 0x00:
                    reason_json = r.string()
                    reason_plain = strip_json_to_plain(reason_json)
                    print(f"[!] Login rejected: {reason_plain}")
                    csock.sendall(b'\xFF' + enc_164_str(reason_plain[:100]))
                    break
                elif pid == 0x01:
                    # Target Server is requesting encryption (online-mode=true). Warn player.
                    print("[!] Target server requires Mojang Online Mode authentication.")
                    reason = "Target server is in Online Mode. Set online-mode=false in server.properties."
                    csock.sendall(b'\xFF' + enc_164_str(reason))
                    break
                elif pid == 0x02:
                    print("[+] Login Success → PLAY")
                    state_box[0] = "PLAY"
                elif pid == 0x03:
                    thresh = r.varint()
                    cs.compression_threshold = thresh
                    print(f"[+] Server enabled compression, threshold={thresh}")

            elif st == "PLAY":
                try:
                    _s2c(pid, r, csock, cs)
                except Exception as e:
                    if DEBUG:
                        print(f"[.] s2c 0x{pid:02X} err: {e!r}")
    except Exception as e:
        print(f"[-] s2c error: {e!r}")
        traceback.print_exc()
    finally:
        done.set()
        try:
            csock.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def _read_slot_raw(r):
    iid = struct.unpack('>h', r.take(2))[0]
    if iid == -1:
        return struct.pack('>h', -1)
    cnt = struct.unpack('>B', r.take(1))[0]
    dmg = struct.unpack('>h', r.take(2))[0]
    nl = struct.unpack('>h', r.take(2))[0]
    nbt = b''
    if nl > 0:
        nbt = r.take(nl)
    new_id, new_dmg = remap_item(iid, dmg)

    # Perform deep-nested item NBT ID remapping
    if nbt:
        try:
            if nbt[0] == 10:  # TAG_Compound
                nlen = struct.unpack('>H', nbt[1:3])[0]
                offset = 3 + nlen
                compound, _ = nbt_read_payload(NBTTag.TAG_COMPOUND, nbt, offset)
                remap_nbt_compound(compound)
                new_payload = nbt_write_payload(NBTTag.TAG_COMPOUND, compound)
                nbt = nbt[:3+nlen] + new_payload
        except Exception:
            pass

    out = struct.pack('>hBhh', new_id, cnt, new_dmg, len(nbt) if len(nbt) > 0 else -1)
    return out + nbt


def _s2c(pid, r, csock, cs):
    if pid == 0x00:
        ka = r.i32()
        csock.sendall(b'\x00' + struct.pack('>i', ka))

    elif pid == 0x01:
        eid = r.i32()
        gm = r.u8()
        dim = r.i8()
        diff = r.u8()
        mp = r.u8()
        lt = "default"
        try:
            lt = r.string()
        except Exception:
            pass

        if cs.in_game:
            # Multi-server network transfer (BungeeCord switch sub-server)
            print(f"[s2c] Server Transfer / Re-Join: dim={dim} gm={gm}")
            out = bytearray([0x09])
            out.extend(struct.pack('>i', dim))
            out.append(diff)
            out.append(gm)
            out.extend(struct.pack('>h', 256))
            out.extend(enc_164_str(lt if lt else 'default'))
            csock.sendall(bytes(out))
        else:
            cs.in_game = True
            out = bytearray([0x01])
            out.extend(struct.pack('>i', eid))
            out.extend(enc_164_str('default'))
            out.append(gm & 0xFF)
            out.extend(struct.pack('>b', dim))
            out.append(diff)
            out.append(0)
            out.append(min(mp, 60))
            csock.sendall(bytes(out))
            print(f"[+] Join Game eid={eid} dim={dim}")

    elif pid == 0x02:
        js = r.string()
        clean_json = chat_json_to_164_json(js)
        if len(clean_json) > 30000:
            clean_json = '{"text":"[too long]"}'
        csock.sendall(b'\x03' + enc_164_str(clean_json))

    elif pid == 0x03:
        csock.sendall(b'\x04' + r.take(16))

    elif pid == 0x04:
        eid = r.i32()
        slot = r.i16()
        item = _read_slot_raw(r)
        csock.sendall(b'\x05' + struct.pack('>ih', eid, slot) + item)

    elif pid == 0x05:
        csock.sendall(b'\x06' + r.take(12))

    elif pid == 0x06:
        csock.sendall(b'\x08' + r.take(10))

    elif pid == 0x07:
        dim = r.i32()
        diff = r.u8()
        gm = r.u8()
        lt = "default"
        try:
            lt = r.string()
        except Exception:
            pass
        out = bytearray([0x09])
        out.extend(struct.pack('>i', dim))
        out.append(diff)
        out.append(gm)
        out.extend(struct.pack('>h', 256))
        out.extend(enc_164_str(lt if lt else 'default'))
        csock.sendall(bytes(out))
        print(f"[s2c] RESPAWN dim={dim} diff={diff} gm={gm}")

    elif pid == 0x08:
        # S2C Player Position and Look — 1.7.2 always 33 bytes (no stance)
        # 1.6.4 client 0x0D needs 41 bytes WITH stance
        x = r.f64()
        feet_y = r.f64()
        z = r.f64()
        yaw = r.f32()
        pitch = r.f32()
        og = r.u8()
        head_y = feet_y + 1.62

        cs.spawn_x = x
        cs.spawn_y = feet_y
        cs.spawn_z = z
        cs.spawn_yaw = yaw
        cs.spawn_pitch = pitch
        cs.last_feet_y = feet_y
        cs.last_head_y = head_y
        cs.on_ground = bool(og)

        csock.sendall(
            b'\x0D' + struct.pack('>ddddffB', x, feet_y, head_y, z, yaw, pitch, og)
        )

    elif pid == 0x09:
        csock.sendall(b'\x10' + struct.pack('>h', r.u8()))

    elif pid == 0x0A:
        eid = r.i32()
        x = r.i32()
        y = r.u8()
        z = r.i32()
        csock.sendall(b'\x11' + struct.pack('>iBiBi', eid, 0, x, y, z))

    elif pid == 0x0B:
        eid = r.varint()
        anim = r.u8()
        anim_map = {0: 1, 1: 2, 2: 3, 3: 5}
        anim_164 = anim_map.get(anim, 0)
        if anim_164 != 0:
            csock.sendall(b'\x12' + struct.pack('>iB', eid, anim_164))

    elif pid == 0x0C:
        # Spawn Player (GameProfile properties deserializer desync bug fixed)
        eid = r.varint()
        uuid = r.string()
        name = r.string()
        pc = r.varint()
        for _ in range(pc):
            _prop_name = r.string()
            _prop_val = r.string()
            _prop_sig = r.string() # Signature is a string, always present! (Removed invalid boolean parsing)
        x = r.i32()
        y = r.i32()
        z = r.i32()
        yaw = r.u8()
        pitch = r.u8()
        cur = r.i16()
        meta_raw = r.metadata_raw()
        clean_name = ''.join(c for c in name if c != '§')[:16]
        if not clean_name:
            clean_name = "Player"
        out = bytearray([0x14])
        out.extend(struct.pack('>i', eid))
        out.extend(enc_164_str(clean_name))
        out.extend(struct.pack('>iiiBBh', x, y, z, yaw, pitch, cur))
        out.extend(translate_datawatcher(meta_raw))
        csock.sendall(bytes(out))

    elif pid == 0x0D:
        csock.sendall(b'\x16' + r.take(8))

    elif pid == 0x0E:
        # Spawn Object / Vehicle (Dropped items, falling blocks, projectiles)
        eid = r.varint()
        typ = r.i8()
        x = r.i32()
        y = r.i32()
        z = r.i32()
        pitch = r.u8()
        yaw = r.u8()
        obj_data = r.i32()
        vx = None
        vy = None
        vz = None
        if obj_data != 0:
            vx = r.i16()
            vy = r.i16()
            vz = r.i16()

        if typ == 70:  # Falling block remapping
            bid = obj_data & 0xFFFF
            meta = (obj_data >> 16) & 0xFFFF
            new_id, new_meta = remap_block(bid, meta)
            obj_data = (new_id & 0xFFFF) | ((new_meta & 0xFFFF) << 16)

        out = bytearray([0x17])
        out.extend(struct.pack('>iB', eid, typ & 0xFF))
        out.extend(struct.pack('>iiiBBi', x, y, z, pitch, yaw, obj_data))
        if vx is not None:
            out.extend(struct.pack('>hhh', vx, vy, vz))
        csock.sendall(bytes(out))

    elif pid == 0x0F:
        # Spawn Mob
        eid = r.varint()
        typ = r.u8()
        x = r.i32()
        y = r.i32()
        z = r.i32()
        yaw = r.u8()
        pitch = r.u8()
        head_yaw = r.u8()
        vx = r.i16()
        vy = r.i16()
        vz = r.i16()
        meta_raw = r.metadata_raw()

        # Remap any unsupported mob ID safely
        if typ > 120:
            typ = 90  # Pig fallback

        out = bytearray([0x18])
        out.extend(
            struct.pack(
                '>iBiiiBBBhhh',
                eid, typ, x, y, z, yaw, pitch, head_yaw, vx, vy, vz
            )
        )
        out.extend(translate_datawatcher(meta_raw))
        csock.sendall(bytes(out))

    elif pid == 0x10:
        eid = r.varint()
        title = r.string()
        x = r.i32()
        y = r.i32()
        z = r.i32()
        direction = r.i32()
        out = bytearray([0x19])
        out.extend(struct.pack('>i', eid))
        out.extend(enc_164_str(title[:13]))
        out.extend(struct.pack('>iiii', x, y, z, direction))
        csock.sendall(bytes(out))

    elif pid == 0x11:
        eid = r.varint()
        x = r.i32()
        y = r.i32()
        z = r.i32()
        count = r.i16()
        out = bytearray([0x1A])
        out.extend(struct.pack('>iiiih', eid, x, y, z, count))
        csock.sendall(bytes(out))

    elif pid == 0x12:
        # Entity Velocity (1.7.2 0x12 -> 1.6.4 0x1C)
        csock.sendall(b'\x1C' + r.take(10))

    elif pid == 0x13:
        cnt = r.u8()
        ids = r.take(cnt * 4)
        csock.sendall(b'\x1D' + bytes([cnt]) + ids)

    elif pid == 0x14:
        csock.sendall(b'\x1E' + r.take(4))

    elif pid == 0x15:
        csock.sendall(b'\x1F' + r.take(7))

    elif pid == 0x16:
        csock.sendall(b'\x20' + r.take(6))

    elif pid == 0x17:
        csock.sendall(b'\x21' + r.take(9))

    elif pid == 0x18:
        csock.sendall(b'\x22' + r.take(18))

    elif pid == 0x19:
        eid = r.i32()
        hy = r.i8()
        csock.sendall(b'\x23' + struct.pack('>ib', eid, hy))

    elif pid == 0x1A:
        csock.sendall(b'\x26' + r.take(5))

    elif pid == 0x1B:
        csock.sendall(b'\x27' + r.take(9))

    elif pid == 0x1C:
        # Entity Metadata (1.7.2 0x1C -> 1.6.4 0x28)
        eid = r.i32()
        meta_raw = r.metadata_raw()
        meta_164 = translate_datawatcher(meta_raw)
        csock.sendall(b'\x28' + struct.pack('>i', eid) + meta_164)

    elif pid == 0x1D:
        csock.sendall(b'\x29' + r.take(8))

    elif pid == 0x1E:
        csock.sendall(b'\x2A' + r.take(5))

    elif pid == 0x1F:
        csock.sendall(b'\x2B' + r.take(8))

    elif pid == 0x20:
        # Entity Properties / Attributes (1.7.2 0x20 -> 1.6.4 0x2C)
        eid = r.i32()
        prop_count = r.i32()
        out = bytearray([0x2C])
        out.extend(struct.pack('>ii', eid, prop_count))
        for _ in range(prop_count):
            key = r.string()
            val = r.f64()
            mod_count = r.u16()
            out.extend(enc_164_str(key))
            out.extend(struct.pack('>dH', val, mod_count))
            for _ in range(mod_count):
                uuid_msb = r.i64()
                uuid_lsb = r.i64()
                amount = r.f64()
                operation = r.u8()
                out.extend(struct.pack('>qqdB', uuid_msb, uuid_lsb, amount, operation))
        csock.sendall(bytes(out))

    elif pid == 0x21:
        x = r.i32()
        z = r.i32()
        gu = r.u8()
        prim = r.u16()
        add_mask = r.u16()
        csz = r.i32()
        cdata = r.take(csz)

        new_cdata = cdata
        try:
            raw_chunk = zlib.decompress(cdata)
            new_raw = _rewrite_chunk_blocks(raw_chunk, prim, add_mask, bool(gu))
            if new_raw is not raw_chunk:
                new_cdata = zlib.compress(new_raw, 1)
        except Exception as e:
            if DEBUG:
                print(f"[!] chunk rewrite failed ({x},{z}): {e!r}")

        out = bytearray([0x33])
        out.extend(struct.pack('>iiBHHi', x, z, gu, prim, add_mask, len(new_cdata)))
        out.extend(new_cdata)
        csock.sendall(bytes(out))

    elif pid == 0x22:
        cx = r.i32()
        cz = r.i32()
        cnt = r.i16()
        dsz = r.i32()
        records = bytearray(r.take(dsz))
        for i in range(cnt):
            off = i * 4
            if off + 4 > len(records):
                break
            rec = struct.unpack('>I', bytes(records[off:off + 4]))[0]
            meta = rec & 0x0F
            bid = (rec >> 4) & 0xFFF
            y = (rec >> 16) & 0xFF
            z = (rec >> 24) & 0x0F
            x = (rec >> 28) & 0x0F
            new_id, new_meta = remap_block(bid, meta)
            if new_id != bid or new_meta != meta:
                new_rec = (
                    ((x & 0x0F) << 28)
                    | ((z & 0x0F) << 24)
                    | ((y & 0xFF) << 16)
                    | ((new_id & 0xFFF) << 4)
                    | (new_meta & 0x0F)
                )
                records[off:off + 4] = struct.pack('>I', new_rec)
        out = bytearray([0x34])
        out.extend(struct.pack('>iihi', cx, cz, cnt, dsz))
        out.extend(records)
        csock.sendall(bytes(out))

    elif pid == 0x23:
        x = r.i32()
        y = r.u8()
        z = r.i32()
        bid = r.varint()
        md = r.u8()
        new_id, new_meta = remap_block(bid, md)
        csock.sendall(b'\x35' + struct.pack('>iBihB', x, y, z, new_id & 0xFFFF, new_meta))

    elif pid == 0x24:
        x = r.i32()
        y = r.i16()
        z = r.i32()
        b1 = r.u8()
        b2 = r.u8()
        bt = r.varint()
        # Remap the target block action block-type identifier
        new_bt, _ = remap_block(bt, 0)
        csock.sendall(b'\x36' + struct.pack('>ihiBBh', x, y, z, b1, b2, new_bt & 0xFFFF))

    elif pid == 0x25:
        eid = r.varint()
        x = r.i32()
        y = r.i32()
        z = r.i32()
        st = r.u8()
        csock.sendall(b'\x37' + struct.pack('>iiiiB', eid, x, y, z, st))

    elif pid == 0x26:
        count = r.i16()
        dsz = r.i32()
        sky = r.u8()
        chunk_data_compressed = r.take(dsz)
        meta_bytes = r.take(count * 12)

        new_compressed = chunk_data_compressed
        try:
            raw_all = zlib.decompress(chunk_data_compressed)
            new_all = bytearray()
            off = 0
            any_dirty = False
            for i in range(count):
                base = i * 12
                cx, cz, prim, addm = struct.unpack('>iiHH', bytes(meta_bytes[base:base + 12]))
                sec_cnt = bin(prim).count('1')
                add_cnt = bin(addm).count('1')
                per_light = (2048 + 2048 + (2048 if sky else 0))
                per_chunk_size = sec_cnt * (4096 + per_light) + add_cnt * 2048 + 256
                chunk_blob = raw_all[off:off + per_chunk_size]
                off += per_chunk_size
                new_blob = _rewrite_chunk_blocks(chunk_blob, prim, addm, True)
                if new_blob is not chunk_blob:
                    any_dirty = True
                new_all.extend(new_blob)
            if any_dirty:
                new_compressed = zlib.compress(bytes(new_all), 1)
        except Exception as e:
            if DEBUG:
                print(f"[!] bulk chunk rewrite failed: {e!r}")

        out = bytearray([0x38])
        out.extend(struct.pack('>hiB', count, len(new_compressed), sky))
        out.extend(new_compressed)
        out.extend(meta_bytes)
        csock.sendall(bytes(out))

    elif pid == 0x27:
        x = r.f32()
        y = r.f32()
        z = r.f32()
        rad = r.f32()
        rc = r.i32()
        if rc < 0 or rc > 65535:
            return
        needed = rc * 3 + 12
        if r.rem() < needed:
            return
        recs = r.take(rc * 3)
        pmx = r.f32()
        pmy = r.f32()
        pmz = r.f32()
        out = bytearray([0x3C])
        out.extend(struct.pack('>ffffi', x, y, z, rad, rc))
        out.extend(recs)
        out.extend(struct.pack('>fff', pmx, pmy, pmz))
        csock.sendall(bytes(out))

    elif pid == 0x28:
        eff = r.i32()
        x = r.i32()
        y = r.u8()
        z = r.i32()
        dat = r.i32()
        nrv = r.u8()
        csock.sendall(b'\x3D' + struct.pack('>iiBiiB', eff, x, y, z, dat, nrv))

    elif pid == 0x29:
        # Named Sound Effect Name Translator
        name = r.string()
        x = r.i32()
        y = r.i32()
        z = r.i32()
        vol = r.f32()
        pit = r.u8()
        translated_sound = translate_sound_name(name)
        out = bytearray([0x3E])
        out.extend(enc_164_str(translated_sound))
        out.extend(struct.pack('>iiifB', x, y, z, vol, pit))
        csock.sendall(bytes(out))

    elif pid == 0x2A:
        # Extensive World Particles Translation (Maps 1.7 particles to standard AuxSFX particles)
        name = r.string()
        x = r.f32()
        y = r.f32()
        z = r.f32()
        _ox = r.f32()
        _oy = r.f32()
        _oz = r.f32()
        pdata = r.f32()
        _count = r.i32()

        sfx_id = None
        data = 0
        if "smoke" in name or "largesmoke" in name:
            sfx_id = 2000
            data = 4
        elif "bonemeal" in name or "happyVillager" in name:
            sfx_id = 2005
            data = int(pdata) if pdata else 1
        elif "angryVillager" in name:
            sfx_id = 2006
            data = 0
        elif "splash" in name or "potion" in name or "instantSpell" in name:
            sfx_id = 2002
            data = int(pdata) if pdata else 0
        elif "portal" in name or "ender" in name:
            sfx_id = 2003
        elif "explode" in name or "hugeexplosion" in name or "largeexplode" in name:
            sfx_id = 2001
            data = 35 # Wool block visual impact fallback
        elif "flame" in name or "lava" in name:
            sfx_id = 2004

        if sfx_id is not None:
            ix = int(x)
            iy = max(0, min(255, int(y)))
            iz = int(z)
            csock.sendall(b'\x3D' + struct.pack('>iiBiiB', sfx_id, ix, iy, iz, data, 0))

    elif pid == 0x2B:
        reason = r.u8()
        val = int(r.f32())
        csock.sendall(b'\x46' + struct.pack('>BB', reason, val & 0xFF))

    elif pid == 0x2C:
        eid = r.varint()
        typ = r.u8()
        x = r.i32()
        y = r.i32()
        z = r.i32()
        csock.sendall(b'\x47' + struct.pack('>iBiii', eid, typ, x, y, z))

    elif pid == 0x2D:
        # Open Window (Filtered window title to prevent raw JSON text leaks)
        wid = r.u8()
        wtype = r.u8()
        title = r.string()
        slots = r.u8()
        use_title = r.u8()
        horse_eid = r.i32() if (wtype == 11 and r.rem() >= 4) else None

        clean_title = strip_json_to_plain(title)
        out = bytearray([0x64])
        out.extend(struct.pack('>BB', wid, wtype))
        out.extend(enc_164_str(clean_title[:32]))
        out.extend(struct.pack('>BB', slots, use_title))
        if wtype == 11 and horse_eid is not None:
            out.extend(struct.pack('>i', horse_eid))
        csock.sendall(bytes(out))

    elif pid == 0x2E:
        wid = r.u8()
        csock.sendall(b'\x65' + bytes([wid]))

    elif pid == 0x2F:
        wid = r.i8()
        slot = r.i16()
        item = _read_slot_raw(r)
        csock.sendall(b'\x67' + struct.pack('>bh', wid, slot) + item)

    elif pid == 0x30:
        wid = r.u8()
        cnt = r.i16()
        out = bytearray([0x68])
        out.extend(struct.pack('>Bh', wid, cnt))
        for _ in range(cnt):
            out.extend(_read_slot_raw(r))
        csock.sendall(bytes(out))

    elif pid == 0x31:
        wid = r.u8()
        prop = r.i16()
        val = r.i16()
        csock.sendall(b'\x69' + struct.pack('>Bhh', wid, prop, val))

    elif pid == 0x32:
        wid = r.u8()
        action = r.i16()
        acc = r.u8()
        csock.sendall(b'\x6A' + struct.pack('>BhB', wid, action, acc))

    elif pid == 0x33:
        x = r.i32()
        y = r.i16()
        z = r.i32()
        l1 = r.string()
        l2 = r.string()
        l3 = r.string()
        l4 = r.string()
        out = bytearray([0x82])
        out.extend(struct.pack('>ihi', x, y, z))
        out.extend(enc_164_str(l1[:15]))
        out.extend(enc_164_str(l2[:15]))
        out.extend(enc_164_str(l3[:15]))
        out.extend(enc_164_str(l4[:15]))
        csock.sendall(bytes(out))

    elif pid == 0x34:
        # Maps Data (1.7.2 0x34 -> 1.6.4 0x83)
        item_type = r.varint()
        map_id = r.i16()
        dlen = r.i16()
        mdata = r.take(dlen) if dlen > 0 else b""
        out = bytearray([0x83])
        out.extend(struct.pack('>hhh', item_type & 0xFFFF, map_id, len(mdata)))
        out.extend(mdata)
        csock.sendall(bytes(out))

    elif pid == 0x35:
        # Update Tile Entity (Safe nested item NBT translator)
        x = r.i32()
        y = r.i16()
        z = r.i32()
        act = r.u8()
        nlen = r.i16()
        ndata = r.take(nlen) if nlen > 0 else b''

        if ndata and nlen > 0:
            try:
                if ndata[0] == 10:  # TAG_Compound
                    nlen_tag = struct.unpack('>H', ndata[1:3])[0]
                    offset = 3 + nlen_tag
                    compound, _ = nbt_read_payload(NBTTag.TAG_COMPOUND, ndata, offset)
                    remap_nbt_compound(compound)
                    new_payload = nbt_write_payload(NBTTag.TAG_COMPOUND, compound)
                    ndata = ndata[:3+nlen_tag] + new_payload
                    nlen = len(ndata)
            except Exception as e:
                if DEBUG:
                    print(f"[!] TileEntity NBT deep translation failed: {e!r}")

        out = bytearray([0x84])
        out.extend(struct.pack('>ihiBh', x, y, z, act, nlen))
        out.extend(ndata)
        csock.sendall(bytes(out))

    elif pid == 0x36:
        # Open Sign Editor (1.7.2 0x36 -> 1.6.4 0x85)
        x = r.i32()
        y = r.i32()
        z = r.i32()
        csock.sendall(b'\x85' + struct.pack('>iii', x, y, z))

    elif pid == 0x37:
        # Statistics / Achievements (1.7.2 0x37)
        count = r.varint()
        for _ in range(count):
            _stat_name = r.string()
            _stat_val = r.varint()

    elif pid == 0x38:
        name = r.string()
        online = r.u8()
        ping = r.i16()
        clean = name.replace('\x00', '').replace('\n', '')[:16]
        if not clean:
            clean = "?"
        csock.sendall(b'\xC9' + enc_164_str(clean) + bytes([online]) + struct.pack('>h', ping))

    elif pid == 0x39:
        csock.sendall(b'\xCA' + r.take(9))

    elif pid == 0x3A:
        # Tab-Complete (1.7.2 0x3A -> 1.6.4 0xCB)
        cnt = r.varint()
        matches = []
        for _ in range(cnt):
            matches.append(r.string())
        all_text = "\x00".join(matches)
        csock.sendall(b'\xCB' + enc_164_str(all_text))

    elif pid == 0x3B:
        # Scoreboard Objective (1.7.2 0x3B -> 1.6.4 0xCE)
        name = r.string()
        val = r.string()
        action = r.u8()
        csock.sendall(b'\xCE' + enc_164_str(name[:16]) + enc_164_str(val[:32]) + bytes([action]))

    elif pid == 0x3C:
        # Update Score (1.7.2 0x3C -> 1.6.4 0xCF)
        item_name = r.string()
        action = r.u8()
        out = bytearray([0xCF])
        out.extend(enc_164_str(item_name[:16]))
        out.append(action)
        if action != 1:
            score_name = r.string()
            value = r.i32()
            out.extend(enc_164_str(score_name[:16]))
            out.extend(struct.pack('>i', value))
        csock.sendall(bytes(out))

    elif pid == 0x3D:
        # Display Scoreboard (1.7.2 0x3D -> 1.6.4 0xD0)
        position = r.u8()
        score_name = r.string()
        csock.sendall(b'\xD0' + bytes([position]) + enc_164_str(score_name[:16]))

    elif pid == 0x3E:
        # Teams (1.7.2 0x3E -> 1.6.4 0xD1)
        team_name = r.string()
        mode = r.u8()
        out = bytearray([0xD1])
        out.extend(enc_164_str(team_name[:16]))
        out.append(mode)
        if mode in (0, 2):
            display_name = r.string()
            prefix = r.string()
            suffix = r.string()
            friendly_fire = r.u8()
            out.extend(enc_164_str(display_name[:32]))
            out.extend(enc_164_str(prefix[:16]))
            out.extend(enc_164_str(suffix[:16]))
            out.append(friendly_fire)
        if mode in (0, 3, 4):
            p_count = r.i16()
            out.extend(struct.pack('>h', p_count))
            for _ in range(p_count):
                pname = r.string()
                out.extend(enc_164_str(pname[:16]))
        csock.sendall(bytes(out))

    elif pid == 0x3F:
        # S2C Plugin Message (Custom Payload)
        channel = r.string()
        dlen = r.i16() if r.rem() >= 2 else 0
        pdata = r.take(dlen) if (dlen > 0 and r.rem() >= dlen) else (r.take(r.rem()) if r.rem() > 0 else b"")

        # Strip unneeded Forge Handshakes for vanilla profile performance safety
        if "FML" in channel and not cs.is_forge:
            return

        # Texture Pack & Resource Pack Rewriting
        if channel in ("MC|RPack", "MC|TPack"):
            try:
                url = pdata.decode('utf-8', 'replace').strip()
                pdata = f"{url}\x0016".encode('utf-8')
            except Exception:
                pass
            channel = "MC|TPack"

        if len(channel) > 64:
            return

        if DEBUG_FORGE and ("FML" in channel or channel in ("FORGE", "REGISTER", "BungeeCord")):
            print(f"[PluginMsg S2C] {channel} ({len(pdata)} bytes)")

        out = bytearray([0xFA])
        out.extend(enc_164_str(channel))
        out.extend(struct.pack('>h', len(pdata)))
        out.extend(pdata)
        csock.sendall(bytes(out))

    elif pid == 0x40:
        reason_json = r.string()
        reason_plain = strip_json_to_plain(reason_json)
        print(f"[!] Server disconnect: {reason_plain}")
        csock.sendall(b'\xFF' + enc_164_str(reason_plain[:100]))


# ─────────────────────────────────────────────────────────────
# CLIENT TO SERVER PACKET DISPATCHER (1.6.4 -> 1.7.2)
# ─────────────────────────────────────────────────────────────
def handle_c2s(cb, ssock, state_box, done, cs):
    try:
        while not done.is_set():
            pid = cb.read_byte()
            if pid is None:
                print("[-] c2s: client sent EOF")
                break
            try:
                _c2s(pid, cb, ssock, cs, done)
            except Exception as e:
                print(f"[!] c2s 0x{pid:02X} FAIL: {e!r}")
                traceback.print_exc()
    except Exception as e:
        print(f"[-] c2s error: {e!r}")
        traceback.print_exc()
    finally:
        done.set()
        try:
            ssock.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def _write_slot_172(slot):
    """Encodes slot preserving full NBT payloads for inventories, shops, and menus."""
    if slot is None or slot.get("id", -1) == -1:
        return struct.pack('>h', -1)
    out = bytearray()
    new_id, new_damage = remap_item(slot["id"], slot.get("damage", 0))
    out.extend(struct.pack('>h', new_id))
    out.append((slot.get("count", 1) or 1) & 0xFF)
    out.extend(struct.pack('>h', new_damage))
    nbt = slot.get("nbt", b"")

    # Traverse nested compounds within client-originated actions (Creative slots, etc.)
    if nbt and len(nbt) > 0:
        try:
            if nbt[0] == 10:
                nlen = struct.unpack('>H', nbt[1:3])[0]
                offset = 3 + nlen
                compound, _ = nbt_read_payload(NBTTag.TAG_COMPOUND, nbt, offset)
                remap_nbt_compound(compound)
                new_payload = nbt_write_payload(NBTTag.TAG_COMPOUND, compound)
                nbt = nbt[:3+nlen] + new_payload
        except Exception:
            pass
        out.extend(struct.pack('>h', len(nbt)))
        out.extend(nbt)
    else:
        out.extend(struct.pack('>h', -1))
    return bytes(out)


def _c2s(pid, cb, ssock, cs, done):
    if pid == 0x00:
        ka = cb.read_int()
        if ka is not None:
            ssock.sendall(pack_172(cs, 0x00, struct.pack('>i', ka)))

    elif pid == 0x01:
        try:
            eid = cb.read_int()
            lt = cb.read_164_string()
            _gm = cb.read_byte()
            _dim = cb.read_byte()
            _diff = cb.read_byte()
            _height = cb.read_byte()
            _max_p = cb.read_byte()
            if DEBUG_FORGE:
                print(f"[c2s] Forge/Client Login packet 0x01: eid={eid} level_type={lt!r}")
        except Exception as e:
            if DEBUG:
                print(f"[!] Exception parsing C2S 0x01: {e!r}")

    elif pid == 0x03:
        msg = cb.read_164_string()
        if msg is not None:
            msg = msg[:100]
            ssock.sendall(pack_172(cs, 0x01, enc_172_str(msg)))

    elif pid == 0x07:
        _u = cb.read_int()
        tgt = cb.read_int()
        btn = cb.read_byte()
        if tgt is None or btn is None:
            return
        typ = 1 if btn == 1 else 0
        ssock.sendall(pack_172(cs, 0x02, struct.pack('>iB', tgt, typ)))

    elif pid == 0x0A:
        og = cb.read_byte()
        if og is None:
            return
        cs.on_ground = bool(og)
        ssock.sendall(pack_172(cs, 0x03, bytes([1 if og else 0])))

    elif pid == 0x0B:
        raw = cb.read_exact(33)
        if not raw or len(raw) < 33:
            return
        x, feet_y, stance, z, og = struct.unpack('>ddddB', raw)
        if DEBUG_MOVEMENT:
            cs.last_feet_y = feet_y
            cs.last_head_y = stance
        payload = struct.pack('>ddddB', x, feet_y, stance, z, 1 if og else 0)
        ssock.sendall(pack_172(cs, 0x04, payload))

    elif pid == 0x0C:
        raw = cb.read_exact(9)
        if not raw or len(raw) < 9:
            return
        yaw, pitch, og = struct.unpack('>ffB', raw)
        payload = struct.pack('>ffB', yaw, pitch, 1 if og else 0)
        ssock.sendall(pack_172(cs, 0x05, payload))

    elif pid == 0x0D:
        raw = cb.read_exact(41)
        if not raw or len(raw) < 41:
            return
        x, feet_y, stance, z, yaw, pitch, og = struct.unpack('>ddddffB', raw)
        if DEBUG_MOVEMENT:
            cs.last_feet_y = feet_y
            cs.last_head_y = stance
        payload = struct.pack('>ddddffB', x, feet_y, stance, z, yaw, pitch, 1 if og else 0)
        ssock.sendall(pack_172(cs, 0x06, payload))

    elif pid == 0x0E:
        st = cb.read_sbyte()
        x = cb.read_int()
        y = cb.read_byte()
        z = cb.read_int()
        face = cb.read_sbyte()
        if st is None or x is None or y is None or z is None or face is None:
            return
        ssock.sendall(pack_172(cs, 0x07, struct.pack('>biBib', st, x, y, z, face)))

    elif pid == 0x0F:
        x = cb.read_int()
        y = cb.read_byte()
        z = cb.read_int()
        direction = cb.read_sbyte()
        slot = cb.read_slot()
        cx = cb.read_byte()
        cy = cb.read_byte()
        cz = cb.read_byte()

        if x is None or y is None or z is None or direction is None:
            return
        if cx is None:
            cx = 8
        if cy is None:
            cy = 8
        if cz is None:
            cz = 8

        is_air = (direction == -1 or (x == -1 and y == 255 and z == -1))

        if is_air:
            p = bytearray()
            p.extend(struct.pack('>iBib', -1, 255, -1, -1))
            p.extend(_write_slot_172(slot))
            p.append(0)
            p.append(0)
            p.append(0)
            ssock.sendall(pack_172(cs, 0x08, p))
        else:
            p = bytearray(struct.pack('>iBib', x, y, z, direction))
            p.extend(_write_slot_172(slot))
            p.append(cx & 0xFF)
            p.append(cy & 0xFF)
            p.append(cz & 0xFF)
            ssock.sendall(pack_172(cs, 0x08, p))

    elif pid == 0x10:
        s = cb.read_short()
        if s is not None:
            ssock.sendall(pack_172(cs, 0x09, struct.pack('>h', s)))

    elif pid == 0x12:
        eid = cb.read_int()
        anim = cb.read_byte()
        if eid is None or anim is None:
            return
        ssock.sendall(pack_172(cs, 0x0A, struct.pack('>iB', eid, anim)))

    elif pid == 0x13:
        eid = cb.read_int()
        action = cb.read_byte()
        jb = cb.read_int()
        if eid is None or action is None or jb is None:
            return
        ssock.sendall(pack_172(cs, 0x0B, struct.pack('>iBi', eid, action, jb)))

    elif pid == 0x1B:
        sw = cb.read_float()
        fw = cb.read_float()
        j = cb.read_bool()
        un = cb.read_bool()
        if sw is None or fw is None:
            return
        ssock.sendall(
            pack_172(
                cs,
                0x0C,
                struct.pack('>ffBB', sw, fw, 1 if j else 0, 1 if un else 0)
            )
        )

    elif pid == 0x65:
        w = cb.read_byte()
        if w is None:
            return
        ssock.sendall(pack_172(cs, 0x0D, bytes([w])))

    elif pid == 0x66:
        # Window Click (Preserve Slot NBT for custom server chest menus)
        w = cb.read_byte()
        s = cb.read_short()
        b = cb.read_byte()
        a = cb.read_short()
        m = cb.read_byte()
        it = cb.read_slot()
        if w is None or s is None:
            return
        p = bytearray(struct.pack('>bhbhb', w, s, b, a, m))
        p.extend(_write_slot_172(it))
        ssock.sendall(pack_172(cs, 0x0E, p))

    elif pid == 0x6A:
        w = cb.read_byte()
        a = cb.read_short()
        ac = cb.read_bool()
        if w is None:
            return
        ssock.sendall(pack_172(cs, 0x0F, struct.pack('>bhB', w, a, 1 if ac else 0)))

    elif pid == 0x6B:
        # Creative Action (Preserve Slot NBT)
        s = cb.read_short()
        it = cb.read_slot()
        if s is None:
            return
        p = bytearray(struct.pack('>h', s))
        p.extend(_write_slot_172(it))
        ssock.sendall(pack_172(cs, 0x10, p))

    elif pid == 0x6C:
        w = cb.read_byte()
        e = cb.read_byte()
        if w is None or e is None:
            return
        ssock.sendall(pack_172(cs, 0x11, bytes([w, e])))

    elif pid == 0x82:
        x = cb.read_int()
        y = cb.read_short()
        z = cb.read_int()
        l1 = cb.read_164_string() or ""
        l2 = cb.read_164_string() or ""
        l3 = cb.read_164_string() or ""
        l4 = cb.read_164_string() or ""
        if x is None:
            return
        p = bytearray(struct.pack('>ihi', x, y, z))
        p.extend(enc_172_str(l1))
        p.extend(enc_172_str(l2))
        p.extend(enc_172_str(l3))
        p.extend(enc_172_str(l4))
        ssock.sendall(pack_172(cs, 0x12, p))

    elif pid == 0xCA:
        flags = cb.read_byte()
        fly = cb.read_float()
        walk = cb.read_float()
        if flags is None:
            return
        ssock.sendall(pack_172(cs, 0x13, struct.pack('>Bff', flags, fly, walk)))

    elif pid == 0xCB:
        t = cb.read_164_string() or ""
        ssock.sendall(pack_172(cs, 0x14, enc_172_str(t)))

    elif pid == 0xCC:
        locale = cb.read_164_string()
        view = cb.read_byte()
        cflag = cb.read_byte()
        diff = cb.read_byte()
        sc = cb.read_byte()

        if not locale or len(locale) > 16:
            locale = "en_US"
        try:
            locale.encode('utf-8')
        except UnicodeEncodeError:
            locale = "en_US"

        view_map = {0: 16, 1: 8, 2: 4, 3: 2}
        view_1_7 = view_map.get(view if view is not None else 1, 8)

        if cflag is None:
            cflag = 0
        if diff is None or diff > 3:
            diff = 0
        if sc is None:
            sc = 1

        chat_mode = cflag & 0x03
        chat_colors = 0 if (cflag & 0x80) else 1

        payload = bytearray()
        payload.extend(enc_172_str(locale))
        payload.append(view_1_7 & 0xFF)
        payload.append(chat_mode & 0xFF)
        payload.append(chat_colors & 0x01)
        payload.append(diff & 0xFF)
        payload.append(1 if sc else 0)
        ssock.sendall(pack_172(cs, 0x15, payload))

    elif pid == 0xCD:
        pl = cb.read_byte()
        if pl is None:
            return
        if pl == 0:
            return
        elif pl == 1:
            mapped = 0
        elif pl == 2:
            mapped = 1
        else:
            mapped = pl
        ssock.sendall(pack_172(cs, 0x16, bytes([mapped])))

    elif pid == 0xFA:
        # C2S Plugin Message
        channel = cb.read_164_string()
        dlen = cb.read_short()
        if channel is None:
            return
        if dlen is None or dlen < 0:
            return
        pdata = cb.read_exact(dlen) if dlen > 0 else b""
        if pdata is None:
            pdata = b""

        if channel == "MC|TPack":
            channel = "MC|RPack"

        if DEBUG_FORGE and ("FML" in channel or channel in ("FORGE", "REGISTER", "BungeeCord")):
            print(f"[PluginMsg C2S] {channel} ({len(pdata)} bytes)")

        payload = bytearray()
        payload.extend(enc_172_str(channel))
        payload.extend(struct.pack('>h', len(pdata)))
        payload.extend(pdata)
        ssock.sendall(pack_172(cs, 0x17, payload))

    elif pid == 0xFF:
        # Client disconnect packet (C2S 0xFF has no 1.7.2 companion. Socket is simply closed cleanly)
        m = cb.read_164_string() or ""
        print(f"[-] Client disconnecting: {m}")
        done.set()


# ─────────────────────────────────────────────────────────────
# INCOMING CLIENT CONNECTION WORKER
# ─────────────────────────────────────────────────────────────
def handle_client(raw, addr=None):
    csock = raw
    cb = SocketBuffer(csock)
    ssock = None
    cs = ConnState()
    if addr:
        cs.client_ip = addr[0]
    try:
        pp = check_proxy_protocol(cb)
        if pp:
            cs.client_ip, _src_port = pp

        first = cb.read_byte()
        if first is None:
            raw.close()
            return
        if first == 0xFE:
            _ping(cb, raw)
            return
        if first != 0x02:
            raw.close()
            return

        proto = cb.read_byte()
        user = cb.read_164_string()
        host = cb.read_164_string()
        port = cb.read_int()
        if user is None:
            raw.close()
            return

        if (host and "\x00FML\x00" in host) or (user and "\x00FML\x00" in user):
            cs.is_forge = True

        cs.handshake_host = host if host else TARGET_HOST
        clean_user = user.split("\x00")[0] if user else "Player"

        print(
            f"[+] Handshake user={clean_user!r} proto={proto} "
            f"host={cs.handshake_host!r} ip={cs.client_ip}"
        )

        vt = os.urandom(4)
        pkt = bytearray([0xFD])
        pkt.extend(enc_164_str("-"))
        pkt.extend(struct.pack('>h', len(_RSA_PUB_DER)))
        pkt.extend(_RSA_PUB_DER)
        pkt.extend(struct.pack('>h', len(vt)))
        pkt.extend(vt)
        raw.sendall(bytes(pkt))

        rid = cb.read_byte()
        if rid != 0xFC:
            raw.close()
            return
        sl = cb.read_short()
        se = cb.read_exact(sl) if sl else b""
        tl = cb.read_short()
        te = cb.read_exact(tl) if tl else b""
        shared = _RSA_KEY.decrypt(se, padding.PKCS1v15())
        rt = _RSA_KEY.decrypt(te, padding.PKCS1v15())
        if rt != vt or len(shared) != 16:
            raw.close()
            return

        raw.sendall(b'\xFC' + struct.pack('>h', 0) + struct.pack('>h', 0))

        es = EncryptedSocket(raw, shared)
        csock = es
        cs.csock = csock
        cb.upgrade(es)

        raw_ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_ssock.connect((TARGET_HOST, TARGET_PORT))
        ssock = LockedSocket(raw_ssock)
        cs.ssock = ssock
        sb = SocketBuffer(raw_ssock)

        hb = cs.handshake_host.encode("utf-8")
        hs = (
            write_varint(4)
            + write_varint(len(hb))
            + hb
            + struct.pack('>H', TARGET_PORT)
            + write_varint(2)
        )
        ssock.sendall(pack_172(cs, 0x00, hs))

        ub = clean_user.encode("utf-8")
        ssock.sendall(pack_172(cs, 0x00, write_varint(len(ub)) + ub))

        state = ["LOGIN"]
        done = threading.Event()
        threading.Thread(
            target=handle_s2c,
            args=(sb, csock, state, done, cs),
            daemon=True
        ).start()
        threading.Thread(
            target=handle_c2s,
            args=(cb, ssock, state, done, cs),
            daemon=True
        ).start()
        done.wait()

    except Exception as e:
        print(f"[-] handle_client error: {e!r}")
        traceback.print_exc()
    finally:
        try:
            if csock:
                csock.close()
        except Exception:
            pass
        try:
            if ssock:
                ssock.close()
        except Exception:
            pass


def _ping(cb, sock):
    try:
        b = cb.read_byte()
        if b == 0x01:
            nxt = cb.peek(1)
            if nxt == b"\xFA":
                cb.read_byte()
                _ch = cb.read_164_string()
                dlen = cb.read_ushort()
                if dlen:
                    cb.read_exact(dlen)

        info = query_172_status(TARGET_HOST, TARGET_PORT)
        if info:
            motd, online, max_p = info
        else:
            motd, online, max_p = "1.7.2 -> 1.6.4 Proxy", 0, 20

        f = f"§1\x0078\x001.6.4\x00{motd}\x00{online}\x00{max_p}"
        sock.sendall(b"\xFF" + struct.pack(">H", len(f)) + f.encode("utf-16-be"))
    except Exception as e:
        if DEBUG:
            print(f"[!] ping error: {e!r}")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(10)
    print(f"[*] Proxy active on {LISTEN_HOST}:{LISTEN_PORT} → {TARGET_HOST}:{TARGET_PORT}")
    print("[*] Compatible with Vanilla 1.6.4, Forge 1.6.4, BungeeCord, ViaProxy, and PROXY protocol")
    while True:
        c, addr = srv.accept()
        threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()


if __name__ == "__main__":
    main()
