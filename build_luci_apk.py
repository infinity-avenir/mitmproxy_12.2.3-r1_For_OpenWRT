#!/usr/bin/env python3
"""
Build script to package luci-app-mitmproxy as an OpenWrt APK v3.

This script is SELF-CONTAINED — all APK v3 ADB binary format code is
embedded directly below. No external adb_v3.py dependency is needed.

This creates a standalone .apk file using the ADB binary format
(apk-tools v3) that can be installed on OpenWrt 25.x routers with:

  apk add --allow-untrusted ./luci-app-mitmproxy_*.apk

The LuCI app is architecture-independent (pure Lua + HTML + JS).
"""

import hashlib
import os
import shutil
import struct
import time
import zlib
from pathlib import Path


###############################################################################
# ─── EMBEDDED APK v3 ADB Binary Format Writer ──────────────────────────────
#
# This section is a self-contained copy of adb_v3.py with all bug fixes
# applied inline.  It implements the ADB (Alpine Database) binary format
# used by apk-tools v3 — the native package format for OpenWrt 25.x.
#
# Reference: https://gitlab.alpinelinux.org/alpine/apk-tools
###############################################################################

# ─── ADB Format Constants ───────────────────────────────────────────────────

ADB_FORMAT_MAGIC = 0x2e424441  # "ADB." little-endian
ADB_SCHEMA_PACKAGE = 0x676b6370  # "pckg" little-endian

# Block types
ADB_BLOCK_ADB = 0
ADB_BLOCK_SIG = 1
ADB_BLOCK_DATA = 2
ADB_BLOCK_EXT = 3
ADB_BLOCK_ALIGNMENT = 8

# Value type tags (upper 4 bits of adb_val_t)
ADB_TYPE_SPECIAL = 0x00000000
ADB_TYPE_INT     = 0x10000000
ADB_TYPE_INT_32  = 0x20000000
ADB_TYPE_INT_64  = 0x30000000
ADB_TYPE_BLOB_8  = 0x80000000
ADB_TYPE_BLOB_16 = 0x90000000
ADB_TYPE_BLOB_32 = 0xa0000000
ADB_TYPE_ARRAY   = 0xd0000000
ADB_TYPE_OBJECT  = 0xe0000000

ADB_TYPE_MASK  = 0xf0000000
ADB_VALUE_MASK = 0x0fffffff

ADB_VAL_NULL = 0x00000000

# Generic object/array indices
ADBI_NUM_ENTRIES = 0x00
ADBI_FIRST = 0x01

# ─── Package Schema Field Indices ────────────────────────────────────────────

# Package (schema_package)
ADBI_PKG_PKGINFO = 0x01
ADBI_PKG_PATHS = 0x02
ADBI_PKG_SCRIPTS = 0x03
ADBI_PKG_TRIGGERS = 0x04
ADBI_PKG_REPLACES_PRIORITY = 0x05
ADBI_PKG_MAX = 0x06

# Package Info (schema_pkginfo)
ADBI_PI_NAME = 0x01
ADBI_PI_VERSION = 0x02
ADBI_PI_HASHES = 0x03
ADBI_PI_DESCRIPTION = 0x04
ADBI_PI_ARCH = 0x05
ADBI_PI_LICENSE = 0x06
ADBI_PI_ORIGIN = 0x07
ADBI_PI_MAINTAINER = 0x08
ADBI_PI_URL = 0x09
ADBI_PI_REPO_COMMIT = 0x0a
ADBI_PI_BUILD_TIME = 0x0b
ADBI_PI_INSTALLED_SIZE = 0x0c
ADBI_PI_FILE_SIZE = 0x0d
ADBI_PI_PROVIDER_PRIORITY = 0x0e
ADBI_PI_DEPENDS = 0x0f
ADBI_PI_PROVIDES = 0x10
ADBI_PI_REPLACES = 0x11
ADBI_PI_INSTALL_IF = 0x12
ADBI_PI_RECOMMENDS = 0x13
ADBI_PI_LAYER = 0x14
ADBI_PI_TAGS = 0x15
ADBI_PI_MAX = 0x16

# ACL
ADBI_ACL_MODE = 0x01
ADBI_ACL_USER = 0x02
ADBI_ACL_GROUP = 0x03
ADBI_ACL_XATTRS = 0x04
ADBI_ACL_MAX = 0x05

# File Info
ADBI_FI_NAME = 0x01
ADBI_FI_ACL = 0x02
ADBI_FI_SIZE = 0x03
ADBI_FI_MTIME = 0x04
ADBI_FI_HASHES = 0x05
ADBI_FI_TARGET = 0x06
ADBI_FI_MAX = 0x07

# Directory Info
ADBI_DI_NAME = 0x01
ADBI_DI_ACL = 0x02
ADBI_DI_FILES = 0x03
ADBI_DI_MAX = 0x04

# Scripts
ADBI_SCRPT_TRIGGER = 0x01
ADBI_SCRPT_PREINST = 0x02
ADBI_SCRPT_POSTINST = 0x03
ADBI_SCRPT_PREDEINST = 0x04
ADBI_SCRPT_POSTDEINST = 0x05
ADBI_SCRPT_PREUPGRADE = 0x06
ADBI_SCRPT_POSTUPGRADE = 0x07
ADBI_SCRPT_MAX = 0x08

# Dependency
ADBI_DEP_NAME = 0x01
ADBI_DEP_VERSION = 0x02
ADBI_DEP_MATCH = 0x03
ADBI_DEP_MAX = 0x04


# ─── Utility Functions ───────────────────────────────────────────────────────

def _round_up(val, alignment):
    """Round up val to the next multiple of alignment."""
    return (val + alignment - 1) & ~(alignment - 1)


def _adb_val(type_tag, value):
    """Create an adb_val_t: htole32(type | value)."""
    return struct.pack('<I', (type_tag | value) & 0xFFFFFFFF)


def _adb_val_int(type_tag, value):
    """Return the integer form of an adb_val_t."""
    return (type_tag | value) & 0xFFFFFFFF


# ─── ADB Writer ──────────────────────────────────────────────────────────────

class ADBWriter:
    """
    Writes an ADB data buffer (the content inside an ADB block).

    The buffer starts with an 8-byte adb_hdr:
      uint8_t  adb_compat_ver = 0
      uint8_t  adb_ver = 0
      uint16_t reserved = 0
      uint32_t root (adb_val_t)

    All data is appended with proper alignment and deduplication.
    """

    def __init__(self, schema=ADB_SCHEMA_PACKAGE):
        self.schema = schema
        self.buf = bytearray()
        self.buf.extend(struct.pack('<BBHI', 0, 0, 0, 0))
        self._cache = {}

    def _align_to(self, alignment):
        padding = _round_up(len(self.buf), alignment) - len(self.buf)
        if padding:
            self.buf.extend(b'\x00' * padding)

    def _write_raw(self, data: bytes, alignment: int) -> int:
        self._align_to(alignment)
        offset = len(self.buf)
        self.buf.extend(data)
        return offset

    def _write_data(self, data: bytes, alignment: int) -> int:
        key = (alignment, bytes(data))
        cached = self._cache.get(key)
        if cached is not None:
            if (cached % alignment) == 0:
                return cached
        offset = self._write_raw(data, alignment)
        self._cache[key] = offset
        return offset

    def _write_data_nocache(self, data: bytes, alignment: int) -> int:
        return self._write_raw(data, alignment)

    def w_blob(self, data: bytes, raw=False) -> int:
        if not data and not isinstance(data, bytes):
            return ADB_VAL_NULL
        if len(data) == 0:
            return ADB_VAL_NULL

        sz = len(data)
        if sz > 0xFFFF:
            prefix = struct.pack('<I', sz)
            alignment = 4
            type_tag = ADB_TYPE_BLOB_32
        elif sz > 0xFF:
            prefix = struct.pack('<H', sz)
            alignment = 2
            type_tag = ADB_TYPE_BLOB_16
        else:
            prefix = struct.pack('<B', sz)
            alignment = 1
            type_tag = ADB_TYPE_BLOB_8

        blob_data = prefix + data

        if raw:
            offset = self._write_data_nocache(blob_data, alignment)
        else:
            offset = self._write_data(blob_data, alignment)

        return _adb_val_int(type_tag, offset)

    def w_blob_str(self, s: str, raw=False) -> int:
        if not s:
            return ADB_VAL_NULL
        return self.w_blob(s.encode('utf-8'), raw=raw)

    def w_int(self, val: int) -> int:
        if val < 0:
            val = 0
        if val >= 0x100000000:
            data = struct.pack('<Q', val)
            offset = self._write_data(data, 4)
            return _adb_val_int(ADB_TYPE_INT_64, offset)
        if val >= 0x10000000:
            data = struct.pack('<I', val)
            offset = self._write_data(data, 4)
            return _adb_val_int(ADB_TYPE_INT_32, offset)
        return _adb_val_int(ADB_TYPE_INT, val)

    def w_obj(self, fields: dict, max_field: int) -> int:
        num_slots = max_field
        slots = [ADB_VAL_NULL] * num_slots
        for idx, val in fields.items():
            if 1 <= idx < num_slots:
                slots[idx] = val

        n = num_slots
        while n > 1 and slots[n - 1] == ADB_VAL_NULL:
            n -= 1

        if n <= 1:
            return ADB_VAL_NULL

        slots[ADBI_NUM_ENTRIES] = n

        data = b''
        for i in range(n):
            data += struct.pack('<I', slots[i])

        offset = self._write_data(data, 4)
        return _adb_val_int(ADB_TYPE_OBJECT, offset)

    def w_arr(self, items: list) -> int:
        if not items:
            return ADB_VAL_NULL

        n = len(items) + 1
        slots = [0] * n
        for i, val in enumerate(items):
            slots[i + 1] = val

        while n > 1 and slots[n - 1] == ADB_VAL_NULL:
            n -= 1

        if n <= 1:
            return ADB_VAL_NULL

        slots[ADBI_NUM_ENTRIES] = n

        data = b''
        for i in range(n):
            data += struct.pack('<I', slots[i])

        offset = self._write_data(data, 4)
        return _adb_val_int(ADB_TYPE_ARRAY, offset)

    def set_root(self, val: int):
        struct.pack_into('<I', self.buf, 4, val)

    def get_buffer(self) -> bytes:
        return bytes(self.buf)

    def compute_unique_id(self, hashes_offset: int):
        digest = hashlib.sha256(bytes(self.buf)).digest()
        self.buf[hashes_offset:hashes_offset + 20] = digest[:20]


# ─── Block and File Assembly ─────────────────────────────────────────────────

def make_block_header(block_type: int, payload_length: int) -> bytes:
    total = 4 + payload_length
    if total <= 0x3FFFFFFF:
        type_size = (block_type << 30) | total
        return struct.pack('<I', type_size)
    else:
        type_size = (ADB_BLOCK_EXT << 30) | block_type
        x_size = 16 + payload_length
        return struct.pack('<IIQ', type_size, 0, x_size)


def block_rawsize(hdr: bytes) -> int:
    type_size = struct.unpack('<I', hdr[:4])[0]
    if (type_size >> 30) == ADB_BLOCK_EXT:
        x_size = struct.unpack('<Q', hdr[8:16])[0]
        return x_size
    return type_size & 0x3FFFFFFF


def write_block(out: bytearray, block_type: int, payload: bytes):
    hdr = make_block_header(block_type, len(payload))
    out.extend(hdr)
    out.extend(payload)
    raw_size = block_rawsize(hdr)
    padded = _round_up(raw_size, ADB_BLOCK_ALIGNMENT)
    padding = padded - raw_size
    if padding:
        out.extend(b'\x00' * padding)


def write_data_block(out: bytearray, path_idx: int, file_idx: int, file_data: bytes):
    hdr = struct.pack('<II', path_idx, file_idx)
    payload = hdr + file_data
    write_block(out, ADB_BLOCK_DATA, payload)


def write_file_header(out: bytearray, schema: int = ADB_SCHEMA_PACKAGE):
    out.extend(struct.pack('<II', ADB_FORMAT_MAGIC, schema))


def assemble_apk(adb_writer: ADBWriter, data_blocks: list = None) -> bytes:
    """
    Assemble a complete APK v3 package file with deflate compression.

    Format: "ADBd" + DEFLATE{ file_header + ADB block + DATA blocks }
    """
    raw = bytearray()
    write_file_header(raw, adb_writer.schema)
    adb_data = adb_writer.get_buffer()
    write_block(raw, ADB_BLOCK_ADB, adb_data)

    if data_blocks:
        for path_idx, file_idx, file_data in data_blocks:
            write_data_block(raw, path_idx, file_idx, file_data)

    compobj = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    compressed = compobj.compress(bytes(raw))
    compressed += compobj.flush(zlib.Z_FINISH)

    out = bytearray()
    out.extend(b'ADBd')
    out.extend(compressed)
    return bytes(out)


# ─── Dependency Helpers ──────────────────────────────────────────────────────

APK_DEPMASK_ANY     = 0
APK_DEPMASK_EQUAL   = 1
APK_DEPMASK_GEQUAL  = 2
APK_DEPMASK_GREATER = 3
APK_DEPMASK_LEQUAL  = 4
APK_DEPMASK_LESS    = 5
APK_DEPMASK_FUZZY   = 6
APK_DEPMASK_CONFLICT = 16


def make_dependency(writer: ADBWriter, name: str, version: str = None,
                    match: int = APK_DEPMASK_ANY) -> int:
    fields = {}
    fields[ADBI_DEP_NAME] = writer.w_blob_str(name)
    if version:
        fields[ADBI_DEP_VERSION] = writer.w_blob_str(version)
    if match != APK_DEPMASK_ANY:
        fields[ADBI_DEP_MATCH] = writer.w_int(match)
    return writer.w_obj(fields, ADBI_DEP_MAX)


def make_dependency_array(writer: ADBWriter, deps: list) -> int:
    if not deps:
        return ADB_VAL_NULL
    items = []
    for dep in deps:
        if isinstance(dep, str):
            items.append(make_dependency(writer, dep))
        elif isinstance(dep, tuple):
            items.append(make_dependency(writer, *dep))
        else:
            items.append(dep)
    return writer.w_arr(items)


# ─── ACL / File / Directory Helpers ──────────────────────────────────────────

def make_acl(writer: ADBWriter, mode: int = 0o644,
             user: str = "root", group: str = "root") -> int:
    fields = {}
    fields[ADBI_ACL_MODE] = writer.w_int(mode)
    fields[ADBI_ACL_USER] = writer.w_blob_str(user)
    fields[ADBI_ACL_GROUP] = writer.w_blob_str(group)
    return writer.w_obj(fields, ADBI_ACL_MAX)


def make_file_info(writer: ADBWriter, name: str, size: int,
                   mtime: int = None, file_hash: bytes = None,
                   acl_val: int = None, target: bytes = None) -> int:
    fields = {}
    fields[ADBI_FI_NAME] = writer.w_blob_str(name)
    if acl_val is not None:
        fields[ADBI_FI_ACL] = acl_val
    if size > 0:
        fields[ADBI_FI_SIZE] = writer.w_int(size)
    if mtime is not None:
        fields[ADBI_FI_MTIME] = writer.w_int(mtime)
    if file_hash is not None:
        fields[ADBI_FI_HASHES] = writer.w_blob(file_hash)
    if target is not None:
        fields[ADBI_FI_TARGET] = writer.w_blob(target)
    return writer.w_obj(fields, ADBI_FI_MAX)


def make_dir_info(writer: ADBWriter, name: str,
                  acl_val: int = None, files_arr_val: int = None) -> int:
    fields = {}
    fields[ADBI_DI_NAME] = writer.w_blob_str(name)
    if acl_val is not None:
        fields[ADBI_DI_ACL] = acl_val
    if files_arr_val is not None:
        fields[ADBI_DI_FILES] = files_arr_val
    return writer.w_obj(fields, ADBI_DI_MAX)


# ─── High-Level Package Builder ─────────────────────────────────────────────

class APKv3Builder:
    """
    High-level builder for APK v3 packages.

    Usage:
        builder = APKv3Builder()
        builder.set_pkginfo(name="mypkg", version="1.0.0-r1", arch="aarch64", ...)
        builder.add_file("usr/bin/hello", file_content, mode=0o755)
        builder.set_script("post-install", script_content)
        apk_bytes = builder.build()
    """

    def __init__(self):
        self.writer = ADBWriter(ADB_SCHEMA_PACKAGE)
        self._pkginfo_fields = {}
        self._depends = []
        self._provides = []
        self._install_if = []
        self._replaces = []
        self._recommends = []
        self._dirs = {}
        self._dir_modes = {}
        self._scripts = {}
        self._triggers = []
        self._replaces_priority = None
        self._installed_size = 0
        self._build_time = int(time.time())

    def set_pkginfo(self, name: str, version: str, arch: str = "noarch",
                    description: str = "", license: str = "GPL-2.0-only",
                    origin: str = None, maintainer: str = None,
                    url: str = None, provider_priority: int = None):
        self._pkginfo_fields['name'] = name
        self._pkginfo_fields['version'] = version
        self._pkginfo_fields['arch'] = arch
        self._pkginfo_fields['description'] = description
        self._pkginfo_fields['license'] = license
        if origin:
            self._pkginfo_fields['origin'] = origin
        if maintainer:
            self._pkginfo_fields['maintainer'] = maintainer
        if url:
            self._pkginfo_fields['url'] = url
        if provider_priority is not None:
            self._pkginfo_fields['provider_priority'] = provider_priority

    def set_build_time(self, timestamp: int):
        self._build_time = timestamp

    def add_depend(self, name: str, version: str = None,
                   match: int = APK_DEPMASK_ANY):
        self._depends.append((name, version, match))

    def add_provide(self, name: str, version: str = None,
                    match: int = APK_DEPMASK_EQUAL):
        self._provides.append((name, version, match))

    def add_install_if(self, name: str, version: str = None,
                       match: int = APK_DEPMASK_ANY):
        self._install_if.append((name, version, match))

    def add_replace(self, name: str, version: str = None,
                    match: int = APK_DEPMASK_ANY):
        self._replaces.append((name, version, match))

    def set_replaces_priority(self, priority: int):
        self._replaces_priority = priority

    def add_trigger(self, path: str):
        self._triggers.append(path)

    def add_file(self, filepath: str, content: bytes, mode: int = 0o644,
                 user: str = "root", group: str = "root",
                 mtime: int = None):
        if isinstance(content, str):
            content = content.encode('utf-8')

        filepath = filepath.lstrip('/')
        if '/' in filepath:
            dirpath = os.path.dirname(filepath)
            filename = os.path.basename(filepath)
        else:
            dirpath = ''
            filename = filepath

        if dirpath not in self._dirs:
            self._dirs[dirpath] = []
        if dirpath not in self._dir_modes:
            self._dir_modes[dirpath] = (0o755, "root", "root")

        self._dirs[dirpath].append((filename, content, mode, user, group, mtime))
        self._installed_size += len(content)

    def add_symlink(self, filepath: str, target: str, mode: int = 0o777,
                    user: str = "root", group: str = "root",
                    mtime: int = None):
        filepath = filepath.lstrip('/')
        if '/' in filepath:
            dirpath = os.path.dirname(filepath)
            filename = os.path.basename(filepath)
        else:
            dirpath = ''
            filename = filepath

        if dirpath not in self._dirs:
            self._dirs[dirpath] = []
        if dirpath not in self._dir_modes:
            self._dir_modes[dirpath] = (0o755, "root", "root")

        self._dirs[dirpath].append((filename, None, mode, user, group, mtime, target))

    def set_dir_mode(self, dirpath: str, mode: int = 0o755,
                     user: str = "root", group: str = "root"):
        dirpath = dirpath.strip('/')
        self._dir_modes[dirpath] = (mode, user, group)

    def set_script(self, script_type: str, content):
        if isinstance(content, str):
            content = content.encode('utf-8')

        type_map = {
            'trigger': ADBI_SCRPT_TRIGGER,
            'pre-install': ADBI_SCRPT_PREINST,
            'post-install': ADBI_SCRPT_POSTINST,
            'pre-deinstall': ADBI_SCRPT_PREDEINST,
            'post-deinstall': ADBI_SCRPT_POSTDEINST,
            'pre-upgrade': ADBI_SCRPT_PREUPGRADE,
            'post-upgrade': ADBI_SCRPT_POSTUPGRADE,
        }
        field_idx = type_map.get(script_type)
        if field_idx is None:
            raise ValueError(f"Unknown script type: {script_type}")
        self._scripts[field_idx] = content

    def build(self) -> bytes:
        """Build the complete APK v3 package. Returns the raw APK file bytes."""
        w = self.writer

        data_blocks = []
        sorted_dirs = sorted(self._dirs.keys())
        dir_objs = []

        for dir_idx, dirpath in enumerate(sorted_dirs):
            files = self._dirs[dirpath]
            files.sort(key=lambda f: f[0])

            dir_mode_info = self._dir_modes.get(dirpath, (0o755, "root", "root"))
            dir_acl = make_acl(w, mode=dir_mode_info[0],
                               user=dir_mode_info[1], group=dir_mode_info[2])

            file_objs = []
            for file_idx, file_entry in enumerate(files):
                is_symlink = len(file_entry) > 6
                if is_symlink:
                    fname, _, fmode, fuser, fgroup, fmtime, target = file_entry
                    file_acl = make_acl(w, mode=fmode & 0o7777,
                                        user=fuser, group=fgroup)
                    target_blob = struct.pack('<H', 0xA000) + target.encode('utf-8')
                    fi = make_file_info(w, fname, size=0,
                                        mtime=fmtime or self._build_time,
                                        acl_val=file_acl,
                                        target=target_blob)
                else:
                    fname, fcontent, fmode, fuser, fgroup, fmtime = file_entry
                    file_acl = make_acl(w, mode=fmode & 0o7777,
                                        user=fuser, group=fgroup)
                    # FIX: Use `is not None` instead of truthiness check.
                    # b"" is falsy but empty files MUST get a SHA256 hash,
                    # otherwise apk-tools rejects with "ADB schema error".
                    if fcontent is not None:
                        file_hash = hashlib.sha256(fcontent).digest()
                    else:
                        file_hash = None

                    # FIX: Use `is not None` for size calculation too.
                    fi = make_file_info(w, fname, size=len(fcontent) if fcontent is not None else 0,
                                        mtime=fmtime or self._build_time,
                                        file_hash=file_hash,
                                        acl_val=file_acl)

                    # FIX: Use `is not None` for data block check.
                    if fcontent is not None and len(fcontent) > 0:
                        data_blocks.append((dir_idx + 1, file_idx + 1, fcontent))

                file_objs.append(fi)

            files_arr = w.w_arr(file_objs) if file_objs else ADB_VAL_NULL

            di = make_dir_info(w, dirpath, acl_val=dir_acl,
                               files_arr_val=files_arr)
            dir_objs.append(di)

        paths_arr = w.w_arr(dir_objs) if dir_objs else ADB_VAL_NULL

        # Scripts
        scripts_val = ADB_VAL_NULL
        if self._scripts:
            script_fields = {}
            for idx, content in self._scripts.items():
                script_fields[idx] = w.w_blob(content)
            scripts_val = w.w_obj(script_fields, ADBI_SCRPT_MAX)

        # Triggers
        triggers_val = ADB_VAL_NULL
        if self._triggers:
            trigger_items = [w.w_blob_str(t) for t in self._triggers]
            triggers_val = w.w_arr(trigger_items)

        # Package info
        pi_fields = {}
        pi = self._pkginfo_fields

        pi_fields[ADBI_PI_NAME] = w.w_blob_str(pi.get('name', ''))
        pi_fields[ADBI_PI_VERSION] = w.w_blob_str(pi.get('version', ''))

        hashes_blob_val = w.w_blob(b'\x00' * 20, raw=True)
        pi_fields[ADBI_PI_HASHES] = hashes_blob_val
        hashes_offset = (hashes_blob_val & ADB_VALUE_MASK) + 1

        if pi.get('description'):
            pi_fields[ADBI_PI_DESCRIPTION] = w.w_blob_str(pi['description'])
        if pi.get('arch'):
            pi_fields[ADBI_PI_ARCH] = w.w_blob_str(pi['arch'])
        if pi.get('license'):
            pi_fields[ADBI_PI_LICENSE] = w.w_blob_str(pi['license'])
        if pi.get('origin'):
            pi_fields[ADBI_PI_ORIGIN] = w.w_blob_str(pi['origin'])
        if pi.get('maintainer'):
            pi_fields[ADBI_PI_MAINTAINER] = w.w_blob_str(pi['maintainer'])
        if pi.get('url'):
            pi_fields[ADBI_PI_URL] = w.w_blob_str(pi['url'])

        pi_fields[ADBI_PI_BUILD_TIME] = w.w_int(self._build_time)

        installed_size = self._installed_size if self._installed_size > 0 else 1
        pi_fields[ADBI_PI_INSTALLED_SIZE] = w.w_int(installed_size)

        if pi.get('provider_priority') is not None:
            pi_fields[ADBI_PI_PROVIDER_PRIORITY] = w.w_int(pi['provider_priority'])

        if self._depends:
            pi_fields[ADBI_PI_DEPENDS] = make_dependency_array(w, self._depends)
        if self._provides:
            pi_fields[ADBI_PI_PROVIDES] = make_dependency_array(w, self._provides)
        if self._replaces:
            pi_fields[ADBI_PI_REPLACES] = make_dependency_array(w, self._replaces)
        if self._install_if:
            pi_fields[ADBI_PI_INSTALL_IF] = make_dependency_array(w, self._install_if)
        if self._recommends:
            pi_fields[ADBI_PI_RECOMMENDS] = make_dependency_array(w, self._recommends)

        pkginfo_val = w.w_obj(pi_fields, ADBI_PI_MAX)

        # Root package object
        pkg_fields = {}
        pkg_fields[ADBI_PKG_PKGINFO] = pkginfo_val
        if paths_arr != ADB_VAL_NULL:
            pkg_fields[ADBI_PKG_PATHS] = paths_arr
        if scripts_val != ADB_VAL_NULL:
            pkg_fields[ADBI_PKG_SCRIPTS] = scripts_val
        if triggers_val != ADB_VAL_NULL:
            pkg_fields[ADBI_PKG_TRIGGERS] = triggers_val
        if self._replaces_priority is not None:
            pkg_fields[ADBI_PKG_REPLACES_PRIORITY] = w.w_int(self._replaces_priority)

        root_val = w.w_obj(pkg_fields, ADBI_PKG_MAX)
        w.set_root(root_val)

        # Compute unique ID
        w.compute_unique_id(hashes_offset)

        # Assemble
        return assemble_apk(w, data_blocks)


###############################################################################
# ─── END OF EMBEDDED APK v3 CODE ───────────────────────────────────────────
###############################################################################


PKG_NAME = "luci-app-mitmproxy"
PKG_VERSION = "1.0.0"
PKG_RELEASE = "1"


def build_luci_apk(source_dir: Path = None, output_dir: Path = None):
    """Build the luci-app-mitmproxy APK v3 package."""

    if source_dir is None:
        source_dir = Path(__file__).parent / "luci-app-mitmproxy"
    if output_dir is None:
        output_dir = Path(__file__).parent / "output"

    output_dir.mkdir(parents=True, exist_ok=True)

    builder = APKv3Builder()
    build_time = int(time.time())
    builder.set_build_time(build_time)

    version_str = f"{PKG_VERSION}-r{PKG_RELEASE}"

    builder.set_pkginfo(
        name=PKG_NAME,
        version=version_str,
        arch="noarch",
        description="LuCI web interface for mitmproxy HTTP proxy",
        license="MIT",
        origin=PKG_NAME,
        maintainer="Open Firewall Project",
        url="https://mitmproxy.org/",
    )

    # Dependencies — only packages available in the OpenWrt 25.x repos.
    # Do NOT list "mitmproxy" here: it's our own local APK, not in any repo,
    # so apk would refuse to install this package if it can't resolve it.
    builder.add_depend("luci-base")

    # ── Collect all package files ────────────────────────────────────────

    def add_source_file(src_path: Path, pkg_path: str, mode: int = 0o644):
        """Read a source file and add it to the package."""
        content = src_path.read_bytes()
        builder.add_file(pkg_path, content, mode=mode, mtime=build_time)

    # LuCI controller
    add_source_file(
        source_dir / "luasrc/controller/mitmproxy.lua",
        "usr/lib/lua/luci/controller/mitmproxy.lua",
    )

    # CBI models
    cbi_dir = source_dir / "luasrc/model/cbi/mitmproxy"
    for f in sorted(cbi_dir.glob("*.lua")):
        add_source_file(f, f"usr/lib/lua/luci/model/cbi/mitmproxy/{f.name}")

    # View templates
    view_dir = source_dir / "luasrc/view/mitmproxy"
    for f in sorted(view_dir.glob("*.htm")):
        add_source_file(f, f"usr/lib/lua/luci/view/mitmproxy/{f.name}")

    # Static assets (CSS/JS) if any exist
    static_src = source_dir / "htdocs/luci-static/mitmproxy"
    if static_src.exists():
        for f in sorted(static_src.rglob("*")):
            if f.is_file():
                rel = f.relative_to(static_src)
                add_source_file(f, f"www/luci-static/mitmproxy/{rel}")

    # UCI defaults script
    uci_defaults_content = """\
#!/bin/sh
# Ensure mitmproxy UCI config exists
[ -f /etc/config/mitmproxy ] || {
cat > /etc/config/mitmproxy <<'CONF'
config mitmproxy 'main'
\toption enabled '0'
\toption listen_host '0.0.0.0'
\toption listen_port '8080'
\toption mode 'regular'
\toption ssl_insecure '0'
\toption confdir '/etc/mitmproxy/certs'
\toption web_host '0.0.0.0'
\toption web_port '8081'

config mitmproxy 'logging'
\toption log_level 'info'
\toption flow_detail '1'

config mitmproxy 'interception'
\toption intercept ''
\toption anticache '0'
\toption anticomp '0'

config mitmproxy 'traffic_analysis'
\toption enabled '0'
\toption flow_collection '1'
\toption behavior_analysis '0'
\toption ai_analysis '0'
\toption max_flows '10000'
CONF
}

# Clear LuCI cache so the new app appears
rm -rf /tmp/luci-modulecache /tmp/luci-indexcache 2>/dev/null
exit 0
"""
    builder.add_file("etc/uci-defaults/99-luci-mitmproxy",
                     uci_defaults_content.encode('utf-8'),
                     mode=0o755, mtime=build_time)

    # ── Post-install script ──────────────────────────────────────────────

    post_install_script = """\
#!/bin/sh
# Run UCI defaults
[ -x /etc/uci-defaults/99-luci-mitmproxy ] && /etc/uci-defaults/99-luci-mitmproxy
# Clear LuCI cache
rm -rf /tmp/luci-modulecache /tmp/luci-indexcache 2>/dev/null
echo "luci-app-mitmproxy installed successfully"
"""
    builder.set_script("post-install", post_install_script)

    # ── Build the APK v3 package ─────────────────────────────────────────

    apk_data = builder.build()

    apk_name = f"{PKG_NAME}_{version_str}_noarch.apk"
    apk_path = output_dir / apk_name
    apk_path.write_bytes(apk_data)

    size_kb = len(apk_data) / 1024
    print(f"Built: {apk_path} ({size_kb:.1f} KB)")
    print(f"\nInstall on OpenWrt:")
    print(f"  scp {apk_name} root@<router-ip>:/tmp/")
    print(f"  ssh root@<router-ip> 'apk add --allow-untrusted /tmp/{apk_name}'")
    print(f"  # Then visit http://<router-ip>/cgi-bin/luci/admin/services/mitmproxy")
    return apk_path


if __name__ == "__main__":
    build_luci_apk()
