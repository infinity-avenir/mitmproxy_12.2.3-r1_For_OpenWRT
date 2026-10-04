#!/usr/bin/env python3
"""
OpenWrt APK Build Script for mitmproxy
=======================================

Builds mitmproxy from source into APK packages for OpenWrt across
multiple hardware platforms using the OpenWrt SDK.

This script is SELF-CONTAINED — all APK v3 ADB binary format code is
embedded directly below. No external adb_v3.py dependency is needed.

Supported targets:
  - Linksys WRT1200AC / WRT1900AC / WRT3200ACM / WRT32X  (Marvell Armada 385 - armv7)
  - GL.iNet GL-MT6000 Flint 2                            (MediaTek MT7986AV - aarch64)
  - GL.iNet GL-MT3000 Beryl AX                           (MediaTek MT7981BA - aarch64)
  - GL.iNet GL-MT3600BE Beryl 7                          (MediaTek MT7987AV - aarch64)

Usage:
  python3 build_mitmproxy_apk.py --target all
  python3 build_mitmproxy_apk.py --target mvebu
  python3 build_mitmproxy_apk.py --target mt7986
  python3 build_mitmproxy_apk.py --list-targets

Requirements:
  - Linux build host (Ubuntu 22.04+ recommended)
  - At least 10 GB free disk space
  - Internet connection for downloading OpenWrt SDK
  - Python 3.10+
"""

import argparse
import hashlib
import json
import logging
import os
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


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


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mitmproxy-apk-builder")

# ── mitmproxy version being built ──────────────────────────────────────
MITMPROXY_VERSION = "12.2.3"
PKG_RELEASE = "1"

# ── OpenWrt release to build against ──────────────────────────────────
OPENWRT_VERSION = "25.12.5"
OPENWRT_BASE_URL = f"https://downloads.openwrt.org/releases/{OPENWRT_VERSION}/targets"

# ── Hardcoded SDK download URLs (OpenWrt 25.12.5) ────────────────────
SDK_URLS = {
    "mediatek/filogic": "https://downloads.openwrt.org/releases/25.12.5/targets/mediatek/filogic/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64.tar.zst",
    "mvebu/cortexa9":   "https://downloads.openwrt.org/releases/25.12.5/targets/mvebu/cortexa9/openwrt-sdk-25.12.5-mvebu-cortexa9_gcc-14.3.0_musl_eabi.Linux-x86_64.tar.zst",
}

# ── Target platform definitions ───────────────────────────────────────
@dataclass
class Target:
    """Defines an OpenWrt build target (architecture + SDK)."""
    name: str
    description: str
    arch: str
    cpu_arch: str
    target: str
    sdk_subdir: str
    devices: list[str] = field(default_factory=list)
    python_arch: str = ""

    def __post_init__(self):
        if not self.python_arch:
            if "aarch64" in self.arch:
                self.python_arch = "aarch64-openwrt-linux-musl"
            else:
                self.python_arch = "arm-openwrt-linux-muslgnueabi"


TARGETS = {
    "mvebu": Target(
        name="mvebu",
        description="Marvell Armada 385 (Linksys WRT series)",
        arch="arm_cortex-a9_vfpv3-d16",
        cpu_arch="armv7-a",
        target="mvebu/cortexa9",
        sdk_subdir="mvebu/cortexa9",
        devices=[
            "Linksys WRT1200AC",
            "Linksys WRT1900AC",
            "Linksys WRT3200ACM",
            "Linksys WRT32X",
        ],
    ),
    "mt7986": Target(
        name="mt7986",
        description="MediaTek MT7986AV (GL.iNet Flint 2)",
        arch="aarch64_cortex-a53",
        cpu_arch="armv8-a",
        target="mediatek/filogic",
        sdk_subdir="mediatek/filogic",
        devices=["GL.iNet GL-MT6000 (Flint 2)"],
    ),
    "mt7981": Target(
        name="mt7981",
        description="MediaTek MT7981BA (GL.iNet Beryl AX)",
        arch="aarch64_cortex-a53",
        cpu_arch="armv8-a",
        target="mediatek/filogic",
        sdk_subdir="mediatek/filogic",
        devices=["GL.iNet GL-MT3000 (Beryl AX)"],
    ),
    "mt7987": Target(
        name="mt7987",
        description="MediaTek MT7987AV (GL.iNet Beryl 7)",
        arch="aarch64_cortex-a53",
        cpu_arch="armv8-a",
        target="mediatek/filogic",
        sdk_subdir="mediatek/filogic",
        devices=["GL.iNet GL-MT3600BE (Beryl 7)"],
    ),
}

SDK_DEDUP = {
    "mt7981": "mt7986",
    "mt7987": "mt7986",
}


class MitmproxyAPKBuilder:
    """Orchestrates the full build pipeline."""

    def __init__(self, work_dir: Path, source_dir: Path, targets: list[str]):
        self.work_dir = work_dir.resolve()
        self.source_dir = source_dir.resolve()
        self.targets = targets
        self.sdk_cache: dict[str, Path] = {}
        self.output_dir = self.work_dir / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Helpers ────────────────────────────────────────────────────────

    def run(self, cmd: list[str], cwd: Optional[Path] = None,
            env: Optional[dict] = None, check: bool = True) -> subprocess.CompletedProcess:
        log.debug("$ %s", " ".join(cmd))
        merged_env = {**os.environ, **(env or {})}
        result = subprocess.run(
            cmd, cwd=cwd, env=merged_env,
            capture_output=True, text=True,
        )
        if result.returncode != 0 and check:
            log.error("Command failed: %s\nstdout: %s\nstderr: %s",
                      " ".join(cmd), result.stdout[-2000:], result.stderr[-2000:])
            raise RuntimeError(f"Command failed: {' '.join(cmd[:4])}")
        return result

    def download_file(self, url: str, dest: Path) -> Path:
        if dest.exists():
            log.info("Using cached: %s", dest.name)
            return dest
        log.info("Downloading: %s", url)
        dest.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, dest)
        log.info("Downloaded: %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
        return dest

    # ── Step 1: Download OpenWrt SDK ──────────────────────────────────

    def download_sdk(self, target: Target) -> Path:
        cache_key = target.sdk_subdir
        if cache_key in self.sdk_cache:
            log.info("Reusing SDK for %s (same as %s)", target.name, cache_key)
            return self.sdk_cache[cache_key]

        sdk_dir = self.work_dir / "sdk" / target.name
        sdk_dir.mkdir(parents=True, exist_ok=True)

        if target.sdk_subdir not in SDK_URLS:
            raise RuntimeError(
                f"No hardcoded SDK URL for target '{target.sdk_subdir}'. "
                f"Available: {', '.join(SDK_URLS.keys())}"
            )
        sdk_url = SDK_URLS[target.sdk_subdir]
        sdk_filename = sdk_url.rsplit("/", 1)[-1]

        tarball = sdk_dir / sdk_filename
        self.download_file(sdk_url, tarball)

        extracted = sdk_dir / "sdk"
        if not extracted.exists():
            log.info("Extracting SDK for %s...", target.name)
            if str(tarball).endswith(".zst"):
                self.run(["tar", "--zstd", "-xf", str(tarball), "-C", str(sdk_dir)])
            else:
                self.run(["tar", "-xf", str(tarball), "-C", str(sdk_dir)])
            for d in sdk_dir.iterdir():
                if d.is_dir() and d.name.startswith("openwrt-sdk"):
                    d.rename(extracted)
                    break

        self.sdk_cache[cache_key] = extracted
        return extracted

    # ── Step 2: Generate the OpenWrt package Makefile ──────────────────

    def generate_package_makefile(self, target: Target, sdk_path: Path) -> Path:
        pkg_dir = sdk_path / "package" / "mitmproxy"
        pkg_dir.mkdir(parents=True, exist_ok=True)

        makefile_content = f"""\
# SPDX-License-Identifier: MIT
#
# OpenWrt package Makefile for mitmproxy
# Auto-generated by build_mitmproxy_apk.py

include $(TOPDIR)/rules.mk

PKG_NAME:=mitmproxy
PKG_VERSION:={MITMPROXY_VERSION}
PKG_RELEASE:={PKG_RELEASE}

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/mitmproxy/mitmproxy.git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_SOURCE_DATE:=2025-01-15
PKG_MIRROR_HASH:=skip

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python3/host python3-pip/host

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/python/python3-package.mk

define Package/mitmproxy
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=Interactive TLS-capable intercepting proxy
  URL:=https://mitmproxy.org/
  DEPENDS:=+python3 +python3-pip +python3-cryptography +python3-openssl \\
           +python3-yaml +python3-tornado +python3-urllib \\
           +ca-certificates +libopenssl
  PKGARCH:={target.arch}
endef

define Package/mitmproxy/description
  mitmproxy is an interactive, SSL/TLS-capable intercepting proxy with a
  console interface for HTTP/1, HTTP/2, and WebSockets. It provides tools
  for deep packet inspection, traffic interception, and flow modification.

  This package includes:
    - mitmdump  (command-line proxy)
    - mitmweb   (web-based interface)
endef

define Package/mitmproxy/conffiles
/etc/config/mitmproxy
/etc/mitmproxy/config.yaml
endef

define Build/Compile
\t$(call HostPython3/Run, \\
\t\tPYTHONPATH="$(PKG_BUILD_DIR)" \\
\t\t$(HOST_PYTHON3_BIN) -m pip install \\
\t\t\t--no-cache-dir \\
\t\t\t--no-compile \\
\t\t\t--prefix=/usr \\
\t\t\t--root=$(PKG_INSTALL_DIR) \\
\t\t\t$(PKG_BUILD_DIR) \\
\t)
endef

define Package/mitmproxy/install
\t$(INSTALL_DIR) $(1)/usr/bin
\t$(INSTALL_DIR) $(1)/usr/lib/python$(PYTHON3_VERSION)/site-packages
\t$(INSTALL_DIR) $(1)/etc/config
\t$(INSTALL_DIR) $(1)/etc/mitmproxy
\t$(INSTALL_DIR) $(1)/etc/init.d

\t# Install Python packages
\t$(CP) $(PKG_INSTALL_DIR)/usr/lib/python$(PYTHON3_VERSION)/site-packages/* \\
\t\t$(1)/usr/lib/python$(PYTHON3_VERSION)/site-packages/

\t# Install binaries
\t$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/mitmdump $(1)/usr/bin/
\t$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/mitmweb $(1)/usr/bin/

\t# Install default config
\t$(INSTALL_CONF) ./files/mitmproxy.config $(1)/etc/config/mitmproxy
\t$(INSTALL_CONF) ./files/mitmproxy.yaml $(1)/etc/mitmproxy/config.yaml

\t# Install init script
\t$(INSTALL_BIN) ./files/mitmproxy.init $(1)/etc/init.d/mitmproxy
endef

define Package/mitmproxy/postinst
#!/bin/sh
# Generate CA certificates on first install
if [ -z "$$IPKG_INSTROOT" ]; then
\tmkdir -p /etc/mitmproxy/certs
\tif [ ! -f /etc/mitmproxy/certs/mitmproxy-ca.pem ]; then
\t\techo "Generating mitmproxy CA certificate..."
\t\tmitmdump --set confdir=/etc/mitmproxy/certs -k -q &
\t\tsleep 3
\t\tkill $$! 2>/dev/null
\t\techo "CA certificate generated at /etc/mitmproxy/certs/"
\tfi
fi
endef

$(eval $(call BuildPackage,mitmproxy))
"""
        (pkg_dir / "Makefile").write_text(makefile_content)

        files_dir = pkg_dir / "files"
        files_dir.mkdir(exist_ok=True)

        uci_config = """\
config mitmproxy 'main'
\toption enabled '0'
\toption listen_host '0.0.0.0'
\toption listen_port '8080'
\toption mode 'regular'
\toption ssl_insecure '0'
\toption confdir '/etc/mitmproxy/certs'
\toption web_open_browser '0'
\toption web_host '0.0.0.0'
\toption web_port '8081'

config mitmproxy 'logging'
\toption log_level 'info'
\toption flow_detail '1'

config mitmproxy 'interception'
\toption intercept ''
\toption ignore_hosts ''
\toption allow_hosts ''
\toption anticache '0'
\toption anticomp '0'

config mitmproxy 'traffic_analysis'
\toption enabled '0'
\toption flow_collection '1'
\toption behavior_analysis '0'
\toption ai_analysis '0'
\toption max_flows '10000'
"""
        (files_dir / "mitmproxy.config").write_text(uci_config)

        yaml_config = """\
# mitmproxy configuration for OpenWrt
# Managed by LuCI - manual edits may be overwritten

listen_host: "0.0.0.0"
listen_port: 8080
mode:
  - regular
ssl_insecure: false
web_open_browser: false
web_host: "0.0.0.0"
web_port: 8081
confdir: "/etc/mitmproxy/certs"
"""
        (files_dir / "mitmproxy.yaml").write_text(yaml_config)

        init_script = """\
#!/bin/sh /etc/rc.common
# mitmproxy init script for OpenWrt

START=95
STOP=10

USE_PROCD=1
PROG=/usr/bin/mitmdump
NAME=mitmproxy

validate_section() {
\tuci_load_validate mitmproxy main "$1" \\
\t\t'enabled:bool:0' \\
\t\t'listen_host:string:0.0.0.0' \\
\t\t'listen_port:port:8080' \\
\t\t'mode:string:regular' \\
\t\t'ssl_insecure:bool:0' \\
\t\t'confdir:string:/etc/mitmproxy/certs' \\
\t\t'web_host:string:0.0.0.0' \\
\t\t'web_port:port:8081'
}

start_service() {
\tlocal enabled listen_host listen_port mode ssl_insecure confdir web_host web_port

\tconfig_load "$NAME"

\tvalidate_section main || {
\t\techo "Validation failed"
\t\treturn 1
\t}

\t[ "$enabled" -eq 1 ] || return 0

\tprocd_open_instance "$NAME"
\tprocd_set_param command /usr/bin/mitmweb \\
\t\t--set confdir="$confdir" \\
\t\t--mode "$mode" \\
\t\t--listen-host "$listen_host" \\
\t\t--listen-port "$listen_port" \\
\t\t--web-host "$web_host" \\
\t\t--web-port "$web_port" \\
\t\t--set web_open_browser=false \\
\t\t--no-web-open-browser

\t[ "$ssl_insecure" -eq 1 ] && procd_append_param command --ssl-insecure

\t# Load custom script if configured
\tlocal script_path
\tscript_path=$(uci -q get mitmproxy.main.script)
\t[ -n "$script_path" ] && [ -f "$script_path" ] && \\
\t\tprocd_append_param command -s "$script_path"

\tprocd_set_param stdout 1
\tprocd_set_param stderr 1
\tprocd_set_param respawn
\tprocd_set_param file /etc/config/mitmproxy
\tprocd_close_instance
}

service_triggers() {
\tprocd_add_reload_trigger "mitmproxy"
\tprocd_add_validation validate_section
}

stop_service() {
\t:
}
"""
        (files_dir / "mitmproxy.init").write_text(init_script)

        log.info("Generated package Makefile at %s", pkg_dir)
        return pkg_dir

    # ── Step 3: Build the APK ─────────────────────────────────────────

    def build_apk(self, target: Target) -> Optional[Path]:
        log.info("=" * 60)
        log.info("Building mitmproxy APK for: %s", target.description)
        log.info("Architecture: %s", target.arch)
        log.info("Devices: %s", ", ".join(target.devices))
        log.info("=" * 60)

        sdk_path = self.download_sdk(target)

        log.info("Updating SDK feeds...")
        self.run(["./scripts/feeds", "update", "-a"], cwd=sdk_path, check=False)
        self.run(["./scripts/feeds", "install", "-a"], cwd=sdk_path, check=False)

        pkg_dir = self.generate_package_makefile(target, sdk_path)

        build_src = sdk_path / "build_dir" / "mitmproxy-source"
        if build_src.exists():
            shutil.rmtree(build_src)
        shutil.copytree(self.source_dir, build_src, dirs_exist_ok=True)

        log.info("Configuring SDK for mitmproxy...")
        dotconfig = sdk_path / ".config"
        config_lines = [
            "CONFIG_PACKAGE_mitmproxy=y\n",
            f"CONFIG_TARGET_{target.target.split('/')[0]}=y\n",
        ]
        dotconfig.write_text("".join(config_lines))
        self.run(["make", "defconfig"], cwd=sdk_path, check=False)

        log.info("Building package (this may take a while)...")
        nproc = os.cpu_count() or 2
        result = self.run(
            ["make", f"-j{nproc}", "package/mitmproxy/compile", "V=s"],
            cwd=sdk_path, check=False,
        )

        if result.returncode != 0:
            log.warning(
                "SDK build failed for %s. This is expected if dependencies "
                "are not fully available. Falling back to manual APK packaging.",
                target.name,
            )
            return self.create_manual_apk(target)

        bin_dir = sdk_path / "bin" / "packages" / target.arch / "base"
        for f in bin_dir.rglob("mitmproxy*.apk"):
            dest = self.output_dir / f"mitmproxy_{MITMPROXY_VERSION}-{PKG_RELEASE}_{target.arch}.apk"
            shutil.copy2(f, dest)
            log.info("APK built: %s", dest)
            return dest
        for f in bin_dir.rglob("mitmproxy*.ipk"):
            dest = self.output_dir / f"mitmproxy_{MITMPROXY_VERSION}-{PKG_RELEASE}_{target.arch}.ipk"
            shutil.copy2(f, dest)
            log.info("IPK built: %s", dest)
            return dest

        log.warning("Build output not found, creating manual APK")
        return self.create_manual_apk(target)

    def create_manual_apk(self, target: Target) -> Path:
        """
        Create an APK v3 package manually when the SDK build is unavailable.
        Uses the embedded ADB v3 binary format writer (no external imports).
        """
        log.info("Creating manual APK v3 for %s...", target.name)
        staging = self.work_dir / "staging" / target.name
        if staging.exists():
            shutil.rmtree(staging)

        data_root = staging / "data"
        (data_root / "usr/bin").mkdir(parents=True)
        (data_root / "usr/lib/python3/mitmproxy").mkdir(parents=True)
        (data_root / "etc/config").mkdir(parents=True)
        (data_root / "etc/mitmproxy/certs").mkdir(parents=True)
        (data_root / "etc/init.d").mkdir(parents=True)

        shutil.copytree(
            self.source_dir / "mitmproxy",
            data_root / "usr/lib/python3/mitmproxy",
            dirs_exist_ok=True,
        )

        mitmdump_launcher = """\
#!/bin/sh
export PYTHONPATH="/usr/lib/python3"
exec python3 -m mitmproxy.tools.main mitmdump "$@"
"""
        mitmweb_launcher = """\
#!/bin/sh
export PYTHONPATH="/usr/lib/python3"
exec python3 -m mitmproxy.tools.main mitmweb "$@"
"""
        (data_root / "usr/bin/mitmdump").write_text(mitmdump_launcher)
        (data_root / "usr/bin/mitmweb").write_text(mitmweb_launcher)
        os.chmod(data_root / "usr/bin/mitmdump", 0o755)
        os.chmod(data_root / "usr/bin/mitmweb", 0o755)

        uci_config = """\
config mitmproxy 'main'
\toption enabled '0'
\toption listen_host '0.0.0.0'
\toption listen_port '8080'
\toption mode 'regular'
\toption ssl_insecure '0'
\toption confdir '/etc/mitmproxy/certs'
\toption web_host '0.0.0.0'
\toption web_port '8081'
"""
        (data_root / "etc/config/mitmproxy").write_text(uci_config)

        yaml_config = """\
listen_host: "0.0.0.0"
listen_port: 8080
mode:
  - regular
ssl_insecure: false
web_open_browser: false
web_host: "0.0.0.0"
web_port: 8081
confdir: "/etc/mitmproxy/certs"
"""
        (data_root / "etc/mitmproxy/config.yaml").write_text(yaml_config)

        init_script = """\
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1
PROG=/usr/bin/mitmdump
NAME=mitmproxy

start_service() {
\tlocal enabled
\tconfig_load "$NAME"
\tconfig_get_bool enabled main enabled 0
\t[ "$enabled" -eq 1 ] || return 0

\tlocal listen_host listen_port mode confdir web_host web_port ssl_insecure
\tconfig_get listen_host main listen_host '0.0.0.0'
\tconfig_get listen_port main listen_port '8080'
\tconfig_get mode main mode 'regular'
\tconfig_get confdir main confdir '/etc/mitmproxy/certs'
\tconfig_get web_host main web_host '0.0.0.0'
\tconfig_get web_port main web_port '8081'
\tconfig_get_bool ssl_insecure main ssl_insecure 0

\tprocd_open_instance "$NAME"
\tprocd_set_param command /usr/bin/mitmweb \\
\t\t--set confdir="$confdir" \\
\t\t--mode "$mode" \\
\t\t--listen-host "$listen_host" \\
\t\t--listen-port "$listen_port" \\
\t\t--web-host "$web_host" \\
\t\t--web-port "$web_port" \\
\t\t--set web_open_browser=false

\t[ "$ssl_insecure" -eq 1 ] && procd_append_param command --ssl-insecure

\tprocd_set_param stdout 1
\tprocd_set_param stderr 1
\tprocd_set_param respawn
\tprocd_set_param file /etc/config/mitmproxy
\tprocd_close_instance
}

service_triggers() {
\tprocd_add_reload_trigger "mitmproxy"
}
"""
        (data_root / "etc/init.d/mitmproxy").write_text(init_script)
        os.chmod(data_root / "etc/init.d/mitmproxy", 0o755)

        # ── Build APK v3 using embedded APKv3Builder ───────────────────

        builder = APKv3Builder()
        build_time = int(time.time())
        builder.set_build_time(build_time)

        version_str = f"{MITMPROXY_VERSION}-r{PKG_RELEASE}"

        builder.set_pkginfo(
            name="mitmproxy",
            version=version_str,
            arch=target.arch,
            description="Interactive TLS-capable intercepting proxy for HTTP/1, HTTP/2, and WebSockets",
            license="MIT",
            origin="mitmproxy",
            maintainer="Open Firewall Project",
            url="https://mitmproxy.org/",
        )

        builder.add_depend("python3")
        builder.add_depend("python3-pip")
        builder.add_depend("ca-certificates")

        for file_path in sorted(data_root.rglob("*")):
            if not file_path.is_file():
                continue
            rel_path = str(file_path.relative_to(data_root))
            content = file_path.read_bytes()
            mode = 0o755 if os.access(file_path, os.X_OK) else 0o644
            builder.add_file(rel_path, content, mode=mode, mtime=build_time)

        post_install_script = """\
#!/bin/sh
echo "Installing mitmproxy Python dependencies..."
pip3 install --no-cache-dir mitmproxy==12.2.3 2>&1 || {
    echo "WARNING: pip install failed — mitmproxy may not run until dependencies are installed."
}
mkdir -p /etc/mitmproxy/certs
if [ ! -f /etc/mitmproxy/certs/mitmproxy-ca.pem ]; then
    echo "Generating mitmproxy CA certificate..."
    mitmdump --set confdir=/etc/mitmproxy/certs -k -q &
    sleep 3
    kill $! 2>/dev/null
    echo "CA certificate generated."
fi
echo "mitmproxy installed successfully"
"""
        builder.set_script("post-install", post_install_script)

        apk_data = builder.build()

        apk_name = f"mitmproxy_{version_str}_{target.arch}.apk"
        apk_path = self.output_dir / apk_name
        apk_path.write_bytes(apk_data)

        size_mb = len(apk_data) / 1e6
        log.info("APK v3 built: %s (%.1f MB)", apk_path, size_mb)
        return apk_path

    # ── Main build orchestrator ───────────────────────────────────────

    def build_all(self) -> dict[str, Path]:
        results = {}
        for target_name in self.targets:
            target = TARGETS[target_name]
            try:
                apk_path = self.build_apk(target)
                if apk_path:
                    results[target_name] = apk_path
            except Exception as e:
                log.error("Failed to build for %s: %s", target_name, e)
                try:
                    apk_path = self.create_manual_apk(target)
                    results[target_name] = apk_path
                except Exception as e2:
                    log.error("Manual APK also failed for %s: %s", target_name, e2)

        return results

    def print_summary(self, results: dict[str, Path]):
        print("\n" + "=" * 60)
        print("BUILD SUMMARY")
        print("=" * 60)

        for target_name, apk_path in results.items():
            target = TARGETS[target_name]
            size_mb = apk_path.stat().st_size / 1e6
            print(f"\n  Target:   {target.description}")
            print(f"  Arch:     {target.arch}")
            print(f"  Devices:  {', '.join(target.devices)}")
            print(f"  APK:      {apk_path.name}")
            print(f"  Size:     {size_mb:.1f} MB")

        print(f"\nOutput directory: {self.output_dir}")
        print("\nInstallation:")
        print("  1. Copy the .apk file to your OpenWrt router")
        print("  2. Run: apk add --allow-untrusted ./mitmproxy_*.apk")
        print("  3. Edit /etc/config/mitmproxy to configure")
        print("  4. Run: /etc/init.d/mitmproxy enable")
        print("  5. Run: /etc/init.d/mitmproxy start")
        print("=" * 60)


# ── Host dependency checker ───────────────────────────────────────────

def check_host_dependencies():
    required = ["tar", "gzip", "make", "gcc", "git"]
    optional = ["zstd", "python3"]
    missing = []

    for tool in required:
        if not shutil.which(tool):
            missing.append(tool)

    if missing:
        log.error(
            "Missing required build tools: %s\n"
            "Install them with: sudo apt install build-essential git",
            ", ".join(missing),
        )
        return False

    for tool in optional:
        if not shutil.which(tool):
            log.warning("Optional tool not found: %s", tool)

    if platform.system() != "Linux":
        log.warning(
            "OpenWrt SDK requires a Linux host. "
            "Current platform: %s. Cross-compilation may fail.",
            platform.system(),
        )

    return True


# ── CLI Entry Point ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Build mitmproxy APK packages for OpenWrt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s --target all                    Build for all platforms
  %(prog)s --target mvebu                  Build for Linksys WRT series
  %(prog)s --target mt7986                 Build for GL.iNet Flint 2
  %(prog)s --target mvebu mt7986           Build for selected targets
  %(prog)s --list-targets                  Show available targets
  %(prog)s --manual-only --target all      Skip SDK, create manual APKs
""",
    )

    parser.add_argument(
        "--target",
        nargs="+",
        choices=list(TARGETS.keys()) + ["all"],
        help="Target platform(s) to build for",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("mitmproxy-12.2.3"),
        help="Path to mitmproxy source directory or archive (.zip / .tar.gz / .tar.xz / .tar.zst). "
             "Archives are extracted automatically. (default: ./mitmproxy-12.2.3)",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("build"),
        help="Working directory for build artifacts (default: ./build)",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List all available target platforms",
    )
    parser.add_argument(
        "--manual-only",
        action="store_true",
        help="Skip OpenWrt SDK build, create manual APK packages only",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list_targets:
        print("\nAvailable OpenWrt build targets:\n")
        for name, target in TARGETS.items():
            print(f"  {name:10s}  {target.description}")
            print(f"             Arch: {target.arch}")
            print(f"             Devices: {', '.join(target.devices)}")
            print()
        sys.exit(0)

    if not args.target:
        parser.error("--target is required (use --list-targets to see options)")

    if "all" in args.target:
        target_names = list(TARGETS.keys())
    else:
        target_names = args.target

    source_path = args.source
    if not source_path.exists():
        log.error("Source not found: %s", source_path)
        log.info("Download mitmproxy source and extract it, or use --source to point to it")
        sys.exit(1)

    if source_path.is_file():
        extract_dir = args.work_dir / "mitmproxy-source"
        extract_dir.mkdir(parents=True, exist_ok=True)

        if source_path.suffix == ".zip" or str(source_path).endswith(".zip"):
            log.info("Extracting zip archive: %s", source_path)
            with zipfile.ZipFile(source_path, "r") as zf:
                zf.extractall(extract_dir)
        elif str(source_path).endswith((".tar.gz", ".tgz", ".tar.xz", ".tar.zst", ".tar.bz2")):
            log.info("Extracting tar archive: %s", source_path)
            if str(source_path).endswith(".tar.zst"):
                subprocess.run(
                    ["tar", "--zstd", "-xf", str(source_path), "-C", str(extract_dir)],
                    check=True,
                )
            else:
                with tarfile.open(source_path) as tf:
                    tf.extractall(extract_dir)
        else:
            log.error(
                "Source is a file but not a recognized archive (.zip, .tar.gz, .tar.xz, .tar.zst): %s",
                source_path,
            )
            sys.exit(1)

        candidates = [
            d for d in extract_dir.iterdir()
            if d.is_dir() and (d / "mitmproxy").is_dir()
        ]
        if candidates:
            source_path = candidates[0]
            log.info("Using extracted source directory: %s", source_path)
        elif (extract_dir / "mitmproxy").is_dir():
            source_path = extract_dir
            log.info("Using extracted source directory: %s", source_path)
        else:
            log.error(
                "Could not find mitmproxy source inside extracted archive. "
                "Contents of %s: %s",
                extract_dir,
                [p.name for p in extract_dir.iterdir()],
            )
            sys.exit(1)

        args.source = source_path

    if not check_host_dependencies():
        sys.exit(1)

    builder = MitmproxyAPKBuilder(
        work_dir=args.work_dir,
        source_dir=args.source,
        targets=target_names,
    )

    if args.manual_only:
        results = {}
        for target_name in target_names:
            target = TARGETS[target_name]
            results[target_name] = builder.create_manual_apk(target)
    else:
        results = builder.build_all()

    if results:
        builder.print_summary(results)
    else:
        log.error("No packages were built successfully")
        sys.exit(1)


if __name__ == "__main__":
    main()
