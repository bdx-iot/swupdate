#!/usr/bin/env python3
#
# Copyright (C) 2026 Joris Offouga <offougajoris@gmail.com>
#
# SPDX-License-Identifier:     GPL-2.0-only

"""
MCUmgr microcontroller emulator

Emulates a microcontroller running Zephyr and MCUboot on a pseudo
terminal, to test the SWUpdate "mcumgr" handler without hardware:

- SMP serial transport (Zephyr MCUmgr UART transport framing)
- image group: state read / write, upload, erase
- OS group: reset
- MCUboot (swap mode): test, confirm and revert at the next reset, plus
  the boot log printed on the UART

The image hash is the SHA-256 of the uploaded file (MCUboot reports the
hash of its TLV, the handler only compares the values it gets).

Example:

    ./mcumgr_emulator.py --link /tmp/ttyMCU &
    # sw-description: device = "/dev/ttyMCU" ... type = "mcumgr"
    swupdate -v -i update.swu
"""

import argparse
import base64
import hashlib
import logging
import os
import pty
import struct
import sys
import threading
import time
import tty

# SMP
OP_READ, OP_READ_RSP, OP_WRITE, OP_WRITE_RSP = 0, 1, 2, 3
GRP_OS, GRP_IMG = 0, 1
ID_OS_RESET = 5
ID_IMG_STATE, ID_IMG_UPLOAD, ID_IMG_ERASE = 0, 1, 5
# MGMT_ERR_*
ERR_EINVAL, ERR_ENOENT, ERR_EBADSTATE, ERR_ENOTSUP = 3, 5, 6, 8

FRAME_B64 = 124  # 127 bytes per frame: marker + base64 + '\n'


# ---------------------------------------------------------------- CBOR

def _head(major, val):
    if val < 24:
        return bytes([major << 5 | val])
    for ai, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if val < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | ai]) + struct.pack(fmt, val)
    raise ValueError(val)


def cbor_dumps(obj):
    """Encode, with indefinite length arrays as zcbor does."""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        return _head(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        data = obj.encode()
        return _head(3, len(data)) + data
    if isinstance(obj, list):
        return b"\x9f" + b"".join(cbor_dumps(x) for x in obj) + b"\xff"
    if isinstance(obj, dict):
        return _head(5, len(obj)) + b"".join(
            cbor_dumps(k) + cbor_dumps(v) for k, v in obj.items())
    raise TypeError(type(obj))


def cbor_loads(data, i=0):
    """Decode one item, return (item, next index)."""
    major, ai = data[i] >> 5, data[i] & 0x1F
    i += 1
    if ai < 24:
        val = ai
    elif ai <= 27:
        n = 1 << (ai - 24)
        val = int.from_bytes(data[i:i + n], "big")
        i += n
    elif ai == 31:
        val = None
    else:
        raise ValueError("invalid CBOR")
    if major == 0:
        return val, i
    if major == 1:
        return -1 - val, i
    if major in (2, 3):
        raw = bytes(data[i:i + val])
        return (raw if major == 2 else raw.decode()), i + val
    if major in (4, 5):
        out = [] if major == 4 else {}
        count = 0
        while (val is None and data[i] != 0xFF) or \
              (val is not None and count < val):
            if major == 4:
                item, i = cbor_loads(data, i)
                out.append(item)
            else:
                key, i = cbor_loads(data, i)
                out[key], i = cbor_loads(data, i)
            count += 1
        return out, (i + 1 if val is None else i)
    if major == 7 and ai in (20, 21, 22):
        return {20: False, 21: True, 22: None}[ai], i
    raise ValueError("unsupported CBOR")


def crc16(data):
    """CRC-16/XMODEM"""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


# ---------------------------------------------------------------- MCU

class Image:
    def __init__(self, data, confirmed=False):
        self.data = bytes(data)
        self.confirmed = confirmed

    @property
    def hash(self):
        return hashlib.sha256(self.data).digest()


class Emulator:
    def __init__(self, fd, args):
        self.fd = fd
        self.args = args
        self.slot0 = Image(b"initial image", confirmed=True)
        self.slot1 = None
        self.pending = False
        self.upload = bytearray()
        self.upload_len = 0
        self.offline = False
        self.answers = 0
        self.lock = threading.Lock()

    # --- transport ---
    def write(self, data):
        os.write(self.fd, data)

    def log_line(self, text):
        self.write(text.encode() + b"\r\n")

    def send(self, smp):
        self.answers += 1
        if self.args.drop_every and self.answers % self.args.drop_every == 0:
            logging.info("answer %d dropped", self.answers)
            return
        crc = crc16(smp)
        if self.args.corrupt_every and \
           self.answers % self.args.corrupt_every == 0:
            logging.info("answer %d corrupted", self.answers)
            crc ^= 0xFFFF
        raw = struct.pack(">H", len(smp) + 2) + smp + struct.pack(">H", crc)
        b64 = base64.b64encode(raw)
        out = bytearray()
        for pos in range(0, len(b64), FRAME_B64):
            out += b"\x06\x09" if pos == 0 else b"\x04\x14"
            out += b64[pos:pos + FRAME_B64] + b"\n"
        self.write(bytes(out))

    # --- image group ---
    def images(self):
        imgs = [{"image": 0, "slot": 0, "version": "0.0.0",
                 "hash": self.slot0.hash, "bootable": True,
                 "pending": False, "confirmed": self.slot0.confirmed,
                 "active": True, "permanent": False}]
        if self.slot1 is not None:
            imgs.append({"image": 0, "slot": 1, "version": "0.0.0",
                         "hash": self.slot1.hash, "bootable": True,
                         "pending": self.pending, "confirmed": False,
                         "active": False, "permanent": False})
        return {"images": imgs}

    def img_state_write(self, req):
        h = req.get("hash")
        if req.get("confirm"):
            if h not in (None, self.slot0.hash):
                return {"rc": ERR_EINVAL}
            self.slot0.confirmed = True
            logging.info("primary slot confirmed by the host")
        elif self.slot1 is not None and h == self.slot1.hash:
            self.pending = True
            logging.info("secondary slot marked for test")
        else:
            return {"rc": ERR_ENOENT}
        return self.images()

    def img_upload(self, req):
        off = req["off"]
        if off == 0:
            self.upload = bytearray()
            self.upload_len = req["len"]
            self.slot1 = None
            self.pending = False
            time.sleep(self.args.erase_time)
        if off != len(self.upload):
            # as Zephyr: success and the expected offset
            return {"rc": 0, "off": len(self.upload)}
        self.upload += req["data"]
        if len(self.upload) == self.upload_len:
            self.slot1 = Image(self.upload)
            logging.info("upload complete, %d bytes", self.upload_len)
        return {"rc": 0, "off": len(self.upload)}

    def img_erase(self, req):
        if req.get("slot", 1) != 1:
            return {"rc": ERR_EINVAL}
        if self.pending and not self.args.allow_erase_pending:
            logging.info("erase of the pending slot refused")
            return {"rc": ERR_EBADSTATE}
        self.slot1 = None
        self.pending = False
        logging.info("secondary slot erased")
        return {"rc": 0}

    # --- OS group / MCUboot ---
    def reboot(self):
        # CONFIG_MCUMGR_GRP_OS_RESET_MS: the old image still answers
        time.sleep(self.args.reset_delay)
        with self.lock:
            self.offline = True
        logging.info("reset")
        time.sleep(0.3)
        self.log_line("*** Booting MCUboot ***")
        if self.pending and self.slot1 is not None:
            if self.args.mode == "reject":
                self.log_line("E: Image in the secondary slot is not valid!")
                self.slot1 = None
            else:
                self.log_line("I: Starting swap using move algorithm.")
                time.sleep(self.args.swap_time)
                self.slot0, self.slot1 = Image(self.slot1.data), self.slot0
                self.slot1.confirmed = False
        elif not self.slot0.confirmed and self.slot1 is not None:
            self.log_line("I: Image not confirmed, reverting.")
            time.sleep(self.args.swap_time)
            self.slot0, self.slot1 = self.slot1, self.slot0
            self.slot0.confirmed = True
        self.pending = False
        self.log_line("I: Jumping to the first image slot")
        logging.info("running %s (%s)", self.slot0.hash.hex()[:16],
                     "confirmed" if self.slot0.confirmed else "test")
        with self.lock:
            self.offline = False
        if not self.slot0.confirmed:
            time.sleep(1)
            if self.args.mode == "good":
                self.slot0.confirmed = True
                logging.info("application confirmed the image")
            else:
                logging.info("application does not confirm the image")

    # --- dispatcher ---
    def handle(self, smp):
        op, _flags, length, grp, seq, cid = struct.unpack(">BBHHBB", smp[:8])
        op &= 0x07
        req = cbor_loads(smp, 8)[0] if length else {}

        if grp == GRP_IMG and cid == ID_IMG_STATE and op == OP_READ:
            rsp = self.images()
        elif grp == GRP_IMG and cid == ID_IMG_STATE and op == OP_WRITE:
            rsp = self.img_state_write(req)
        elif grp == GRP_IMG and cid == ID_IMG_UPLOAD and op == OP_WRITE:
            rsp = self.img_upload(req)
        elif grp == GRP_IMG and cid == ID_IMG_ERASE and op == OP_WRITE:
            rsp = self.img_erase(req)
        elif grp == GRP_OS and cid == ID_OS_RESET and op == OP_WRITE:
            rsp = {}
            threading.Thread(target=self.reboot, daemon=True).start()
        else:
            rsp = {"rc": ERR_ENOTSUP}

        body = cbor_dumps(rsp)
        self.send(struct.pack(">BBHHBB", op + 1, 0, len(body), grp, seq,
                              cid) + body)

    def run(self):
        line = bytearray()
        pkt = bytearray()
        held = b""
        while True:
            try:
                data = held + os.read(self.fd, 4096)
            except OSError:
                # no client connected to the pseudo terminal
                time.sleep(0.1)
                continue
            if self.args.hold_tail:
                # as some USB-serial bridges: the last byte of a write is
                # delivered only with the next one, even in a new session
                data, held = data[:-1], data[-1:]
            for byte in data:
                if byte != 0x0A:
                    line.append(byte)
                    continue
                frame, line = bytes(line), bytearray()
                with self.lock:
                    if self.offline:
                        continue
                if frame[:2] == b"\x06\x09":
                    pkt = bytearray(base64.b64decode(frame[2:]))
                elif frame[:2] == b"\x04\x14" and pkt:
                    pkt += base64.b64decode(frame[2:])
                else:
                    continue
                size = struct.unpack(">H", pkt[:2])[0]
                if len(pkt) < size + 2:
                    continue
                if crc16(bytes(pkt[2:size + 2])) != 0:
                    logging.warning("request with bad CRC")
                else:
                    self.handle(bytes(pkt[2:size]))
                pkt = bytearray()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--link", default="/tmp/ttyMCU",
                        help="symlink to the pseudo terminal (default: %(default)s)")
    parser.add_argument("--mode", choices=("good", "bad", "reject"),
                        default="good",
                        help="good: the new image confirms itself; "
                             "bad: it never confirms; "
                             "reject: MCUboot refuses it")
    parser.add_argument("--reset-delay", type=float, default=0.25,
                        help="seconds before the reset, the old image "
                             "still answers (default: %(default)s)")
    parser.add_argument("--swap-time", type=float, default=3,
                        help="seconds needed by MCUboot to swap")
    parser.add_argument("--erase-time", type=float, default=0.5,
                        help="seconds needed to erase the secondary slot")
    parser.add_argument("--drop-every", type=int, default=0, metavar="N",
                        help="drop every Nth answer (lost frame)")
    parser.add_argument("--corrupt-every", type=int, default=0, metavar="N",
                        help="send every Nth answer with a bad CRC")
    parser.add_argument("--hold-tail", action="store_true",
                        help="hold the last byte written by the host until "
                             "the next write, as OpenSDA / DAPLink bridges")
    parser.add_argument("--allow-erase-pending", action="store_true",
                        help="as CONFIG_MCUMGR_GRP_IMG_ALLOW_ERASE_PENDING")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="[mcu] %(message)s")

    master, slave = pty.openpty()
    tty.setraw(master)
    if os.path.lexists(args.link):
        os.unlink(args.link)
    os.symlink(os.ttyname(slave), args.link)
    # keep only the master side: the slave is opened by SWUpdate
    os.close(slave)
    logging.info("emulator (%s) on %s", args.mode, args.link)
    try:
        Emulator(master, args).run()
    except KeyboardInterrupt:
        pass
    finally:
        os.unlink(args.link)
    return 0


if __name__ == "__main__":
    sys.exit(main())
