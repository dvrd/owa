#!/usr/bin/env python3
"""Explicit live probe launcher and private, exact QR-matrix PNG renderer."""
import argparse
import binascii
import json
import os
import re
from pathlib import Path
import secrets
import stat
import struct
import subprocess
import sys
import threading
import zlib

QR_JSON_MAX = 256 * 1024
STATUS_LINE_MAX = 4096
PROBE_WALL_SECONDS_MAX = 615
QUIET_MODULES = 4
PIXELS_PER_MODULE = 8
PHASES = frozenset({"STORAGE_READY", "VERSION_DISCOVERY", "VERSION_DISCOVERED",
    "VERSION_PINNED", "CONNECTING", "PAIRED", "RECONNECTING", "ONLINE", "TARGET_READY",
    "TEXT_QUEUED", "PDF_QUEUED", "ACK_WAIT", "SERVER_ACKED", "ACK_PENDING", "COMPLETE",
    "PREVIEW_READY", "RESUME_UNKNOWN", "CONNECTED_HOLD",
    "WATCH_RECONNECTING", "WATCH_COMPLETE", "CANARY_PREPARED", "CANARY_TEXT_ACKED",
    "CANARY_PDF_ACKED", "CANARY_COMPLETE", "CANARY_UNKNOWN"})


class DisplayError(Exception):
    def __init__(self, code, details=None):
        super().__init__(code)
        self.details = details


ERROR_LINE = re.compile(rb"ERROR ([A-Za-z_][A-Za-z_0-9]{0,63}) STORAGE "
    rb"([A-Za-z_][A-Za-z_0-9]{0,63}) SOCKET ([A-Za-z_][A-Za-z_0-9]{0,63}) "
    rb"CERTIFICATE ([A-Za-z_][A-Za-z_0-9]{0,63})"
    rb"(?: SESSION ([A-Za-z_][A-Za-z_0-9]{0,63}) CODE ([0-9]{1,5}))?\n")


def native_error(line):
    found = ERROR_LINE.fullmatch(line)
    if found is None:
        return None
    fields = found.groups()
    details = dict(zip(("error", "storage", "socket", "certificate"),
                       (field.decode("ascii") for field in fields[:4])))
    if fields[4] is not None:
        code = int(fields[5])
        if code > 65535:
            return None
        details.update(session=fields[4].decode("ascii"), server_code=code)
    return details


GROUP_COUNTS_LINE = re.compile(rb"GROUP_COUNTS total=([0-9]{1,5}) "
    rb"empty_subjects=([0-9]{1,5}) exact_matches=([0-9]{1,5})\n")


def native_group_counts(line):
    found = GROUP_COUNTS_LINE.fullmatch(line)
    if found is None:
        return None
    total, empty, exact = (int(field) for field in found.groups())
    if total > 10000 or empty + exact > total:
        return None
    return dict(total=total, empty_subjects=empty, exact_matches=exact)


WATCH_VERSION = re.compile(rb"WATCH_VERSION major=([0-9]{1,10}) "
    rb"minor=([0-9]{1,10}) patch=([0-9]{1,10})\n")
WATCH_HEALTH = re.compile(rb"WATCH_HEALTH uptime_seconds=([0-9]{1,6}) reconnects=([0-9]{1,4})\n")
CANARY_STATUS = re.compile(rb"CANARY_STATUS completed_cycles=([0-9]{1,2}) "
    rb"durable_completed_cycles=([0-9]{1,20}) first_ack_unix_seconds=([0-9]{1,19}) "
    rb"last_ack_unix_seconds=([0-9]{1,19})\n")


def native_watch_metadata(line):
    found = WATCH_VERSION.fullmatch(line)
    if found:
        values = tuple(map(int,found.groups()))
        if all(value <= 0xffffffff for value in values):
            return dict(phase="WATCH_VERSION",major=values[0],minor=values[1],patch=values[2])
        return None
    found = WATCH_HEALTH.fullmatch(line)
    if found:
        elapsed,reconnects = map(int,found.groups())
        if elapsed <= 172800 and reconnects <= 1000:
            return dict(phase="WATCH_HEALTH",process_elapsed_seconds=elapsed,reconnects=reconnects)
        return None
    found = CANARY_STATUS.fullmatch(line)
    if found:
        cycles,durable,first,last = map(int,found.groups())
        if (cycles <= 48 and durable <= 0xffffffffffffffff and cycles <= durable and
                first <= last <= 0x7fffffffffffffff and
                ((durable == 0 and first == last == 0) or (durable > 0 and first > 0))):
            return dict(phase="CANARY_STATUS",completed_cycles=cycles,
                durable_completed_cycles=durable,first_ack_unix_seconds=first,
                last_ack_unix_seconds=last)
    return None


def drain_diagnostics(stream, state):
    discarding = False
    try:
        while True:
            line = stream.readline(STATUS_LINE_MAX + 1)
            if not line:
                return
            complete = line.endswith(b"\n")
            if discarding or len(line) > STATUS_LINE_MAX or not complete:
                discarding = not complete
                continue
            parsed = native_error(line)
            if parsed is not None:
                state["last"] = parsed
    except (OSError, ValueError):
        return


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = item
    return value


def native_phase(line):
    if line == b"QR_READY qr.json\n":
        return "QR_READY"
    if not line.startswith(b"PHASE ") or not line.endswith(b"\n"):
        raise DisplayError("PROBE_STATUS_INVALID")
    try:
        phase = line[6:-1].decode("ascii")
    except UnicodeError:
        raise DisplayError("PROBE_STATUS_INVALID") from None
    if phase not in PHASES:
        raise DisplayError("PROBE_STATUS_INVALID")
    return phase


def matrix_decode(data):
    if len(data) > QR_JSON_MAX:
        raise DisplayError("QR_INVALID")
    try:
        value = json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise DisplayError("QR_INVALID") from None
    if not isinstance(value, dict) or set(value) != {"size", "modules"}:
        raise DisplayError("QR_INVALID")
    size, modules = value["size"], value["modules"]
    if type(size) is not int or size < 21 or size > 177 or size % 4 != 1:
        raise DisplayError("QR_INVALID")
    if (not isinstance(modules, list) or len(modules) != size * size or
            any(type(module) is not bool for module in modules)):
        raise DisplayError("QR_INVALID")
    return size, modules


def png_chunk(kind, payload):
    checksum = binascii.crc32(kind + payload) & 0xffffffff
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", checksum)


def matrix_png(size, modules):
    # Exact grayscale pixels: True is black, with a four-module white quiet zone.
    width = (size + 2 * QUIET_MODULES) * PIXELS_PER_MODULE
    white = b"\xff" * width
    rows = bytearray()
    for _ in range(QUIET_MODULES * PIXELS_PER_MODULE):
        rows += b"\0" + white
    for y in range(size):
        row = bytearray(white)
        for x in range(size):
            if modules[y * size + x]:
                at = (x + QUIET_MODULES) * PIXELS_PER_MODULE
                row[at:at + PIXELS_PER_MODULE] = b"\0" * PIXELS_PER_MODULE
        for _ in range(PIXELS_PER_MODULE):
            rows += b"\0" + row
    for _ in range(QUIET_MODULES * PIXELS_PER_MODULE):
        rows += b"\0" + white
    header = struct.pack(">IIBBBBB", width, width, 8, 0, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", header) +
            png_chunk(b"IDAT", zlib.compress(rows, 9)) + png_chunk(b"IEND", b""))


def private_directory(path):
    if not path.is_absolute() or ".." in path.parts:
        raise DisplayError("AUTH_DIR_INVALID")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(descriptor)
            raise DisplayError("AUTH_DIR_NOT_PRIVATE")
        return descriptor
    except OSError:
        raise DisplayError("AUTH_DIR_INVALID") from None


def render_private(auth_dir):
    directory = private_directory(auth_dir)
    temporary = None
    try:
        descriptor = os.open("qr.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > QR_JSON_MAX):
                raise DisplayError("QR_NOT_PRIVATE")
            data = bytearray()
            while len(data) <= QR_JSON_MAX:
                chunk = os.read(descriptor, min(8192, QR_JSON_MAX + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
        finally:
            os.close(descriptor)
        size, modules = matrix_decode(data)
        png = matrix_png(size, modules)
        temporary = ".qr.png." + secrets.token_hex(8) + ".tmp"
        output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
        try:
            os.fchmod(output, 0o600)
            view = memoryview(png)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise DisplayError("QR_WRITE_FAILED")
                view = view[written:]
            os.fsync(output)
        finally:
            os.close(output)
        os.replace(temporary, "qr.png", src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
        os.fsync(directory)
    except OSError:
        raise DisplayError("QR_IO_FAILED") from None
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=directory)
        os.close(directory)


def status(phase, reason=None, details=None):
    value = {"phase": phase}
    if reason is not None:
        value["reason"] = reason
    if details is not None:
        value.update(details)
    print(json.dumps(value, separators=(",", ":")), flush=True)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise DisplayError("INVALID_ARGUMENTS")


def arguments(argv):
    if "--" in argv:
        at = argv.index("--")
        wrapper, native = argv[:at], argv[at + 1:]
    else:
        wrapper, native = argv, []
    parser = Parser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--auth-dir", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("command", choices=("pair", "inspect", "qualify", "preview"))
    args = parser.parse_args(wrapper)
    if not args.live:
        raise DisplayError("LIVE_OPT_IN_REQUIRED")
    if not args.auth_dir.is_absolute() or ".." in args.auth_dir.parts:
        raise DisplayError("AUTH_DIR_INVALID")
    if not args.binary.is_absolute() or not args.binary.is_file():
        raise DisplayError("BINARY_INVALID")
    if any(value == "--live" or value.startswith("--auth-dir") for value in native):
        raise DisplayError("NATIVE_OVERRIDE_REFUSED")
    return args, native


def launch(args, native):
    command = [str(args.binary), args.command, "--auth-dir", str(args.auth_dir), *native]
    try:
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        raise DisplayError("PROBE_START_FAILED") from None
    diagnostic_state = {"last": None}
    diagnostic_worker = threading.Thread(target=drain_diagnostics,
        args=(child.stderr, diagnostic_state), daemon=True)
    diagnostic_worker.start()
    watchdog = threading.Timer(PROBE_WALL_SECONDS_MAX, child.kill)
    watchdog.daemon = True
    watchdog.start()
    try:
        while True:
            line = child.stdout.readline(STATUS_LINE_MAX + 1)
            if not line:
                break
            if len(line) > STATUS_LINE_MAX or not line.endswith(b"\n"):
                raise DisplayError("PROBE_STATUS_INVALID")
            metadata = native_watch_metadata(line)
            if metadata is not None:
                phase = metadata.pop("phase")
                status(phase,details=metadata)
                continue
            counts = native_group_counts(line)
            if counts is not None:
                status("GROUP_COUNTS", details=counts)
                continue
            phase = native_phase(line)
            status(phase)
            if phase == "QR_READY":
                render_private(args.auth_dir)
                status("QR_RENDERED")
        result = child.wait()
        diagnostic_worker.join(timeout=5)
        if diagnostic_worker.is_alive():
            raise DisplayError("PROBE_DIAGNOSTIC_TIMEOUT")
        if result != 0 or diagnostic_state["last"] is not None:
            raise DisplayError("PROBE_FAILED", diagnostic_state["last"])
        return 0
    finally:
        watchdog.cancel()
        child.stdout.close()
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        diagnostic_worker.join(timeout=5)
        child.stderr.close()


def main(argv=None):
    try:
        args, native = arguments(sys.argv[1:] if argv is None else argv)
        return launch(args, native)
    except DisplayError as error:
        status("FAILED", str(error), error.details)
        return 2
    except OSError:
        status("FAILED", "QR_IO_FAILED")
        return 2
    except KeyboardInterrupt:
        status("STOPPED")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
