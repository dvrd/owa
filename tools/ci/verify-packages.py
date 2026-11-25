"""Verify a preinstalled private mirror against KRS's path/length/content digest."""
import hashlib
import json
from pathlib import Path
import sys

shared = Path(sys.argv[1])
for package in json.loads(Path(".krs/packages.json").read_text())["packages"]:
    directory = shared / package["name"]
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*"), key=lambda p: p.relative_to(directory).as_posix()):
        if path.is_symlink():
            sys.exit("Unexpected symlink in " + package["name"])
        if path.is_file():
            data = path.read_bytes()
            digest.update(path.relative_to(directory).as_posix().encode() + b"\0")
            digest.update(len(data).to_bytes(8, "little"))
            digest.update(data)
    if digest.hexdigest() != package["hash"]:
        sys.exit("Locked package mismatch: " + package["name"])
