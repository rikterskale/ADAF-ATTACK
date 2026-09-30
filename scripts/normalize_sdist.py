#!/usr/bin/env python3
"""Rewrite setuptools sdists into deterministic bytes.

setuptools does not reliably honor ``SOURCE_DATE_EPOCH`` for source-distribution
tar member mtimes, and gzip records a wall-clock header mtime, so two builds from
identical input produce different ``.tar.gz`` bytes. Byte-for-byte reproducibility
matters here because the sdist is a shipped, checksummed release artifact (see
``attach-release-artifacts.yml`` and ``check_install_contracts``).

This repacks each archive with every non-content field pinned -- member order,
mtime (clamped to ``SOURCE_DATE_EPOCH``), mode, ownership, and the gzip header
mtime -- yielding identical output for identical file content. File contents and
names are preserved exactly, so the installable result is unchanged.
"""

from __future__ import annotations

import gzip
import io
import os
import sys
import tarfile
from collections.abc import Iterable
from pathlib import Path


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isfile():
        return b""
    extracted = archive.extractfile(member)
    return extracted.read() if extracted is not None else b""


def _normalize_one(path: Path, epoch: int) -> None:
    with gzip.open(path, "rb") as raw_in, tarfile.open(fileobj=raw_in, mode="r:") as src:
        members = sorted(src.getmembers(), key=lambda item: item.name)
        payloads = {member.name: _read_member(src, member) for member in members}

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:", format=tarfile.USTAR_FORMAT) as out:
        for member in members:
            info = tarfile.TarInfo(member.name)
            info.type = member.type
            info.size = member.size if member.isfile() else 0
            info.mtime = epoch
            info.mode = 0o644 if member.isfile() else 0o755
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            out.addfile(info, io.BytesIO(payloads[member.name]) if member.isfile() else None)

    with (
        open(path, "wb") as handle,
        gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as compressed,
    ):
        compressed.write(buffer.getvalue())


def _iter_targets(args: Iterable[str]) -> list[Path]:
    targets: list[Path] = []
    for arg in args:
        candidate = Path(arg)
        if candidate.is_dir():
            targets.extend(sorted(candidate.glob("*.tar.gz")))
        elif candidate.is_file():
            targets.append(candidate)
    return targets


def main(argv: list[str]) -> int:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    targets = _iter_targets(argv)
    if not targets:
        print("normalize_sdist: no .tar.gz targets found", file=sys.stderr)
        return 1
    for target in targets:
        _normalize_one(target, epoch)
        print(f"normalized {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
