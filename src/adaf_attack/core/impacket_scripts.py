"""Locate Impacket example scripts that are not importable as packages."""

from __future__ import annotations

import importlib
import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from adaf_attack.core.impacket_helper import ImpacketMissingError, require_impacket


def find_impacket_script(*names: str) -> Path:
    """Return the first Impacket example script found on PATH or beside impacket."""
    require_impacket(names[0] if names else "impacket")
    candidates: list[str] = []
    for name in names:
        candidates.extend([name, f"{name}.py", f"impacket-{name}"])
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return Path(found)
    try:
        import impacket
    except ImportError as exc:
        raise ImpacketMissingError(names[0] if names else "impacket") from exc
    package_dir = Path(impacket.__file__).resolve().parent
    search_roots = [
        package_dir / "examples",
        package_dir.parent.parent / "bin",
        Path(sys.executable).resolve().parent,
    ]
    for root in search_roots:
        for name in names:
            for filename in (name, f"{name}.py"):
                path = root / filename
                if path.is_file():
                    return path
    joined = ", ".join(names)
    raise ImpacketMissingError(
        f"{joined} (Impacket example script not on PATH; install adaf-attack[kerberos])"
    )


def load_impacket_example(script_name: str, class_name: str) -> Any:
    """Load a class from an Impacket example, preferring an importable module.

    Older Impacket trees expose ``impacket.examples.getST``; 0.13+ ships many
    examples as console scripts only. Tests also inject stub modules.
    """
    stem = Path(script_name).stem
    try:
        imported = importlib.import_module(f"impacket.examples.{stem}")
    except (ImportError, ModuleNotFoundError):
        imported = None
    if imported is not None:
        try:
            return getattr(imported, class_name)
        except AttributeError as exc:
            raise ImpacketMissingError(f"{script_name}:{class_name}") from exc
    path = find_impacket_script(script_name)
    spec = importlib.util.spec_from_file_location(f"adaf_impacket_{script_name}", path)
    if spec is None or spec.loader is None:
        raise ImpacketMissingError(script_name)
    module = ModuleType(spec.name)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    try:
        return getattr(module, class_name)
    except AttributeError as exc:
        raise ImpacketMissingError(f"{script_name}:{class_name}") from exc
