"""ESC6 probe — detect EDITF_ATTRIBUTESUBJECTALTNAME2 on a CA.

Full fidelity requires RPC/remote registry or local certutil against the CA.
This module tries, in order:
  1. Local certutil -getreg when available
  2. Impacket remote registry (RRP) over SMB when credentials allow
  3. Soft-fail with an actionable note

EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any

from adaf_attack.core.target import Target

EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
POLICY_KEY = r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"


def _parse_editflags(text: str) -> int | None:
    """Extract EditFlags value from certutil or reg query style output."""
    m = re.search(r"EditFlags\s*(?:REG_DWORD\s*)?[:=]?\s*(0x[0-9a-fA-F]+|\d+)", text)
    if not m:
        return None
    raw = m.group(1)
    return int(raw, 16) if raw.lower().startswith("0x") else int(raw)


def probe_certutil(ca_config: str | None = None) -> dict[str, Any]:
    """Run local certutil -getreg for policy EditFlags if certutil exists."""
    if not shutil.which("certutil"):
        return {"method": "certutil", "available": False, "note": "certutil not on PATH"}

    args = ["certutil", "-getreg", r"policy\EditFlags"]
    if ca_config:
        args = ["certutil", "-config", ca_config, "-getreg", r"policy\EditFlags"]

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        flags = _parse_editflags(out)
        if flags is None:
            return {
                "method": "certutil",
                "available": True,
                "ok": False,
                "stdout": out[:500],
                "note": "Could not parse EditFlags from certutil output",
            }
        esc6 = bool(flags & EDITF_ATTRIBUTESUBJECTALTNAME2)
        return {
            "method": "certutil",
            "available": True,
            "ok": True,
            "edit_flags": flags,
            "edit_flags_hex": hex(flags),
            "esc6": esc6,
        }
    except Exception as exc:
        return {"method": "certutil", "available": True, "ok": False, "error": str(exc)}


def probe_impacket_rrp(target: Target, ca_hostname: str | None = None) -> dict[str, Any]:
    """Attempt remote registry read of CA EditFlags via Impacket RRP."""
    try:
        from impacket.dcerpc.v5 import rrp, transport
        from impacket.smbconnection import SMBConnection
    except ImportError:
        return {
            "method": "impacket-rrp",
            "available": False,
            "note": "Impacket not installed",
        }

    host = ca_hostname or target.dc_ip
    lm, nt = target.lm_nt_hashes()
    password = target.password or ""

    try:
        smb = SMBConnection(host, host)
        if target.hashes:
            smb.login(target.username or "", password, target.domain, lmhash=lm, nthash=nt)
        else:
            smb.login(target.username or "", password, target.domain)

        string_binding = rf"ncacn_np:{host}[\pipe\winreg]"
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_smb_connection(smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        ans = rrp.hOpenLocalMachine(dce)
        h_root = ans["phKey"]

        try:
            ans = rrp.hBaseRegOpenKey(dce, h_root, POLICY_KEY)
        except Exception as exc:
            dce.disconnect()
            return {
                "method": "impacket-rrp",
                "available": True,
                "ok": False,
                "error": f"Open CertSvc Configuration failed: {exc}",
                "note": "CA registry hive may not be on this host, or access denied",
            }

        h_cfg = ans["phkResult"]
        ca_names: list[str] = []
        for i in range(32):
            try:
                enum = rrp.hBaseRegEnumKey(dce, h_cfg, i)
                ca_names.append(enum["lpNameOut"])
            except Exception:
                break

        results = []
        for name in ca_names:
            try:
                ans = rrp.hBaseRegOpenKey(dce, h_cfg, name + r"\Policy")
                h_pol = ans["phkResult"]
                val = rrp.hBaseRegQueryValue(dce, h_pol, "EditFlags")
                data = val[1]
                if isinstance(data, bytes):
                    flags = int.from_bytes(data[:4], "little")
                elif isinstance(data, int):
                    flags = data
                else:
                    flags = int(data)
                esc6 = bool(flags & EDITF_ATTRIBUTESUBJECTALTNAME2)
                results.append(
                    {
                        "ca": name,
                        "edit_flags": flags,
                        "edit_flags_hex": hex(flags),
                        "esc6": esc6,
                    }
                )
            except Exception as exc:
                results.append({"ca": name, "error": str(exc)})

        dce.disconnect()
        any_esc6 = any(r.get("esc6") for r in results)
        return {
            "method": "impacket-rrp",
            "available": True,
            "ok": True,
            "host": host,
            "cas": results,
            "esc6": any_esc6,
        }
    except Exception as exc:
        return {
            "method": "impacket-rrp",
            "available": True,
            "ok": False,
            "host": host,
            "error": str(exc),
        }


def probe_esc6(
    target: Target,
    *,
    ca_hostnames: list[str] | None = None,
    ca_config: str | None = None,
) -> dict[str, Any]:
    """Run available ESC6 probes; never raises."""
    attempts: list[dict[str, Any]] = []

    cert = probe_certutil(ca_config=ca_config)
    attempts.append(cert)
    if cert.get("ok") and "esc6" in cert:
        return {
            "esc6": cert["esc6"],
            "resolved": True,
            "attempts": attempts,
            "primary": cert,
        }

    hosts = ca_hostnames or [target.dc_ip]
    for host in hosts:
        if not target.has_credentials:
            attempts.append(
                {
                    "method": "impacket-rrp",
                    "available": True,
                    "ok": False,
                    "host": host,
                    "note": "Credentials required for remote registry",
                }
            )
            continue
        rrp = probe_impacket_rrp(target, ca_hostname=host)
        attempts.append(rrp)
        if rrp.get("ok") and "esc6" in rrp:
            return {
                "esc6": rrp["esc6"],
                "resolved": True,
                "attempts": attempts,
                "primary": rrp,
            }

    return {
        "esc6": None,
        "resolved": False,
        "attempts": attempts,
        "note": (
            "ESC6 not definitively resolved. On a host with CA rights, run: "
            "certutil -config <CA> -getreg policy\\EditFlags "
            "and check bit 0x40000 (EDITF_ATTRIBUTESUBJECTALTNAME2)."
        ),
    }
