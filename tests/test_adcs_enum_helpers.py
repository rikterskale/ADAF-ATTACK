"""Offline unit tests for AD CS LDAP-entry normalization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adaf_attack.capabilities.adcs_enum import (
    _analyze_template,
    _client_auth_eku,
    _int_attr,
    _list_attr,
)


@dataclass
class _Attr:
    value: Any = None

    def __bool__(self) -> bool:
        return self.value is not None

    def __str__(self) -> str:
        return str(self.value)


class _Template:
    cn = _Attr("UserTemplate")
    displayName = _Attr("User Template")
    entry_dn = "CN=UserTemplate,CN=Certificate Templates,DC=corp,DC=test"
    msPKI_Certificate_Name_Flag = _Attr(1)
    msPKI_Enrollment_Flag = _Attr(0)
    msPKI_RA_Signature = _Attr(0)
    pKIExtendedKeyUsage = _Attr(["1.3.6.1.5.5.7.3.2"])
    msPKI_Certificate_Application_Policy = _Attr([])
    msPKI_RA_Application_Policies = _Attr([])

    def __getattr__(self, name: str) -> Any:
        return getattr(self, name.replace("-", "_"))


def test_attribute_normalizers_handle_missing_invalid_scalar_and_sequence_values() -> None:
    assert _int_attr(object(), "missing") == 0
    assert _int_attr(type("Entry", (), {"flag": _Attr("not-an-int")})(), "flag") == 0
    assert _int_attr(type("Entry", (), {"flag": _Attr("7")})(), "flag") == 7
    assert _list_attr(object(), "missing") == []
    assert _list_attr(type("Entry", (), {"items": _Attr("one")})(), "items") == ["one"]
    assert _list_attr(type("Entry", (), {"items": _Attr([1, "two"])})(), "items") == ["1", "two"]


def test_client_auth_eku_treats_empty_as_any_purpose_and_filters_server_only_eku() -> None:
    assert _client_auth_eku([]) is True
    assert _client_auth_eku(["1.3.6.1.5.5.7.3.1"]) is False
    assert _client_auth_eku(["1.3.6.1.5.5.7.3.2"]) is True


def test_template_adapter_preserves_normalized_flags_and_esc_classification() -> None:
    result = _analyze_template(_Template())

    assert result["cn"] == "UserTemplate"
    assert result["display_name"] == "User Template"
    assert result["name_flags"] == 1
    assert result["esc1_candidate"] is True
    assert result["esc_tags"] == ["ESC1"]
