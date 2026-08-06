"""Basic registry tests."""

from adaf_attack.core.registry import Capability, CapabilityRegistry


def test_register_and_list() -> None:
    reg = CapabilityRegistry()
    reg.register(Capability(id="test-cap", summary="A test capability"))
    assert reg.get("test-cap") is not None
    assert len(reg.list()) == 1
    assert reg.ids() == ["test-cap"]
