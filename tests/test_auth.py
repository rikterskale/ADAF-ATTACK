"""Auth helper unit tests (no network)."""

from adaf_attack.core.auth import describe_auth, ldap3_bind_kwargs
from adaf_attack.core.target import Target


def test_describe_auth_password() -> None:
    t = Target(domain="corp.local", dc_ip="10.0.0.1", username="alice", password="x")
    assert "password" in describe_auth(t)


def test_describe_auth_hash() -> None:
    t = Target(domain="corp.local", dc_ip="10.0.0.1", username="alice", hashes=":aabb")
    assert "hash" in describe_auth(t).lower() or "ntlm" in describe_auth(t).lower()


def test_describe_auth_ccache() -> None:
    t = Target(domain="corp.local", dc_ip="10.0.0.1", use_kerberos=True, ccache="/tmp/cc")
    assert "ccache" in describe_auth(t)


def test_lm_nt_hashes_split() -> None:
    t = Target(domain="c", dc_ip="1.1.1.1", hashes="aad3b435b51404eeaad3b435b51404ee:ntnt")
    lm, nt = t.lm_nt_hashes()
    assert lm.startswith("aad3")
    assert nt == "ntnt"

    t2 = Target(domain="c", dc_ip="1.1.1.1", hashes="onlynt")
    lm2, nt2 = t2.lm_nt_hashes()
    assert lm2 == ""
    assert nt2 == "onlynt"


def test_has_credentials() -> None:
    assert not Target(domain="c", dc_ip="1.1.1.1").has_credentials
    assert Target(domain="c", dc_ip="1.1.1.1", password="x", username="a").has_credentials
    assert Target(domain="c", dc_ip="1.1.1.1", use_kerberos=True).has_credentials


def test_ldap3_bind_kwargs_password() -> None:
    t = Target(domain="corp.local", dc_ip="10.0.0.1", username="alice", password="secret")
    kw = ldap3_bind_kwargs(t)
    assert kw["authentication"] == "NTLM"
    user = str(kw["user"]).lower()
    assert user == "alice" or user.endswith("\\alice") or "corp.local\\alice" in user
