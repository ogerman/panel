"""
Unit tests for subscription TLS settings (min_version / max_version) across formats.

Verifies that tls_min_version and tls_max_version from the host flow into:
- Xray: minVersion/maxVersion in streamSettings.tlsSettings
- sing-box: min_version/max_version in outbound TLS config
- Links: minVersion/maxVersion in share URL payload (VLESS/Trojan/VMess)
Clash/Clash Meta: no TLS version options in documented proxy TLS config; not tested.
"""

import pytest

from app.models.subscription import TLSConfig
from app.subscription.links import StandardLinks
from app.subscription.singbox import SingBoxConfiguration
from app.subscription.xray import XrayConfiguration


def test_xray_apply_tls_includes_min_max_version_when_set():
    """TLS config with min_version and max_version produces minVersion and maxVersion in Xray output."""
    tls_config = TLSConfig(
        tls="tls",
        sni=["example.com"],
        fingerprint="chrome",
        allowinsecure=False,
        min_version="1.2",
        max_version="1.3",
    )
    xray = XrayConfiguration()
    result = xray._apply_tls(tls_config, "tls")

    assert result.get("minVersion") == "1.2"
    assert result.get("maxVersion") == "1.3"
    assert result.get("serverName") == "example.com"
    assert result.get("fingerprint") == "chrome"


def test_xray_apply_tls_omits_min_max_version_when_not_set():
    """TLS config without min_version/max_version does not add minVersion/maxVersion to Xray output."""
    tls_config = TLSConfig(
        tls="tls",
        sni=["example.com"],
        fingerprint="",
        allowinsecure=False,
        min_version=None,
        max_version=None,
    )
    xray = XrayConfiguration()
    result = xray._apply_tls(tls_config, "tls")

    assert "minVersion" not in result
    assert "maxVersion" not in result
    assert result.get("serverName") == "example.com"


def test_xray_apply_tls_reality_unchanged():
    """Reality security branch does not include minVersion/maxVersion (not applicable)."""
    tls_config = TLSConfig(
        tls="reality",
        sni=["example.com"],
        fingerprint="chrome",
        reality_public_key="pk",
        reality_short_id="sid",
        min_version="1.2",
        max_version="1.3",
    )
    xray = XrayConfiguration()
    result = xray._apply_tls(tls_config, "reality")

    assert "minVersion" not in result
    assert "maxVersion" not in result
    assert result.get("publicKey") == "pk"
    assert result.get("shortId") == "sid"


# ---------- sing-box ----------


def test_singbox_apply_tls_includes_min_max_version_when_set():
    """TLS config with min_version and max_version produces min_version/max_version in sing-box output."""
    tls_config = TLSConfig(
        tls="tls",
        sni=["example.com"],
        fingerprint="chrome",
        allowinsecure=False,
        min_version="1.2",
        max_version="1.3",
    )
    singbox = SingBoxConfiguration()
    result = singbox._apply_tls(tls_config, None)

    assert result.get("min_version") == "1.2"
    assert result.get("max_version") == "1.3"
    assert result.get("server_name") == "example.com"


def test_singbox_apply_tls_omits_min_max_version_when_not_set():
    """TLS config without min_version/max_version does not add them to sing-box output."""
    tls_config = TLSConfig(
        tls="tls",
        sni=["example.com"],
        fingerprint="",
        allowinsecure=False,
        min_version=None,
        max_version=None,
    )
    singbox = SingBoxConfiguration()
    result = singbox._apply_tls(tls_config, None)

    assert "min_version" not in result
    assert "max_version" not in result


def test_singbox_apply_tls_reality_has_no_min_max_version():
    """Reality TLS config does not add min_version/max_version in sing-box (Reality uses its own handshake)."""
    tls_config = TLSConfig(
        tls="reality",
        sni=["example.com"],
        fingerprint="chrome",
        reality_public_key="pk",
        reality_short_id="sid",
        min_version="1.2",
        max_version="1.3",
    )
    singbox = SingBoxConfiguration()
    result = singbox._apply_tls(tls_config, None)

    assert "min_version" not in result
    assert "max_version" not in result
    assert result.get("reality", {}).get("public_key") == "pk"


# ---------- Links (share URL payload) ----------


def test_links_apply_tls_settings_includes_min_max_version_when_set():
    """TLS config with min_version and max_version produces minVersion/maxVersion in link payload."""
    tls_config = TLSConfig(
        tls="tls",
        sni="example.com",
        fingerprint="chrome",
        allowinsecure=False,
        min_version="1.2",
        max_version="1.3",
    )
    payload = {}
    links = StandardLinks()
    links._apply_tls_settings(payload, tls_config, None)

    assert payload.get("minVersion") == "1.2"
    assert payload.get("maxVersion") == "1.3"
    assert payload.get("sni") == "example.com"


def test_links_apply_tls_settings_omits_min_max_version_when_not_set():
    """TLS config without min_version/max_version does not add them to link payload."""
    tls_config = TLSConfig(
        tls="tls",
        sni="example.com",
        fingerprint="",
        allowinsecure=False,
        min_version=None,
        max_version=None,
    )
    payload = {}
    links = StandardLinks()
    links._apply_tls_settings(payload, tls_config, None)

    assert "minVersion" not in payload
    assert "maxVersion" not in payload


def test_links_apply_tls_settings_reality_has_no_min_max_version():
    """Reality TLS config does not add minVersion/maxVersion to link payload (not applicable)."""
    tls_config = TLSConfig(
        tls="reality",
        sni="example.com",
        fingerprint="chrome",
        reality_public_key="pk",
        reality_short_id="sid",
        min_version="1.2",
        max_version="1.3",
    )
    payload = {}
    links = StandardLinks()
    links._apply_tls_settings(payload, tls_config, None)

    assert "minVersion" not in payload
    assert "maxVersion" not in payload
    assert payload.get("pbk") == "pk"
    assert payload.get("sid") == "sid"
