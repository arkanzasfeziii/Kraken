"""Tests for utility helpers."""

from kraken.utils.helpers import b64d, scan_for_secrets


def test_b64d_valid():
    import base64

    encoded = base64.b64encode(b"hello world").decode()
    assert b64d(encoded) == "hello world"


def test_b64d_invalid():
    assert b64d("not-base64!!!") == "not-base64!!!"


def test_scan_for_secrets_aws_key():
    text = 'AWS_KEY="AKIAIOSFODNN7EXAMPLE"'
    results = scan_for_secrets(text)
    assert any(r["type"] == "AWS_ACCESS_KEY" for r in results)


def test_scan_for_secrets_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
    results = scan_for_secrets(text)
    assert any(r["type"] == "PRIVATE_KEY" for r in results)


def test_scan_for_secrets_password():
    text = 'password = "SuperSecret123!"'
    results = scan_for_secrets(text)
    assert any(r["type"] == "PASSWORD" for r in results)


def test_scan_for_secrets_clean():
    assert scan_for_secrets("nothing sensitive here") == []


def test_scan_for_secrets_truncate():
    text = 'password = "' + "A" * 300 + '"'
    results = scan_for_secrets(text)
    for r in results:
        assert len(r["value"]) <= 200
