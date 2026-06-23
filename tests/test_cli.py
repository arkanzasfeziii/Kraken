"""Tests for CLI argument parsing."""

from kraken.cli import MODULE_REGISTRY, build_parser


def test_all_modules_registered():
    expected = {"enum", "secret-dump", "escape", "sa-abuse", "cloud-bridge", "etcd"}
    assert set(MODULE_REGISTRY.keys()) == expected


def test_default_namespace():
    p = build_parser()
    args = p.parse_args(["--modules", "enum"])
    assert args.namespace == "default"


def test_api_host_port():
    p = build_parser()
    args = p.parse_args(["--api-host", "10.0.0.1", "--api-port", "8443", "--modules", "enum"])
    assert args.api_host == "10.0.0.1"
    assert args.api_port == 8443


def test_target_sa():
    p = build_parser()
    args = p.parse_args(["--modules", "sa-abuse", "--target-sa", "admin-sa"])
    assert args.target_sa == "admin-sa"


def test_etcd_args():
    p = build_parser()
    args = p.parse_args(["--modules", "etcd", "--etcd-host", "10.0.0.2", "--cert-dir", "/certs"])
    assert args.etcd_host == "10.0.0.2"
    assert args.cert_dir == "/certs"
