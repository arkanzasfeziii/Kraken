"""Tests for data models."""

from kraken.models import AttackResult, Credential, EngagementContext


def test_attack_result_defaults():
    r = AttackResult(module="enum", action="namespaces", status="SUCCESS")
    assert r.severity == "INFO"
    assert r.target == ""


def test_credential_creation():
    c = Credential(type="sa_token", value={"token": "eyJ..."}, source="k8s:default:sa")
    assert c.type == "sa_token"


def test_engagement_context_defaults():
    ctx = EngagementContext()
    assert ctx.api_port == 6443
    assert ctx.namespace == "default"
    assert ctx.delay == 0.2
    assert ctx.results == []
    assert ctx.credentials == []


def test_engagement_context_custom():
    ctx = EngagementContext(api_host="10.0.0.1", namespace="kube-system")
    assert ctx.api_host == "10.0.0.1"
    assert ctx.namespace == "kube-system"
