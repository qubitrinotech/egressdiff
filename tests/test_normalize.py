from egressdiff.normalize import normalize


def report(dns, tcp, sni):
    return {"service": "app", "events": {"dns": dns, "tcp": tcp, "tls_sni": sni}}


def test_sni_aggregates_dns_and_tcp_evidence() -> None:
    result = normalize(
        report(
            ["db.example", "telemetry.example"],
            ["172.31.0.10:8000", "172.31.0.20:9443"],
            ["telemetry.example@172.31.0.20:9443"],
        )
    )
    assert [item["key"] for item in result] == [
        "dns://db.example",
        "tcp://172.31.0.10:8000",
        "tls-sni://telemetry.example:9443",
    ]
    assert result[-1]["evidence"] == ["DNS", "TCP", "TLS-SNI"]


def test_direct_ip_tcp_remains_visible() -> None:
    result = normalize(report([], ["192.0.2.10:443"], []))
    assert result == [
        {
            "key": "tcp://192.0.2.10:443",
            "service": "app",
            "kind": "tcp",
            "address": "192.0.2.10:443",
            "evidence": ["TCP"],
        }
    ]
