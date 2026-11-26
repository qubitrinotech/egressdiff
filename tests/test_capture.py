from __future__ import annotations

import errno
import socket
import struct

from egressdiff import capture as capture_module
from egressdiff.capture import Capture, report

APP_IP = "172.20.0.5"


def frame(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        1,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return b"\x00" * 12 + struct.pack("!H", 0x0800) + ip + payload


def udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def tcp(src_port: int, dst_port: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", src_port, dst_port, 1, 0, 5 << 4, flags, 65535, 0, 0) + payload


def dns_query(name: str, transaction_id: int = 1) -> bytes:
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        + question
        + b"\x00"
        + struct.pack("!HH", 1, 1)
    )


def dns_response(name: str, transaction_id: int = 1) -> bytes:
    query = dns_query(name, transaction_id)
    return query[:2] + struct.pack("!H", 0x8180) + query[4:]


def client_hello(name: str) -> bytes:
    encoded = name.encode("ascii")
    names = b"\x00" + struct.pack("!H", len(encoded)) + encoded
    sni = struct.pack("!H", len(names)) + names
    extension = struct.pack("!HH", 0, len(sni)) + sni
    hello = (
        b"\x03\x03"
        + b"\x01" * 32
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(extension))
        + extension
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def test_dns_query_and_matching_response_share_one_destination() -> None:
    capture = Capture(APP_IP)
    query = frame(APP_IP, "192.0.2.53", 17, udp(50000, 53, dns_query("db.example")))
    response = frame(
        "192.0.2.53",
        APP_IP,
        17,
        udp(53, 50000, dns_response("db.example")),
    )
    capture.process_frame(query)
    capture.process_frame(response)
    assert capture.dns == {"db.example"}
    assert capture.stats["ipv4"] == 2
    assert capture.stats["udp"] == 2
    assert capture.stats["dns_query"] == 1
    assert capture.stats["dns_response"] == 1
    assert capture.udp53 == {f"{APP_IP}:50000→192.0.2.53:53"}
    assert capture.udp_endpoints == capture.udp53
    assert not capture.unknown


def test_loopback_dns_after_nat_redirect_dedupes_query_and_response() -> None:
    capture = Capture(APP_IP)
    query = frame(
        "127.0.0.1",
        "127.0.0.1",
        17,
        udp(50000, 45327, dns_query("telemetry.example", 7)),
    )
    response = frame(
        "127.0.0.11",
        "127.0.0.1",
        17,
        udp(53, 50000, dns_response("telemetry.example", 7)),
    )
    for packet in (query, response, query, response):
        capture.process_frame(packet)
    assert capture.dns == {"telemetry.example"}
    assert capture.stats["dns_query"] == 2
    assert capture.stats["dns_response"] == 2
    assert capture.udp53 == set()
    assert capture.udp_endpoints == {"127.0.0.1:50000→127.0.0.1:45327"}
    assert not capture.unknown


def test_non_dns_loopback_udp_is_ignored() -> None:
    capture = Capture(APP_IP)
    capture.process_frame(frame("127.0.0.1", "127.0.0.1", 17, udp(50000, 45327, b"not dns")))
    assert not capture.dns
    assert capture.udp_endpoints == set()
    assert not capture.unknown


def test_dns_response_without_query_is_ignored() -> None:
    capture = Capture(APP_IP)
    capture.process_frame(
        frame(
            "127.0.0.11",
            "127.0.0.1",
            17,
            udp(53, 50000, dns_response("ghost.example", 9)),
        )
    )
    assert not capture.dns
    assert not capture.udp_endpoints
    assert "dns_response" not in capture.stats
    assert not capture.unknown


def test_foreign_dns_query_is_ignored() -> None:
    capture = Capture(APP_IP)
    capture.process_frame(
        frame("172.20.0.99", "192.0.2.53", 17, udp(50000, 53, dns_query("foreign.example")))
    )
    assert not capture.dns
    assert not capture.udp_endpoints
    assert not capture.udp53
    assert not capture.unknown


def test_multicast_dns_like_udp_is_ignored() -> None:
    capture = Capture(APP_IP)
    capture.process_frame(
        frame(APP_IP, "224.0.0.251", 17, udp(50000, 5353, dns_query("multicast.example")))
    )
    assert not capture.dns
    assert not capture.udp_endpoints
    assert not capture.udp53
    assert not capture.unknown


def test_app_udp_443_is_explicit_unknown() -> None:
    capture = Capture(APP_IP)
    capture.process_frame(frame(APP_IP, "172.31.0.20", 17, udp(50000, 443, b"quic")))
    assert capture.unknown == {"udp_unsupported:172.31.0.20:443"}
    assert not capture.dns
    assert not capture.udp_endpoints


def test_ipv6_is_explicit_unknown() -> None:
    capture = Capture(APP_IP)
    packet = b"\x00" * 12 + struct.pack("!H", 0x86DD) + b"\x60" + b"\x00" * 39
    capture.process_frame(packet)
    assert capture.unknown == {"ipv6_unsupported"}
    assert capture.stats["ipv6"] == 1


def test_report_declares_dns_loopback_attribution_limit(monkeypatch) -> None:
    monkeypatch.setattr(capture_module, "capability_status", lambda: {})
    result = report(Capture(APP_IP), "baseline", {"status": "PASS"})
    assert result["capture_limitations"] == [
        "dns_loopback_attribution_single_app_only",
        "single_app_service_only",
        "smoke_executed_paths_only",
    ]


def test_tcp_syn_destination() -> None:
    capture = Capture(APP_IP)
    capture.process_frame(frame(APP_IP, "192.0.2.10", 6, tcp(50000, 443, 0x02)))
    assert capture.tcp == {"192.0.2.10:443"}


def test_tls_sni() -> None:
    capture = Capture(APP_IP)
    capture.process_frame(
        frame(
            APP_IP,
            "192.0.2.10",
            6,
            tcp(50000, 443, 0x18, client_hello("telemetry.example")),
        )
    )
    assert capture.sni == {"telemetry.example@192.0.2.10:443"}


def test_fragmented_tls_sni() -> None:
    capture = Capture(APP_IP)
    hello = client_hello("telemetry.example")
    for part in (hello[:17], hello[17:]):
        capture.process_frame(frame(APP_IP, "192.0.2.10", 6, tcp(50000, 443, 0x18, part)))
    assert capture.sni == {"telemetry.example@192.0.2.10:443"}
    assert not capture.unknown


def test_plain_tcp_payload_is_not_tls_unknown() -> None:
    capture = Capture(APP_IP)
    capture.process_frame(
        frame(APP_IP, "192.0.2.10", 6, tcp(50000, 80, 0x18, b"GET / HTTP/1.1\r\n"))
    )
    assert not capture.sni
    assert not capture.unknown


def test_network_down_is_reported_and_socket_closed(monkeypatch) -> None:
    class DownSocket:
        closed = False

        def recv(self, size: int) -> bytes:
            raise OSError(errno.ENETDOWN, "Network is down")

        def getsockname(self) -> tuple[str, int]:
            return ("eth0", 0)

        def close(self) -> None:
            self.closed = True

    sock = DownSocket()
    sockets = [sock]
    monkeypatch.setattr(
        capture_module.select,
        "select",
        lambda *_args: ([sock], [], []),
    )
    capture = Capture(APP_IP)
    capture_module.receive_available(sockets, capture, 0)
    assert not sockets
    assert sock.closed
    assert capture.unknown == {"recv:eth0:errno=100"}
