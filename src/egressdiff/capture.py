from __future__ import annotations

import ipaddress
import json
import os
import select
import socket
import struct
import sys
import time
from pathlib import Path

ETH_P_ALL = 0x0003
CAP_NET_RAW = 1 << 13
MAX_FLOW_BYTES = 65536
CAPTURE_LIMITATIONS = [
    "dns_loopback_attribution_single_app_only",
    "single_app_service_only",
    "smoke_executed_paths_only",
]


class IncompleteTLS(Exception):
    pass


def parse_tls_sni(data: bytes) -> str | None:
    if len(data) < 5:
        raise IncompleteTLS
    if data[0] != 22:
        return None
    record_length = struct.unpack("!H", data[3:5])[0]
    if len(data) < 5 + record_length:
        raise IncompleteTLS
    record = data[5 : 5 + record_length]
    if len(record) < 4 or record[0] != 1:
        return None
    hello_length = int.from_bytes(record[1:4], "big")
    if len(record) < 4 + hello_length:
        raise IncompleteTLS
    hello = record[4 : 4 + hello_length]
    if len(hello) < 34:
        raise ValueError("short ClientHello")
    offset = 34
    if offset >= len(hello):
        raise ValueError("no session id")
    session_len = hello[offset]
    offset += 1 + session_len
    if offset + 2 > len(hello):
        raise ValueError("no cipher suites")
    cipher_len = struct.unpack("!H", hello[offset : offset + 2])[0]
    offset += 2 + cipher_len
    if offset >= len(hello):
        raise ValueError("no compression methods")
    compression_len = hello[offset]
    offset += 1 + compression_len
    if offset + 2 > len(hello):
        raise ValueError("no extensions")
    extensions_len = struct.unpack("!H", hello[offset : offset + 2])[0]
    offset += 2
    end = offset + extensions_len
    if end > len(hello):
        raise IncompleteTLS
    while offset + 4 <= end:
        extension_type, extension_len = struct.unpack("!HH", hello[offset : offset + 4])
        offset += 4
        extension = hello[offset : offset + extension_len]
        if len(extension) != extension_len:
            raise IncompleteTLS
        offset += extension_len
        if extension_type != 0:
            continue
        if len(extension) < 5:
            raise ValueError("short SNI")
        name_len = struct.unpack("!H", extension[3:5])[0]
        if len(extension) < 5 + name_len:
            raise IncompleteTLS
        return extension[5 : 5 + name_len].decode("ascii").lower()
    return None


def dns_question(data: bytes) -> tuple[int, bool, str]:
    if len(data) < 12:
        raise ValueError("short DNS")
    transaction_id, flags, questions = struct.unpack("!HHH", data[:6])
    if questions != 1:
        raise ValueError("DNS questions != 1")
    if flags & 0x7800:
        raise ValueError("unsupported DNS opcode")
    offset = 12
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(data):
            raise ValueError("unsupported DNS label")
        labels.append(data[offset : offset + length].decode("ascii"))
        offset += length
    if offset + 4 > len(data):
        raise ValueError("truncated DNS question")
    return transaction_id, bool(flags & 0x8000), ".".join(labels).lower()


class Capture:
    def __init__(self, app_ip: str) -> None:
        self.app_ip = app_ip
        self.dns: set[str] = set()
        self.tcp: set[str] = set()
        self.sni: set[str] = set()
        self.unknown: set[str] = set()
        self.stats: dict[str, int] = {}
        self.udp53: set[str] = set()
        self.udp_endpoints: set[str] = set()
        self._dns_queries: dict[tuple[int, int, str], tuple[str, str, int]] = {}
        self.flows: dict[tuple[str, int, str, int], bytes] = {}

    def process_frame(self, frame: bytes) -> None:
        try:
            self._process_frame(frame)
        except (ValueError, IndexError, struct.error, UnicodeDecodeError) as exc:
            self.unknown.add(f"parse:{type(exc).__name__}")

    def _process_frame(self, frame: bytes) -> None:
        if len(frame) < 14:
            return
        ethertype = struct.unpack("!H", frame[12:14])[0]
        if ethertype == 0x86DD:
            self.stats["ipv6"] = self.stats.get("ipv6", 0) + 1
            self.unknown.add("ipv6_unsupported")
            return
        if len(frame) < 34 or ethertype != 0x0800:
            return
        ip = frame[14:]
        if ip[0] >> 4 != 4:
            return
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl:
            raise ValueError("bad IPv4 header")
        total_length = struct.unpack("!H", ip[2:4])[0]
        if total_length < ihl or len(ip) < total_length:
            raise ValueError("truncated IPv4 packet")
        flags_fragment = struct.unpack("!H", ip[6:8])[0]
        if flags_fragment & 0x3FFF:
            self.unknown.add("ipv4_fragment")
            return
        self.stats["ipv4"] = self.stats.get("ipv4", 0) + 1
        protocol = ip[9]
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        payload = ip[ihl:total_length]
        if protocol == 17:
            self._udp(src, dst, payload)
        elif protocol == 6:
            self._tcp(src, dst, payload)

    def _udp(self, src: str, dst: str, data: bytes) -> None:
        if len(data) < 8:
            raise ValueError("short UDP")
        self.stats["udp"] = self.stats.get("udp", 0) + 1
        src_port, dst_port, length = struct.unpack("!HHH", data[:6])
        if length < 8 or len(data) < length:
            raise ValueError("truncated UDP")
        if ipaddress.ip_address(dst).is_multicast:
            return
        loopback = src.startswith("127.") and dst.startswith("127.")
        if not loopback and src != self.app_ip and dst != self.app_ip:
            return
        if dst_port != 53 and src_port != 53 and not loopback:
            destination = f"{dst}:{dst_port}" if src == self.app_ip else f"{src}:{src_port}"
            self.unknown.add(f"udp_unsupported:{destination}")
            return
        try:
            transaction_id, is_response, name = dns_question(data[8:length])
        except ValueError:
            if dst_port == 53 or src_port == 53:
                raise
            return
        if is_response:
            query = self._dns_queries.get((transaction_id, dst_port, name))
            if query is None:
                return
            query_src, query_dst, query_dst_port = query
            query_loopback = query_src.startswith("127.") and query_dst.startswith("127.")
            if query_loopback:
                if not loopback:
                    return
            elif (src, src_port, dst) != (query_dst, query_dst_port, query_src):
                return
            self.stats["dns_response"] = self.stats.get("dns_response", 0) + 1
            return
        if src != self.app_ip and not loopback:
            return
        if dst_port != 53 and not loopback:
            return
        endpoint = f"{src}:{src_port}→{dst}:{dst_port}"
        self._dns_queries[(transaction_id, src_port, name)] = (src, dst, dst_port)
        self.stats["dns_query"] = self.stats.get("dns_query", 0) + 1
        self.dns.add(name)
        self.udp_endpoints.add(endpoint)
        if dst_port == 53:
            self.udp53.add(endpoint)

    def _tcp(self, src: str, dst: str, data: bytes) -> None:
        if len(data) < 20 or src != self.app_ip:
            return
        src_port, dst_port = struct.unpack("!HH", data[:4])
        offset = (data[12] >> 4) * 4
        if offset < 20 or len(data) < offset:
            raise ValueError("bad TCP header")
        flags = data[13]
        destination = f"{dst}:{dst_port}"
        if flags & 0x02 and not flags & 0x10:
            self.tcp.add(destination)
        payload = data[offset:]
        if not payload:
            return
        key = (src, src_port, dst, dst_port)
        buffered = self.flows.get(key, b"") + payload
        if len(buffered) > MAX_FLOW_BYTES:
            self.flows.pop(key, None)
            self.unknown.add(f"tls_overflow:{destination}")
            return
        if buffered[0] != 22:
            self.flows.pop(key, None)
            return
        self.flows[key] = buffered
        try:
            name = parse_tls_sni(buffered)
        except IncompleteTLS:
            return
        except ValueError:
            self.flows.pop(key, None)
            self.unknown.add(f"tls_parse:{destination}")
            return
        self.flows.pop(key, None)
        if name:
            self.sni.add(f"{name}@{destination}")
        else:
            self.unknown.add(f"tls_without_sni:{destination}")


def interface_ip(name: str) -> str:
    import fcntl

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        request = struct.pack("256s", name.encode("ascii"))
        response = fcntl.ioctl(sock.fileno(), 0x8915, request)
    return socket.inet_ntoa(response[20:24])


def receive_available(sockets: list[socket.socket], capture: Capture, wait: float) -> None:
    if not sockets:
        time.sleep(wait)
        return
    readable, _, _ = select.select(sockets, [], [], wait)
    for sock in readable:
        interface = sock.getsockname()[0]
        try:
            frame = sock.recv(65535)
        except OSError as exc:
            capture.unknown.add(f"recv:{interface}:errno={exc.errno}")
            sockets.remove(sock)
            sock.close()
            continue
        key = f"frames:{interface}"
        capture.stats[key] = capture.stats.get(key, 0) + 1
        capture.process_frame(frame)


def capability_status() -> dict[str, str | int]:
    result: dict[str, str | int] = {"uid": os.getuid(), "gid": os.getgid()}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if line.startswith(("CapInh", "CapPrm", "CapEff", "CapBnd", "NoNewPrivs")):
            key, value = line.split(":", 1)
            result[key] = value.strip()
    return result


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def report(capture: Capture, variant: str, smoke: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "variant": variant,
        "security": capability_status(),
        "events": {
            "dns": sorted(capture.dns),
            "tcp": sorted(capture.tcp),
            "tls_sni": sorted(capture.sni),
        },
        "unknown": sorted(capture.unknown),
        "capture_limitations": list(CAPTURE_LIMITATIONS),
        "capture_stats": dict(sorted(capture.stats.items())),
        "udp53": sorted(capture.udp53),
        "udp_endpoints": sorted(capture.udp_endpoints),
        "smoke": smoke,
    }


def main() -> int:
    out = Path("/out")
    variant = os.environ.get("VARIANT", "unknown")
    capture = Capture("0.0.0.0")
    try:
        capture.app_ip = interface_ip("eth0")
        sockets = []
        for interface in ("eth0", "lo"):
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((interface, 0))
            sock.setblocking(False)
            sockets.append(sock)
    except Exception as exc:
        failure = report(capture, variant, {"status": "NOT_RUN"})
        failure["unknown"] = [f"af_packet_open:{type(exc).__name__}:{exc}"]
        write_json(out / "capture.json", failure)
        (out / "capture.failed").write_text(str(exc), encoding="utf-8")
        (out / "capture.done").write_text("done\n", encoding="ascii")
        return 3

    (out / "capture.ready").write_text("ready\n", encoding="ascii")
    deadline = time.monotonic() + 45
    try:
        while time.monotonic() < deadline:
            if (out / "smoke.done").exists():
                drain_until = time.monotonic() + 1
                while time.monotonic() < drain_until:
                    receive_available(sockets, capture, 0.1)
                break
            receive_available(sockets, capture, 0.2)
        else:
            capture.unknown.add("capture_timeout")
        smoke_path = out / "smoke.json"
        smoke = (
            json.loads(smoke_path.read_text(encoding="utf-8"))
            if smoke_path.exists()
            else {"status": "MISSING"}
        )
        write_json(out / "capture.json", report(capture, variant, smoke))
        (out / "capture.done").write_text("done\n", encoding="ascii")
        return int(smoke.get("rc", 2))
    finally:
        for sock in sockets:
            sock.close()


if __name__ == "__main__":
    sys.exit(main())
