from __future__ import annotations


def normalize(report: dict[str, object]) -> list[dict[str, object]]:
    events = report["events"]
    dns = set(events["dns"])
    tcp = set(events["tcp"])
    sni = set(events["tls_sni"])
    service = str(report.get("service", "app"))
    result: dict[str, dict[str, object]] = {}
    sni_names = set()
    sni_targets = set()

    for item in sorted(sni):
        name, target = item.rsplit("@", 1)
        _, port = target.rsplit(":", 1)
        sni_names.add(name)
        sni_targets.add(target)
        evidence = ["TLS-SNI"]
        if name in dns:
            evidence.insert(0, "DNS")
        if target in tcp:
            evidence.insert(-1, "TCP")
        key = f"tls-sni://{name}:{port}"
        result[key] = {
            "key": key,
            "service": service,
            "kind": "tls-sni",
            "name": name,
            "port": int(port),
            "address": target,
            "evidence": evidence,
        }

    for name in sorted(dns - sni_names):
        key = f"dns://{name}"
        result[key] = {
            "key": key,
            "service": service,
            "kind": "dns",
            "name": name,
            "evidence": ["DNS"],
        }
    for target in sorted(tcp - sni_targets):
        key = f"tcp://{target}"
        result[key] = {
            "key": key,
            "service": service,
            "kind": "tcp",
            "address": target,
            "evidence": ["TCP"],
        }
    return [result[key] for key in sorted(result)]
