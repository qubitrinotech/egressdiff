# EgressDiff

EgressDiff is a local CLI for comparing outbound network destinations between two versions of a Docker Compose application.

It runs the same smoke scenario against a baseline and a candidate, records DNS names, TCP destinations, and TLS SNI, and produces JSON and Markdown reports. New destinations require an explicit approval.

**Current status:** an experimental synthetic proof of concept, not a general-purpose network monitor.

## Requirements

- Linux.
- Docker Engine with Docker Compose v2.
- Python 3.12 or newer.
- `uv`.
- Access to the pinned container base image during the first build.

Use a local Docker daemon and trusted synthetic fixtures only. Do not run this version against production.

## Quickstart

From the repository root:

```bash
uv sync --frozen
uv run --frozen --no-sync python scripts/prove_synthetic.py
```

The proof runs seven local captures and checks the baseline/candidate diff, approval flow, repeatable results, cleanup, secret redaction, and unsupported-path reporting. No real telemetry service is contacted.

Expected final markers include:

```text
NEW_COUNT=1
CHECK_BEFORE_RC=1
CHECK_AFTER_RC=0
CHECK_NEGATIVE_RC=2
CLEANUP_OK=1
SYNTHETIC_PROOF_OK=1
```

## Manual baseline/candidate workflow

Each output directory must be new or empty. These commands use a fresh temporary directory:

```bash
work="$(mktemp -d)"

uv run --frozen --no-sync egressdiff capture \
  --fixture-dir fixtures/synthetic \
  --variant baseline \
  --out "$work/baseline"

uv run --frozen --no-sync egressdiff capture \
  --fixture-dir fixtures/synthetic \
  --variant candidate \
  --out "$work/candidate"

uv run --frozen --no-sync egressdiff diff \
  --baseline "$work/baseline/capture.json" \
  --candidate "$work/candidate/capture.json" \
  --out "$work/diff"
```

Review `$work/diff/diff.md`, then apply an initially empty policy:

```bash
uv run --frozen --no-sync egressdiff check \
  --diff "$work/diff/diff.json" \
  --policy "$work/policy.json" \
  --out "$work/check-before"
```

The synthetic candidate adds `tls-sni://telemetry.example:9443`, so this check reports `REVIEW_REQUIRED` and exits with code `1`.

If the destination is expected, approve that exact key and run the check again:

```bash
uv run --frozen --no-sync egressdiff approve \
  --diff "$work/diff/diff.json" \
  --key "tls-sni://telemetry.example:9443" \
  --policy "$work/policy.json"

uv run --frozen --no-sync egressdiff check \
  --diff "$work/diff/diff.json" \
  --policy "$work/policy.json" \
  --out "$work/check-after"
```

The second check reports `PASS` and exits with code `0`.

For `check`, exit code `2` means `UNKNOWN`. An `UNKNOWN` result is not evidence that a connection is absent.

Use `uv run --frozen --no-sync egressdiff --help` for the command summary.

## How it works

A capture sidecar shares the application container's network namespace and reads frames through `AF_PACKET`. It runs as root only inside the synthetic capture container, with all capabilities dropped except `CAP_NET_RAW`, a read-only root filesystem, and `no-new-privileges`.

The sidecar records connection metadata, not application payloads. TLS is not intercepted or decrypted. Host networking, host PID mode, privileged containers, and Docker socket mounts are not used by the capture sidecar.

## Limits

- The current proof covers one application service and only the paths executed by the smoke scenario.
- IPv6, non-DNS UDP such as QUIC-shaped traffic, and unsupported multi-service paths are reported as `UNKNOWN` where observed.
- Direct TCP/IP destinations, DNS questions, and TLS ClientHello SNI are supported within the synthetic fixture.
- The tool does not determine whether a destination is malicious or benign.
- It is not a firewall, a software supply-chain scanner, or a privacy certification.

The fixtures contain a self-signed certificate and matching private key solely for the local `telemetry.example` service. They are disposable public test fixtures; never reuse them for real systems.

## Development

```bash
uv run --frozen --no-sync ruff format --check .
uv run --frozen --no-sync ruff check .
uv run --frozen --no-sync pytest
```

## License

MIT. See `LICENSE`.
