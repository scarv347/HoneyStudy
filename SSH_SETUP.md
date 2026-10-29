# SSH honeypot: Cowrie

HoneyStudy includes the adapter and analysis for SSH observations. The SSH server simulation itself is provided by [Cowrie](https://github.com/cowrie/cowrie), a separate project under its own license; it is not copied into this repository.

## Try Cowrie locally

With Docker installed, use the upstream image bound to loopback:

```sh
docker run --name honeystudy-cowrie -p 127.0.0.1:2222:2222 cowrie/cowrie:latest
```

From another terminal:

```sh
ssh -p 2222 root@127.0.0.1
```

This opens a simulated SSH service on local port 2222; it does not replace your computer's administrative SSH service. Cowrie is a separate process from `demo.py`.

See [Cowrie's official Docker instructions](https://docs.cowrie.org/en/latest/docker/README.html) for configuration and persistent log storage. The `latest` image changes; pin a reviewed version or digest for repeatable deployments. This command is based on upstream documentation; the Cowrie image was not run as part of HoneyStudy's local demo checks.

## What HoneyStudy adds

- `src/cowrie_adapter.py` normalizes connection, login, command, transfer, and forwarding events from Cowrie's JSON logs. Submitted passwords are excluded from normalized dashboard records.
- `src/classification.py` adds observation categories; captured commands are treated as text, never run by HoneyStudy.
- `src/ship.py` reads Cowrie records, retains its checkpoint until the collector acknowledges delivery, and forwards to `src/hub.py`.
- The dashboard can display normalized SSH history once a sensor and private collector are configured. Raw Cowrie logs can contain sensitive content and must stay private.

The included HTTP demo uses synthetic data and does **not** automatically ingest Cowrie logs. Multi-sensor configuration and authentication are operator-supplied; do not copy credentials or network addresses from someone else's deployment. Cowrie and exposed sensors belong in an isolated lab, with administration and the collector kept private.
