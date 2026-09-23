# xmip-core-library-tls

TLS for every transport that needs it: a connection this node opens, one it
answers, and one upgraded in place where a protocol negotiates first
(STARTTLS, STLS, FTPS). The certificate and the trust store are here; when to
upgrade and what to send before the handshake stay with the protocol.

**Hybrid first.** The key exchange offers X25519MLKEM768 — X25519 and
ML-KEM-768 together — ahead of X25519, P-256 and P-384, so a session is as
safe as the stronger of the two and a recording kept for a quantum computer
is no easier to read later than it is today. A peer that knows only classical
groups is served with X25519, and the handshake says which was agreed.
ADR-0033, amended 2026-09-22.

Until 2026-09-23 TLS sat inside `xmip-core-transport-http`, so the transports
riding on HTTP could reach it and the twenty that do not — SMTP and IMAP with
STARTTLS, MQTT, AMQP, Kafka, the databases, syslog — could not; four mapped
their `https` URLs to a stack they had no way to load.

`architecture.toml` carries the maturity.
