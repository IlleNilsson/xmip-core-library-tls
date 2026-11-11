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

**The protocol inside, agreed in the handshake.** ALPN, RFC 7301 (`alpn`):
`client_offering` offers the protocols a client speaks, in its order of
preference; `alpn::selecting` lets a server pick the first of its own it
was offered; `alpn::agreed` finishes the handshake on either side and says
which was chosen, or none where a side offered nothing. HTTP agrees `h2` or
`http/1.1` this way — the identifiers are HTTP's (`net::http::Version`),
not this crate's.

**Who the client is, before its content** (`peer`). `peer::answered`
finishes a server's handshake on an accepted socket and reports the
certificate its client presented, `Peer`: its subject and issuer as `Name`
writes them and its SHA-256 fingerprint (`peer::fingerprint`). `peer::authenticates_servers` says
whether a certificate's extended key usage names `serverAuth` — a node's
does, a person's does not — which the Storage wire admits by (ADR-0009,
amendment 2026-10-29). A server that
verifies clients has refused one whose chain does not reach its anchors by
then. `Name` is a distinguished name as its attributes, written in one
order, so `CN=x,O=y` and `O = y, cn = x` are one name; it moved here from
`xmip-core-authenticate` on 2026-10-19, so the name a transport writes and
the name the identity gates compare are one reading (ADR-0033, amendment
2026-10-19). `peer::handshaken` finishes the handshake the same way and says
of one that did not finish whether the client's certificate was refused —
one that does not reach the anchors, or none where one is required — or the
client merely stopped (`peer::Unanswered`), so a host tells its audit of the
first alone; `peer::presented` hands the client's leaf over whole, DER.

**A browser's key, proven to a node that did not serve it** (`possession`;
ADR-0009, amendment 2026-11-02). A web host takes its browsers' TLS and the
nodes decide who acts, so the proof is the handshake itself.
`possession::proving` is the one configuration that makes it: the host's
identity, a client's certificate asked for, no session resumed, as no
server here resumes one — a resumed session signs nothing — and a random
source that, on a thread a handshake is armed on, writes
`possession::binding` of the nodes' fresh nonces into the first 24 bytes
of every 32-byte random it draws, the `ServerHello`'s among them (rustls
0.23.46 draws one for a `HelloRetryRequest` and another for the
`ServerHello`, and in TLS 1.2 no session ID, as no session is stored; the
last 8 bytes stay random, TLS 1.2's downgrade sentinel there). `Cargo.toml`
pins that rustls exactly, because the binding holds only for the draw
order the tests pin; the pin moves with those tests. The thread is armed by
a guard that disarms it and zeroes the handshake's secrets on every way
out, a panic's unwind included, so a binding never reaches a later draw.
`possession::handshaken` makes the handshake over a recording of the
socket, and its
`Recorded::transcript` recovers the transcript after, apart from the
handshake — the handshake messages from the ClientHello through the
client's CertificateVerify — reading TLS 1.3's sealed handshake records
with the two handshake traffic secrets its own key log keeps for that one
handshake and zeroes after; they are never written, logged or kept on the
session. `possession::proved` is the node's check: the client's
CertificateVerify verified with its own certificate's key over the messages
before it, as TLS 1.3 signs them (a retried handshake's first ClientHello
as its `message_hash`) or as TLS 1.2 does, answering the client's chain,
the server's leaf and the random. Tests pin the draw order for TLS 1.3, 1.3
retried and 1.2; the timing program holds binding and recording to under a
millisecond added to a handshake, and the check to under one (about 0.15 ms
and 0.35 ms, debug build).

**A server a browser reaches.** `Identity::server_asking` presents the
identity and asks the client for a certificate, verifying one presented
against the anchors and refusing one that does not reach them, but lets a
client that presents none through: a browser may decline, and is then no
one, who only watches. A web host's HTTPS is this, through the runtime's
`xmip_operate.h` section 21 (ADR-0009, amendment 2026-10-21);
`Identity::server` refuses a client without a certificate, as everything
between Xmip's own parts does.

**A revoked client is refused** (`Revocation`, `Identity::revoking`). A
server given its authority's revocation lists refuses a client whose
certificate a list revokes, and one whose issuer published no list it holds;
every certificate on the path below the anchor is checked. The lists are
read from the file the authority keeps (`Revocation::from_file`, the
register's `authority.crl`, DER or PEM) or handed over
(`Revocation::from_lists`, changed by `replace`). Every handshake that
verifies a client looks at the file's metadata and reads the file again
only where it changed, so a revocation counts from the next handshake on;
nothing watches it, and a file gone or unreadable refuses the client. A
list past its nextUpdate refuses every client it would decide unless the
configuration says otherwise (`accepting_expired`). Every mutual-TLS
listener between Xmip's own parts is given its authority's lists; tests
refuse a revoked client and let its neighbor through, refuse every client
on an expired list and accept it where configured, read a list written
anew at the next handshake, and refuse a client revoked after its first
connection at its second, which no session resumed lets in.

**No session is resumed** (`configuration`; ADR-0033, amendment
2026-11-10). rustls resumes a session without calling the verifier: a
resumed TLS 1.3 handshake asks the client for no certificate and copies
the chain the session stored (rustls 0.23.46, `server/tls13.rs`), and a
client resuming does not look at the server's certificate again. Until
2026-11-10 the library kept rustls's defaults — a server's session cache
and two tickets after every handshake, a client's cache of 256 sessions —
so a client admitted once was admitted again after it was revoked, expired
or its anchor was taken away, for as long as it resumed. Every server and
client configuration is now built in one place, `configuration`, which
stores no session, sends no ticket and keeps none to offer, TLS 1.3 and
1.2 alike: `server_config`, `configure`, `Identity::server`,
`server_asking` and `client`, and `possession::proving`. A test reads the
library's own source and fails where any other file builds a
configuration or sets its resumption; a caller holding a `ClientConfig` or
`ServerConfig` can still set those fields, which no module does. Every
handshake is full and verifies the peer's certificate as it stands, which
taking trust back depends on. A client still keeps the key exchange group
each server chose, as rustls's cache did, so a server that takes neither
X25519MLKEM768 nor X25519 — one limited to P-256 or P-384 — asks for
another group with a `HelloRetryRequest` at the first connection only.

The price, measured by the timing program (`tests/measured/resumption.rs`,
`cargo test --test measured --all-features -- --test-threads=1`), both ends
on one thread over memory against rustls's defaults, 201 rounds each, four
runs on 2026-11-10 with the processor at 80 to 94% from other builds: a
mutual-TLS handshake 1.66 to 2.24 ms at its fastest where a resumed one
took 1.27 to 1.42 ms, 0.38 to 0.87 ms more (medians 2.37 to 3.68 ms
against 1.86 to 2.91 ms); a server authenticated alone 1.37 to 1.63 ms
where it took 1.24 to 1.49 ms, 0.07 to 0.29 ms more (medians 2.04 to 2.92
against 1.82 to 2.60 ms). The program holds the added cost, at the
fastest, under a millisecond; a run on a quiet machine is still owed, and
the more loaded the machine, the closer the mutual-TLS cost came to the
bound. A resumed TLS 1.3 handshake still agrees a fresh X25519MLKEM768
key, which is why resuming saved only the certificates' signatures and
their checks, and it takes the same one round trip as a full one. A TLS
1.2 peer pays a second round trip on top: a full TLS 1.2 handshake takes
two where a resumed one took one, milliseconds to tens of milliseconds
more to a Party across a wide-area link. It is paid once per connection;
what is sent on a connection already open pays nothing more. Tests: a
kept client configuration resumes nothing from a server of rustls's
defaults, a client of rustls's defaults is given nothing to resume in TLS
1.3 or by a TLS 1.2 session ID, a kept client is asked for its group again
only once, and the revocation test above.

**One login resumes its own session** (`login_trusting`). FTPS (RFC 4217)
opens a data connection beside its control connection for each transfer,
and a server may refuse a data connection that does not resume the control
connection's session — vsftpd's `require_ssl_reuse`, on by default.
`login_trusting` builds a client configuration for one login, trusting as
`client_trusting` does, with a session store of its own: the control
connection's handshake is full and checks the server's certificate, and the
data connections of that login resume it while the control connection they
belong to stays open, checked no more than they are. No other login and no
other connection sees the store, and a test holds it: one login's
connections full, resumed, resumed against a server of rustls's defaults,
another login's first full. The ftp transport builds one per login
(`Secured::login`, called as `Client::connect_secured` starts the login)
and guards that login's control and data connections with it; no test yet
holds a data connection to resuming against a far end that refuses one
that does not (open problem 61).

**A key it cannot read.** `Identity::from_pem` presents a chain with its PEM
key; `Identity::from_signer` presents a chain whose key its platform's
keeper holds — the Android Keystore, the Secure Enclave, Windows CNG and the
TPM — every signature the handshake needs asked of a `Sign`: ECDSA on P-256
with SHA-256, DER, the one scheme it offers. A phone's operator key never
leaves its keeper (ADR-0034, amendment 2026-10-15).

**Read on one thread, written on another** (`duplex`). `duplex::split`
finishes a connection's handshake and gives its two directions to two
threads: the `Reading` side waits on the socket holding nothing and takes
the session only to decrypt what came, the `Writing` side takes it to
encrypt and send, so a protocol that streams to its peer and listens to it
at once never waits to write behind its own waiting read. A read timeout on
the socket loses nothing of a record. The Event link between nodes
(`xmip-core-event`) runs on it.

**Loaded once.** The operating system's trust store is read the first time
a connection needs it, and a client configuration is built once per list
of protocols offered and shared by every connection after; the
cryptographic provider is built once. Until 2026-09-27 every connection
read the store and built its own configuration. A caller with its own
trust store (`client_with`) keeps its configuration the same way. No
connection resumes a session but within one login (above).
A protocol whose trust store is optional calls `client_trusting`: the
configured store where one is given, the operating system's otherwise, a
choice made here once and not in each transport; `login_trusting` makes
the same choice for one login.

Until 2026-09-23 TLS sat inside `xmip-core-transport-http`, so the transports
riding on HTTP could reach it and the twenty that do not — SMTP and IMAP with
STARTTLS, MQTT, AMQP, Kafka, the databases, syslog — could not; four mapped
their `https` URLs to a stack they had no way to load.

`architecture.toml` carries the maturity.
