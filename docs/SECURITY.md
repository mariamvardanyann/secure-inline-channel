# Security Analysis

## Security goals

The prototype aims to provide, for selected TCP/IPv4 payloads on the link
between Device1 and Device2:

- confidentiality with AES-256-GCM;
- payload and stable-header integrity;
- peer/session key agreement with ephemeral FFDHE2048;
- optional PSK-based handshake authentication;
- unique nonces per direction and session;
- replay rejection;
- fail-closed handling of invalid protected packets.

## Nonce-uniqueness argument

For one session and direction, the nonce is `prefix || counter`:

- `prefix` is a fixed 32-bit value derived for that direction by HKDF;
- `counter` starts at 0, is reserved atomically once per encryption, and never
  decreases or repeats;
- encryption stops before counter wrap;
- the opposite direction has an independently derived prefix and key;
- a new session has new ephemeral DH public values and 32-byte randoms, so its
  HKDF output changes with overwhelming probability.

Therefore, within a session—the assignment's explicit requirement—two packets
in one direction cannot use the same 96-bit nonce. A TCP retransmission is a
new encryption operation and receives a new counter.

## Replay protection

The receiver stores a bounded bitmap indexed by packet counter. A counter is
marked only after GCM authentication succeeds. A marked counter, or one older
than the replay window, is never attempted/accepted again. Authentication
failure does not advance or consume a counter, so random invalid packets cannot
force permanent desynchronization.

## Header integrity

The headers are not encrypted, as required, but their stable fields are GCM
associated data. An attacker cannot silently redirect a packet, change ports,
alter sequence/ACK numbers, or modify flags/options without tag failure.

TTL and checksum fields are excluded through normalization because legitimate
forwarding changes them. IPv4 total length is authenticated in its original
plaintext form. Source/destination NAT between the two devices is not supported
because it changes authenticated addresses.

## Handshake authentication

Ephemeral DH alone is vulnerable to an active man-in-the-middle. The optional
`psk_hex` is mixed into the HKDF salt; finished HMACs confirm both the DH secret
and the resulting transcript-bound schedule. With a strong secret PSK, an
attacker who substitutes DH values cannot produce a valid finished HMAC.

The supplied configuration value is demonstrative and must be replaced on a
real lab network. `scripts/generate_psk.sh` creates a random 256-bit value.

For a production system, replace the shared PSK scheme with certificates or
static authenticated public keys and a reviewed standard handshake such as
TLS 1.3, Noise, or IPsec/IKE.

## Fail-closed properties

- nftables queue rules do not use the `bypass` flag.
- Queue handles are created only after a successful handshake.
- Authentication and parsing errors return `NF_DROP`.
- Selected fragments are dropped before port selection can be bypassed.
- Unknown configuration keys and invalid security parameters prevent startup.
- Queue receive overflow is logged as an error; the kernel drops affected
  queued packets rather than forwarding plaintext.

## Secrets in memory

OpenSSL obtains cryptographic randomness and performs FFDHE, HKDF, HMAC, and
AES-GCM. Temporary DH secrets and derived key material use clear-free or
`OPENSSL_cleanse`. Session keys, plaintext output buffers, nonces, PSKs, and
configuration memory are cleared during cleanup. Keys are never printed.

## Explicit prototype limitations

1. **Implicit counter window.** No counter metadata is allowed in the required
   wire format. Loss/reordering larger than `counter_lookahead`/`replay_window`
   causes a drop. Increasing them improves tolerance but makes invalid-packet
   verification more CPU-intensive.
2. **No automatic rekey.** Restart both peers to establish a fresh session.
   Counter exhaustion also requires rekey, although it is infeasible in a lab.
3. **One session/selected service.** The supplied nft rules protect one TCP
   service flow class, not arbitrary multi-policy traffic.
4. **No IPv4 fragmentation.** Selected fragments are deliberately rejected.
5. **MTU overhead.** The peer link must provide 16 bytes of extra MTU or the
   endpoint path MTU must be reduced.
6. **No NAT/header-changing middlebox between devices.** Stable authenticated
   header changes fail verification.
7. **Traffic analysis remains possible.** Headers, timing, direction, and
   approximate payload lengths are visible; only payload content is encrypted.
8. **Control-plane denial of service remains possible.** An attacker can block
   the handshake or send invalid protected packets. Verification work is
   bounded but not rate-limited in this prototype.
9. **Linux-specific.** It depends on nftables, NFQUEUE, and routing behavior.

These limitations do not contradict the assignment; they make the exact scope
and engineering trade-offs explicit.
