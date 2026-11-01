# Secure Inline Communication Channel — Submission Report

## Objective

The objective was to implement a Linux/C prototype that protects selected
TCP/IPv4 communication along `PC1 → Device1 → Device2 → PC2`. Device1 and
Device2 must agree on a session key with Diffie–Hellman, encrypt only TCP
payloads with AES-GCM, preserve the native packet headers, add only the GCM tag,
and restore a valid original packet at the receiver.

## Implementation

The devices operate as Linux routers. nftables selects a configurable TCP
service and sends matching forwarded packets to user space through
libnetfilter_queue. The program is written in C17 and uses OpenSSL 3 EVP APIs.

Before packet processing, Device1 and Device2 perform an ephemeral RFC 7919
FFDHE2048 exchange. HKDF-SHA256 derives separate AES-256 keys and 32-bit nonce
prefixes for each direction. Finished HMACs confirm the shared schedule. A
pre-shared key can be configured to protect the unauthenticated DH exchange
against a man-in-the-middle.

For a data packet, the original IP and TCP headers stay visible. Their stable
fields are authenticated as GCM associated data. Only the TCP payload is
encrypted, and a 16-byte tag is appended. The IPv4 length and IPv4/TCP
checksums are recalculated for the protected hop. Device2 verifies the tag,
decrypts, removes the tag, restores the original length/checksums, and forwards
the packet to PC2. The response path uses independent keys and counters.

## Nonce strategy

Every nonce is 96 bits: a directional 32-bit prefix from HKDF followed by a
monotonic 64-bit counter. A counter is reserved once and never reused, including
for TCP retransmissions. It is implicit rather than transmitted, preserving the
required absence of a custom protocol header. A bounded verification/replay
window tolerates limited loss and reordering and rejects duplicates.

## Validation

The test suite includes an official AES-256-GCM vector, encryption/decryption,
ciphertext/tag/header tamper rejection, IPv4/TCP checksum validation,
out-of-order delivery, replay rejection, and a real two-party FFDHE2048
handshake. ASan/UBSan builds check memory and undefined behavior.

A privileged integration test creates four Linux network namespaces matching
the required topology. It runs a bidirectional HTTP exchange and verifies that
the application plaintext marker does not appear on the inter-device capture.

## Result

The prototype satisfies the requested data-plane format: native TCP/IPv4
headers, AES-GCM ciphertext, and exactly one appended 16-byte tag—without UDP
encapsulation or a custom data header. It also adds replay protection, header
authentication, optional handshake authentication, strict configuration
validation, fail-closed firewall behavior, automated tests, and reproducible
Linux setup/cleanup scripts.
