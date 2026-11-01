# Oral Defense Guide

## One-minute explanation

“The two devices are Linux routers, not TCP proxies. They first perform an
ephemeral FFDHE2048 handshake and derive separate AES-256-GCM keys and nonce
prefixes for both directions using HKDF-SHA256. nftables sends only the selected
TCP flow to NFQUEUE. Device1 keeps the IP and TCP headers, encrypts only the TCP
payload, appends the 16-byte GCM tag, recalculates length and checksums, and
reinjects the same native packet. Device2 authenticates the headers and
ciphertext, removes the tag, decrypts, restores the length/checksums, and
forwards it. The nonce is an implicit per-session directional prefix plus a
monotonic 64-bit counter, so no custom header is needed.”

## Likely questions

### Why do you use two AES keys?

To separate the two traffic directions. Both counters may start at zero without
ever reusing the same key/nonce pair, and a compromise/mistake in one direction
does not create a cross-direction nonce collision.

### How is the nonce unique if it is not inside the packet?

Each direction has an HKDF-derived 4-byte session prefix and a 64-bit counter.
The sender increments the counter once per encryption and refuses wrap. The
receiver finds the counter by trying a bounded unused window and accepting only
the value whose GCM tag verifies.

### What about TCP retransmissions?

They are new packets entering the encrypt queue and receive new counter values.
Even if their plaintext and TCP sequence number are identical, their nonces and
ciphertexts differ.

### Why can the tag be added without changing TCP sequence numbers?

The extra 16 bytes exist only between Device1 and Device2. Device2 removes them
before the destination TCP stack sees the packet. Both endpoints still see the
original payload length and sequence space.

### Which header fields change?

The content fields are preserved. Device1 changes IPv4 total length and both
checksums because the tag changes packet length. Device2 restores the original
length and recomputes checksums. TTL also changes normally at router hops.

### Are headers protected?

Yes. They are not encrypted, but stable header fields are AES-GCM AAD. A change
to addresses, ports, sequence numbers, flags, or options makes authentication
fail. TTL/checksums are normalized because routers legitimately change them.

### Why use a PSK if the assignment asks for Diffie–Hellman?

Diffie–Hellman still creates the shared session secret and forward secrecy. The
PSK only authenticates the handshake, fixing DH's man-in-the-middle weakness.
It is optional, but recommended.

### Why FFDHE2048 instead of inventing `p`, `g`, and arithmetic?

It is a standardized RFC 7919 finite-field group with validated OpenSSL
implementation. This avoids weak parameters, overflow, side-channel-prone
home-made big-integer code, and invalid public values.

### Why NFQUEUE?

It is the Linux interface designed to send kernel-filtered packets to user
space and accept, drop, or reinject modified packets. It lets the prototype use
normal Linux routing without UDP or another tunnel.

### What happens if authentication fails?

The packet is dropped. Plaintext is never forwarded before `EVP_DecryptFinal`
confirms the GCM tag.

### What happens before the handshake finishes?

The daemon has not opened its queues, and nftables has no `bypass` flag, so the
selected protected payload does not pass unencrypted. Processing starts only
after both finished HMACs verify.

### Why reject fragmentation?

Non-initial IPv4 fragments do not contain the TCP port, so a simple port rule
could miss them. Dropping selected-path fragments prevents bypass and keeps
packet transformation unambiguous.

### What is the main limitation?

Because a custom header is forbidden, the packet counter is implicit. Very
large packet loss/reordering outside the configured window causes drops. A
production design would normally transmit authenticated sequence metadata or
use a standardized protocol such as IPsec.
