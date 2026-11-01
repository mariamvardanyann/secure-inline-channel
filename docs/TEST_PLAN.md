# Test Plan

## Test levels

### 1. Compiler and script checks

```bash
make test
make syntax-daemon
```

- C17, `-Wall -Wextra -Wpedantic -Werror`, conversion/shadow/format checks.
- All shell scripts pass `bash -n`; ShellCheck runs automatically when present.
- The real daemon build requires real OpenSSL and libnetfilter_queue packages.

### 2. Unit tests

`tests/test_runner.c` covers:

| Test | Expected result |
|---|---|
| 96-bit nonce byte layout | Prefix and big-endian 64-bit counter match specification |
| NIST AES-256-GCM vector | Expected authentication tag matches |
| AES-GCM positive round trip | Recovered bytes equal plaintext |
| Ciphertext tampering | Authentication fails |
| Tag tampering | Authentication fails |
| Packet encryption | Size grows by exactly 16; payload is not plaintext |
| Packet decryption | Output equals original packet |
| IPv4/TCP checksums | Valid before encryption, on protected packet, and after restoration |
| Reordering | Counters `1,0,2` are accepted within the window |
| Replay | A second copy of counter `0` is rejected |
| Header tamper | Modified TCP destination port fails GCM authentication |
| FFDHE2048 handshake | Client TX equals server RX and vice versa; session IDs match |
| Mismatched PSKs | Both handshake peers reject key confirmation |

### 3. Sanitizers

```bash
make sanitize
```

Builds the full unit-test target with AddressSanitizer and UndefinedBehaviorSanitizer.
LeakSanitizer is disabled because it is incompatible with some container
ptrace environments; Valgrind may be run separately when available.

### 4. Daemon handshake smoke test

```bash
make smoke
```

Starts two real `sicd` processes over loopback, completes FFDHE2048/HKDF/HMAC
confirmation, and verifies that both log the same non-secret session identifier.
It stops the daemons after confirmation, so nftables rules are not required.

### 5. Full integration

```bash
sudo ./tests/test_integration.sh
```

The script creates:

```text
sic-pc1 -- sic-d1 -- sic-d2 -- sic-pc2
```

It then:

1. Configures addresses, routes, forwarding, 1520 peer MTU, and nftables.
2. Starts an HTTP server on PC2.
3. Starts Device2 and Device1 with the same test PSK.
4. Waits for both secure sessions and NFQUEUE loops.
5. Captures the inter-device TCP packets when tcpdump exists.
6. Downloads the marker file from PC1.
7. Confirms all four transform directions are logged.
8. Confirms the plaintext marker is absent from peer-link capture.
9. Removes processes and namespaces even if a test fails.

## Negative manual tests

### Different PSKs

Set different `psk_hex` values. Expected: finished verification fails and no
NFQUEUE processing loop starts.

### Modified protected packet

Change one ciphertext/tag/header bit on the peer link. Expected: Device2 logs
an authentication failure and drops the packet.

### Daemon not running

Leave nftables rules installed but stop `sicd`. Expected: selected protected
payload traffic does not pass because no `bypass` flag is present.

### Duplicate packet

Replay a captured protected packet. Expected: its counter is already marked;
the packet is dropped.

### Fragment

Send fragmented selected IPv4/TCP traffic. Expected: nftables fragment rule
drops it before a non-initial fragment can bypass the port selector.

## Acceptance criteria

- All unit and sanitizer tests pass.
- Both handshakes derive matching directional keys without logging them.
- HTTP completes through the four-node topology.
- No application plaintext marker appears on the inter-device capture.
- Protected-packet size overhead is exactly 16 bytes.
- Header/tag/ciphertext tampering and replay are rejected.
- ZIP contains sources, scripts, tests, configs, and documentation, but no build
  artifacts or captured secrets.
