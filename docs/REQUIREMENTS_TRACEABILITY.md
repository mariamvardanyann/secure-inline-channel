# Requirements Traceability Matrix

| Assignment requirement | Design/code evidence | Test evidence |
|---|---|---|
| Linux-based prototype | `src/nfqueue.c`, `scripts/setup_device.sh` | `tests/test_integration.sh` uses four Linux namespaces |
| PC1 → Device1 → Device2 → PC2 | Routing/namespaces in integration script; architecture document | End-to-end HTTP request across all four nodes |
| Process selected TCP/IPv4 | nftables matches IPv4/TCP and configurable service port | HTTP port 8080 selected; ICMP/control traffic is outside queue |
| Secure session before protected transmission | `main.c` calls `sic_handshake_run` before `sic_nfqueue_run`; queue has no bypass | Daemons must log session and queue readiness before curl |
| Diffie–Hellman key exchange | `generate_dh_key`, `derive_secret` in `src/handshake.c`; named `ffdhe2048` | Unit test verifies directional keys; daemon smoke test verifies matching session IDs |
| Encrypt only TCP payload | `sic_packet_encrypt` starts at `ip_hlen + tcp_hlen` | Round-trip test confirms headers remain and payload changes |
| AES-GCM | OpenSSL `AES-256-GCM` in `src/crypto.c` | NIST empty-message vector plus positive round trip |
| Preserve IP/TCP headers | Packet transform copies header bytes; only required length/checksums change | Round-trip byte equality and checksum validation |
| Append authentication tag | `SIC_GCM_TAG_LEN` is 16; tag copied after ciphertext | Encrypted size equals plaintext packet size + 16 |
| No UDP encapsulation | `nfq_set_verdict` reinjects modified native packet; no UDP socket/data path | tcpdump filter observes native TCP port 8080 |
| No custom protocol header | Data-plane layout has ciphertext followed only by tag | Encrypted size test confirms exactly +16 bytes |
| Verify tag before decrypt/forward | `EVP_CTRL_GCM_SET_TAG` then `EVP_DecryptFinal_ex`; failure yields drop | Ciphertext and tag tamper tests both fail |
| Restore original packet | Decrypt removes exactly 16 bytes and restores IP length | Decrypted packet equals original packet byte-for-byte in unit test |
| Recalculate IPv4 checksum | `sic_ipv4_checksum`, `update_lengths_and_checksums` | Checksum validator before/after both transformations |
| Recalculate TCP checksum | Pseudo-header implementation in `sic_tcp_checksum` | Checksum validator before/after both transformations |
| Unique GCM nonce per packet | directional HKDF prefix + atomic 64-bit monotonic counter | Nonce layout/counter test; retransmissions allocate a new counter |
| Replay protection (hardening) | bitmap window in `src/crypto.c` | Reordered packets accepted once; duplicate rejected |
| Header integrity (hardening) | canonical IP/TCP headers used as GCM AAD | TCP destination-port tamper is rejected |
| Linux configuration scripts | install, setup, cleanup, PSK scripts | `bash -n`/optional ShellCheck; namespace integration uses setup script |
| Makefile | build, test, sanitizer, install, package targets | `make test`, `make sanitize`, daemon syntax check |
| README/run instructions | `README.md` and `docs/` | Commands and expected outcomes documented |
| Automated tests | C unit runner and shell integration test | Unit, ASan/UBSan, full namespace path |
| Submission ZIP | `scripts/create_submission_zip.sh`, `make package` | ZIP listing and checksum verified before delivery |
