# rustls-platform-verifier

The broker verifies TLS for protected targets with `rustls-platform-verifier`. Verified by reading
the 0.7.1 source (with `rustls-native-certs` 0.8.4 and `openssl-probe` 0.2.1) on 2026-10-04.

## What we rely on

- The crate reads **no environment variables** itself.
- macOS uses Security.framework trust evaluation and Windows the CryptoAPI chain engine; neither
  path reads `SSL_CERT_*`.
- **Linux** calls `rustls_native_certs::load_native_certs()`, which honours `SSL_CERT_FILE` and
  `SSL_CERT_DIR`. If either is set, they **replace** the system store instead of adding to it
  (`rustls-native-certs` `src/lib.rs:47-58,118-125`). That's why the broker drops inherited TLS
  variables ([[claude-code-client]]: a settings `env` block can set them).
- Extra roots: `Verifier::new_with_extra_roots(roots, provider)` adds to system trust on every
  platform (not Android). This is how a user-level corporate CA bundle is applied.

## Sources

- crate source, `src/verification/{others,apple,windows}.rs`, read 2026-10-04
