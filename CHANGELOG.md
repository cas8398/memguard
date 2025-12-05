# Changelog

## 2.1.4

- Added Linux platform support (x86_64, glibc 2.31+).

## 2.1.3 – Initial Release

- Initial release of `memguard`.
- Flutter resource, memory, and secure storage lifecycle guard.
- Provides integration with `memguard_core` (Rust FFI) for secure memory caching.
- Automatic tiered storage: KeyStore-backed persistent storage + optional Rust in-memory cache.
- Platform channel contract ensures Kotlin → Dart returns only: `true`, `false`, `null`, or `rust_not_ready`.
- Includes example Flutter app demonstrating secure store/retrieve/delete operations.
- TODO: Expand documentation and usage examples.
