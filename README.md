# Rakomi for Rust

Rust crates for [Rakomi](https://rakomi.com).

| Crate | What it does |
|---|---|
| [`rakomi`](crates/rakomi) | OpenID Connect discovery and JSON Web Key Set retrieval |
| [`rakomi-sdk`](crates/rakomi-sdk) | Re-exports `rakomi`; nothing of its own yet |

```rust,no_run
let discovery = rakomi::discover("https://api.rakomi.com")?;
# Ok::<(), rakomi::Error>(())
```

Run the example against an issuer:

```sh
cargo run --example discover -- https://api.rakomi.com
```

Minimum supported Rust version: 1.85. Both crates are at `0.1`; the API may change between `0.x` minor
versions.

Security reports: see [SECURITY.md](SECURITY.md).

Licensed under the [MIT License](LICENSE).
