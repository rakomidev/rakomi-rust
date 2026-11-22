# rakomi-sdk

Rakomi SDK for Rust.

This crate currently re-exports the [`rakomi`](https://crates.io/crates/rakomi) crate and adds nothing of its
own: today it gives you OpenID Connect discovery and JSON Web Key Set retrieval, nothing more. If that is
all you need, depending on `rakomi` directly is equivalent.

```toml
[dependencies]
rakomi-sdk = "0.1"
```

```rust,no_run
let discovery = rakomi_sdk::discover("https://api.rakomi.com")?;
println!("issuer: {}", discovery.metadata.issuer);
# Ok::<(), rakomi_sdk::Error>(())
```

## Status

Version 0.1. The API may change between `0.x` minor versions.

## License

MIT, see [LICENSE](https://github.com/rakomidev/rakomi-rust/blob/main/LICENSE).
