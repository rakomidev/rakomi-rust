# rakomi

OpenID Connect discovery and JSON Web Key Set retrieval for Rust, for [Rakomi](https://rakomi.com) and
other OpenID providers.

```toml
[dependencies]
rakomi = "0.1"
```

```rust,no_run
let discovery = rakomi::discover("https://api.rakomi.com")?;
println!("token endpoint: {:?}", discovery.metadata.token_endpoint);
println!("{} signing keys", discovery.jwks.keys.len());
# Ok::<(), rakomi::Error>(())
```

`discover(issuer)` is blocking. It fetches `{issuer}/.well-known/openid-configuration`, then the key set
named by its `jwks_uri`, and returns an error when:

- the issuer or any endpoint URL in the configuration is not `https`, or the issuer has a query or a
  fragment;
- the `issuer` in the configuration is not exactly the issuer requested;
- a field OpenID Connect Discovery 1.0 requires is missing or empty (`token_endpoint` counts as required
  when a supported response type includes `code`);
- the key set is empty or a key has no `kty`;
- a request times out (10 seconds by default; see `discover_with_timeout`), redirects, answers with a
  status other than 200, or returns more than 1 MiB.

Requests use `ureq` with `rustls` and the Mozilla root certificates.

This crate does not verify tokens; it gives you the provider configuration and keys to verify them with.

## Status

Version 0.1. The API may change between `0.x` minor versions.

## License

MIT, see [LICENSE](https://github.com/rakomidev/rakomi-rust/blob/main/LICENSE).
