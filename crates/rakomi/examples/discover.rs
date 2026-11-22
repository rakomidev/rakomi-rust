//! Prints what discovery finds for an issuer: `cargo run --example discover -- https://api.rakomi.com`

fn main() -> Result<(), rakomi::Error> {
    let issuer = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://api.rakomi.com".to_owned());
    let discovery = rakomi::discover(&issuer)?;
    let m = &discovery.metadata;
    println!("issuer:                 {}", m.issuer);
    println!("authorization_endpoint: {}", m.authorization_endpoint);
    if let Some(token) = &m.token_endpoint {
        println!("token_endpoint:         {token}");
    }
    println!("jwks_uri:               {}", m.jwks_uri);
    for key in &discovery.jwks.keys {
        println!(
            "key: kty={} kid={} alg={}",
            key.kty,
            key.kid.as_deref().unwrap_or("-"),
            key.alg.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}
