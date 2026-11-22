//! OpenID Connect discovery and JWKS retrieval.
//!
//! [`discover`] fetches an OpenID Provider's configuration from
//! `{issuer}/.well-known/openid-configuration`, checks it, and then fetches the JSON Web Key Set the
//! configuration names in `jwks_uri`.
//!
//! The checks applied:
//!
//! - the issuer and every endpoint URL in the configuration use `https`;
//! - the issuer has no query and no fragment;
//! - the `issuer` value in the configuration is exactly the issuer you asked for
//!   (OpenID Connect Discovery 1.0, section 4.3);
//! - the fields that specification requires are present and non-empty, and `token_endpoint` is
//!   present when the provider supports a response type that includes `code`;
//! - the key set holds at least one key, and every key has a `kty`;
//! - each request has a timeout, follows no redirects and reads at most 1 MiB.
//!
//! This crate does not verify tokens.
//!
//! ```no_run
//! let discovery = rakomi::discover("https://api.rakomi.com")?;
//! println!("token endpoint: {:?}", discovery.metadata.token_endpoint);
//! println!("{} signing keys", discovery.jwks.keys.len());
//! # Ok::<(), rakomi::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Timeout [`discover`] applies to each request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest response body read, in bytes.
pub const MAX_BODY_BYTES: u64 = 1024 * 1024;

const WELL_KNOWN_PATH: &str = "/.well-known/openid-configuration";

/// The result of [`discover`]: the provider configuration and its key set.
#[derive(Debug, Clone, PartialEq)]
pub struct Discovery {
    /// The provider configuration.
    pub metadata: ProviderMetadata,
    /// The key set fetched from [`ProviderMetadata::jwks_uri`].
    pub jwks: Jwks,
}

/// OpenID Provider configuration (OpenID Connect Discovery 1.0, section 3).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProviderMetadata {
    /// The issuer identifier.
    pub issuer: String,
    /// URL of the authorization endpoint.
    pub authorization_endpoint: String,
    /// URL of the token endpoint.
    pub token_endpoint: Option<String>,
    /// URL of the JSON Web Key Set.
    pub jwks_uri: String,
    /// URL of the UserInfo endpoint.
    pub userinfo_endpoint: Option<String>,
    /// URL of the token revocation endpoint (RFC 7009).
    pub revocation_endpoint: Option<String>,
    /// URL of the end-session (logout) endpoint.
    pub end_session_endpoint: Option<String>,
    /// Supported `response_type` values.
    pub response_types_supported: Vec<String>,
    /// Supported subject identifier types.
    pub subject_types_supported: Vec<String>,
    /// Supported ID token signing algorithms.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported scopes.
    pub scopes_supported: Option<Vec<String>>,
    /// Supported grant types.
    pub grant_types_supported: Option<Vec<String>>,
    /// Every other member of the configuration, unchecked.
    pub other: Map<String, Value>,
}

#[derive(Deserialize)]
struct RawMetadata {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    jwks_uri: Option<String>,
    userinfo_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    response_types_supported: Option<Vec<String>>,
    subject_types_supported: Option<Vec<String>>,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
    scopes_supported: Option<Vec<String>>,
    grant_types_supported: Option<Vec<String>>,
    #[serde(flatten)]
    other: Map<String, Value>,
}

impl ProviderMetadata {
    /// Parses and checks a provider configuration document that was published for `expected_issuer`.
    pub fn from_json(expected_issuer: &str, body: &str) -> Result<Self, Error> {
        validate_issuer(expected_issuer)?;
        let raw: RawMetadata = serde_json::from_str(body).map_err(|e| Error::Json {
            document: Document::Configuration,
            source: Box::new(e),
        })?;

        let issuer = required_string(raw.issuer, "issuer")?;
        if issuer != expected_issuer {
            return Err(Error::IssuerMismatch {
                expected: expected_issuer.to_owned(),
                actual: issuer,
            });
        }
        let authorization_endpoint =
            required_string(raw.authorization_endpoint, "authorization_endpoint")?;
        let jwks_uri = required_string(raw.jwks_uri, "jwks_uri")?;
        let response_types_supported =
            required_list(raw.response_types_supported, "response_types_supported")?;
        let subject_types_supported =
            required_list(raw.subject_types_supported, "subject_types_supported")?;
        let id_token_signing_alg_values_supported = required_list(
            raw.id_token_signing_alg_values_supported,
            "id_token_signing_alg_values_supported",
        )?;

        let needs_token_endpoint = response_types_supported
            .iter()
            .any(|t| t.split(' ').any(|part| part == "code"));
        if needs_token_endpoint && raw.token_endpoint.is_none() {
            return Err(Error::MissingField {
                document: Document::Configuration,
                field: "token_endpoint",
            });
        }

        let urls = [
            ("authorization_endpoint", Some(&authorization_endpoint)),
            ("jwks_uri", Some(&jwks_uri)),
            ("token_endpoint", raw.token_endpoint.as_ref()),
            ("userinfo_endpoint", raw.userinfo_endpoint.as_ref()),
            ("revocation_endpoint", raw.revocation_endpoint.as_ref()),
            ("end_session_endpoint", raw.end_session_endpoint.as_ref()),
        ];
        for (field, value) in urls {
            if let Some(url) = value {
                if !is_https_url(url) {
                    return Err(Error::InsecureUrl { field });
                }
            }
        }

        Ok(Self {
            issuer,
            authorization_endpoint,
            token_endpoint: raw.token_endpoint,
            jwks_uri,
            userinfo_endpoint: raw.userinfo_endpoint,
            revocation_endpoint: raw.revocation_endpoint,
            end_session_endpoint: raw.end_session_endpoint,
            response_types_supported,
            subject_types_supported,
            id_token_signing_alg_values_supported,
            scopes_supported: raw.scopes_supported,
            grant_types_supported: raw.grant_types_supported,
            other: raw.other,
        })
    }
}

/// A JSON Web Key Set (RFC 7517, section 5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Jwks {
    /// The keys in the set.
    pub keys: Vec<Jwk>,
}

/// A JSON Web Key (RFC 7517, section 4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type, such as `RSA` or `EC`.
    pub kty: String,
    /// Key identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Algorithm the key is meant for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Intended use (`sig` or `enc`).
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// The key's other parameters (for example `n` and `e`, or `crv`, `x` and `y`).
    #[serde(flatten)]
    pub params: Map<String, Value>,
}

impl Jwks {
    /// Parses and checks a JSON Web Key Set document.
    pub fn from_json(body: &str) -> Result<Self, Error> {
        let jwks: Jwks = serde_json::from_str(body).map_err(|e| Error::Json {
            document: Document::KeySet,
            source: Box::new(e),
        })?;
        if jwks.keys.is_empty() {
            return Err(Error::EmptyKeySet);
        }
        Ok(jwks)
    }
}

/// Fetches and checks the provider configuration of `issuer` and its key set, waiting at most
/// [`DEFAULT_TIMEOUT`] for each request.
pub fn discover(issuer: &str) -> Result<Discovery, Error> {
    discover_with_timeout(issuer, DEFAULT_TIMEOUT)
}

/// Like [`discover`], with a timeout of your choice for each request.
pub fn discover_with_timeout(issuer: &str, timeout: Duration) -> Result<Discovery, Error> {
    let config_url = configuration_url(issuer)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(timeout))
        .user_agent(concat!("rakomi-rust/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();

    let body = fetch(&agent, &config_url)?;
    let metadata = ProviderMetadata::from_json(issuer, &body)?;
    let body = fetch(&agent, &metadata.jwks_uri)?;
    let jwks = Jwks::from_json(&body)?;
    Ok(Discovery { metadata, jwks })
}

/// The URL of the configuration document of `issuer`.
pub fn configuration_url(issuer: &str) -> Result<String, Error> {
    validate_issuer(issuer)?;
    Ok(format!(
        "{}{}",
        issuer.strip_suffix('/').unwrap_or(issuer),
        WELL_KNOWN_PATH
    ))
}

/// Checks that `issuer` is an `https` URL with a host and without a query or fragment.
pub fn validate_issuer(issuer: &str) -> Result<(), Error> {
    if !is_https_url(issuer) {
        return Err(Error::InvalidIssuer(
            "the issuer must be an https URL with a host",
        ));
    }
    if issuer.contains('?') || issuer.contains('#') {
        return Err(Error::InvalidIssuer(
            "the issuer must not have a query or a fragment",
        ));
    }
    Ok(())
}

fn fetch(agent: &ureq::Agent, url: &str) -> Result<String, Error> {
    let http_err = |e: ureq::Error| Error::Http {
        url: url.to_owned(),
        source: Box::new(e),
    };
    let mut response = agent
        .get(url)
        .header("Accept", "application/json")
        .call()
        .map_err(http_err)?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(Error::UnexpectedStatus {
            url: url.to_owned(),
            status,
        });
    }
    response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_string()
        .map_err(http_err)
}

fn is_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..host_end];
    !authority.is_empty()
        && !authority.contains('@')
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn required_string(value: Option<String>, field: &'static str) -> Result<String, Error> {
    match value {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(Error::MissingField {
            document: Document::Configuration,
            field,
        }),
    }
}

fn required_list(value: Option<Vec<String>>, field: &'static str) -> Result<Vec<String>, Error> {
    match value {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(Error::MissingField {
            document: Document::Configuration,
            field,
        }),
    }
}

/// Which document an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Document {
    /// The provider configuration.
    Configuration,
    /// The JSON Web Key Set.
    KeySet,
}

impl fmt::Display for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Document::Configuration => "provider configuration",
            Document::KeySet => "key set",
        })
    }
}

/// Why discovery failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The issuer given is not acceptable.
    InvalidIssuer(&'static str),
    /// A URL in the configuration does not use `https`.
    InsecureUrl {
        /// The configuration field holding the URL.
        field: &'static str,
    },
    /// The configuration names an issuer other than the one requested.
    IssuerMismatch {
        /// The issuer requested.
        expected: String,
        /// The issuer in the configuration.
        actual: String,
    },
    /// A required field is missing or empty.
    MissingField {
        /// The document.
        document: Document,
        /// The field.
        field: &'static str,
    },
    /// The key set holds no keys.
    EmptyKeySet,
    /// A document is not valid JSON of the expected shape.
    Json {
        /// The document.
        document: Document,
        /// The parse error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The request failed: connection, TLS, timeout, error status or body too large.
    Http {
        /// The URL requested.
        url: String,
        /// The underlying error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The server answered with a status other than 200.
    UnexpectedStatus {
        /// The URL requested.
        url: String,
        /// The status code.
        status: u16,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidIssuer(reason) => write!(f, "invalid issuer: {reason}"),
            Error::InsecureUrl { field } => write!(f, "`{field}` is not an https URL"),
            Error::IssuerMismatch { expected, actual } => write!(
                f,
                "the configuration names issuer `{actual}`, expected `{expected}`"
            ),
            Error::MissingField { document, field } => {
                write!(f, "the {document} lacks the required field `{field}`")
            }
            Error::EmptyKeySet => f.write_str("the key set holds no keys"),
            Error::Json { document, source } => write!(f, "invalid {document}: {source}"),
            Error::Http { url, source } => write!(f, "request to {url} failed: {source}"),
            Error::UnexpectedStatus { url, status } => {
                write!(f, "request to {url} answered with status {status}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Json { source, .. } | Error::Http { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://auth.example.com";

    fn metadata() -> Value {
        json!({
            "issuer": ISSUER,
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/oauth/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "userinfo_endpoint": "https://auth.example.com/userinfo",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "email"],
            "code_challenge_methods_supported": ["S256"]
        })
    }

    fn parse(value: &Value) -> Result<ProviderMetadata, Error> {
        ProviderMetadata::from_json(ISSUER, &value.to_string())
    }

    #[test]
    fn parses_valid_configuration() {
        let m = parse(&metadata()).unwrap();
        assert_eq!(m.issuer, ISSUER);
        assert_eq!(
            m.token_endpoint.as_deref(),
            Some("https://auth.example.com/oauth/token")
        );
        assert_eq!(m.id_token_signing_alg_values_supported, ["RS256"]);
        assert_eq!(
            m.other.get("code_challenge_methods_supported"),
            Some(&json!(["S256"]))
        );
    }

    #[test]
    fn refuses_other_issuer() {
        let mut v = metadata();
        v["issuer"] = json!("https://evil.example.com");
        assert!(matches!(parse(&v), Err(Error::IssuerMismatch { .. })));
    }

    #[test]
    fn issuer_comparison_is_exact() {
        let mut v = metadata();
        v["issuer"] = json!("https://auth.example.com/");
        assert!(matches!(parse(&v), Err(Error::IssuerMismatch { .. })));
    }

    #[test]
    fn refuses_missing_required_fields() {
        for field in [
            "issuer",
            "authorization_endpoint",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
            "token_endpoint",
        ] {
            let mut v = metadata();
            v.as_object_mut().unwrap().remove(field);
            match parse(&v) {
                Err(Error::MissingField { field: f, .. }) => assert_eq!(f, field),
                other => panic!("{field}: {other:?}"),
            }
        }
    }

    #[test]
    fn refuses_empty_required_list() {
        let mut v = metadata();
        v["subject_types_supported"] = json!([]);
        assert!(matches!(
            parse(&v),
            Err(Error::MissingField {
                field: "subject_types_supported",
                ..
            })
        ));
    }

    #[test]
    fn token_endpoint_optional_without_code() {
        let mut v = metadata();
        v["response_types_supported"] = json!(["id_token"]);
        v.as_object_mut().unwrap().remove("token_endpoint");
        assert!(parse(&v).unwrap().token_endpoint.is_none());
    }

    #[test]
    fn refuses_non_https_endpoint() {
        for field in ["jwks_uri", "token_endpoint", "userinfo_endpoint"] {
            let mut v = metadata();
            v[field] = json!("http://auth.example.com/x");
            match parse(&v) {
                Err(Error::InsecureUrl { field: f }) => assert_eq!(f, field),
                other => panic!("{field}: {other:?}"),
            }
        }
    }

    #[test]
    fn refuses_invalid_json() {
        assert!(matches!(
            ProviderMetadata::from_json(ISSUER, "not json"),
            Err(Error::Json {
                document: Document::Configuration,
                ..
            })
        ));
    }

    #[test]
    fn validates_issuer() {
        assert!(validate_issuer("https://auth.example.com").is_ok());
        assert!(validate_issuer("https://auth.example.com/tenant").is_ok());
        for bad in [
            "http://auth.example.com",
            "https://",
            "https:///path",
            "https://auth.example.com?x=1",
            "https://auth.example.com#f",
            "https://user@auth.example.com",
            "https://auth.example.com/a b",
            "auth.example.com",
        ] {
            assert!(
                matches!(validate_issuer(bad), Err(Error::InvalidIssuer(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn builds_configuration_url() {
        assert_eq!(
            configuration_url("https://auth.example.com").unwrap(),
            "https://auth.example.com/.well-known/openid-configuration"
        );
        assert_eq!(
            configuration_url("https://auth.example.com/tenant/").unwrap(),
            "https://auth.example.com/tenant/.well-known/openid-configuration"
        );
        assert!(configuration_url("http://auth.example.com").is_err());
    }

    #[test]
    fn parses_key_set() {
        let body = json!({"keys": [{
            "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": "abc", "e": "AQAB"
        }]})
        .to_string();
        let jwks = Jwks::from_json(&body).unwrap();
        let key = &jwks.keys[0];
        assert_eq!(key.kty, "RSA");
        assert_eq!(key.kid.as_deref(), Some("k1"));
        assert_eq!(key.use_.as_deref(), Some("sig"));
        assert_eq!(key.params.get("e"), Some(&json!("AQAB")));
    }

    #[test]
    fn refuses_empty_key_set() {
        assert!(matches!(
            Jwks::from_json(r#"{"keys": []}"#),
            Err(Error::EmptyKeySet)
        ));
    }

    #[test]
    fn refuses_key_without_kty() {
        assert!(matches!(
            Jwks::from_json(r#"{"keys": [{"kid": "k1"}]}"#),
            Err(Error::Json {
                document: Document::KeySet,
                ..
            })
        ));
    }
}
