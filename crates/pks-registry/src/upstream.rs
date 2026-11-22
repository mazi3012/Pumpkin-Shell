//! The connection to the real registries (PRD FR-REG, Phase 14 step 2).
//!
//! Only three hosts are reachable, all over HTTPS with the system's trust roots
//! (rustls, aws-lc-rs). Nothing else is connected to, and nothing is followed:
//! a redirect is an error, so the mirror never fetches an address the registry
//! did not give it. The response body is limited in size.

use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Bytes;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// The only hosts the mirror downloads from.
pub const ALLOWED_HOSTS: [&str; 3] = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"];
/// The one host the mirror POSTs to: the OSV vulnerability query (PRD FR-REG check 3).
pub const OSV_HOST: &str = "api.osv.dev";
/// Largest response body accepted (a large wheel is well under this).
pub const MAX_BODY: usize = 128 * 1024 * 1024;

/// Why an upstream request failed. Messages never contain credentials, and
/// URLs are shown without their query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    /// The URL is not one the mirror may fetch.
    Refused(String),
    /// The TLS setup or the connection failed.
    Transport(String),
    /// The registry answered with something other than 200.
    Status(u16),
    /// The body is larger than [`MAX_BODY`].
    TooLarge,
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Transport(why) => write!(f, "upstream failed: {why}"),
            Self::Status(code) => write!(f, "the registry answered {code}"),
            Self::TooLarge => write!(f, "the registry sent more than {MAX_BODY} bytes"),
        }
    }
}

/// Checks a URL against the allowlist and returns it parsed. Only `https`,
/// one of [`ALLOWED_HOSTS`], no user information, and port 443 (or none).
///
/// # Errors
/// Refuses every other URL before anything is connected.
pub fn check_url(url: &str) -> Result<Uri, UpstreamError> {
    check_url_for(url, &ALLOWED_HOSTS)
}

/// [`check_url`] for a given set of hosts.
///
/// # Errors
/// Refuses any URL that is not https on one of `hosts`, port 443, no user
/// information.
pub fn check_url_for(url: &str, hosts: &[&str]) -> Result<Uri, UpstreamError> {
    let uri: Uri = url
        .parse()
        .map_err(|_| UpstreamError::Refused("not a valid URL".to_owned()))?;
    if uri.scheme_str() != Some("https") {
        return Err(UpstreamError::Refused("only https is allowed".to_owned()));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| UpstreamError::Refused("the URL has no host".to_owned()))?;
    if authority.as_str().contains('@') {
        return Err(UpstreamError::Refused(
            "user information is not allowed".to_owned(),
        ));
    }
    let host = authority.host();
    if !hosts.contains(&host) {
        return Err(UpstreamError::Refused(format!(
            "{host} is not a registry the mirror uses"
        )));
    }
    if let Some(port) = authority.port_u16()
        && port != 443
    {
        return Err(UpstreamError::Refused(
            "only port 443 is allowed".to_owned(),
        ));
    }
    Ok(uri)
}

type Connector = HttpsConnector<HttpConnector>;

/// An HTTPS client for the registries, with its own single-threaded runtime.
pub struct Upstream {
    runtime: tokio::runtime::Runtime,
    client: Client<Connector, Empty<Bytes>>,
    post_client: Client<Connector, Full<Bytes>>,
}

impl Upstream {
    /// Builds the client, loading the system's trust roots.
    ///
    /// # Errors
    /// Fails when the trust roots cannot be loaded or the runtime cannot start.
    pub fn new() -> Result<Self, UpstreamError> {
        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| UpstreamError::Transport(format!("trust roots: {e}")))?
            .https_only()
            .enable_http1()
            .build();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| UpstreamError::Transport(format!("runtime: {e}")))?;
        let post_connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| UpstreamError::Transport(format!("trust roots: {e}")))?
            .https_only()
            .enable_http1()
            .build();
        Ok(Self {
            runtime,
            client: Client::builder(TokioExecutor::new()).build(connector),
            post_client: Client::builder(TokioExecutor::new()).build(post_connector),
        })
    }

    /// Sends a JSON `POST` to the OSV query endpoint and returns the body. Only
    /// a 200 answer counts, and only [`OSV_HOST`] is reachable this way.
    ///
    /// # Errors
    /// Refuses any other URL before connecting; the same errors as [`Upstream::get`].
    pub fn post_json(&self, url: &str, json: &str) -> Result<Vec<u8>, UpstreamError> {
        let uri = check_url_for(url, &[OSV_HOST])?;
        let request = Request::post(uri)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json.to_owned())))
            .map_err(|e| UpstreamError::Transport(format!("request: {e}")))?;
        self.runtime.block_on(async {
            let response = self
                .post_client
                .request(request)
                .await
                .map_err(|e| UpstreamError::Transport(e.to_string()))?;
            if response.status() != StatusCode::OK {
                return Err(UpstreamError::Status(response.status().as_u16()));
            }
            let body = Limited::new(response.into_body(), MAX_BODY)
                .collect()
                .await
                .map_err(|e| {
                    if e.is::<http_body_util::LengthLimitError>() {
                        UpstreamError::TooLarge
                    } else {
                        UpstreamError::Transport(e.to_string())
                    }
                })?;
            Ok(body.to_bytes().to_vec())
        })
    }

    /// Fetches `url` and returns its body. Only a 200 answer counts.
    ///
    /// # Errors
    /// Refuses URLs outside the allowlist before connecting; fails on any
    /// transport error, any answer other than 200 (redirects included), and on
    /// a body over [`MAX_BODY`].
    pub fn get(&self, url: &str) -> Result<Vec<u8>, UpstreamError> {
        self.get_accept(url, None)
    }

    /// [`Upstream::get`] with an `Accept` header, for registries that answer
    /// differently by media type (the PyPI index needs the JSON type).
    ///
    /// # Errors
    /// The same as [`Upstream::get`].
    pub fn get_accept(&self, url: &str, accept: Option<&str>) -> Result<Vec<u8>, UpstreamError> {
        let uri = check_url(url)?;
        let mut builder = Request::get(uri);
        if let Some(value) = accept {
            builder = builder.header(http::header::ACCEPT, value);
        }
        let request = builder
            .body(Empty::<Bytes>::new())
            .map_err(|e| UpstreamError::Transport(format!("request: {e}")))?;
        self.runtime.block_on(async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|e| UpstreamError::Transport(e.to_string()))?;
            if response.status() != StatusCode::OK {
                return Err(UpstreamError::Status(response.status().as_u16()));
            }
            let body = Limited::new(response.into_body(), MAX_BODY)
                .collect()
                .await
                .map_err(|e| {
                    if e.is::<http_body_util::LengthLimitError>() {
                        UpstreamError::TooLarge
                    } else {
                        UpstreamError::Transport(e.to_string())
                    }
                })?;
            Ok(body.to_bytes().to_vec())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allowlisted_registry_urls_are_accepted() {
        for url in [
            "https://registry.npmjs.org/left-pad",
            "https://registry.npmjs.org/@babel%2fcore",
            "https://pypi.org/simple/requests/",
            "https://files.pythonhosted.org/packages/x/requests-2.34.2.tar.gz",
            "https://pypi.org:443/simple/requests/",
        ] {
            assert!(check_url(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn the_osv_host_is_reachable_for_post_only_and_nothing_else_is() {
        assert!(check_url_for("https://api.osv.dev/v1/query", &[OSV_HOST]).is_ok());
        assert!(matches!(
            check_url("https://api.osv.dev/v1/query"),
            Err(UpstreamError::Refused(_))
        ));
        assert!(matches!(
            check_url_for("https://pypi.org/simple/", &[OSV_HOST]),
            Err(UpstreamError::Refused(_))
        ));
    }

    #[test]
    fn everything_else_is_refused_before_any_connection() {
        for url in [
            "http://registry.npmjs.org/left-pad",
            "ftp://pypi.org/simple/",
            "file:///etc/passwd",
            "https://example.com/x",
            "https://registry.npmjs.org.evil.example/x",
            "https://evil.example/?registry.npmjs.org",
            "https://registry.npmjs.org@evil.example/x",
            "https://user:pass@pypi.org/simple/",
            "https://pypi.org:8443/simple/",
            "https://127.0.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://localhost/",
            "not a url",
            "",
        ] {
            assert!(
                matches!(check_url(url), Err(UpstreamError::Refused(_))),
                "accepted {url:?}"
            );
        }
    }

    #[test]
    fn the_client_builds_with_the_system_trust_roots() -> Result<(), UpstreamError> {
        Upstream::new().map(|_| ())
    }

    #[test]
    fn a_real_registry_document_is_fetched_over_tls() -> Result<(), UpstreamError> {
        let upstream = Upstream::new()?;
        let body = upstream.get("https://registry.npmjs.org/left-pad")?;
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("\"name\":\"left-pad\""), "unexpected body");
        Ok(())
    }

    #[test]
    fn a_missing_package_is_reported_as_the_status_not_as_a_body() -> Result<(), UpstreamError> {
        let upstream = Upstream::new()?;
        let result = upstream.get("https://registry.npmjs.org/pks-no-such-package-0123456789");
        assert_eq!(result, Err(UpstreamError::Status(404)));
        Ok(())
    }
}
