//! OSV.dev malware lookup (PRD FR-REG check 3, REG-MALWARE).
//!
//! The query is `POST /v1/query` with `{"package": {"name", "ecosystem"},
//! "version"}`. The answer lists advisories. Only ids starting with `MAL-` are
//! malware; `GHSA-` and `CVE-` entries are vulnerabilities and do not block
//! (checked live on 2026-11-21: lodash 4.17.21 has GHSA entries and is not
//! malware; python-dateutil2 99.0.0 has `MAL-2026-6400`).
//!
//! Results are cached for a day. A failed query is never cached, so the next
//! request asks again. When OSV cannot be reached the verdict is `Unknown`:
//! the caller allows the version and records that it was not checked, and the
//! new-package rule still applies to the package.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;

use crate::upstream::{OSV_HOST, Upstream, UpstreamError};

/// The OSV query endpoint.
pub const QUERY_URL: &str = "https://api.osv.dev/v1/query";
/// How long a result is kept.
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 3600);
/// Most results kept at once. Beyond this the cache is cleared.
const CACHE_LIMIT: usize = 10_000;

/// What OSV said about one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No `MAL-` advisory for this version.
    Clean,
    /// One or more `MAL-` advisories. The ids are listed.
    Malware(Vec<String>),
    /// OSV could not be asked or answered. The reason is recorded.
    Unknown(String),
}

/// Where the malware verdict comes from. The real one is [`Osv`]; tests use
/// their own.
pub trait Advisories: Send + Sync {
    /// The verdict for `version` of `name` in `ecosystem` (`npm` or `PyPI`).
    fn check(&self, ecosystem: &str, name: &str, version: &str) -> Verdict;
}

/// The POST the OSV client needs. [`Upstream`] implements it; tests do not
/// need a network.
pub trait Post: Send + Sync {
    fn post_json(&self, url: &str, json: &str) -> Result<Vec<u8>, UpstreamError>;
}

impl Post for Upstream {
    fn post_json(&self, url: &str, json: &str) -> Result<Vec<u8>, UpstreamError> {
        Upstream::post_json(self, url, json)
    }
}

/// A shared client, so one upstream connection can serve the mirror and OSV.
impl<T: Post> Post for std::sync::Arc<T> {
    fn post_json(&self, url: &str, json: &str) -> Result<Vec<u8>, UpstreamError> {
        (**self).post_json(url, json)
    }
}

/// The JSON body of an OSV query for one version.
#[must_use]
pub fn query_body(ecosystem: &str, name: &str, version: &str) -> String {
    serde_json::json!({
        "package": { "name": name, "ecosystem": ecosystem },
        "version": version,
    })
    .to_string()
}

/// Reads an OSV answer and returns the `MAL-` ids in it. An empty object means
/// nothing is known. Anything that is not an object with a `vulns` array (when
/// the array is present) is an error, never a "clean" answer.
///
/// # Errors
/// Returns the reason when the answer is not one OSV sends.
pub fn parse_answer(body: &[u8]) -> Result<Vec<String>, String> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| "the answer is not JSON".to_owned())?;
    let object = value.as_object().ok_or("the answer is not an object")?;
    let Some(vulns) = object.get("vulns") else {
        return Ok(Vec::new());
    };
    let list = vulns.as_array().ok_or("the vulns field is not a list")?;
    let mut malware = Vec::new();
    for vuln in list {
        let id = vuln
            .get("id")
            .and_then(Value::as_str)
            .ok_or("an advisory has no id")?;
        if id.starts_with("MAL-") {
            malware.push(id.to_owned());
        }
    }
    Ok(malware)
}

/// A cache key: ecosystem, name, version.
type CacheKey = (String, String, String);
/// A cached answer and the time it was given.
type CacheEntry = (i64, Verdict);

/// The OSV-backed advisory source with its cache.
pub struct Osv<P: Post> {
    post: P,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
}

impl<P: Post> Osv<P> {
    pub fn new(post: P, clock: Box<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            post,
            clock,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn query(&self, ecosystem: &str, name: &str, version: &str) -> Verdict {
        let body = query_body(ecosystem, name, version);
        let answer = match self.post.post_json(QUERY_URL, &body) {
            Ok(answer) => answer,
            Err(error) => return Verdict::Unknown(format!("OSV {OSV_HOST} failed: {error}")),
        };
        match parse_answer(&answer) {
            Ok(ids) if ids.is_empty() => Verdict::Clean,
            Ok(ids) => Verdict::Malware(ids),
            Err(why) => Verdict::Unknown(format!("OSV answer refused: {why}")),
        }
    }
}

impl<P: Post> Advisories for Osv<P> {
    fn check(&self, ecosystem: &str, name: &str, version: &str) -> Verdict {
        let key = (ecosystem.to_owned(), name.to_owned(), version.to_owned());
        let now = (self.clock)();
        if let Ok(cache) = self.cache.lock()
            && let Some((at, verdict)) = cache.get(&key)
            && now.saturating_sub(*at) < i64::try_from(CACHE_TTL.as_secs()).unwrap_or(i64::MAX)
        {
            return verdict.clone();
        }
        let verdict = self.query(ecosystem, name, version);
        // A failure is not cached: the next request asks again.
        if !matches!(verdict, Verdict::Unknown(_))
            && let Ok(mut cache) = self.cache.lock()
        {
            if cache.len() >= CACHE_LIMIT {
                cache.clear();
            }
            cache.insert(key, (now, verdict.clone()));
        }
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Answers from a list of replies in order, and counts the calls.
    struct Scripted {
        replies: Mutex<Vec<Result<Vec<u8>, UpstreamError>>>,
        calls: Arc<AtomicUsize>,
    }

    impl Post for Scripted {
        fn post_json(&self, url: &str, json: &str) -> Result<Vec<u8>, UpstreamError> {
            assert_eq!(url, QUERY_URL);
            assert!(json.contains("\"version\""), "the query names the version");
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.replies
                .lock()
                .ok()
                .and_then(|mut list| {
                    if list.is_empty() {
                        None
                    } else {
                        Some(list.remove(0))
                    }
                })
                .unwrap_or(Err(UpstreamError::Status(500)))
        }
    }

    fn scripted(replies: Vec<Result<Vec<u8>, UpstreamError>>) -> (Scripted, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Scripted {
                replies: Mutex::new(replies),
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }

    #[test]
    fn only_mal_advisories_are_malware() -> Result<(), String> {
        // lodash 4.17.20 has GHSA entries only: clean.
        let ghsa = br#"{"vulns":[{"id":"GHSA-29mw-wpgm-hmr9"},{"id":"CVE-2020-8203"}]}"#;
        assert_eq!(parse_answer(ghsa)?, Vec::<String>::new());
        // python-dateutil2 99.0.0 has a MAL advisory.
        let mal = br#"{"vulns":[{"id":"MAL-2026-6400"},{"id":"GHSA-xxxx"}]}"#;
        assert_eq!(parse_answer(mal)?, vec!["MAL-2026-6400".to_owned()]);
        assert_eq!(parse_answer(b"{}")?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn an_answer_that_is_not_what_osv_sends_is_an_error_not_clean() {
        for bad in [
            &b""[..],
            b"not json",
            b"[]",
            br#"{"vulns":"x"}"#,
            br#"{"vulns":[{"summary":"no id"}]}"#,
        ] {
            assert!(
                parse_answer(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn the_query_names_the_ecosystem_the_name_and_the_version() {
        let body: Value = serde_json::from_str(&query_body("PyPI", "python-dateutil2", "99.0.0"))
            .unwrap_or(Value::Null);
        assert_eq!(body["package"]["ecosystem"], "PyPI");
        assert_eq!(body["package"]["name"], "python-dateutil2");
        assert_eq!(body["version"], "99.0.0");
    }

    #[test]
    fn a_malware_version_is_reported_and_a_clean_one_is_not() {
        let (post, _) = scripted(vec![
            Ok(br#"{"vulns":[{"id":"MAL-2026-6400"}]}"#.to_vec()),
            Ok(b"{}".to_vec()),
        ]);
        let osv = Osv::new(post, Box::new(|| 1_000));
        assert_eq!(
            osv.check("PyPI", "python-dateutil2", "99.0.0"),
            Verdict::Malware(vec!["MAL-2026-6400".to_owned()])
        );
        assert_eq!(osv.check("PyPI", "requests", "2.34.2"), Verdict::Clean);
    }

    #[test]
    fn results_are_cached_for_a_day_and_then_asked_again() {
        let (post, calls) = scripted(vec![Ok(b"{}".to_vec()), Ok(b"{}".to_vec())]);
        let now = Arc::new(AtomicUsize::new(1_000));
        let clock = Arc::clone(&now);
        let osv = Osv::new(
            post,
            Box::new(move || i64::try_from(clock.load(Ordering::SeqCst)).unwrap_or(0)),
        );
        assert_eq!(osv.check("npm", "left-pad", "1.3.0"), Verdict::Clean);
        now.store(1_000 + 3600, Ordering::SeqCst);
        assert_eq!(osv.check("npm", "left-pad", "1.3.0"), Verdict::Clean);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second answer came from the cache"
        );
        now.store(1_000 + 24 * 3600, Ordering::SeqCst);
        assert_eq!(osv.check("npm", "left-pad", "1.3.0"), Verdict::Clean);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "after a day the answer is asked again"
        );
    }

    #[test]
    fn a_failed_query_is_unknown_and_is_not_cached() {
        let (post, calls) = scripted(vec![
            Err(UpstreamError::Transport("offline".to_owned())),
            Ok(b"{}".to_vec()),
        ]);
        let osv = Osv::new(post, Box::new(|| 1_000));
        assert!(matches!(
            osv.check("npm", "a", "1.0.0"),
            Verdict::Unknown(_)
        ));
        assert_eq!(
            osv.check("npm", "a", "1.0.0"),
            Verdict::Clean,
            "the retry asked OSV again"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
