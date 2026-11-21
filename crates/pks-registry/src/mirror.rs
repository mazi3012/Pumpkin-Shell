//! The mirror (PRD FR-REG): answers the npm and PyPI requests a package
//! manager sends, from the registries, after the guard checks.
//!
//! Routes (all `GET`):
//! - `/npm/<name>` npm packument. Versions inside the cooldown are removed, and
//!   tarball links point back at the mirror.
//! - `/npm/<name>/-/<file>.tgz` tarball, checked against the published checksum.
//! - `/pypi/simple/<project>/` PyPI index (JSON). Young files are removed, and
//!   file links point back at the mirror.
//! - `/pypi/packages/<project>/<filename>` file, checked against its sha256.
//!
//! A package whose first release is under 30 days old is refused as a whole
//! (403, REG-TOO-NEW). Every refusal names the rule in its body. Nothing is
//! served unless the registry answered 200 for it.

use std::sync::Arc;

use serde_json::Value;

use crate::document::{filter_npm, filter_pypi};
use crate::integrity::{Verifier, from_npm_dist, from_sha256_hex};
use crate::names::{percent_decode, valid_npm_name, valid_pypi_name};
use crate::upstream::UpstreamError;

/// The npm registry the packuments and tarballs come from.
pub const NPM_REGISTRY: &str = "https://registry.npmjs.org";
/// The PyPI index the project pages come from.
pub const PYPI_INDEX: &str = "https://pypi.org/simple";
/// The media type the PyPI index is asked for (PEP 691).
pub const PYPI_JSON: &str = "application/vnd.pypi.simple.v1+json";

/// Where the mirror gets registry responses from. The real implementation is
/// [`crate::upstream::Upstream`]; tests supply their own.
pub trait Source: Send + Sync {
    /// Fetches `url`, sending `accept` when it is given.
    fn fetch(&self, url: &str, accept: Option<&str>) -> Result<Vec<u8>, UpstreamError>;
}

impl Source for crate::upstream::Upstream {
    fn fetch(&self, url: &str, accept: Option<&str>) -> Result<Vec<u8>, UpstreamError> {
        self.get_accept(url, accept)
    }
}

/// One answer to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// Facts worth recording (for example install scripts), for the session log.
    pub notes: Vec<String>,
}

const JSON: &str = "application/json";
const BINARY: &str = "application/octet-stream";

impl Reply {
    fn json(status: u16, value: &Value) -> Self {
        Self {
            status,
            content_type: JSON,
            body: value.to_string().into_bytes(),
            notes: Vec::new(),
        }
    }

    /// A refusal: the status and a body that names the rule.
    fn refuse(status: u16, rule: &str, message: &str) -> Self {
        Self::json(
            status,
            &serde_json::json!({ "error": format!("{rule}: {message}"), "rule": rule }),
        )
    }

    fn fail(error: &UpstreamError) -> Self {
        match error {
            UpstreamError::Status(404) => {
                Self::refuse(404, "NOT-FOUND", "the registry has no such package")
            }
            UpstreamError::Refused(why) => Self::refuse(400, "BAD-REQUEST", why),
            other => Self::refuse(502, "UPSTREAM", &other.to_string()),
        }
    }
}

/// The mirror. `base` is how a client reaches the mirror, for example
/// `http://127.0.0.1:3130`; links in documents are built from it.
pub struct Mirror<S: Source> {
    source: S,
    base: String,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
}

/// A parsed npm packument, filtered, with the original tarball links.
struct NpmDoc {
    doc: Value,
    notes: Vec<String>,
}

impl<S: Source> Mirror<S> {
    /// Builds a mirror. `base` is the mirror's own address as clients see it.
    pub fn new(source: S, base: &str, clock: Box<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            source,
            base: base.trim_end_matches('/').to_owned(),
            clock,
        }
    }

    /// Answers a request path (without query).
    #[must_use]
    pub fn handle(&self, path: &str) -> Reply {
        let path = path.split('?').next().unwrap_or("");
        if let Some(rest) = path.strip_prefix("/npm/") {
            self.npm(rest)
        } else if let Some(rest) = path.strip_prefix("/pypi/simple/") {
            self.pypi_index(rest)
        } else if let Some(rest) = path.strip_prefix("/pypi/packages/") {
            self.pypi_file(rest)
        } else {
            Reply::refuse(404, "NOT-FOUND", "the mirror has no such route")
        }
    }

    fn npm(&self, rest: &str) -> Reply {
        match rest.split_once("/-/") {
            Some((name_part, file)) => self.npm_tarball(name_part, file),
            None => self.npm_packument(rest),
        }
    }

    /// Fetches and filters a packument. `Err` is the reply to send instead.
    fn npm_document(&self, name_part: &str) -> Result<NpmDoc, Reply> {
        let name = percent_decode(name_part).unwrap_or_default();
        if !valid_npm_name(&name) {
            return Err(Reply::refuse(
                400,
                "BAD-REQUEST",
                "not a valid npm package name",
            ));
        }
        let url = format!("{NPM_REGISTRY}/{}", name.replace('/', "%2f"));
        let raw = self.source.fetch(&url, None).map_err(|e| Reply::fail(&e))?;
        let mut doc: Value = serde_json::from_slice(&raw).map_err(|_| {
            Reply::refuse(
                502,
                "UPSTREAM",
                "the registry did not send a package document",
            )
        })?;
        let report = filter_npm(&mut doc, (self.clock)()).ok_or_else(|| {
            Reply::refuse(
                502,
                "UPSTREAM",
                "the registry did not send a package document",
            )
        })?;
        if report.too_new {
            return Err(Reply::refuse(
                403,
                "REG-TOO-NEW",
                &format!("{name} was first released less than 30 days ago; the package is blocked"),
            ));
        }
        let notes = report
            .install_scripts
            .iter()
            .map(|s| format!("REG-INSTALL-SCRIPT {s}"))
            .chain(
                report
                    .hidden
                    .iter()
                    .map(|v| format!("REG-COOLDOWN {name}@{v} hidden")),
            )
            .collect();
        Ok(NpmDoc { doc, notes })
    }

    fn npm_packument(&self, name_part: &str) -> Reply {
        let mut parsed = match self.npm_document(name_part) {
            Ok(parsed) => parsed,
            Err(reply) => return reply,
        };
        let encoded = name_part.to_owned();
        if let Some(versions) = parsed
            .doc
            .get_mut("versions")
            .and_then(Value::as_object_mut)
        {
            for meta in versions.values_mut() {
                if let Some(dist) = meta.get_mut("dist").and_then(Value::as_object_mut)
                    && let Some(tarball) = dist.get("tarball").and_then(Value::as_str)
                    && let Some(file) = tarball.rsplit('/').next()
                {
                    let link = format!("{}/npm/{encoded}/-/{file}", self.base);
                    dist.insert("tarball".to_owned(), Value::String(link));
                }
            }
        }
        let mut reply = Reply::json(200, &parsed.doc);
        reply.notes = parsed.notes;
        reply
    }

    fn npm_tarball(&self, name_part: &str, file: &str) -> Reply {
        if !file.ends_with(".tgz") || file.contains('/') {
            return Reply::refuse(400, "BAD-REQUEST", "not a tarball name");
        }
        let parsed = match self.npm_document(name_part) {
            Ok(parsed) => parsed,
            Err(reply) => return reply,
        };
        let versions = parsed.doc.get("versions").and_then(Value::as_object);
        let found = versions.and_then(|all| {
            all.values().find(|meta| {
                meta.get("dist")
                    .and_then(|d| d.get("tarball"))
                    .and_then(Value::as_str)
                    .and_then(|t| t.rsplit('/').next())
                    == Some(file)
            })
        });
        let Some(meta) = found else {
            return Reply::refuse(
                403,
                "REG-COOLDOWN",
                "this version is hidden: it is inside the 72-hour cooldown or unknown",
            );
        };
        let Some(dist) = meta.get("dist") else {
            return Reply::refuse(502, "UPSTREAM", "the version has no dist section");
        };
        let Some(url) = dist
            .get("tarball")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return Reply::refuse(502, "UPSTREAM", "the version has no tarball");
        };
        let Some(expected) = from_npm_dist(dist) else {
            return Reply::refuse(
                502,
                "REG-INTEGRITY",
                "the registry publishes no checksum for this version",
            );
        };
        let bytes = match self.source.fetch(&url, None) {
            Ok(bytes) => bytes,
            Err(error) => return Reply::fail(&error),
        };
        verified(&expected, &bytes, BINARY)
    }

    fn pypi_document(&self, project: &str) -> Result<Value, Reply> {
        if !valid_pypi_name(project) {
            return Err(Reply::refuse(
                400,
                "BAD-REQUEST",
                "not a valid PyPI project name",
            ));
        }
        let url = format!("{PYPI_INDEX}/{project}/");
        let raw = self
            .source
            .fetch(&url, Some(PYPI_JSON))
            .map_err(|e| Reply::fail(&e))?;
        let mut doc: Value = serde_json::from_slice(&raw)
            .map_err(|_| Reply::refuse(502, "UPSTREAM", "the registry did not send an index"))?;
        let report = filter_pypi(&mut doc, (self.clock)())
            .ok_or_else(|| Reply::refuse(502, "UPSTREAM", "the registry did not send an index"))?;
        if report.too_new {
            return Err(Reply::refuse(
                403,
                "REG-TOO-NEW",
                &format!(
                    "{project} was first released less than 30 days ago; the project is blocked"
                ),
            ));
        }
        Ok(doc)
    }

    fn pypi_index(&self, rest: &str) -> Reply {
        let project = rest.trim_end_matches('/');
        let mut doc = match self.pypi_document(project) {
            Ok(doc) => doc,
            Err(reply) => return reply,
        };
        let name = doc
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(project)
            .to_owned();
        if let Some(files) = doc.get_mut("files").and_then(Value::as_array_mut) {
            for file in files {
                let Some(filename) = file
                    .get("filename")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                else {
                    continue;
                };
                let link = format!("{}/pypi/packages/{name}/{filename}", self.base);
                if let Some(object) = file.as_object_mut() {
                    object.insert("url".to_owned(), Value::String(link));
                }
            }
        }
        let mut reply = Reply::json(200, &doc);
        reply.content_type = PYPI_JSON;
        reply
    }

    fn pypi_file(&self, rest: &str) -> Reply {
        let Some((project, filename)) = rest.split_once('/') else {
            return Reply::refuse(400, "BAD-REQUEST", "a file needs a project and a filename");
        };
        if filename.contains('/') || filename.is_empty() {
            return Reply::refuse(400, "BAD-REQUEST", "not a file name");
        }
        let doc = match self.pypi_document(project) {
            Ok(doc) => doc,
            Err(reply) => return reply,
        };
        let entry = doc
            .get("files")
            .and_then(Value::as_array)
            .and_then(|files| {
                files
                    .iter()
                    .find(|f| f.get("filename").and_then(Value::as_str) == Some(filename))
            });
        let Some(entry) = entry else {
            return Reply::refuse(
                403,
                "REG-COOLDOWN",
                "this file is hidden: it is inside the 72-hour cooldown or unknown",
            );
        };
        let Some(url) = entry.get("url").and_then(Value::as_str).map(str::to_owned) else {
            return Reply::refuse(502, "UPSTREAM", "the file has no URL");
        };
        let sha256 = entry
            .get("hashes")
            .and_then(|h| h.get("sha256"))
            .and_then(Value::as_str);
        let Some(expected) = sha256.and_then(from_sha256_hex) else {
            return Reply::refuse(
                502,
                "REG-INTEGRITY",
                "the registry publishes no sha256 for this file",
            );
        };
        let bytes = match self.source.fetch(&url, None) {
            Ok(bytes) => bytes,
            Err(error) => return Reply::fail(&error),
        };
        verified(&expected, &bytes, BINARY)
    }
}

/// Serves `bytes` only when they match the published checksum.
fn verified(
    expected: &crate::integrity::Expected,
    bytes: &[u8],
    content_type: &'static str,
) -> Reply {
    let mut check = Verifier::new(expected);
    check.update(bytes);
    if check.finish() {
        Reply {
            status: 200,
            content_type,
            body: bytes.to_vec(),
            notes: Vec::new(),
        }
    } else {
        Reply::refuse(
            502,
            "REG-INTEGRITY",
            "the download does not match the published checksum; it was not served",
        )
    }
}

/// A mirror shared between connections.
pub type SharedMirror<S> = Arc<Mirror<S>>;

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Digest as _;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;
    const BASE: &str = "http://127.0.0.1:3130";

    /// An RFC 3339 time `secs` before NOW.
    fn ago(secs: i64) -> String {
        time::OffsetDateTime::from_unix_timestamp(NOW - secs)
            .ok()
            .and_then(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .unwrap_or_default()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A registry that answers from a fixed map. It records each request, and
    /// refuses PyPI index requests that do not ask for the JSON type.
    #[derive(Default)]
    struct Fake {
        answers: HashMap<String, Vec<u8>>,
        requests: Mutex<Vec<String>>,
    }

    impl Fake {
        fn with(mut self, url: &str, body: impl Into<Vec<u8>>) -> Self {
            self.answers.insert(url.to_owned(), body.into());
            self
        }
    }

    impl Source for Fake {
        fn fetch(&self, url: &str, accept: Option<&str>) -> Result<Vec<u8>, UpstreamError> {
            if let Ok(mut log) = self.requests.lock() {
                log.push(url.to_owned());
            }
            if url.starts_with(PYPI_INDEX) && accept != Some(PYPI_JSON) {
                return Err(UpstreamError::Refused(
                    "the index must be asked as JSON".to_owned(),
                ));
            }
            self.answers
                .get(url)
                .cloned()
                .ok_or(UpstreamError::Status(404))
        }
    }

    fn mirror(fake: Fake) -> Mirror<Fake> {
        Mirror::new(fake, BASE, Box::new(|| NOW))
    }

    fn json(reply: &Reply) -> Value {
        serde_json::from_slice(&reply.body).unwrap_or(Value::Null)
    }

    fn npm_doc(name: &str, tarball: &str, shasum: &str, scripts: bool) -> Vec<u8> {
        let mut meta = serde_json::json!({
            "name": name,
            "dist": { "tarball": tarball, "shasum": shasum },
        });
        if scripts {
            meta["scripts"] = serde_json::json!({ "postinstall": "node install.js" });
        }
        serde_json::json!({
            "name": name,
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": { "name": name, "dist": { "tarball": format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"), "shasum": shasum } },
                "2.0.0": meta,
            },
            "time": {
                "created": ago(200 * DAY),
                "1.0.0": ago(200 * DAY),
                "2.0.0": ago(2 * 3600),
            },
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn a_packument_hides_the_cooldown_version_and_links_back_to_the_mirror() {
        let tarball_1 = b"tarball one";
        let shasum = hex(&sha1::Sha1::digest(tarball_1));
        let fake = Fake::default().with(
            "https://registry.npmjs.org/pkg",
            npm_doc(
                "pkg",
                "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                &shasum,
                true,
            ),
        );
        let reply = mirror(fake).handle("/npm/pkg");
        assert_eq!(reply.status, 200);
        let doc = json(&reply);
        assert!(
            doc["versions"].get("2.0.0").is_none(),
            "the new version is hidden"
        );
        assert_eq!(
            doc["versions"]["1.0.0"]["dist"]["tarball"],
            format!("{BASE}/npm/pkg/-/pkg-1.0.0.tgz")
        );
        assert!(
            reply
                .notes
                .iter()
                .any(|n| n.starts_with("REG-COOLDOWN pkg@2.0.0"))
        );
    }

    #[test]
    fn a_package_that_is_first_released_recently_is_refused_with_the_rule_name() {
        let body = serde_json::json!({
            "name": "fresh",
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "dist": { "tarball": "https://registry.npmjs.org/fresh/-/fresh-1.0.0.tgz" } } },
            "time": { "created": ago(3 * DAY), "1.0.0": ago(3 * DAY) },
        })
        .to_string();
        let fake = Fake::default().with("https://registry.npmjs.org/fresh", body);
        let reply = mirror(fake).handle("/npm/fresh");
        assert_eq!(reply.status, 403);
        assert!(json(&reply)["rule"] == "REG-TOO-NEW");
    }

    #[test]
    fn a_tarball_with_the_published_checksum_is_served() {
        let bytes = b"tarball one";
        let shasum = hex(&sha1::Sha1::digest(bytes));
        let fake = Fake::default()
            .with(
                "https://registry.npmjs.org/pkg",
                npm_doc(
                    "pkg",
                    "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                    &shasum,
                    false,
                ),
            )
            .with(
                "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                bytes.to_vec(),
            );
        let reply = mirror(fake).handle("/npm/pkg/-/pkg-1.0.0.tgz");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, bytes);
    }

    #[test]
    fn a_tarball_that_does_not_match_its_checksum_is_not_served() {
        let shasum = hex(&sha1::Sha1::digest(b"the real file"));
        let fake = Fake::default()
            .with(
                "https://registry.npmjs.org/pkg",
                npm_doc(
                    "pkg",
                    "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                    &shasum,
                    false,
                ),
            )
            .with(
                "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                b"a swapped file".to_vec(),
            );
        let reply = mirror(fake).handle("/npm/pkg/-/pkg-1.0.0.tgz");
        assert_eq!(reply.status, 502);
        assert!(json(&reply)["rule"] == "REG-INTEGRITY");
        assert!(!String::from_utf8_lossy(&reply.body).contains("a swapped file"));
    }

    #[test]
    fn a_tarball_of_a_hidden_version_is_refused() {
        let shasum = hex(&sha1::Sha1::digest(b"x"));
        let fake = Fake::default()
            .with(
                "https://registry.npmjs.org/pkg",
                npm_doc(
                    "pkg",
                    "https://registry.npmjs.org/pkg/-/pkg-2.0.0.tgz",
                    &shasum,
                    false,
                ),
            )
            .with(
                "https://registry.npmjs.org/pkg/-/pkg-2.0.0.tgz",
                b"x".to_vec(),
            );
        let reply = mirror(fake).handle("/npm/pkg/-/pkg-2.0.0.tgz");
        assert_eq!(reply.status, 403);
        assert!(json(&reply)["rule"] == "REG-COOLDOWN");
    }

    #[test]
    fn unknown_packages_and_routes_are_reported_and_bad_names_are_refused() {
        let m = mirror(Fake::default());
        assert_eq!(m.handle("/npm/nothere").status, 404);
        assert_eq!(m.handle("/elsewhere").status, 404);
        assert_eq!(m.handle("/npm/..%2fetc%2fpasswd").status, 400);
        assert_eq!(m.handle("/npm/a%3fb").status, 400);
        assert_eq!(m.handle("/pypi/simple/bad%2fname/").status, 400);
        assert_eq!(m.handle("/npm/pkg/-/../../x.tgz").status, 400);
    }

    #[test]
    fn a_pypi_index_is_asked_as_json_and_its_links_point_back_at_the_mirror() {
        let index = serde_json::json!({
            "name": "requests",
            "versions": ["2.34.1", "2.34.2"],
            "files": [
                { "filename": "requests-2.34.1.tar.gz", "url": "https://files.pythonhosted.org/a", "upload-time": ago(100 * DAY), "hashes": { "sha256": "00" } },
                { "filename": "requests-2.34.2.tar.gz", "url": "https://files.pythonhosted.org/b", "upload-time": ago(60), "hashes": { "sha256": "00" } },
            ],
        })
        .to_string();
        let fake = Fake::default().with("https://pypi.org/simple/requests/", index);
        let reply = mirror(fake).handle("/pypi/simple/requests/");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.content_type, PYPI_JSON);
        let doc = json(&reply);
        assert_eq!(doc["versions"], serde_json::json!(["2.34.1"]));
        assert_eq!(
            doc["files"][0]["url"],
            format!("{BASE}/pypi/packages/requests/requests-2.34.1.tar.gz")
        );
        assert_eq!(doc["files"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn a_pypi_file_with_the_published_sha256_is_served() {
        let bytes = b"wheel bytes";
        let sha = hex(&sha2::Sha256::digest(bytes));
        let index = serde_json::json!({
            "name": "pkg",
            "versions": ["1.0"],
            "files": [{ "filename": "pkg-1.0-py3-none-any.whl", "url": "https://files.pythonhosted.org/w", "upload-time": ago(100 * DAY), "hashes": { "sha256": sha } }],
        })
        .to_string();
        let fake = Fake::default()
            .with("https://pypi.org/simple/pkg/", index)
            .with("https://files.pythonhosted.org/w", bytes.to_vec());
        let reply = mirror(fake).handle("/pypi/packages/pkg/pkg-1.0-py3-none-any.whl");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, bytes);
    }

    #[test]
    fn a_pypi_file_that_does_not_match_its_sha256_is_not_served() {
        let index = serde_json::json!({
            "name": "pkg",
            "versions": ["1.0"],
            "files": [{ "filename": "pkg-1.0.tar.gz", "url": "https://files.pythonhosted.org/s", "upload-time": ago(100 * DAY), "hashes": { "sha256": hex(&sha2::Sha256::digest(b"real")) } }],
        })
        .to_string();
        let fake = Fake::default()
            .with("https://pypi.org/simple/pkg/", index)
            .with("https://files.pythonhosted.org/s", b"fake".to_vec());
        let reply = mirror(fake).handle("/pypi/packages/pkg/pkg-1.0.tar.gz");
        assert_eq!(reply.status, 502);
        assert!(json(&reply)["rule"] == "REG-INTEGRITY");
    }

    #[test]
    fn a_young_pypi_file_is_refused_and_a_new_project_is_too_new() {
        let index = serde_json::json!({
            "name": "pkg",
            "versions": ["1.0", "2.0"],
            "files": [
                { "filename": "pkg-1.0.tar.gz", "url": "https://files.pythonhosted.org/o", "upload-time": ago(100 * DAY), "hashes": { "sha256": "00" } },
                { "filename": "pkg-2.0.tar.gz", "url": "https://files.pythonhosted.org/n", "upload-time": ago(60), "hashes": { "sha256": "00" } },
            ],
        })
        .to_string();
        let fake = Fake::default().with("https://pypi.org/simple/pkg/", index);
        let m = mirror(fake);
        assert_eq!(m.handle("/pypi/packages/pkg/pkg-2.0.tar.gz").status, 403);

        let fresh = serde_json::json!({
            "name": "fresh",
            "versions": ["1.0"],
            "files": [{ "filename": "fresh-1.0.tar.gz", "url": "https://files.pythonhosted.org/f", "upload-time": ago(2 * DAY), "hashes": { "sha256": "00" } }],
        })
        .to_string();
        let fake = Fake::default().with("https://pypi.org/simple/fresh/", fresh);
        let reply = mirror(fake).handle("/pypi/simple/fresh/");
        assert_eq!(reply.status, 403);
        assert!(json(&reply)["rule"] == "REG-TOO-NEW");
    }
}
