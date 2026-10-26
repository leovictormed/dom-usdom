//! Security middleware: rate limiting, CORS, Bearer auth.

use axum::{
    extract::{Request, State},
    http::{header, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
// Note: `governor` is added as direct dependency for stability.
// It is already a transitive dependency via `tower_governor`,
// but we declare it directly to control the version explicitly.
use governor::middleware::NoOpMiddleware;
use std::ffi::OsStr;
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
#[cfg(test)]
use tower_governor::key_extractor::GlobalKeyExtractor;
#[cfg(not(test))]
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Bearer token for authenticated endpoints.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BearerToken(pub String);

const MAX_RPC_HEADER_FIELDS: usize = 32;
const MAX_RPC_HEADER_BYTES: usize = 16 * 1024;
const MAX_RPC_URI_BYTES: usize = 4 * 1024;

/// Enforce the RPC's deliberately small and uncompressed HTTP profile.
///
/// Hyper supplies safe HTTP parsing, but accepting every valid HTTP framing
/// creates avoidable differences between clients/proxies.  Reject ambiguous
/// singleton fields, transfer codings, compressed bodies, bodies on read-only
/// methods and oversized metadata before authentication or route extraction.
pub async fn require_canonical_http_framing(req: Request, next: Next) -> Response {
    if req.uri().to_string().len() > MAX_RPC_URI_BYTES
        || req.headers().len() > MAX_RPC_HEADER_FIELDS
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let mut header_bytes = 0usize;
    for (name, value) in req.headers() {
        let Some(next_size) = header_bytes
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
        else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        header_bytes = next_size;
    }
    if header_bytes > MAX_RPC_HEADER_BYTES {
        return StatusCode::BAD_REQUEST.into_response();
    }

    for singleton in [
        header::HOST,
        header::AUTHORIZATION,
        header::CONTENT_LENGTH,
        header::CONTENT_TYPE,
    ] {
        if req.headers().get_all(singleton).iter().nth(1).is_some() {
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    // This RPC never decompresses request bodies and does not need streaming
    // HTTP/1 transfer codings.  A fixed body or HTTP/2 DATA remains bounded by
    // the route-specific RequestBodyLimitLayer.
    if req.headers().contains_key(header::CONTENT_ENCODING)
        || req.headers().contains_key(header::TRANSFER_ENCODING)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    if matches!(*req.method(), Method::GET | Method::HEAD) {
        let content_length_is_zero = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .map(|value| value.as_bytes() == b"0")
            .unwrap_or(true);
        if !content_length_is_zero {
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    next.run(req).await
}

/// Reject requests whose HTTP authority does not name the actual loopback
/// listener.
///
/// A loopback-only socket is not, by itself, a browser security boundary: an
/// attacker-controlled DNS name can resolve to loopback, and a local reverse
/// proxy can forward an arbitrary `Host`.  This layer is installed only by the
/// real server (rather than `router`) so it can bind the accepted authority to
/// the listener's resolved address and ephemeral port.  It must remain the
/// outermost layer, before authentication, body buffering and admission work.
pub async fn require_listener_host(
    State(local): State<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let expected_socket = local.to_string();
    let expected_localhost = format!("localhost:{}", local.port());
    let accepted = req
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|authority| {
            authority.eq_ignore_ascii_case(&expected_socket)
                || authority.eq_ignore_ascii_case(&expected_localhost)
        });

    if !accepted {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    next.run(req).await
}

/// Reject work when every bounded response-generation slot is occupied.
///
/// `ConcurrencyLimitLayer` applies backpressure, which is appropriate for a
/// single trusted proof job but permits HTTP request futures to queue. Scanner
/// clients can retry a page, so fail fast instead of retaining an unbounded
/// number of large-response requests behind the node snapshot/serializer.
pub async fn require_inflight_capacity(
    State(capacity): State<Arc<Semaphore>>,
    req: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = capacity.try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    next.run(req).await
}

const DEFAULT_SUBMIT_BURST: u32 = 10;
const MAX_SUBMIT_BURST: u32 = 1_000;
const DEFAULT_READ_BURST: u32 = 100;
const MAX_READ_BURST: u32 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RpcRateLimitPolicy {
    pub(crate) submit_burst: u32,
    pub(crate) read_burst: u32,
}

impl RpcRateLimitPolicy {
    pub(crate) fn from_env() -> Result<Self, String> {
        Self::from_raw(
            std::env::var_os("DOM_RPC_RATELIMIT_SUBMIT").as_deref(),
            std::env::var_os("DOM_RPC_RATELIMIT_READ").as_deref(),
        )
    }

    fn from_raw(submit: Option<&OsStr>, read: Option<&OsStr>) -> Result<Self, String> {
        Ok(Self {
            submit_burst: parse_burst_limit(
                "DOM_RPC_RATELIMIT_SUBMIT",
                submit,
                DEFAULT_SUBMIT_BURST,
                MAX_SUBMIT_BURST,
            )?,
            read_burst: parse_burst_limit(
                "DOM_RPC_RATELIMIT_READ",
                read,
                DEFAULT_READ_BURST,
                MAX_READ_BURST,
            )?,
        })
    }
}

/// Parse one governor burst setting without silently weakening policy.
///
/// Environment input is an operator-controlled security boundary. Falling
/// back to a default on malformed input can make the running policy differ
/// from the reviewed deployment policy, while accepting an arbitrarily large
/// burst effectively disables admission control. Keep the accepted grammar
/// canonical and the range deliberately finite.
fn parse_burst_limit(
    name: &str,
    raw: Option<&OsStr>,
    default: u32,
    maximum: u32,
) -> Result<u32, String> {
    if !(1..=maximum).contains(&default) {
        return Err(format!(
            "internal {name} default must be between 1 and {maximum}"
        ));
    }
    let Some(raw) = raw else {
        return Ok(default);
    };
    let text = raw
        .to_str()
        .ok_or_else(|| format!("{name} must be valid UTF-8 decimal text"))?;
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(format!("{name} must be canonical unsigned decimal text"));
    }
    let value = text
        .parse::<u32>()
        .map_err(|_| format!("{name} is outside the supported u32 range"))?;
    if !(1..=maximum).contains(&value) {
        return Err(format!("{name} must be between 1 and {maximum}"));
    }
    Ok(value)
}

/// Build submit admission control (burst 10, sustained refill 1 req/sec).
#[cfg(not(test))]
pub fn rate_limit_submit(limit: u32) -> GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware> {
    let config = GovernorConfigBuilder::default()
        // The node accepts TCP connections directly and has no trusted-proxy
        // allowlist. Key only on ConnectInfo: SmartIpKeyExtractor trusts
        // attacker-controlled forwarding headers and permits trivial limit
        // evasion by rotating X-Forwarded-For values.
        .key_extractor(PeerIpKeyExtractor)
        .per_second(1)
        .burst_size(limit)
        .finish()
        .expect("rate limit config valid");

    GovernorLayer {
        config: Arc::new(config),
    }
}

// Design decision (kept long-term): tests use `GlobalKeyExtractor` because
// `tower::ServiceExt::oneshot()` doesn't inject the `ConnectInfo<SocketAddr>`
// that `PeerIpKeyExtractor` requires (and `axum::extract::ConnectInfo` cannot
// be inserted as a plain request extension — its extractor depends on the
// `MakeService` layer wiring it via `into_make_service_with_connect_info`).
// The production per-IP flow is wired in `serve()` (`lib.rs`) and exercised
// end-to-end by `dom-integration-tests` against a bound socket. Unit tests
// here verify that rate limiting is *configured*; per-IP enforcement is an
// integration-level concern.
#[cfg(test)]
pub fn rate_limit_submit(limit: u32) -> GovernorLayer<GlobalKeyExtractor, NoOpMiddleware> {
    let config = GovernorConfigBuilder::default()
        .key_extractor(GlobalKeyExtractor)
        .per_second(1)
        .burst_size(limit)
        .finish()
        .expect("rate limit config valid");

    GovernorLayer {
        config: Arc::new(config),
    }
}

/// Build read admission control (burst 100, sustained refill 1 req/sec).
#[cfg(not(test))]
pub fn rate_limit_read(limit: u32) -> GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware> {
    let config = GovernorConfigBuilder::default()
        .key_extractor(PeerIpKeyExtractor)
        .per_second(1)
        .burst_size(limit)
        .finish()
        .expect("rate limit config valid");

    GovernorLayer {
        config: Arc::new(config),
    }
}

// See `rate_limit_submit` above for the rationale — same trade-off applies
// to the read path.
#[cfg(test)]
pub fn rate_limit_read(limit: u32) -> GovernorLayer<GlobalKeyExtractor, NoOpMiddleware> {
    let config = GovernorConfigBuilder::default()
        .key_extractor(GlobalKeyExtractor)
        .per_second(1)
        .burst_size(limit)
        .finish()
        .expect("rate limit config valid");

    GovernorLayer {
        config: Arc::new(config),
    }
}

/// Add the minimal cross-origin response header to public, read-only routes.
///
/// This middleware must only be attached to the router containing public GET
/// endpoints. In particular, authenticated routes must not opt into browser
/// cross-origin access: the RPC bearer token protects node administration and
/// private USDOM history, transfer and burn operations.
pub async fn public_get_cors_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    // Height-addressed blocks, canonical ancestry and node status can change
    // across a reorg or the next block. Do not let a browser/proxy persist an
    // old projection and mistake it for current node state.
    headers.insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        axum::http::HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        axum::http::HeaderValue::from_static("GET"),
    );
    response
}

/// Middleware to validate Bearer token.
pub async fn require_bearer_token(
    axum::extract::State(token): axum::extract::State<Arc<BearerToken>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if token.0.trim().is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let provided = header[7..].trim();
            if provided.is_empty() {
                return Err(StatusCode::UNAUTHORIZED);
            }
            // Constant-time comparison to avoid leaking the token via a
            // short-circuiting byte compare (timing side-channel). `ct_eq`
            // compares equal-length byte slices without an observable early
            // return; differing lengths compare unequal (the token length is
            // public, so that carries no secret). Accept/reject logic is
            // identical to the previous `==`.
            if bool::from(provided.as_bytes().ct_eq(token.0.as_bytes())) {
                let mut response = next.run(req).await;
                // Authenticated reads include wallet state and private USDOM
                // scan results. Never permit an intermediary or browser cache
                // to retain them, even on the loopback-only transport.
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    axum::http::HeaderValue::from_static("no-store"),
                );
                Ok(response)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, middleware::from_fn_with_state, routing::get, Router};
    use tower::ServiceExt;

    /// A 64-char (256-bit) token, the shape produced by `generate_token`.
    const TOK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    async fn protected() -> &'static str {
        "ok"
    }

    #[tokio::test]
    async fn listener_host_is_exact_and_checked_before_handler() {
        let local: SocketAddr = "127.0.0.1:33372".parse().unwrap();
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(from_fn_with_state(local, require_listener_host));

        for host in ["127.0.0.1:33372", "localhost:33372", "LOCALHOST:33372"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header(header::HOST, host)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "host {host}");
        }

        for host in [
            None,
            Some("attacker.example:33372"),
            Some("127.0.0.1:33373"),
            Some("127.0.0.1"),
            Some("localhost:33372.example"),
        ] {
            let mut request = Request::builder().uri("/");
            if let Some(host) = host {
                request = request.header(header::HOST, host);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::MISDIRECTED_REQUEST,
                "host {host:?}"
            );
        }
    }

    #[tokio::test]
    async fn canonical_http_framing_rejects_ambiguous_or_oversized_metadata() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(require_canonical_http_framing));

        let valid = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/?page=1")
                    .header(header::CONTENT_LENGTH, "0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(valid.status(), StatusCode::OK);

        for (name, value) in [
            (header::CONTENT_ENCODING, "gzip"),
            (header::TRANSFER_ENCODING, "chunked"),
            (header::CONTENT_LENGTH, "1"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header(name, value)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let oversized = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-padding", "x".repeat(MAX_RPC_HEADER_BYTES + 1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
    }

    fn auth_app(token: &str) -> Router {
        let bt = Arc::new(BearerToken(token.to_string()));
        Router::new()
            .route("/protected", get(protected))
            .layer(from_fn_with_state(bt, require_bearer_token))
    }

    #[tokio::test]
    async fn inflight_capacity_rejects_instead_of_queueing_and_releases_on_cancel() {
        let capacity = Arc::new(Semaphore::new(1));
        let app = Router::new()
            .route(
                "/held",
                get(|| async { std::future::pending::<()>().await }),
            )
            .layer(from_fn_with_state(
                Arc::clone(&capacity),
                require_inflight_capacity,
            ));

        let first = tokio::spawn(
            app.clone()
                .oneshot(Request::builder().uri("/held").body(Body::empty()).unwrap()),
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while capacity.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first request holds the only response-generation slot");

        let second = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.oneshot(Request::builder().uri("/held").body(Body::empty()).unwrap()),
        )
        .await
        .expect("excess request must be rejected without queueing")
        .unwrap();
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);

        first.abort();
        let _ = first.await;
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while capacity.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancellation releases the response-generation slot");
    }

    /// Drive one request through the auth middleware and return the status.
    async fn status_for(app_token: &str, auth_header: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().uri("/protected");
        if let Some(h) = auth_header {
            builder = builder.header(header::AUTHORIZATION, h);
        }
        let req = builder.body(Body::empty()).expect("request");
        auth_app(app_token)
            .oneshot(req)
            .await
            .expect("oneshot")
            .status()
    }

    #[tokio::test]
    async fn bearer_correct_token_authorizes() {
        let request = Request::builder()
            .uri("/protected")
            .header(header::AUTHORIZATION, format!("Bearer {TOK}"))
            .body(Body::empty())
            .unwrap();
        let response = auth_app(TOK).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    #[tokio::test]
    async fn bearer_wrong_token_same_length_rejected() {
        // Flip the first char → same length, different content (exercises the
        // constant-time equal-length path).
        let mut wrong = TOK.to_string();
        wrong.replace_range(0..1, "f");
        assert_ne!(wrong, TOK);
        assert_eq!(
            status_for(TOK, Some(&format!("Bearer {wrong}"))).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn bearer_short_token_rejected() {
        assert_eq!(
            status_for(TOK, Some("Bearer short")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn bearer_long_token_rejected() {
        assert_eq!(
            status_for(TOK, Some(&format!("Bearer {TOK}extra"))).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn bearer_missing_header_rejected() {
        assert_eq!(status_for(TOK, None).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_non_bearer_scheme_rejected() {
        assert_eq!(
            status_for(TOK, Some(&format!("Basic {TOK}"))).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn rate_limit_submit_default_is_10() {
        let layer = rate_limit_submit(DEFAULT_SUBMIT_BURST);
        assert!(Arc::strong_count(&layer.config) >= 1);
    }

    #[test]
    fn rate_limit_read_default_is_100() {
        let layer = rate_limit_read(DEFAULT_READ_BURST);
        assert!(Arc::strong_count(&layer.config) >= 1);
    }

    #[test]
    fn burst_limit_parser_is_canonical_and_bounded() {
        assert_eq!(parse_burst_limit("LIMIT", None, 10, 1_000), Ok(10));
        assert_eq!(
            parse_burst_limit("LIMIT", Some(OsStr::new("1")), 10, 1_000),
            Ok(1)
        );
        assert_eq!(
            parse_burst_limit("LIMIT", Some(OsStr::new("1000")), 10, 1_000),
            Ok(1_000)
        );
        for invalid in [
            "",
            "0",
            "01",
            "1001",
            "-1",
            "+1",
            " 1",
            "1 ",
            "01x",
            "4294967296",
        ] {
            assert!(
                parse_burst_limit("LIMIT", Some(OsStr::new(invalid)), 10, 1_000).is_err(),
                "accepted invalid burst setting {invalid:?}"
            );
        }
        assert!(parse_burst_limit("LIMIT", None, 0, 1_000).is_err());
        assert!(parse_burst_limit("LIMIT", None, 1_001, 1_000).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn burst_limit_parser_rejects_non_utf8_environment_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let raw = std::ffi::OsString::from_vec(vec![0xff]);
        assert!(parse_burst_limit("LIMIT", Some(raw.as_os_str()), 10, 1_000).is_err());
    }

    #[test]
    fn complete_rate_limit_policy_rejects_either_invalid_value() {
        assert_eq!(
            RpcRateLimitPolicy::from_raw(None, None),
            Ok(RpcRateLimitPolicy {
                submit_burst: DEFAULT_SUBMIT_BURST,
                read_burst: DEFAULT_READ_BURST,
            })
        );
        assert!(RpcRateLimitPolicy::from_raw(Some(OsStr::new("0")), None).is_err());
        assert!(RpcRateLimitPolicy::from_raw(None, Some(OsStr::new("10001"))).is_err());
    }
}
