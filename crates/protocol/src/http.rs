//! Bounded HTTP/1.1 framing shared by local and encrypted API transports.
use crate::{MAX_REQUEST_BODY, Request, Response};

pub const MAX_HEADER_BYTES: usize = 8192;
pub const MAX_RESPONSE_BYTES: usize = wgfeel_core::MAX_MANAGEMENT_BYTES + MAX_HEADER_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub struct HttpError(pub u16);

pub fn encode_request(request: Request<'_>) -> Result<zeroize::Zeroizing<Vec<u8>>, HttpError> {
    encode_request_with_limit(request, MAX_REQUEST_BODY)
}
pub fn encode_request_with_limit(
    request: Request<'_>,
    body_limit: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, HttpError> {
    if request.method.is_empty()
        || !request.method.bytes().all(|byte| byte.is_ascii_uppercase())
        || !request.target.starts_with('/')
        || !request.target.bytes().all(|byte| byte.is_ascii_graphic())
        || [request.authorization, request.if_match]
            .into_iter()
            .flatten()
            .any(|value| {
                !value
                    .bytes()
                    .all(|byte| byte == b' ' || byte.is_ascii_graphic())
            })
        || request.body.len() > body_limit
    {
        return Err(HttpError(400));
    }
    let prefix = format!(
        "{} {} HTTP/1.1\r\nHost: wgfeel\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        request.method,
        request.target,
        request.body.len()
    );
    let header_len = prefix
        .len()
        .saturating_add(2)
        .saturating_add(
            request
                .authorization
                .map_or(0, |value| value.len().saturating_add(17)),
        )
        .saturating_add(
            request
                .if_match
                .map_or(0, |value| value.len().saturating_add(12)),
        );
    if header_len > MAX_HEADER_BYTES {
        return Err(HttpError(431));
    }
    // Allocate before copying credentials: growing a secret-bearing allocation
    // would free its old storage without Zeroizing seeing that old allocation.
    let mut output = zeroize::Zeroizing::new(Vec::with_capacity(header_len + request.body.len()));
    output.extend_from_slice(prefix.as_bytes());
    if let Some(value) = request.authorization {
        output.extend_from_slice(b"Authorization: ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    if let Some(value) = request.if_match {
        output.extend_from_slice(b"If-Match: ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(request.body);
    Ok(output)
}

pub fn decode_response(input: &[u8]) -> Result<Option<Response>, HttpError> {
    if input.len() > MAX_RESPONSE_BYTES {
        return Err(HttpError(413));
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut headers);
    let end = match parsed.parse(input).map_err(|_| HttpError(400))? {
        httparse::Status::Complete(end) if end <= MAX_HEADER_BYTES => end,
        httparse::Status::Complete(_) => return Err(HttpError(431)),
        httparse::Status::Partial if input.len() <= MAX_HEADER_BYTES => return Ok(None),
        httparse::Status::Partial => return Err(HttpError(431)),
    };
    if parsed.version != Some(1) {
        return Err(HttpError(400));
    }
    let (mut length, mut generation) = (None, None);
    for header in parsed.headers.iter() {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpError(400));
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            let text = std::str::from_utf8(header.value).map_err(|_| HttpError(400))?;
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(HttpError(400));
            }
            let value = text.parse::<usize>().map_err(|_| HttpError(413))?;
            if length.replace(value).is_some() {
                return Err(HttpError(400));
            }
        }
        if header.name.eq_ignore_ascii_case("etag") {
            let text = std::str::from_utf8(header.value).map_err(|_| HttpError(400))?;
            let value = parse_revision(text).ok_or(HttpError(400))?;
            if generation.replace(value).is_some() {
                return Err(HttpError(400));
            }
        }
    }
    let length = length.ok_or(HttpError(400))?;
    if length > MAX_RESPONSE_BYTES - end {
        return Err(HttpError(413));
    }
    if input.len() < end + length {
        return Ok(None);
    }
    if input.len() != end + length {
        return Err(HttpError(400));
    }
    Ok(Some(Response {
        status: parsed.code.ok_or(HttpError(400))?,
        generation,
        body: input[end..].to_vec(),
        is_config: parsed.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type") && header.value == b"text/plain"
        }),
    }))
}

pub fn parse_revision(value: &str) -> Option<u64> {
    let number = value.strip_prefix('"')?.strip_suffix('"')?;
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let result = number.parse::<u64>().ok()?;
    (result > 0 && result.to_string() == number).then_some(result)
}

pub fn decode_request(input: &[u8]) -> Result<Option<Request<'_>>, HttpError> {
    decode_request_with_limit(input, MAX_REQUEST_BODY)
}
pub fn decode_request_with_limit(
    input: &[u8],
    body_limit: usize,
) -> Result<Option<Request<'_>>, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Request::new(&mut headers);
    let end = match parsed.parse(input) {
        Ok(httparse::Status::Complete(end)) if end <= MAX_HEADER_BYTES => end,
        Ok(httparse::Status::Complete(_)) => return Err(HttpError(431)),
        Ok(httparse::Status::Partial) if input.len() <= MAX_HEADER_BYTES => return Ok(None),
        Ok(httparse::Status::Partial) | Err(httparse::Error::TooManyHeaders) => {
            return Err(HttpError(431));
        }
        Err(_) => return Err(HttpError(400)),
    };
    if parsed.version != Some(1)
        || input[..end]
            .iter()
            .enumerate()
            .any(|(i, byte)| *byte == b'\n' && (i == 0 || input[i - 1] != b'\r'))
    {
        return Err(HttpError(400));
    }
    let (mut host, mut authorization, mut revision, mut length, mut content_type) =
        (None, None, None, None, None);
    for header in parsed.headers.iter() {
        let name = header.name;
        let slot = if name.eq_ignore_ascii_case("host") {
            &mut host
        } else if name.eq_ignore_ascii_case("authorization") {
            &mut authorization
        } else if name.eq_ignore_ascii_case("if-match") {
            &mut revision
        } else if name.eq_ignore_ascii_case("content-length") {
            &mut length
        } else if name.eq_ignore_ascii_case("content-type") {
            &mut content_type
        } else if ["transfer-encoding", "upgrade", "expect", "content-encoding"]
            .iter()
            .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
        {
            return Err(HttpError(400));
        } else {
            continue;
        };
        let value = std::str::from_utf8(header.value).map_err(|_| HttpError(400))?;
        if slot.replace(value).is_some() {
            return Err(HttpError(400));
        }
    }
    if host.is_none_or(str::is_empty) {
        return Err(HttpError(400));
    }
    let method = parsed.method.ok_or(HttpError(400))?;
    if method == "POST" && content_type != Some("application/json") {
        return Err(HttpError(415));
    }
    if method == "POST" && length.is_none() {
        return Err(HttpError(411));
    }
    let length = match length {
        None => 0,
        Some(text) if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) => {
            text.parse::<usize>().map_err(|_| HttpError(413))?
        }
        Some(_) => return Err(HttpError(400)),
    };
    if length > body_limit {
        return Err(HttpError(413));
    }
    let total = end + length;
    if input.len() < total {
        return Ok(None);
    }
    // One request per connection. No pipelining, implicit bodies or ambiguous
    // trailing bytes are dispatched to the authoritative handler.
    if input.len() != total {
        return Err(HttpError(400));
    }
    Ok(Some(Request {
        method,
        target: parsed.path.ok_or(HttpError(400))?,
        authorization,
        if_match: revision,
        body: &input[end..total],
    }))
}

/// Encoded responses can contain device keys or newly issued credentials.
/// Keep erasure attached to the buffer across all transports and error paths.
pub fn encode_response(response: &Response) -> zeroize::Zeroizing<Vec<u8>> {
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let mut output = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        response.status,
        if response.is_config {
            "text/plain"
        } else {
            "application/json"
        },
        response.body.len()
    );
    if let Some(generation) = response.generation {
        output.push_str(&format!("ETag: \"{generation}\"\r\n"));
    }
    if response.status == 401 {
        output.push_str("WWW-Authenticate: Bearer\r\n");
    }
    output.push_str("\r\n");
    let mut bytes = zeroize::Zeroizing::new(output.into_bytes());
    // Grow before copying the sensitive body; no secret-bearing allocation moves.
    bytes.reserve(response.body.len());
    bytes.extend_from_slice(&response.body);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_REQUEST_BODY;

    #[test]
    fn fragmented_request_preserves_exact_auth_path_revision_and_body() {
        let input = b"POST /api/v1/users HTTP/1.1\r\nHost: wgfeel\r\nAuthorization: Bearer credential\r\nIf-Match: \"7\"\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        for end in 0..input.len() {
            assert!(decode_request(&input[..end]).unwrap().is_none());
        }
        let parsed = decode_request(input).unwrap().unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/api/v1/users");
        assert_eq!(parsed.authorization, Some("Bearer credential"));
        assert_eq!(parsed.if_match, Some("\"7\""));
        assert_eq!(parsed.body, b"{}");
    }

    #[test]
    fn rejects_smuggling_ambiguous_headers_and_unsupported_framing() {
        for headers in [
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            "Content-Length: +0\r\n",
            "Content-Length: 0, 0\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Transfer-Encoding: identity\r\n",
            "Authorization: Bearer a\r\nauthorization: Bearer b\r\n",
            "If-Match: \"1\"\r\nIF-MATCH: \"1\"\r\n",
            "Host: another\r\n",
            "Upgrade: websocket\r\n",
            "Expect: 100-continue\r\n",
            "Content-Type: application/json\r\nContent-Type: text/plain\r\n",
        ] {
            let input = format!("GET /api/v1/config HTTP/1.1\r\nHost: wgfeel\r\n{headers}\r\n");
            assert!(decode_request(input.as_bytes()).is_err(), "{headers}");
        }
        for input in [
            "GET /api/v1/config HTTP/1.0\r\nHost: wgfeel\r\n\r\n",
            "GET /api/v1/config HTTP/1.1\r\n\r\n",
            "GET /api/v1/config HTTP/1.1\nHost: wgfeel\n\n",
            "GET /api/v1/config HTTP/1.1\r\nHost: wgfeel\r\n\r\nextra",
            "POST /api/v1/users HTTP/1.1\r\nHost: wgfeel\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            assert!(decode_request(input.as_bytes()).is_err());
        }
    }

    #[test]
    fn bounds_declared_body_and_partial_headers_without_waiting_for_payload() {
        let input = format!(
            "POST /api/v1/users HTTP/1.1\r\nHost: wgfeel\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY + 1
        );
        assert!(matches!(
            decode_request(input.as_bytes()),
            Err(HttpError(413))
        ));
        let input = format!(
            "GET / HTTP/1.1\r\nX-Padding: {}",
            "a".repeat(MAX_HEADER_BYTES)
        );
        assert!(matches!(
            decode_request(input.as_bytes()),
            Err(HttpError(431))
        ));
    }

    #[test]
    fn response_has_byte_length_revision_close_and_no_cache() {
        let response = Response {
            status: 201,
            generation: Some(42),
            body: "{\"name\":\"Ноутбук\"}".as_bytes().to_vec(),
            is_config: false,
        };
        let wire = encode_response(&response);
        let text = std::str::from_utf8(&wire).unwrap();
        let (headers, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("HTTP/1.1 201 Created\r\n"));
        assert!(headers.contains(&format!("Content-Length: {}\r\n", response.body.len())));
        assert!(headers.contains("ETag: \"42\""));
        assert!(headers.contains("Cache-Control: no-store"));
        assert!(headers.contains("Connection: close"));
        assert_eq!(body.as_bytes(), response.body);
    }

    #[test]
    fn client_request_and_response_keep_framing_and_status() {
        let bytes = encode_request(Request {
            method: "POST",
            target: "/api/v1/users",
            authorization: Some("Bearer value"),
            if_match: Some("\"1\""),
            body: b"{}",
        })
        .unwrap();
        let request = decode_request(&bytes).unwrap().unwrap();
        assert_eq!(request.authorization, Some("Bearer value"));
        assert_eq!(request.if_match, Some("\"1\""));
        assert_eq!(request.body, b"{}");
        let wire = b"HTTP/1.1 412 Precondition Failed\r\nContent-Length: 20\r\nETag: \"2\"\r\n\r\n{\"error\":\"conflict\"}";
        for end in 0..wire.len() {
            assert!(decode_response(&wire[..end]).unwrap().is_none());
        }
        let response = decode_response(wire).unwrap().unwrap();
        assert_eq!(response.status, 412);
        assert_eq!(response.generation, Some(2));
        assert_eq!(response.body, br#"{"error":"conflict"}"#);
        for bad in [
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: \"1\"\r\nETag: \"2\"\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nx",
        ] {
            assert!(decode_response(bad.as_bytes()).is_err());
        }
        assert!(
            encode_request(Request {
                method: "GET",
                target: "/",
                authorization: Some("x\r\nHost: injected"),
                if_match: None,
                body: b"",
            })
            .is_err()
        );
    }
}
