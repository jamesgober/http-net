# Migration guide

How to move between `http-net` versions. Each section lists every change a
user of the previous version can notice, why it was made, and what to do.
Additions that change no existing behaviour are listed at the end of each
section.

## 0.2 to 0.3

Update the dependency:

```toml
[dependencies]
http-net = "0.3"
```

Most code builds unchanged. The changes below are behavioural: they refuse
or hide things 0.2.0 accepted or printed. Each one closes a smuggling or
leak path, so none of them has an opt-out.

### `Debug` output hides credential values

**What changed.** Every `Debug` implementation in the crate now replaces the
values of `authorization`, `proxy-authorization`, `cookie`, and `set-cookie`
with `<redacted N bytes>`, where `N` is the value's length. This covers
`RequestHead`, `ResponseHead`, `Headers`, `ServerEvent` and `ClientEvent`
(which print the views they carry), `Request`, `Response`, and
`blocking::ClientResponse`. Field names are matched ASCII
case-insensitively. In 0.2.0 these values were printed in full.

**Why.** A `{:?}` of a request in a log line printed session cookies and
bearer tokens (threat T-35, requirement FR-55).

**What to do.** Nothing, unless a test or a log parser compared `Debug`
output that contained one of these values. To read a value, use the
accessors, which are unchanged: `header`, `header_str`, `headers`,
`header_all`, and `header_value` on the builders still return the real
bytes.

```rust
use http_net::{ServerConn, ServerEvent};

let mut conn = ServerConn::new();
let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer t0k3n\r\n\r\n");
let ServerEvent::Request(req) = conn.poll()? else { unreachable!() };
assert!(!format!("{req:?}").contains("t0k3n"));
assert_eq!(req.header("authorization"), Some(&b"Bearer t0k3n"[..]));
# Ok::<(), http_net::HttpError>(())
```

### `h2c` is no longer an upgrade offer

**What changed.** A request whose `Upgrade` field offers only `h2c` now
reports `is_upgrade() == false` and is served as plain HTTP/1.1.
`Upgrade: h2c, websocket` is still an upgrade offer (for `websocket`).
`Response::switching_protocols("h2c")` and `Request::upgrade("h2c")` are
refused with the new `HttpError::UpgradeNotOffered` (when the response is
written, or when the request is sent).

**Why.** RFC 9113 section 3.1 deprecates the `h2c` upgrade, and proxies that
forward `Upgrade: h2c` blindly are the h2c smuggling attack (threat T-20).
RFC 9110 section 7.8 lets a server ignore `Upgrade`, so ignoring `h2c` breaks
no client: it falls back to HTTP/1.1.

**What to do.** If you answered `h2c` upgrades, stop: route prior-knowledge
HTTP/2 to an HTTP/2 engine instead (preface detection is planned for 0.5).

### A `101` must name a protocol the client offered

**What changed.** `ServerConn::respond` with `Response::switching_protocols(p)`
now fails with `HttpError::UpgradeNotOffered` unless the request's `Upgrade`
list offered `p`. Names are compared ASCII case-insensitively
(`WebSocket` matches `websocket`), and a `101` naming only a protocol name
matches an offer of that name with or without a version (`websocket`
matches `websocket/13`). In 0.2.0 any token was accepted.

**Why.** RFC 9110 section 7.8: a server MUST NOT switch to a protocol the
client did not indicate. A proxy that believes an upgrade succeeded while
the origin switched to something else is the upgrade smuggling shape
(threat T-21).

**What to do.** Answer with a protocol taken from the request's `Upgrade`
field (`req.header("upgrade")`), or send a normal response.

### New error variant `HttpError::UpgradeNotOffered`

**What changed.** A usage error for the two cases above. `status()` is
`None`; `is_usage_error()` is true.

**What to do.** `HttpError` has been `#[non_exhaustive]` since it was introduced, so every
`match` on it already has a wildcard arm and keeps compiling. Add an arm if
you want to handle it explicitly.

### Stricter `Host` and authority validation

**What changed.** An empty host before a port (`Host: :80`) and a `%` not
followed by two hex digits (`Host: a%zz`, `Host: a%4`) are now refused:
`InvalidHost` for the `Host` field, `InvalidTarget` for the authority of a
`CONNECT` target or an absolute-form target, and `InvalidHost` from
`Request::header("host", ...)`. Valid escapes (`a%41`), IPvFuture literals,
an empty port (`example.com:`), and an empty `Host` (a target with no
authority) are still accepted. A port above 65535 is still accepted by
syntax, as RFC 3986 does not bound it.

**Why.** Requirement FR-12 and threat T-18: hosts that different components
parse differently are a routing and cache-key confusion vector, and RFC 9112
section 3.2 requires 400 for an invalid `Host`.

**What to do.** Nothing for well-formed clients. Such requests are now
answered 400 by the blocking server.

### The client accepts a status line without the space after the code

**What changed.** `ClientConn` now accepts `HTTP/1.1 200` CRLF (no space and
no reason phrase); `ResponseHead::reason()` is then `""`. In 0.2.0 it was
`InvalidStartLine`. The server side is unaffected.

**Why.** Real servers send it, and it cannot change framing (requirement
FR-41).

**What to do.** Nothing. If you relied on the error to reject such servers,
check `reason()` yourself.

### `reason_phrase` covers the whole status registry

**What changed.** `reason_phrase` now returns the registered phrase for
`102`, `103`, `207`, `208`, `226`, `305`, `402`, `407`, `423`, `424`, `425`,
`451`, `506`, `507`, `508`, `510`, and `511`, which returned `""` in 0.2.0.
`306` and `418` return `""`: the registry lists them as unused (RFC 9110
sections 15.4.7 and 15.5.19). `ServerConn::respond` writes these phrases in
the status line, so a response with one of these codes now carries its
phrase.

**What to do.** Nothing, unless a test compared a status line byte for byte.

### Upgrade protocols may carry a version

**What changed.** `Response::switching_protocols` and `Request::upgrade`
accept a `name/version` product token (`foo/2`) as RFC 9110 section 7.8
defines a protocol; 0.2.0 refused anything but a plain token with
`InvalidHeaderValue`.

**What to do.** Nothing.

### Added in 0.3

These change no existing behaviour:

- `VERSION`: the crate version string.
- `HttpError::is_peer_error` and `HttpError::is_usage_error`.
- `Limits::buffer_capacity`: the input buffer's hard capacity, for memory
  planning.
- `RequestHead::target_form` and the `TargetForm` enum.
- `RequestHead::header_all`, `ResponseHead::header_all`, and the
  `HeaderValues` iterator: every field with one name, in order (each
  `Set-Cookie` separately).
- `RequestHead::content_length` and `ResponseHead::content_length`: the
  declared `Content-Length`, so `Content-Length: 0` (`Some(0)`) can be told
  apart from an absent one; `framing()` still reports `BodyFraming::None`
  for both.
- `Method::is_safe`, `Method::is_idempotent`, `Method::index`, and the
  `MethodSet` bit set (with `write_allow` for the `Allow` field of a 405).
- `StatusClass`, `status_class`, and the `status` module of named status
  code constants.
- `Response::from_error`: the response for a request parse error (the
  blocking server now builds its error answers with it; the bytes it sends
  are the same as in 0.2.0).
- `Request::head`, `Request::put`, `Request::delete`, `Request::options`.
