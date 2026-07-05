// AUTHORED-BY Claude Fable 5
//! P1.4 (`docs/design/beyond-50k-throughput.md` §4, item P1.4 — the vectored-write /
//! response-coalescing audit): a DETERMINISTIC guard that pins the number of write-family
//! syscalls the HTTP/1.1 response path emits per response, measured at the hyper→transport seam.
//!
//! ## Why this test exists — the P1.4 finding
//!
//! The P0.1 Linux syscall baseline (`bench/syscalls-results/2026-07-04-linux.md`) shows a
//! **`writev` 1.04/req + `write` 1.04/req** pair on every read class (anon-doc, listing,
//! authed-doc). The design doc's §2.1/§4 flagged, as UNVERIFIED, whether the response
//! "header+body coalesce into one vectored write" — the P1.4 lever was to collapse a presumed
//! two-writes-per-response into one.
//!
//! This test resolves that flag with a deterministic, cross-platform measurement. It wraps a REAL
//! accepted loopback `TcpStream` in a counting adapter that tallies every `poll_write` vs
//! `poll_write_vectored` hyper issues (== the real `write`/`writev` syscalls on the connection
//! socket, modulo partial writes — which do not occur for these tiny loopback responses), then
//! drives K sequential keep-alive GETs through the SAME `hyper_util` auto `Builder` that
//! `axum::serve` uses.
//!
//! The measured result (asserted below): **exactly 1 `writev` and 0 plain `write` per response**
//! for the small-RDF hot path, a container-listing-sized body, AND a `206 Partial Content` Range
//! response. hyper's h1 encoder ALREADY buffers the response head + a length-delimited `Bytes`
//! body into ONE `WriteBuf` and flushes it as a single vectored write (Queue strategy, since a
//! loopback `TcpStream` advertises `is_write_vectored() == true`). Over TLS the same bytes leave
//! as a single flattened `write` (rustls advertises `is_write_vectored() == false`); either way
//! the response is ONE write-family syscall.
//!
//! **Therefore the P0.1 `write` 1.04/req is NOT the HTTP response** — the response is already at
//! the P1.4 target of one write per response. The second per-request `write` is a process-level
//! (non-connection-socket) syscall: the tokio multi-threaded runtime's mio reactor waker
//! (`write()` to an `eventfd`), which fires ~once per request under a single-connection
//! work-stealing ping-pong. It is NOT reducible by any response-serialization change; reducing it
//! is a runtime-level lever (`SO_REUSEPORT` sharded single-thread accept — P1.7 — or the Phase-3
//! thread-per-core direction), out of P1.4's scope. Confirming the strace `write` is specifically
//! the reactor waker fd needs an EC2 re-run of `bench/syscalls.sh` with `strace -yy -e
//! trace=write,writev` (the `-yy` shows the fd kind: `<eventfd:...>` vs the connection socket).
//!
//! ## What this guards
//!
//! This is a REGRESSION guard, not an optimization: it locks in the coalescing so a future change
//! that splits the response into a header write + a separate body write (e.g. returning the body
//! as a multi-frame / unknown-length streaming body instead of a single length-delimited `Bytes`
//! frame, or a body wrapper that breaks `is_end_stream`/`size_hint`) is caught here — that would
//! double the response write syscalls on the hot path. It also asserts the response BYTES are
//! byte-identical to what was constructed (the coalesced write must not truncate/reorder).

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{header, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

type BoxBody = UnsyncBoxBody<Bytes, std::convert::Infallible>;

/// Counts hyper's write-family calls at the transport seam.
struct Counters {
    writes: AtomicUsize,
    writevs: AtomicUsize,
}

/// Wraps a real accepted `TcpStream`, forwarding all I/O to it while counting how many times
/// hyper calls `poll_write` (a plain `write(2)`) vs `poll_write_vectored` (a `writev(2)`). Because
/// hyper writes exclusively through the IO handed to it, these counts equal the response's real
/// write-family syscalls on the connection socket (partial writes, which would inflate the count,
/// do not occur for these tiny loopback responses).
struct CountIo {
    inner: TcpStream,
    c: Arc<Counters>,
}

impl AsyncRead for CountIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CountIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.c.writes.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.c.writevs.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A representative small-RDF GET response: length-delimited `Bytes` body + Content-Length, exactly
/// the shape the LDP handler emits (`src/ldp/handler.rs`, `RangeOutcome::Full`).
fn full_response(body: Bytes) -> Response<BoxBody> {
    let len = body.len();
    let mut resp = Response::new(Full::new(body).boxed_unsync());
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, "text/turtle".parse().unwrap());
    h.insert(header::CONTENT_LENGTH, len.to_string().parse().unwrap());
    h.insert(
        header::ACCEPT_RANGES,
        header::HeaderValue::from_static("bytes"),
    );
    h.insert("etag", "\"abc123\"".parse().unwrap());
    h.insert(header::VARY, "Accept".parse().unwrap());
    resp
}

/// A `206 Partial Content` Range response (`src/ldp/handler.rs`, `RangeOutcome::Satisfied`).
fn range_response(full: Bytes, start: usize, end_inclusive: usize) -> Response<BoxBody> {
    let slice = full.slice(start..=end_inclusive);
    let len = slice.len();
    let total = full.len();
    let mut resp = Response::new(Full::new(slice).boxed_unsync());
    *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, "text/turtle".parse().unwrap());
    h.insert(header::CONTENT_LENGTH, len.to_string().parse().unwrap());
    h.insert(
        header::CONTENT_RANGE,
        format!("bytes {start}-{end_inclusive}/{total}")
            .parse()
            .unwrap(),
    );
    h.insert(
        header::ACCEPT_RANGES,
        header::HeaderValue::from_static("bytes"),
    );
    resp
}

/// Serve K sequential keep-alive requests through the `auto::Builder` (what `axum::serve` uses),
/// returning `(writes, writevs, is_write_vectored)`. Asserts the response body bytes each request
/// are byte-identical to `expected_body`.
async fn measure(
    request: &'static [u8],
    response_factory: impl Fn() -> Response<BoxBody> + Send + Sync + 'static,
    expected_body: &'static [u8],
    k: usize,
) -> (usize, usize, bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let c = Arc::new(Counters {
        writes: AtomicUsize::new(0),
        writevs: AtomicUsize::new(0),
    });
    let c2 = c.clone();

    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        sock.set_nodelay(true).ok();
        let vectored = sock.is_write_vectored();
        let cio = CountIo { inner: sock, c: c2 };
        let factory = Arc::new(response_factory);
        let svc = service_fn(move |_req: http::Request<hyper::body::Incoming>| {
            let factory = factory.clone();
            async move { Ok::<_, std::convert::Infallible>(factory()) }
        });
        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(cio), svc)
            .await;
        vectored
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.set_nodelay(true).ok();
    let mut rbuf = vec![0u8; 8192];
    for i in 0..k {
        stream.write_all(request).await.unwrap();
        stream.flush().await.unwrap();
        // Read exactly one full response: parse headers, then read Content-Length body bytes.
        let mut acc: Vec<u8> = Vec::new();
        let (hdr_end, body_len) = loop {
            if let Some(pos) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = &acc[..pos];
                let head_str = String::from_utf8_lossy(head).to_ascii_lowercase();
                let cl = head_str
                    .split("\r\n")
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse::<usize>().unwrap())
                    .expect("content-length header present");
                break (pos + 4, cl);
            }
            let n = stream.read(&mut rbuf).await.unwrap();
            assert!(n > 0, "unexpected EOF reading headers (req {i})");
            acc.extend_from_slice(&rbuf[..n]);
        };
        while acc.len() < hdr_end + body_len {
            let n = stream.read(&mut rbuf).await.unwrap();
            assert!(n > 0, "unexpected EOF reading body (req {i})");
            acc.extend_from_slice(&rbuf[..n]);
        }
        let body = &acc[hdr_end..hdr_end + body_len];
        assert_eq!(
            body, expected_body,
            "response body must be byte-identical (req {i})"
        );
    }
    drop(stream);
    let vectored = server.await.unwrap();
    (
        c.writes.load(Ordering::SeqCst),
        c.writevs.load(Ordering::SeqCst),
        vectored,
    )
}

const HOT_DOC: &[u8] = b"<https://pod.example/a/x#me> <http://p> <http://o> .\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn small_rdf_get_is_single_vectored_write() {
    let k = 16;
    let (writes, writevs, vectored) = measure(
        b"GET /a/x HTTP/1.1\r\nHost: pod.example\r\n\r\n",
        || full_response(Bytes::from_static(HOT_DOC)),
        HOT_DOC,
        k,
    )
    .await;
    assert!(
        vectored,
        "loopback TcpStream must advertise vectored writes"
    );
    // The P1.4 target: exactly one write-family syscall per response, and it is vectored (head+body
    // coalesced), never a header-writev + body-write split.
    assert_eq!(
        writes, 0,
        "no plain write() — head+body must not split (got {writes})"
    );
    assert_eq!(
        writevs, k,
        "exactly one writev per response (got {writevs} over {k})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn container_listing_sized_get_is_single_vectored_write() {
    // A container-listing-sized body (~5 KiB, matching the P0.1 `listing` class at 5199 B).
    let listing: &'static [u8] = Box::leak(vec![b'x'; 5199].into_boxed_slice());
    let k = 16;
    let (writes, writevs, _vectored) = measure(
        b"GET /c/ HTTP/1.1\r\nHost: pod.example\r\n\r\n",
        move || full_response(Bytes::from_static(listing)),
        listing,
        k,
    )
    .await;
    // Robust invariant: the body is never split off into a separate plain write. A ~5 KiB body is
    // atomic on loopback, so it stays exactly one writev per response.
    assert_eq!(
        writes, 0,
        "no plain write() for the listing body (got {writes})"
    );
    assert_eq!(
        writevs, k,
        "one writev per listing response (got {writevs} over {k})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn range_206_is_single_vectored_write() {
    let k = 16;
    let expected: &[u8] = &HOT_DOC[0..=9];
    let (writes, writevs, _vectored) = measure(
        b"GET /a/x HTTP/1.1\r\nHost: pod.example\r\nRange: bytes=0-9\r\n\r\n",
        || range_response(Bytes::from_static(HOT_DOC), 0, 9),
        expected,
        k,
    )
    .await;
    assert_eq!(
        writes, 0,
        "no plain write() for a 206 Range body (got {writes})"
    );
    assert_eq!(
        writevs, k,
        "one writev per 206 response (got {writevs} over {k})"
    );
}
