//! The connection guard: a stream wrapper between the socket and `tokio-postgres` (§6.9).
//!
//! It parses backend message **headers** as bytes arrive, so it can act before the driver does:
//! - **During authentication** it allows only `AuthenticationOk` (0) and the SASL/SCRAM steps
//!   (10, 11, 12). Cleartext (3), MD5 (5), Kerberos, GSS and SSPI requests are refused before
//!   `tokio-postgres` could answer them, so no password is sent (M0: the driver has no option
//!   for this). The only other messages allowed then are `ErrorResponse` and
//!   `NegotiateProtocolVersion`. Anything else, including a `NoticeResponse` or
//!   `ParameterStatus` that some poolers or proxies send early, refuses the connection
//!   (fail closed).
//! - **For the whole connection** it caps every message's length. `tokio-postgres` buffers a
//!   whole message (e.g. a `DataRow`) before decoding it, so without the cap one huge value would
//!   be allocated in full whatever the row and byte limits say (M2 review, blocker B2). The guard
//!   rejects the message from its 5-byte header, before the body arrives.
//!
//! Messages split across reads are handled: the parser keeps its position between reads.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Why the guard cut the connection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardViolation {
    #[error("the server asked for authentication method {0}, which valetkey refuses (only SCRAM is allowed)")]
    AuthMethod(i32),
    #[error("the server sent an unexpected message `{}` during authentication; connection refused (only errors and protocol negotiation may come before authentication succeeds)", char::from(*.0))]
    UnexpectedDuringAuth(u8),
    #[error("the server sent a {len}-byte message; the limit is {max}")]
    MessageTooLarge { len: u32, max: u32 },
    #[error("the server sent a malformed message header")]
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Authenticating,
    Ready,
}

/// The incremental header parser.
#[derive(Debug)]
struct Parser {
    phase: Phase,
    max_message: u32,
    header: [u8; 5],
    header_len: usize,
    /// Body bytes still to skip in the current message.
    body_left: u32,
    msg_type: u8,
    /// The auth code of an `R` message, collected during authentication.
    auth_code: [u8; 4],
    auth_code_len: usize,
}

impl Parser {
    fn new(max_message: u32) -> Self {
        Self {
            phase: Phase::Authenticating,
            max_message,
            header: [0; 5],
            header_len: 0,
            body_left: 0,
            msg_type: 0,
            auth_code: [0; 4],
            auth_code_len: 0,
        }
    }

    fn feed(&mut self, mut data: &[u8]) -> Result<(), GuardViolation> {
        while !data.is_empty() {
            if self.body_left == 0 && self.header_len < 5 {
                let take = (5 - self.header_len).min(data.len());
                self.header[self.header_len..self.header_len + take].copy_from_slice(&data[..take]);
                self.header_len += take;
                data = &data[take..];
                if self.header_len == 5 {
                    self.start_message()?;
                }
                continue;
            }
            let take = (self.body_left as usize).min(data.len());
            if self.phase == Phase::Authenticating && self.msg_type == b'R' && self.auth_code_len < 4 {
                let code_take = (4 - self.auth_code_len).min(take);
                self.auth_code[self.auth_code_len..self.auth_code_len + code_take].copy_from_slice(&data[..code_take]);
                self.auth_code_len += code_take;
                if self.auth_code_len == 4 {
                    self.check_auth_code()?;
                }
            }
            self.body_left -= take as u32;
            data = &data[take..];
            if self.body_left == 0 {
                self.header_len = 0;
            }
        }
        Ok(())
    }

    fn start_message(&mut self) -> Result<(), GuardViolation> {
        self.msg_type = self.header[0];
        let len = u32::from_be_bytes([self.header[1], self.header[2], self.header[3], self.header[4]]);
        if len < 4 {
            return Err(GuardViolation::Malformed);
        }
        if len > self.max_message {
            return Err(GuardViolation::MessageTooLarge {
                len,
                max: self.max_message,
            });
        }
        if self.phase == Phase::Authenticating {
            match self.msg_type {
                b'R' => {
                    if len < 8 {
                        return Err(GuardViolation::Malformed);
                    }
                    self.auth_code_len = 0;
                }
                b'E' | b'v' => {}
                other => return Err(GuardViolation::UnexpectedDuringAuth(other)),
            }
        }
        self.body_left = len - 4;
        if self.body_left == 0 {
            self.header_len = 0;
        }
        Ok(())
    }

    fn check_auth_code(&mut self) -> Result<(), GuardViolation> {
        match i32::from_be_bytes(self.auth_code) {
            0 => {
                self.phase = Phase::Ready;
                Ok(())
            }
            10..=12 => Ok(()),
            other => Err(GuardViolation::AuthMethod(other)),
        }
    }
}

/// Wraps a connection; see the module docs.
#[derive(Debug)]
pub struct Guarded<S> {
    inner: S,
    parser: Parser,
    violation: Option<GuardViolation>,
    report: Option<Arc<OnceLock<GuardViolation>>>,
}

impl<S> Guarded<S> {
    /// `max_message`: the largest backend message accepted, in bytes.
    pub fn new(inner: S, max_message: u32) -> Self {
        Self {
            inner,
            parser: Parser::new(max_message),
            violation: None,
            report: None,
        }
    }

    /// Also records a violation in `report`, which the caller keeps after handing the stream to
    /// the driver.
    pub fn reporting_to(mut self, report: Arc<OnceLock<GuardViolation>>) -> Self {
        self.report = Some(report);
        self
    }

    /// What tripped the guard, if anything (the driver only sees an I/O error).
    pub fn violation(&self) -> Option<&GuardViolation> {
        self.violation.as_ref()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(v) = &this.violation {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::PermissionDenied, v.to_string())));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let fresh = &buf.filled()[before..];
                if let Err(v) = this.parser.feed(fresh) {
                    // Hide the bytes from the caller and fail the read.
                    buf.set_filled(before);
                    let err = io::Error::new(io::ErrorKind::PermissionDenied, v.to_string());
                    if let Some(report) = &this.report {
                        let _ = report.set(v.clone());
                    }
                    this.violation = Some(v);
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(t: u8, body: &[u8]) -> Vec<u8> {
        let mut m = vec![t];
        m.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
        m.extend_from_slice(body);
        m
    }

    fn auth(code: i32, extra: &[u8]) -> Vec<u8> {
        let mut body = code.to_be_bytes().to_vec();
        body.extend_from_slice(extra);
        msg(b'R', &body)
    }

    fn feed_all(p: &mut Parser, bytes: &[u8], chunk: usize) -> Result<(), GuardViolation> {
        for c in bytes.chunks(chunk.max(1)) {
            p.feed(c)?;
        }
        Ok(())
    }

    #[test]
    fn scram_then_ok_then_data_passes_at_any_chunking() {
        let mut stream = auth(10, b"SCRAM-SHA-256\0\0");
        stream.extend(auth(11, b"r=nonce,s=salt,i=4096"));
        stream.extend(auth(12, b"v=sig"));
        stream.extend(auth(0, b""));
        stream.extend(msg(b'S', b"server_version\x0017\0"));
        stream.extend(msg(b'Z', b"I"));
        stream.extend(msg(b'D', &[0u8; 1000]));
        for chunk in [1, 2, 3, 7, 4096] {
            let mut p = Parser::new(64 * 1024);
            assert_eq!(feed_all(&mut p, &stream, chunk), Ok(()), "chunk {chunk}");
            assert_eq!(p.phase, Phase::Ready);
        }
    }

    #[test]
    fn refuses_every_non_scram_method_at_any_chunking() {
        for code in [2, 3, 5, 7, 8, 9, 6, 13, -1] {
            for chunk in [1, 3, 64] {
                let mut p = Parser::new(64 * 1024);
                let r = feed_all(&mut p, &auth(code, b"salt"), chunk);
                assert_eq!(r, Err(GuardViolation::AuthMethod(code)), "code {code} chunk {chunk}");
            }
        }
    }

    #[test]
    fn errors_and_protocol_negotiation_are_allowed_during_auth() {
        let mut p = Parser::new(64 * 1024);
        assert!(feed_all(&mut p, &msg(b'v', &[0, 0, 0, 0, 0, 0, 0, 0]), 1).is_ok());
        assert!(feed_all(&mut p, &msg(b'E', b"SFATAL\0"), 2).is_ok());
    }

    #[test]
    fn notices_and_parameter_status_before_authentication_are_refused() {
        for t in *b"NS" {
            let mut p = Parser::new(64 * 1024);
            assert_eq!(
                feed_all(&mut p, &msg(t, b"x\0"), 1),
                Err(GuardViolation::UnexpectedDuringAuth(t))
            );
        }
    }

    #[test]
    fn data_before_authentication_is_refused() {
        let mut p = Parser::new(64 * 1024);
        assert_eq!(
            feed_all(&mut p, &msg(b'D', b"x"), 5),
            Err(GuardViolation::UnexpectedDuringAuth(b'D'))
        );
    }

    #[test]
    fn oversized_messages_are_refused_from_the_header() {
        let mut p = Parser::new(64 * 1024);
        feed_all(&mut p, &auth(0, b""), 64).unwrap();
        // Only the 5-byte header of a 900 MB DataRow: refused before any body arrives.
        let mut header = vec![b'D'];
        header.extend_from_slice(&900_000_000u32.to_be_bytes());
        assert_eq!(
            p.feed(&header),
            Err(GuardViolation::MessageTooLarge {
                len: 900_000_000,
                max: 64 * 1024
            })
        );
    }

    #[test]
    fn malformed_lengths_are_refused() {
        let mut p = Parser::new(64 * 1024);
        assert_eq!(p.feed(&[b'R', 0, 0, 0, 2]), Err(GuardViolation::Malformed));
        let mut p = Parser::new(64 * 1024);
        assert_eq!(
            p.feed(&[b'R', 0, 0, 0, 6]),
            Err(GuardViolation::Malformed),
            "an R message needs a 4-byte code"
        );
    }

    #[tokio::test]
    async fn the_wrapper_fails_the_read_and_hides_the_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut server, client) = tokio::io::duplex(1024);
        server.write_all(&auth(3, b"")).await.unwrap();
        let mut g = Guarded::new(client, 64 * 1024);
        let mut buf = [0u8; 64];
        let err = g.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(g.violation(), Some(&GuardViolation::AuthMethod(3)));
        assert!(g.read(&mut buf).await.is_err(), "stays failed");
    }
}
