//! M0 spike: refuse cleartext / MD5 password auth in tokio-postgres.
//! usage: q2auth <plain|guard|cbreq|multi> <port> <user> <password>
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_postgres::config::ChannelBinding;
use tokio_postgres::{Config, NoTls};

/// Wraps the (post-TLS) stream. Buffers the server's first backend message header
/// (type byte, i32 length, i32 auth code) before tokio-postgres sees it, and fails
/// the read if the server asks for a cleartext (3) or MD5 (5) password. Afterwards
/// it's a transparent pass-through.
struct AuthGuard<S> {
    inner: S,
    head: Vec<u8>, // bytes read during inspection
    pos: usize,    // how many of `head` were handed to the caller
    checked: bool,
}

impl<S> AuthGuard<S> {
    fn new(inner: S) -> Self {
        Self { inner, head: Vec::with_capacity(9), pos: 0, checked: false }
    }
}

fn verdict(h: &[u8]) -> io::Result<()> {
    match (h[0], i32::from_be_bytes([h[5], h[6], h[7], h[8]])) {
        (b'R', 3) => Err(io::Error::new(io::ErrorKind::PermissionDenied, "server requested cleartext password; refused")),
        (b'R', 5) => Err(io::Error::new(io::ErrorKind::PermissionDenied, "server requested MD5 password; refused")),
        (b'R', 0 | 10) | (b'E', _) => Ok(()), // AuthenticationOk, SASL (SCRAM), ErrorResponse
        (t, c) => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("unexpected first message {:?}/{c}; refused", t as char))),
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AuthGuard<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while !this.checked {
            let mut tmp = [0u8; 9];
            let need = 9 - this.head.len();
            let mut rb = ReadBuf::new(&mut tmp[..need]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) if rb.filled().is_empty() => return Poll::Ready(Ok(())), // EOF
                Poll::Ready(Ok(())) => this.head.extend_from_slice(rb.filled()),
            }
            if this.head.len() == 9 {
                verdict(&this.head)?;
                this.checked = true;
            }
        }
        if this.pos < this.head.len() {
            let n = (this.head.len() - this.pos).min(out.remaining());
            out.put_slice(&this.head[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AuthGuard<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (mode, port, user, pw) = (a[1].as_str(), a[2].parse::<u16>().unwrap(), &a[3], &a[4]);
    let mut cfg = Config::new();
    cfg.host("127.0.0.1").port(port).user(user).password(pw.as_str()).dbname("postgres");
    if mode == "cbreq" {
        cfg.channel_binding(ChannelBinding::Require);
    }
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let res = match mode {
        "guard" => cfg.connect_raw(AuthGuard::new(tcp), NoTls).await.map(|(c, conn)| {
            tokio::spawn(conn);
            c
        }),
        _ => cfg.connect_raw(tcp, NoTls).await.map(|(c, conn)| {
            tokio::spawn(conn);
            c
        }),
    };
    let client = match res {
        Ok(c) => c,
        Err(e) => {
            println!("[{mode}] user={user}: CONNECT FAILED: {e:?}");
            return;
        }
    };
    let who: String = client.query_one("select current_user::text", &[]).await.unwrap().get(0);
    println!("[{mode}] user={user}: connected as {who}");
    if mode == "multi" {
        // Extended protocol (Parse/Bind/Execute): multiple statements must be rejected.
        client.batch_execute("BEGIN READ ONLY").await.unwrap();
        match client.query("COMMIT; DELETE FROM vk_t", &[]).await {
            Ok(r) => println!("multi-statement via extended protocol: OK?! rows={}", r.len()),
            Err(e) => println!("multi-statement via extended protocol: ERROR: {}", e.as_db_error().map(|d| d.message().to_string()).unwrap_or(e.to_string())),
        }
    }
}
