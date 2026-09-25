//! Application-Layer Protocol Negotiation, RFC 7301: a client offers the
//! protocols it speaks in its hello, the server selects one of them in
//! its own preference, and both read the choice once the handshake is
//! done. HTTP agrees `h2` or `http/1.1` this way; the identifiers are the
//! protocol's (`net::http::Version::alpn`), not TLS's, and nothing here
//! knows one from another.

use std::net::TcpStream;
use std::ops::{Deref, DerefMut};

use crate::{Result, TlsError};

/// `config`, offering `protocols` in order of the client's preference.
#[must_use]
pub fn offering(mut config: rustls::ClientConfig, protocols: &[&[u8]]) -> rustls::ClientConfig {
    config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

/// `config`, selecting the first of `protocols` the client offered. A
/// client that offers none is served without; one that offers only what
/// is not here is refused by the handshake, as RFC 7301 section 3.2 asks.
#[must_use]
pub fn selecting(mut config: rustls::ServerConfig, protocols: &[&[u8]]) -> rustls::ServerConfig {
    config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

/// Finish the handshake on `stream`, either side, and say which protocol
/// it agreed: `None` where either side offered nothing.
///
/// # Errors
///
/// Where the handshake failed, the peer's certificate among the reasons.
pub fn agreed<C, D>(stream: &mut rustls::StreamOwned<C, TcpStream>) -> Result<Option<Vec<u8>>>
where
    C: Deref<Target = rustls::ConnectionCommon<D>> + DerefMut,
    D: rustls::SideData,
{
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|failure| TlsError::new(format!("the tls handshake: {failure}")))?;
    }
    Ok(stream.conn.alpn_protocol().map(<[u8]>::to_vec))
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Arc;

    use super::*;
    use crate::client::{client_with, configure};
    use crate::server::{server, server_config};

    const H2: &[u8] = b"h2";
    const HTTP_1_1: &[u8] = b"http/1.1";

    /// A handshake between a client offering `offered` and a server
    /// selecting from `selected`: what each side read as agreed.
    fn agree(offered: &[&[u8]], selected: &[&[u8]]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        let config = server_config(
            signed.cert.pem().as_bytes(),
            signed.key_pair.serialize_pem().as_bytes(),
        )
        .expect("server config");
        let config = Arc::new(selecting(config, selected));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(signed.cert.der().clone()).expect("trusted");
        let client = Arc::new(offering(configure(roots), offered));
        let near = std::thread::spawn(move || {
            let tcp = TcpStream::connect(address).expect("connect");
            let mut stream = client_with("localhost", tcp, client).expect("client");
            agreed(&mut stream)
        });
        let (tcp, _) = listener.accept().expect("accept");
        let mut far = server(tcp, config).expect("server");
        let served = agreed(&mut far);
        let asked = near.join().expect("client thread");
        (asked.unwrap_or(None), served.unwrap_or(None))
    }

    #[test]
    fn the_client_offers_h2_and_http_1_1_and_the_server_selects() {
        let both = [H2, HTTP_1_1];
        assert_eq!(agree(&both, &both), (Some(H2.to_vec()), Some(H2.to_vec())));
        let old = (Some(HTTP_1_1.to_vec()), Some(HTTP_1_1.to_vec()));
        assert_eq!(agree(&both, &[HTTP_1_1]), old);
        assert_eq!(agree(&[HTTP_1_1], &both), old);
    }

    #[test]
    fn nothing_is_agreed_where_either_side_offers_nothing() {
        assert_eq!(agree(&[], &[H2, HTTP_1_1]), (None, None));
        assert_eq!(agree(&[H2, HTTP_1_1], &[]), (None, None));
    }
}
