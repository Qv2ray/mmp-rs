use aead::{Aad, Nonce};
use ring::aead;
use ring::{error, hkdf};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::IpAddr;
use smol::{future, io, Async};
use std::collections::HashMap;
use std::net::TcpListener;
use std::net::TcpStream;

struct Multiplexer {
    listener: Async<TcpListener>,
    servers: HashMap<String, (IpAddr, u16)>, // password, server addr
}

pub const CHACHA20_SALT_LEN: usize = 32;
pub const CHACHA20_KEY_LEN: usize = 32;
pub const CHACHA20_TAG_LEN: usize = 16;
pub const LEN_LEN: usize = 2;
pub const fn chacha20_buffer_len() -> usize {
    (CHACHA20_SALT_LEN + LEN_LEN + CHACHA20_TAG_LEN) as usize
}

pub const SUBKEY_INFO: &'static [u8] = b"ss-subkey";

async fn copy_steam(stream0: Async<TcpStream>, addr: (IpAddr, u16), buf: &[u8]) -> io::Result<()> {
    let mut stream1 = Async::<TcpStream>::connect(addr).await?;
    stream1.write(buf).await?;
    future::try_zip(
        io::copy(&stream0, &mut &stream1),
        io::copy(&stream1, &mut &stream0),
    )
    .await?;
    Ok(())
}

impl Multiplexer {
    pub async fn accept(&self) -> io::Result<()> {
        let (mut stream, _) = self.listener.accept().await?;
        let mut buf = [0u8; chacha20_buffer_len()];
        stream.read_exact(&mut buf).await?;
        let mut buf2 = buf.clone();
        for (password, addr) in &self.servers {
            let salt = hkdf::Salt::new(
                hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
                &buf[0..CHACHA20_SALT_LEN],
            );
            let prk = salt.extract(password.as_bytes());
            let result = prk.expand(&[SUBKEY_INFO], My(CHACHA20_KEY_LEN)).unwrap();
            let mut sub_key_buf = [0u8; CHACHA20_KEY_LEN];
            result.fill(&mut sub_key_buf).unwrap();
            let open_res = open_with_key(
                &aead::CHACHA20_POLY1305,
                &sub_key_buf,
                &mut buf2[CHACHA20_SALT_LEN..],
            );
            if open_res.is_ok() {
                let stream = stream;
                let buf = buf;
                let addr = addr.clone();
                smol::spawn(async move { copy_steam(stream, addr, &buf).await }).detach();
                return Ok(());
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct My<T: core::fmt::Debug + PartialEq>(T);

impl hkdf::KeyType for My<usize> {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<hkdf::Okm<'_, My<usize>>> for My<Vec<u8>> {
    fn from(okm: hkdf::Okm<My<usize>>) -> Self {
        let mut r = vec![0u8; okm.len().0];
        okm.fill(&mut r).unwrap();
        My(r)
    }
}

fn make_key<K: aead::BoundKey<OneNonceSequence>>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: aead::Nonce,
) -> K {
    let key = aead::UnboundKey::new(algorithm, key).unwrap();
    let nonce_sequence = OneNonceSequence::new(nonce);
    K::new(key, nonce_sequence)
}

struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
    fn new(nonce: aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        self.0.take().ok_or(error::Unspecified)
    }
}

fn open_with_key<'a>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    in_out: &'a mut [u8],
) -> Result<&'a mut [u8], error::Unspecified> {
    let mut o_key: aead::OpeningKey<OneNonceSequence> =
        make_key(algorithm, key, Nonce::assume_unique_for_key([0u8; 12]));
    o_key.open_in_place(Aad::empty(), in_out)
}
