use crate::crypto::AEADMethod;
use crate::infra::InfraAlgorithm;
use aead::{Aad, Nonce};
use lru::LruCache;
use ring::aead;
use ring::{error, hkdf};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::IpAddr;
use smol::{future, io, Async};
use std::net::TcpListener;
use std::net::TcpStream;
use std::ptr;

struct ServerInfo {
    addr: (IpAddr, u16),
    method: AEADMethod,
}

struct Multiplexer {
    listener: Async<TcpListener>,
    servers_lru: LruCache<String, ServerInfo>, //password, ServerInfo
}

pub const fn buffer_len() -> usize {
    32 + 2 + 16 // enough for all the case
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

fn match_server(password: &String, buf: &[u8; buffer_len()], method: AEADMethod) -> bool {
    let salt = hkdf::Salt::new(
        hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
        &buf[0..method.salt_len()],
    );
    let mut buf2 = buf.clone();
    let prk = salt.extract(password.as_bytes());
    let result = prk.expand(&[SUBKEY_INFO], My(method.key_len())).unwrap();
    let mut sub_key_buf = [0u8; 32]; // enough for all the case
    result.fill(&mut sub_key_buf).unwrap();
    let open_res = open_with_key(
        &aead::CHACHA20_POLY1305,
        &sub_key_buf[0..method.key_len()],
        &mut buf2[method.salt_len()..method.buffer_len()],
    );
    open_res.is_ok()
}

impl Multiplexer {
    fn linear_scan(&self, buf: [u8; buffer_len()], stream: Async<TcpStream>) -> *const String {
        for (password, info) in &self.servers_lru {
            let open_res = match_server(password, &buf, info.method);
            if open_res {
                let buf = buf;
                let addr = info.addr.clone();
                smol::spawn(async move { copy_steam(stream, addr, &buf).await }).detach();
                return password;
            }
        }
        ptr::null()
    }

    pub async fn accept(&mut self, infra_algo: InfraAlgorithm) -> io::Result<()> {
        let (mut stream, _) = self.listener.accept().await?;
        let mut buf = [0u8; buffer_len()]; // enough for all the case
        stream.read_exact(&mut buf).await?;
        match infra_algo {
            InfraAlgorithm::LinearScan => {
                self.linear_scan(buf, stream);
            }
            InfraAlgorithm::LinearScanWithLRU => {
                let hit_pass = self.linear_scan(buf, stream);
                if !hit_pass.is_null() {
                    self.servers_lru.get(unsafe { &*hit_pass }); // change lru list, we don't want to copy password.
                }
            }
            InfraAlgorithm::ConcurrentScan => {}
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
