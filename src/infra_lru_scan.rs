use crate::config::Config;
use crate::crypto::AEADMethod;
use crate::infra::InfraImplTrait;
use crate::util::{buffer_len, match_server, relay};
use async_trait::async_trait;
use lru::LruCache;
use smol::io::AsyncReadExt;
use smol::Async;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::ptr;
use std::str::FromStr;

struct ServerInfo {
    addr: SocketAddr,
    method: AEADMethod,
}

pub struct LRUScanImpl {
    servers_lru: LruCache<String, ServerInfo>, //password, ServerInfo
}

#[async_trait]
impl InfraImplTrait for LRUScanImpl {
    fn from_config(config: &Config) -> LRUScanImpl {
        let mut servers_lru = lru::LruCache::unbounded();
        for (_server_name, server_config) in &config.servers {
            for password in &server_config.passwords {
                let digest = md5::compute(password).0;
                servers_lru.put(
                    String::from_utf8_lossy(&digest).parse().unwrap(),
                    ServerInfo {
                        addr: SocketAddr::from_str(server_config.address.as_str()).unwrap(),
                        method: server_config.method,
                    },
                );
            }
        }

        LRUScanImpl { servers_lru }
    }

    async fn handle_tcp(
        &mut self,
        mut stream: Async<TcpStream>,
        _client_address: SocketAddr,
    ) -> smol::io::Result<()> {
        let mut buf = [0u8; buffer_len()];
        stream.read_exact(&mut buf).await?;
        let hit_pass = self.linear_scan(buf, stream);
        if !hit_pass.is_null() {
            self.servers_lru.get(unsafe { &*hit_pass }); // change lru list, we don't want to copy password.
        }
        Ok(())
    }
}

impl LRUScanImpl {
    fn linear_scan(&self, buf: [u8; buffer_len()], stream: Async<TcpStream>) -> *const String {
        for (password, info) in &self.servers_lru {
            let open_res = match_server(password, &buf, info.method);
            if open_res {
                let buf = buf;
                let addr = info.addr.clone();
                smol::spawn(async move { relay(stream, addr, &buf).await }).detach();
                return password;
            }
        }
        ptr::null()
    }
}
