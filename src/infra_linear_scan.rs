use crate::config::Config;
use crate::crypto::AEADMethod;
use crate::infra::InfraImplTrait;
use crate::util::{classic_bytes_to_key, match_server, relay};
use async_trait::async_trait;
use bytes::Bytes;
use smol::io::AsyncReadExt;
use smol::net::SocketAddr;
use smol::Async;
use std::net::TcpStream;
use std::str::FromStr;

pub struct LinearScanImpl {
    servers: Vec<(AEADMethod, Bytes, SocketAddr)>,
}

#[async_trait]
impl InfraImplTrait for LinearScanImpl {
    fn from_config(config: &Config) -> LinearScanImpl {
        let mut servers = Vec::new();
        for (_server_name, server_config) in &config.servers {
            for password in &server_config.passwords {
                servers.push((
                    server_config.method,
                    classic_bytes_to_key(server_config.method.key_len(), password.as_bytes()),
                    SocketAddr::from_str(server_config.address.as_str()).unwrap(),
                ))
            }
        }

        LinearScanImpl { servers }
    }

    async fn handle_tcp(
        &mut self,
        mut stream: Async<TcpStream>,
        _client_address: SocketAddr,
    ) -> smol::io::Result<()> {
        let mut buf = [0u8; 32 + 2 + 16];
        stream.read_exact(&mut buf).await?;
        for (method, password, addr) in &self.servers {
            if match_server(&password, &buf, *method) {
                let buf = buf;
                let addr = addr.clone();
                smol::spawn(async move { relay(stream, addr, &buf).await }).detach();
                break;
            }
        }
        Ok(())
    }
}
