use crate::infra::InfraImplTrait;
use smol::net::{SocketAddr};
use smol::{Async, future, io};
use crate::config::Config;
use crate::crypto::AEADMethod;
use std::str::FromStr;
use std::net::TcpStream;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use crate::shadom_plexer::{match_server};
use async_trait::async_trait;

pub struct LinearScanImpl {
    servers: Vec<(AEADMethod, String, SocketAddr)>
}

async fn relay(stream0: Async<TcpStream>, addr: SocketAddr, buf: &[u8]) -> io::Result<()> {
    let mut stream1 = Async::<TcpStream>::connect(addr).await?;
    stream1.write(buf).await?;
    future::try_zip(
        io::copy(&stream0, &mut &stream1),
        io::copy(&stream1, &mut &stream0),
    )
        .await?;
    Ok(())
}

#[async_trait]
impl InfraImplTrait for LinearScanImpl {
    fn from_config(config: &Config) -> LinearScanImpl {
        let mut servers = Vec::<(AEADMethod, String, SocketAddr)>::new();
        for (_server_name, server_config) in &config.servers {
            for password in &server_config.passwords {
                servers.push((server_config.method, password.clone(), SocketAddr::from_str(server_config.address.as_str()).unwrap()))
            }
        }

        LinearScanImpl {
            servers
        }
    }

    async fn handle_tcp(&self, mut stream: Async<TcpStream>, _client_address: SocketAddr) -> smol::io::Result<()> {
        let mut buf = [0u8; 32+2+16];
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