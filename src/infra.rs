use crate::config::Config;
use crate::infra_linear_scan::LinearScanImpl;
use crate::infra_lru_scan::LRUScanImpl;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use smol::net::SocketAddr;
use smol::Async;
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum InfraAlgorithm {
    #[serde(rename = "linear-scan")]
    LinearScan,
    #[serde(rename = "linear-scan-with-lru")]
    LinearScanWithLRU,
    #[serde(rename = "concurrent-scan")]
    ConcurrentScan,
}

impl InfraAlgorithm {
    fn new_impl(&self, config: &Config) -> Box<dyn InfraImplTrait> {
        match self {
            InfraAlgorithm::LinearScan => Box::new(LinearScanImpl::from_config(&config)),
            InfraAlgorithm::LinearScanWithLRU => Box::new(LRUScanImpl::from_config(&config)),
            _ => panic!("shit"),
        }
    }
}

#[async_trait]
pub trait InfraImplTrait {
    fn from_config(config: &Config) -> Self
    where
        Self: Sized;
    async fn handle_tcp(
        &mut self,
        mut stream: Async<TcpStream>,
        client_address: SocketAddr,
    ) -> smol::io::Result<()>;
}

pub struct Server {
    listener: Async<TcpListener>,
    infra_impl: Box<dyn InfraImplTrait>,
}

impl Server {
    pub fn new(config: Config) -> Server {
        let listener =
            Async::<TcpListener>::bind(SocketAddr::from_str(config.listen.as_str()).unwrap())
                .unwrap();
        let infra_impl = config.algorithm.name.new_impl(&config);
        Server {
            listener,
            infra_impl,
        }
    }

    pub async fn run(&mut self) -> smol::io::Result<()> {
        loop {
            let (stream, address) = self.listener.accept().await.unwrap();
            self.infra_impl.handle_tcp(stream, address).await;
        }
    }
}
