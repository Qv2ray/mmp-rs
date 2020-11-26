use serde::{Deserialize, Serialize};
use smol::net::SocketAddr;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    listen: String,
    servers: BTreeMap<String, ServerConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerConfig {
    address: String,
    method: String,
    passwords: Vec<String>,
}

#[cfg(test)]
mod test {
    use crate::config::Config;

    #[test]
    fn test_deserialize_config() {
        let config: Config = serde_yaml::from_str(include_str!("config_test.yaml"))
            .expect("failed to parse test config file");
        println!("Config: {:?}", config);
    }
}
