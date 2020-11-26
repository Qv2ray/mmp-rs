use std::collections::BTreeMap;
use std::str::FromStr;

use serde::de::Error;
use serde::export::Formatter;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::AEADMethod;
use crate::infra::InfraAlgorithm;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    listen: String,
    algorithm: AlgorithmConfig,
    servers: BTreeMap<String, ServerConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AlgorithmConfig {
    name: InfraAlgorithm,
    options: Option<BTreeMap<String, i32>>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerConfig {
    address: String,
    method: AEADMethod,
    passwords: Vec<String>,
}

#[cfg(test)]
mod test {
    use serde::Deserialize;

    use crate::config::Config;

    #[test]
    fn test_deserialize_config() {
        let config: Config = serde_yaml::from_str(include_str!("config_test.yaml"))
            .expect("failed to parse test config file");
        println!("Config: {:?}", config);
    }
}
