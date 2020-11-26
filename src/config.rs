use std::collections::BTreeMap;
use std::str::FromStr;

use serde::de::Error;
use serde::export::Formatter;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::AEADMethod;
use crate::infra::InfraAlgorithm;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub listen: String,
    pub algorithm: AlgorithmConfig,
    pub fallback: Option<FallbackConfig>,
    pub servers: BTreeMap<String, ServerConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AlgorithmConfig {
    pub name: InfraAlgorithm,
    pub options: Option<BTreeMap<String, i32>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FallbackConfig {
    pub address: String,
    pub delay: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerConfig {
    pub address: String,
    pub method: AEADMethod,
    pub passwords: Vec<String>,
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
