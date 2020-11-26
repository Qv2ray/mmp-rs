use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum InfraAlgorithm {
    #[serde(rename = "linear-scan")]
    LinearScan,
    #[serde(rename = "linear-scan-with-lru")]
    LinearScanWithLRU,
    #[serde(rename = "concurrent-scan")]
    ConcurrentScan,
}
