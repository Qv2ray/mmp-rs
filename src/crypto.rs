use ring::aead::Algorithm;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AEADMethod {
    AES128GCM,
    AES256GCM,
    CHACHA20POLY1305,
}

impl Serialize for AEADMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match *self {
            AEADMethod::AES128GCM => "aes-128-gcm",
            AEADMethod::AES256GCM => "aes-256-gcm",
            AEADMethod::CHACHA20POLY1305 => "chacha20-ietf-poly1305",
        })
    }
}

impl<'de> Deserialize<'de> for AEADMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "aes-128-gcm" => Ok(AEADMethod::AES128GCM),
            "aes-256-gcm" => Ok(AEADMethod::AES256GCM),
            "chacha20-ietf-poly1305" => Ok(AEADMethod::CHACHA20POLY1305),
            other => Err(D::Error::custom(format!("unknown method {}", other))),
        }
    }
}

impl Into<&ring::aead::Algorithm> for AEADMethod {
    fn into(self) -> &'static Algorithm {
        match self {
            AEADMethod::AES128GCM => &ring::aead::AES_128_GCM,
            AEADMethod::AES256GCM => &ring::aead::AES_256_GCM,
            AEADMethod::CHACHA20POLY1305 => &ring::aead::CHACHA20_POLY1305,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::AEADMethod;

    #[test]
    fn test_method_deserialize_normal() {
        debug_assert!(serde_yaml::from_str::<AEADMethod>("aes-128-gcm")
            .unwrap()
            .eq(&AEADMethod::AES128GCM));
        debug_assert!(serde_yaml::from_str::<AEADMethod>("aes-256-gcm")
            .unwrap()
            .eq(&AEADMethod::AES256GCM));
        debug_assert!(serde_yaml::from_str::<AEADMethod>("chacha20-ietf-poly1305")
            .unwrap()
            .eq(&AEADMethod::CHACHA20POLY1305));
    }

    #[test]
    fn test_method_deserialize_upper_case() {
        debug_assert!(serde_yaml::from_str::<AEADMethod>("AES-128-GCM")
            .unwrap()
            .eq(&AEADMethod::AES128GCM));
        debug_assert!(serde_yaml::from_str::<AEADMethod>("AES-256-GCM")
            .unwrap()
            .eq(&AEADMethod::AES256GCM));
        debug_assert!(serde_yaml::from_str::<AEADMethod>("CHACHA20-IETF-POLY1305")
            .unwrap()
            .eq(&AEADMethod::CHACHA20POLY1305));
    }
}
