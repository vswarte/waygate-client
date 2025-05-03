#[cfg(not(feature = "lib"))]
use std::fs;
#[cfg(not(feature = "lib"))]
use std::path;
use serde::Deserialize;

use base64::prelude::*;

#[cfg(not(feature = "lib"))]
const CONFIG_FILE: &str = "./waygate.toml";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub enable_ssl: bool,
    pub client_secret_key: String,
    pub server_public_key: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: "127.0.0.1".to_string(),
            #[cfg(feature="eldenring")]
            port: 10901,
            #[cfg(feature="armoredcore6")]
            port: 10902,
            enable_ssl: false,
            client_secret_key: "j+7K1pfsAE1W82FCRyJbs65BHInOQ+xN9qog0sjDpTM=".to_string(),
            server_public_key: "KUdoBOUIdx1mmn9oOpFggrGUgTb3ljoO3l+R4tyYpUo=".to_string(),
        }
    }
}

impl Config {
    pub fn client_secret_key(&self) -> Vec<u8> {
        BASE64_STANDARD.decode(self.client_secret_key.as_str()).unwrap()
    }

    pub fn server_public_key(&self) -> Vec<u8> {
        BASE64_STANDARD.decode(self.server_public_key.as_str()).unwrap()
    }
}

#[cfg(not(feature = "lib"))]
pub(crate) fn read_config_file() -> Option<Config> {
    path::absolute(path::PathBuf::from(CONFIG_FILE))
        .map(|p| fs::read_to_string(p).ok()).ok()
        .flatten()
        .and_then(|f| toml::from_str(f.as_str()).ok())
}
