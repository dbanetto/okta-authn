use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;

use tracing::debug;


#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub(crate) struct Config {
    pub profiles: HashMap<String, Profile>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub(crate) struct Profile {
    pub domain: String,
    pub username: String,
    pub keyring_name: String,
}

impl Config {
    pub fn new_from_file_or_empty() -> io::Result<Self> {
        let path = get_config_dir().join("config.toml");

        if path.exists() {
            debug!("Loading existing config: {:?}", path);
            let mut config_file = File::open(path)?;

            let mut buffer = vec![];
            config_file.read_to_end(&mut buffer)?;

            debug!("Deserializing from TOML");
            toml::from_slice(&buffer).map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        } else {
            debug!("No config found, creating new one");
            Ok(Config {
                profiles: HashMap::<String, Profile>::new(),
            })
        }
    }

    pub fn save(self) -> io::Result<()> {
        let path = get_config_dir().join("config.toml");

        debug!("creating file handle: {:?}", path);
        let mut file = File::create(path.clone())?;

        debug!("serializing into toml");
        let buffer = toml::to_string_pretty(&self)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        debug!("serialized into toml");

        debug!("writing to config file: {:?}", path);
        file.write_all(buffer.as_bytes())?;
        file.flush()?;
        debug!("flushed config file: {:?}", path);

        Ok(())
    }
}

impl Profile {
    pub fn new<T: Into<String>>(domain: T, username: T) -> Self {
        Self {
            domain: domain.into(),
            username: username.into(),
            keyring_name: format!("{}", uuid::Uuid::new_v4()),
        }
    }
}

pub fn ensure_config_dir() -> io::Result<()> {
    let path = get_config_dir();

    if path.exists() {
        debug!("path exists {:?}", path);
        return Ok(());
    }

    debug!("creating path {:?}", path);
    return std::fs::create_dir_all(path);
}

fn get_config_dir() -> PathBuf {
    dirs::config_dir().unwrap().join("okta-auth")
}

