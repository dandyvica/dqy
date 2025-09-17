//! Module for managing YAML configuration
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use home::home_dir;
use log::{error, info};
use serde::Deserialize;

use dnslib::dns::rfc::qtype::QType;
use dnslib::error::Error;

// constant file name for the moment
const CONFIG_FILE: &'static str = "dqy.yml";

// main struct is deserialized from YAML file
#[derive(Debug, Deserialize)]
pub struct YAMLConfig {
    // list of RRs to query in case of no RR passed
    pub default_rrs: Vec<QType>,
}

// load YAML data
pub fn read_yaml<P: AsRef<Path>>(path: P) -> dnslib::error::Result<YAMLConfig> {
    // Open YAML file and create a reader
    let p = path.as_ref();

    let file = File::open(p).map_err(|e| Error::OpenFile(e, p.to_path_buf()))?;
    let reader = BufReader::new(file);

    // Deserialize into Config struct
    let config: YAMLConfig = serde_yaml::from_reader(reader).map_err(|e| Error::YAML(e))?;

    Ok(config)
}

// check whether a defauly dqy.yml file exists
pub fn get_config() -> Option<PathBuf> {
    // check current directory first
    let cfg = Path::new(CONFIG_FILE);

    // first check on current dir
    let cfg_path = if cfg.exists() {
        std::env::current_dir().unwrap_or(PathBuf::from(".")).join(cfg)
    } else {
        // otherwise, on OS-specific home directory
        let home_dir = match home_dir() {
            Some(path) => {
                if !path.as_os_str().is_empty() {
                    info!("home dir is: {}", path.display());
                    path
                } else {
                    error!("home directory is empty, setting it to '.'");
                    PathBuf::from(".")
                }
            }
            None => {
                error!("can't get home directory, setting it to '.'");
                PathBuf::from(".")
            }
        };
        home_dir.join(cfg)
    };

    // check for existence
    match cfg_path.try_exists() {
        Ok(b) => {
            if b {
                return Some(cfg_path);
            } else {
                None
            }
        }
        Err(_) => None,
    }
}
