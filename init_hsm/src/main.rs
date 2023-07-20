//{{ Liquid }}
//Copyright (C) {{ 2015,2016,2017,2018 }}  {{ Blockstream }}

//This program is free software: you can redistribute it and/or modify
//it under the terms of the GNU Affero General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU Affero General Public License for more details.

//You should have received a copy of the GNU Affero General Public License
//along with this program.  If not, see <http://www.gnu.org/licenses/>.


//! # HSM initialization tool
//!
//! Sends the HSM_INIT message to the HSM, with a configured key
//! and the current time; writes the reply to disk for later processing.
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

// External libs
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate toml;

extern crate functionary;
extern crate functionary_logs as logs;

mod config;

use std::{env, fs, io, time};
use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;

#[macro_use] extern crate functionary_logs;
use functionary::common::constants::GIT_COMMIT_ID;
use functionary::hsm;

use config::Configuration;
use functionary::common::hsm::Address;

fn remove_file_if_zero_length(path: &Path) -> Result<(), String> {
    match fs::metadata(path) {
        Ok(metadata) => {
            if (metadata.is_file()) && (metadata.len() == 0) {
                match fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(e.to_string()),
                }
            } else {
                Err("remove_file_if_zero_length - file has non-zero length or is not a file".to_owned())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logs::initialize(logs::Severity::Trace, None, None, "init_hsm", Box::new(io::stderr()));

    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        let exe_name = Path::new(&args[0]).file_name().unwrap_or(OsStr::new("init_hsm"));
        println!("Usage: {} <datadir>", exe_name.to_string_lossy());
        return Err("Usage".into());
    }

    let mut config_path = args[1].clone();
    config_path.push_str("/config.toml");
    let s = match fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open configuration file {}: {}", config_path, e);
            return Err(e.into());
        }
    };
    let config: Configuration = match toml::from_str(&s) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to parse configuration file {}: {}", config_path, e);
            return Err(e.into());
        }
    };

    let mut output_path_string = args[1].clone();
    output_path_string.push_str("/hsm_init_reply");

    // Deal with a potentially failed previous run
    let output_path = Path::new(&output_path_string);
    if output_path.exists() {
        log!(Warn, "Initialization file \"{}\" exists (perhaps from a previous run?) will remove if empty.",
            output_path_string
        );
        if let Err(e) = remove_file_if_zero_length(output_path) {
            log!(Error, "Could not remove file \"{}\", aborting: {}", output_path_string, e);
            return Err(e.into());
        }
    }

    let mut outfile = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("Unable to create output file");

    log!(Info, "Starting up with configuration {}, revision {}, log_level {:?}", config_path, GIT_COMMIT_ID, config.init_hsm.log_level);
    logs::initialize(config.init_hsm.log_level, None, None, "init_hsm", Box::new(io::stderr()));

    let security_module = Box::new(hsm::LiquidHsm::new(config.init_hsm.hsm_socket.clone()))
        as Box<dyn hsm::SecurityModule>;

    // Do a query to generate the hsm_signing_key if it doesn't exist. The key should only not exist
    // in test and development settings having be pre-set in production HSM. If the key exists, this
    // request will just return it.
    let signing_key = match security_module.get_signing_key(Address::BlockSigner) {
        Ok(pk) => pk,
        Err(e) => {
            log!(Error, "Could not retrieve the HSMs public signing key: {}", e.to_string());
            return Err(e.into());
        }
    };
    log!(Info, "HSM signing key is: {:?}", signing_key);

    let now = match time::SystemTime::now().duration_since(time::UNIX_EPOCH) {
        Ok(t) => t,
        Err(e) => {
            log!(Error, "Failed to get current time: {}", e);
            return Err(e.into());
        }
    };
    let timestamp_millis: u64 = now.as_secs() * 1000 + (now.subsec_nanos() as u64) / 1000000;

    match security_module.initialize_hsm(config.init_hsm, timestamp_millis) {
        Ok(result_packet) => {
            match outfile.write_all(&result_packet) {
                Ok(()) => {
                    match outfile.sync_all() {
                        Ok(()) => {}
                        Err(e) => {
                            drop(outfile); // Close the file
                            log!(Error,
                                "Sync operation on {} failed after initialization and write: {} - cleaning up",
                                output_path.display(), e.to_string(),
                            );
                            remove_file_if_zero_length(output_path)
                                .expect("Couldn't delete result file after write error");
                            // Initialization apparently succeeded but result wasn't written -
                            // this is a bad state to be in.
                            return Err("Aborting".into())
                        }
                    }
                }
                Err(e) => {
                    drop(outfile); // Close the file
                    log!(Error, "Write operation on {} failed after initialization: {} - cleaning up",
                        output_path.display(), e.to_string(),
                    );
                    remove_file_if_zero_length(output_path)
                        .expect("Couldn't delete result file after write error");
                    // Initialization apparently succeeded but result wasn't written -
                    // this is a bad state to be in.
                    return Err("Aborting".into());
                }
            }
        }
        Err(e) => {
            drop(outfile); // Close the file
            log!(Error, "Initialization of hsm failed: {} - cleaning up", e.to_string());
            remove_file_if_zero_length(output_path)
                .expect("Couldn't delete result file after failed initialization");
            log!(Error, "Initialization of hsm failed - Aborting");
            // This is not a local problem or an indication of a local bug so just return.
            return Err(e.into());
        }
    }

    log!(Info, "Configuration completed successfully.");

    Ok(())
}

