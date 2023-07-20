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


//! # Block Signer
//!
//! This implements a 5-of-7 rotating consensus for signing blocks
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

// External libs
extern crate toml;

#[macro_use]
extern crate functionary_logs as logs;
extern crate functionary;

use std::{env, fs, io};

use functionary::blocksigner::BlockSigner;
use functionary::blocksigner::config::Configuration;
use functionary::rotator::Rotator;
use functionary::common::constants::set_constants_on_startup;
use functionary::common::rollouts::set_rollouts_on_startup;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <datadir>", args[0]);
        return;
    }

    let mut config_path = args[1].clone();
    config_path.push_str("/config.toml");
    let s = match fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => panic!(
            "Failed to open configuration file {}: {}",
            config_path,
            e
        ),
    };
    // nb: https://gl.blockstream.io/liquid/functionary/-/issues/957
    let replaced = s.replace("thresh_m(", "multi(");
    let config: Configuration = match toml::from_str(&replaced) {
        Ok(config) => config,
        Err(e) => panic!(
            "Failed to parse configuration file {}: {}",
            config_path,
            e,
        ),
    };
    logs::initialize(
        config.local.log_level,
        config.local.log_period_ms,
        config.local.log_max_instance_per_period,
        "blocksigner",
        Box::new(io::stderr()),
    );
    slog!(StartingBlocksigner, config_path: &config_path[..],
        git_commit: functionary::common::constants::GIT_COMMIT_ID,
        functionary_version: env!("CARGO_PKG_VERSION"),
    );

    if let Some(config_rollouts) = config.local.feature_rollouts.as_ref() {
        set_rollouts_on_startup(config_rollouts.clone());
    }
    if let Some(config_constants) = config.local.constants.as_ref() {
        set_constants_on_startup(config_constants.clone());
    }

    let mut signer = BlockSigner::new(config);
    signer.run();
}

