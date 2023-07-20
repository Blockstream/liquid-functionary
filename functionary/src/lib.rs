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


//! # Functionary
//! This is the library used by the blocksigner and withdrawal watcher to maintain
//! a rotating consensus system. It is separated into its own library mainly for
//! ease of testing; it is not expected to be used outside of this project.
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused)]
#![deny(unused_mut)]
#![warn(missing_docs)]

// External libs
extern crate bitcoin;
extern crate byteorder;
#[cfg(test)]
#[macro_use] extern crate hex_literal;
extern crate jsonrpc;
extern crate elements;
extern crate miniscript;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
#[cfg(test)]
extern crate tempfile;
extern crate time;

#[macro_use]
pub extern crate functionary_logs as logs;
#[macro_use]
pub extern crate functionary_common as common;

#[macro_use] pub mod macros;
#[macro_use] pub mod rotator;
pub mod blocksigner;
pub mod config;
pub mod descriptor;
pub mod dynafed;
pub mod hsm;
pub mod message;
pub mod network;
pub mod peer;
pub mod rpc;
pub mod tweak;
pub mod utils;
pub mod watchman;
pub mod running_avg;

