//{{ Liquid }}
//Copyright (C) {{ 2022 }}  {{ Blockstream }}

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

use serde::{Deserialize};
use std::env;
use std::time::Duration;
use functionary_common::deserialize_option_duration_ms;
use functionary_logs::Severity;

pub const MAX_CONNECTIONS_PER_SOCKET: usize = 10;
pub const CHANNEL_BUFFER_SIZE: usize = 1000;

#[derive(Debug)]
pub struct ParallelPortConfig {
    pub serial_port_baud: u32,
    pub heartbeat_period: Duration,
    pub serial_write_timeout: Duration,
    pub serial_read_timeout: Duration,
    pub increment_sequence_numbers: bool,
    pub log_level: Severity,
}

impl Default for ParallelPortConfig {
    fn default() -> Self {
        Self {
            serial_port_baud: 38400,
            heartbeat_period: Duration::from_secs(20),
            //17.5 minutes which is the extreme length of a watchman round.
            serial_write_timeout: Duration::from_secs(1050),
            serial_read_timeout: Duration::from_secs(20),
            increment_sequence_numbers: env::var("HSM_SEQNUM_DISABLED").is_err(),
            log_level: Severity::Debug,
        }
    }
}

/// Struct with option fields to deserialize from a file that might not contian all the fields
#[derive(Debug, Deserialize)]
pub struct ParallelPortConfigFile {
    pub serial_port_baud: Option<u32>,
    #[serde(alias="heartbeat_period_ms")]
    #[serde(deserialize_with = "deserialize_option_duration_ms")]
    pub heartbeat_period: Option<Duration>,
    #[serde(alias="serial_write_timeout_ms")]
    #[serde(deserialize_with = "deserialize_option_duration_ms")]
    pub serial_write_timeout: Option<Duration>,
    #[serde(alias="serial_read_timeout_ms")]
    #[serde(deserialize_with = "deserialize_option_duration_ms")]
    pub serial_read_timeout: Option<Duration>,
    pub increment_sequence_numbers: Option<bool>,
    pub log_level: Option<Severity>,
    
}

impl From<ParallelPortConfigFile> for ParallelPortConfig {
    fn from(file: ParallelPortConfigFile) -> Self {
        let default = ParallelPortConfig::default();
        ParallelPortConfig {
            serial_port_baud: file.serial_port_baud.unwrap_or(default.serial_port_baud),
            heartbeat_period: file.heartbeat_period.unwrap_or(default.heartbeat_period),
            serial_write_timeout: file.serial_write_timeout.unwrap_or(default.serial_write_timeout),
            serial_read_timeout: file.serial_read_timeout.unwrap_or(default.serial_read_timeout),
            increment_sequence_numbers: file.increment_sequence_numbers.unwrap_or(default.increment_sequence_numbers),
            log_level: file.log_level.unwrap_or(default.log_level),
        }
    }
}