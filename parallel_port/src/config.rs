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

use std::env;
use std::time::Duration;

pub const MAX_CONNECTIONS_PER_SOCKET: usize = 10;
pub const CHANNEL_BUFFER_SIZE: usize = 1000;

pub struct ParallelPortConfig {
    pub serial_port_baud: u32,
    pub heartbeat_period: Duration,
    pub serial_write_timeout: Duration,
    pub serial_read_timeout: Duration,
    pub increment_sequence_numbers: bool,
}

impl Default for ParallelPortConfig {
    fn default() -> Self {
        Self {
            serial_port_baud: 38400,
            heartbeat_period: Duration::from_secs(20),
            serial_write_timeout: Duration::from_secs(1050), //17.5 minutes which is the extreme length of a watchman round.
            serial_read_timeout: Duration::from_secs(20),
            increment_sequence_numbers:  ! env::var("HSM_SEQNUM_DISABLED").is_ok(),
        }
    }
}
