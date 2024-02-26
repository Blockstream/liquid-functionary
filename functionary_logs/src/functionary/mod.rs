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


//! # Functionary-related Logs
//!

pub mod accounting;
pub use self::accounting::*;
pub mod blocksigner;
pub use self::blocksigner::*;
pub mod dynafed;
pub use self::dynafed::*;
pub mod fee;
pub use self::fee::*;
pub mod network;
pub use self::network::*;
pub mod pegout;
pub use self::pegout::*;
pub mod txindex;
pub use self::txindex::*;
pub mod utxo;
pub use self::utxo::*;
pub mod watchman;
pub use self::watchman::*;

use std::time::{Duration, SystemTime};

use common::PeerId;
use bitcoin::secp256k1::PublicKey;

/// Some system information printed in the beginning of each round.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct SystemInfo<'a> {
    /// The semver version of the functionary software.
    pub functionary_version: &'a str,
    /// git commit ID the software was compiled with, and config file path
    pub git_commit: &'a str,
    /// Our own peer id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_id: Option<PeerId>,
    /// Our own network addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_addresses: Option<&'a [String]>,
}

/// Log with information about a peer
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PeerInfo<'a> {
    /// Human readable name from the configuration file
    pub name: &'a str,
    /// ID used internally by the functionary software
    pub id: PeerId,
    /// Public key used for functionary network messages
    pub communication_pubkey: PublicKey,
    /// Public key used for functionary network messages that is being removed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_communication_pubkey: Option<PublicKey>,
    /// Public key used for signing blocks or transactions
    pub signing_pubkey: PublicKey,
    /// Whether this peer is currently part of consensus.
    pub in_consensus: bool,
    /// List of network addresses from the configuration file
    /// to connect to this peer on
    pub network_addresses: &'a [String],
}

/// Wait for the start of the next stage
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WaitForStage {
    /// Round number of the next stage
    pub next_round: u64,
    /// Stage number of the next stage
    pub next_stage: i32,
    /// Amount of time we will wait, in milliseconds
    pub delay_ms: u64,
}

/// Overran the start of the next stage
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StageOverrun {
    /// Round number of the overrun stage
    pub overrun_round: u64,
    /// Stage number of the overrun stage
    pub overrun_stage: i32,
    /// Amount of time we overran the stage start, in milliseconds
    pub overrun_ms: u64,
    /// Round number of the next stage that will run after this overrun
    pub next_round: u64,
    /// The next stage that will run after this overrun
    pub next_stage: i32,
}

/// Underran the start of the next stage (in fact, the start
/// of the current stage). This log means that the clock has
/// moved backward. The functionary's response will be to stall
/// until the clock catches up to where we previously thought
/// it was, to ensure that we do not process any rounds twice.
///
/// If the clock has moved significantly backward (e.g. because
/// at some point it was set significantly and incorrectly
/// forward) a manual restart of the functionary may be required
/// to get it moving again.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct StageUnderrun {
    /// Round number of the expected next stage
    pub underrun_round: u64,
    /// Stage number of the expected next stage
    pub underrun_stage: i32,
    /// Amount of time we before the start of that stage we observed
    /// the clock to be, in milliseconds
    pub underrun_ms: u64,
    /// Round number of the next stage (which we will start from
    /// the beginning, i.e. at stage number 0)
    pub next_round: u64,
}

/// The peer's status at the end of the round.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PeerStatus<'a> {
    pub peer: PeerId,
    pub name: &'a str,
    pub last_status_msg: SystemTime,
    pub clock_skew: Duration,
    pub n_rounds_up: u32,
    pub last_msg: &'a str,
    pub state: String,
}
