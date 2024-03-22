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


//! # Constants
//! Various constant values needed by other parts of the code

use ::BlockHeight;

/// The number of confirmations for a sidechain tx to be considered final.
pub const SIDECHAIN_CONFIRMS: BlockHeight = 2;

/// The minimum allowable size of a change output, in satoshis. If a change output
/// is computed to be smaller than this, drop it into fees. For now hardcoded to 0.00001BTC.
/// Must be larger than `MINIMUM_MAINCHAIN_UTXO_AMOUNT`.
pub const MINIMUM_DUST_CHANGE: u64 = 1000;

/// The minimum allowable size of additional change outputs, in satoshis. This is used
/// to create as many economical change outputs as possible during pegout processing.
/// Currently hard-coded to 0.001BTC, the current minimum allowed pegout value in Liquid.
pub const MINIMUM_OPPORTUNISTIC_CHANGE: u64 = 100000;

/// The maximum allowable weight of a signed mainchain transaction that we create.
/// Bitcoin Core's default IsStandard rules have a limit of 400K for relaying, so
/// this should be below this.
/// N.B. We are targeting 20 seconds round-trip over HSMv1 serial to avoid timeouts
/// see functionary issue #288
/// N.B. This value was once changed to 150_000 but was changed back to be
/// compatible with our production code. Should consider changing later.
pub const MAXIMUM_TX_WEIGHT: usize = 60_000 * 4;

/// The maximum tx weight for our own proposals.
pub const MAX_PROPOSAL_TX_WEIGHT: usize = 150_000; // equivalent to 37.5 kB

/// The maximum number of payload bytes we want to send to the HSM.
///
/// The majority of the data exchanges are the payloads and therefore we use
/// them as an easy-to-calculate estimate of the total data exchanged.
/// We only count the total proposal unsigned tx size and all the PAK proofs.
/// We do not count (1) the HSM message headers for the msg and for the reply
/// and (2) the signature value the HSM responds on the very last message and
/// (3) potentially other small offsets (like length prefixes).
///
/// Calculated with a data rate of 3kB/s and
/// an arbitrary target limit of 30 seconds.
pub const MAX_PROPOSAL_TOTAL_HSM_PAYLOAD: usize = 90_000; // 90 kB

/// When in need of consolidation, a maximum number of inputs to *require* a new
/// transaction to have. Should be set to avoid exceeding `MAXIMUM_TX_WEIGHT` with
/// only one output.
pub const MAXIMUM_REQUIRED_INPUTS: usize = 50;

/// The maximum number of change outputs created in a transaction of the functionary.
pub const MAXIMUM_CHANGE_OUTPUTS: usize = 10;

/// Specifies the acceptable interval of the number of main chain outputs. If the actual number is
/// not in `[n_main_outputs - N_MAIN_OUTPUTS_RADIUS, n_main_outputs + N_MAIN_OUTPUTS_RADIUS]` then
/// watchman spends or creates additional outputs to get close to `n_main_outputs` again. This is
/// set to `MAXIMUM_CHANGE_OUTPUTS - 1` to allow adding MAXIMUM_CHANGE_OUTPUTS to a transaction
/// when the number barely misses the interval from below.
pub const N_MAIN_OUTPUTS_RADIUS: usize = MAXIMUM_CHANGE_OUTPUTS - 1;

/// Our transactions should be included in one of the next TX_CONFIRM_TARGET blocks.
pub const TX_CONFIRM_TARGET: BlockHeight = 5;

/// The prefix for the mainchain commitment in the Liquid coinbase txs.
pub const MAINCHAIN_COMMITMENT_HEADER: [u8; 4] = [0x0a, 0x8c, 0xe2, 0x6f];

/// The prefix for the blocksigner descriptor commitment in Liquid coinbase at DynaFed proposal.
pub const BLOCKSIGNER_DESCRIPTOR_HEADER: [u8; 4] = [0x42, 0x4c, 0x4b, 0x53]; // BLKS

/// The prefix for the fedpeg descriptor commitment in Liquid coinbase at DynaFed proposal.
pub const FEDPEG_DESCRIPTOR_HEADER: [u8; 4] = [0x46, 0x44, 0x50, 0x47]; // FDPG

/// The dynafed epoch length for liquidv1.
pub const EPOCH_LENGTH_LIQUIDV1: u32 = 14 * 24 * 60; // 2 weeks, 20160 blocks

/// The dynafed epoch length for testing chains.
pub const EPOCH_LENGTH_TESTING: u32 = 10;

/// Constants that are given by the sidechain
pub mod sidechain {
    /// Maximum size of a block in bytes
    /// It is assumed that the sidechain's MAX_BLOCK_SIZE also
    /// applies to the block results of RPC calls to the daemon
    pub const MAX_BLOCK_SIZE: usize = 4000000;
    /// Size of a block signature
    pub const MAX_BLOCK_SIGNATURE_SIZE: usize = 80;
    /// Total value on the sidechain, in satoshis
    pub const TOTAL_FUNDS: u64 = 21_000_000__00000000;
}

// Include build-time constants
#[cfg(feature = "build-constants")]
include!(concat!(env!("OUT_DIR"), "/build_constants.rs"));

/// Struct to contain all configurable constants.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct Constants {
    /// Minimal Per Mille of the current funds to be swept
    /// It is set to 10 (1%)
    pub min_sweep_permille: u64,
    /// Minimum absolute value to sweep to avoid utxos that are too small
    /// It is set to 1 BTC
    pub min_sweep_value_sats: u64,
    /// In order to consolidate, certain UTXOs won't be swept unless they reach a
    /// critical "near-expiry" threshold.
    /// It is 2 days worth of Bitcoin blocks.
    pub critical_expiry_threshold: u64,
    /// The number of blocks before CSV expiry an output is considered "near-expiry".
    /// It is 5 days worth of Bitcoin blocks.
    pub near_expiry_threshold: u64,
    /// Do we use the economical fee rate estimate from bitcoind or the conservative?
    pub use_economical_feerate_estimation: bool,
}

impl Default for Constants {
    fn default() -> Self {
        Constants {
            min_sweep_permille: 10,
            min_sweep_value_sats: 100_000_000,
            critical_expiry_threshold: 720,
            near_expiry_threshold: 720,
            use_economical_feerate_estimation: false,
        }
    }
}

static mut CONSTANTS_STATIC: Option<Constants> = None;

lazy_static! {
    static ref CONSTANTS_DEFAULT: Constants = Constants::default();
}

/// Should only be set ONCE on startup before the program starts running.
pub fn set_constants_on_startup(constants: Constants) {
    unsafe {
        assert!(CONSTANTS_STATIC.is_none(), "Must not set Constants more than once");
        CONSTANTS_STATIC = Some(constants);
    }
}

pub struct ConstantsDeref;

impl std::ops::Deref for ConstantsDeref {
    type Target = Constants;
    fn deref(&self) -> &Self::Target {
        unsafe {
            match CONSTANTS_STATIC.as_ref() {
                None => &CONSTANTS_DEFAULT,
                Some(c) => c,
            }
        }
    }
}

pub const CONSTANTS: ConstantsDeref = ConstantsDeref;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn new_header_prefixes() {
        assert_eq!(b"FDPG", &FEDPEG_DESCRIPTOR_HEADER);
        assert_eq!(b"BLKS", &BLOCKSIGNER_DESCRIPTOR_HEADER);
    }
}
