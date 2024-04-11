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


//! # HSM Support
//! Parses and creates HSM messages
//!
//! All constants should be reflected in message.h of the HSM software

use std::os::unix::net::UnixStream;

use bitcoin::secp256k1::{self, PublicKey};

pub use self::local::{LocalBlocksigner, LocalWatchman};
pub use self::liquid::LiquidHsm;
use config;
use common::PakList;
use common::hsm::{self, Error, WatchmanSignStatus};
use watchman::transaction::TransactionSignatures;
use watchman::utxotable::SpendableUtxo;

pub mod message;
mod local;
pub mod liquid;

/// The chainstate of the watchman HSM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchmanState {
    /// The signing status of the HSM.
    pub sign_status: WatchmanSignStatus,
    /// The last header known to the HSM.
    pub last_header: Option<elements::BlockHash>,
}

/// Security Module trait. All communication with the HSM goes through an object
/// implementing this trait.
pub trait SecurityModule {
    // blocksigner
    /// Requests the security module sign a block. Returns a raw ECDSA signature.
    /// Before signing, the security module will execute the equivalent of `validate_block`
    /// and reject if it does not pass.
    fn sign_block(&self, sidechain_block: &elements::BlockHeader) -> Result<secp256k1::ecdsa::Signature, Error>;

    /// Checks whether a block would be signed, if it were requested to be.
    fn validate_block(&self, sidechain_block: &elements::BlockHeader) -> Result<(), Error>;

    // watchman
    /// Requests the public half of the signing keypair from the security module.
    /// Needed by watchman to compute contracthash tweaks
    fn public_key(&self) -> Result<PublicKey, Error>;

    /// Sets the signing redemption script (which will be hashed into a P2WSH-P2SH
    /// scriptpubkey). Needed by watchman to compute its change address.
    fn set_witness_script(&self, script: &bitcoin::ScriptBuf) -> Result<(), Error>;

    /// Empties the cache of authorized addreses to prepare for a new transaction
    fn authorized_addresses_clear(&self) -> Result<(), Error>;

    /// Adds an address to the list of authorized ones for the next pegout
    fn authorized_addresses_add(&self, pk: &[u8], sig: &[u8]) -> Result<(), Error>;

    /// Replaces the master keys used for pegout address authorization
    fn authorization_master_keys_replace(&self, master_keys: &PakList) -> Result<(), Error>;

    /// Segwit version of sign_transaction. Just returns an array of ECDSA signatures
    /// in DER format with SIGHASH_ALL appended, suitable for putting into a witness
    /// array in a complete transaction.
    fn sign_segwit_transaction(
        &self, tx: &bitcoin::Transaction, inputs: &[SpendableUtxo],
    ) -> Result<TransactionSignatures, Error>;

    /// Send a valid and signed block header to the watchman HSM.
    fn send_header(&self, header: &elements::BlockHeader) -> Result<(), Error>;

    /// Get the watchman chain state.
    fn get_watchman_state(&self) -> Result<WatchmanState, Error>;

    /// Ask the HSM to initialize itself and perform key generation, OR restore
    /// an HSM from a backup, depending on the config flags.
    fn initialize_hsm(
        &self, config: config::InitHSM, timestamp_millis: u64,
    ) -> Result<Vec<u8>, Error>;

    /// Initialize HSM operations from a specific address
    fn initialize_hsm_from(
        &self, config: config::InitHSM, timestamp_millis: u64, return_address: hsm::Address,
    ) -> Result<Vec<u8>, Error>;

    /// Ask the HSM to send back its signing key. The return address is used by parallel_port
    /// to route the response back to the caller.
    fn get_signing_key(&self, return_address: hsm::Address) -> Result<Vec<u8>, Error>;

    /// Send an update packet (either a file info packet or file chunk packet)
    /// To an hsm.
    fn update_tool_send(&self, data_packet: &[u8]) -> Result<UnixStream, Error>;

    /// Wait for and return a response from the HSM
    fn update_tool_recv(&self, sock: &mut UnixStream) -> Result<(hsm::Command, Vec<u8>), Error>;

    /// Ask the HSM to send back the RTC (in milliseconds) from SRAM chip
    fn get_rtc(&self, return_address: hsm::Address) -> Result<u64, Error>;
}

