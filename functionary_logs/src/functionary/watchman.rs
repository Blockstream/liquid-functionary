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


//! # General logs
//!
//! Split into "W" tags for watchman logs, "B" tags for blocksigner logs,
//! and "G" (general) for logs that may be triggered by either one.
//!

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use bitcoin::hashes::{sha256, sha256d};
use bitcoin::{Amount, OutPoint};

use common::{PakList, PeerId};

/// git commit ID the software was compiled with, and config file path
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct StartingWatchman<'a> {
    /// Path to the configuration file
    pub config_path: &'a str,
    /// git commit ID the software was compiled with, and config file path
    pub git_commit: &'a str,
    /// The semver version of the functionary software.
    pub functionary_version: &'a str,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WatchmanStartupStarted {}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WatchmanStartupFinished {}

/// The cache file (which stores the state of both blockchains) was missing
/// or could not be read. A full rescan of both blockchains is
/// required before starting up.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct NoCacheFile<'a> {
    /// Path to the cache file
    pub cache_path: &'a str,
    /// Error that was encountered trying to read it
    pub error: String,
}
///
/// The cache file (which stores the state of both blockchains) was
/// corrupt and could not be parsed. A full rescan of both blockchains is
/// required before starting up.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct CorruptCacheFile<'a> {
    /// Path to the cache file
    pub cache_path: &'a str,
    /// Error that was encountered trying to parse it
    pub error: String,
    /// The path where the file is backed up
    pub backup_path: &'a str,
}

/// The cache file (which stores the state of both blockchains) was written
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct SaveCacheFile<'a> {
    /// Path to the cache file
    pub cache_path: &'a str,
    /// Duration of the serde serialization and file I/O
    pub duration: Duration,
}

/// The cache file (which stores the state of both blockchains) was missing
/// or corrupt and could not be read. A full rescan of both blockchains is
/// required before starting up.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PublicKeyRetrievalFailed {
    /// Error that was encountered trying to read it
    pub error: String,
}

/// The descriptor in our configuration file changed relative to the one in
/// cache file, necessitating a rescan of both blockchains to learn the state
/// of all coins
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DescriptorChanged<'a> {
    /// Path to the cache file
    pub cache_path: &'a str,
    /// Cached descriptor
    pub old_descriptor: String,
    /// Currently loaded descriptor
    pub new_descriptor: String,
}

/// The confirmation requirement on the mainchain in our configuration file
/// changed relative to the one in our cache file. This has the potential
/// to cause skipped or double-counted blocks, so to be safe we simply
/// rescan both chains entirely.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MainConfsChanged<'a> {
    /// Path to the cache file
    pub cache_path: &'a str,
    /// Cached mainchain confirmation requirement
    pub old_requirement: u64,
    /// Currently loaded mainchain confirmation requirement
    pub new_requirement: u64,
}

/// The confirmation requirement on the sidechain in our configuration file
/// changed relative to the one in our cache file. This has the potential
/// to cause skipped or double-counted blocks, so to be safe we simply
/// rescan both chains entirely.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct SideConfsChanged<'a> {
    /// Path to the cache file
    pub cache_path: &'a str,
    /// Cached sidechain confirmation requirement
    pub old_requirement: u64,
    /// Currently loaded sidechain confirmation requirement
    pub new_requirement: u64,
}

/// A v1-style descriptor was provided but the peers are not listed in
/// the order that production peers will infer from their templates. The
/// resulting network will therefore not work with production peers.
///
/// If compatibility with non-v1 peers isn't needed, you should use a
/// more efficient descriptor to avoid this check :)
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct BadDescriptorOrder {
    /// Descriptor provided in the configuration file
    pub bad_descriptor: String,
    /// Reordered version of the descriptor to be production-compatible
    pub reordered: String,
}

/// Regular, untweaked, change mainnet address
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChangeAddress {
    /// an address (as if that weren't already obvious)
    pub address: bitcoin::Address,
}

impl serde::Serialize for ChangeAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>  {
        use serde::ser::SerializeMap;
        let mut ser = serializer.serialize_map(Some(3))?;
        let mut addr = self.address.clone();
        ser.serialize_entry("address_mainnet", &addr)?;
        addr = bitcoin::Address::new(bitcoin::Network::Testnet, addr.into_parts().1);
        ser.serialize_entry("address_testnet", &addr)?;
        addr = bitcoin::Address::new(bitcoin::Network::Regtest, addr.into_parts().1);
        ser.serialize_entry("address_regtest", &addr)?;
        ser.end()
    }
}

/// CSV-tweaked change mainnet address
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CsvTweakedChangeAddress {
    /// an address (as if that weren't already obvious)
    pub address: bitcoin::Address,
}

impl serde::Serialize for CsvTweakedChangeAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>  {
        use serde::ser::SerializeMap;
        let mut ser = serializer.serialize_map(Some(3))?;
        let mut addr = self.address.clone();
        ser.serialize_entry("address_mainnet", &addr)?;
        addr = bitcoin::Address::new(bitcoin::Network::Testnet, addr.into_parts().1);
        ser.serialize_entry("address_testnet", &addr)?;
        addr = bitcoin::Address::new(bitcoin::Network::Regtest, addr.into_parts().1);
        ser.serialize_entry("address_regtest", &addr)?;
        ser.end()
    }
}

/// Status of sync'ing a blockchain
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WatchmanSyncStatus<'a> {
    /// Which blockchain is being sync'd
    pub blockchain: &'a str,
    /// Current height that we are sync'd to
    pub current_height: u64,
    /// Maximum "finalized" height that we are aware of
    pub max_height: u64,
    /// Indicates if this is the final report for the sync
    /// or is a mid-scan status.
    pub sync_complete: bool,
    /// How long it took to do this sync
    pub duration: Duration,
}

/// Status of the mainchain mempool cache
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MempoolCacheStatus {
    /// Number of hits during this sync
    pub number_of_hits: u64,
    /// Current cache size in entries
    pub cache_size: u64,
    /// Entries prunes this round
    pub number_pruned: u64
}

pub(crate) mod serde_btc_addr {
    use serde::ser::SerializeMap;

    pub fn serialize<S: serde::Serializer>(addr: &bitcoin::Address, s: S) -> Result<S::Ok, S::Error>  {
        let mut ser = s.serialize_map(Some(3))?;
        let mut addr = addr.clone();
        addr = bitcoin::Address::new(bitcoin::Network::Bitcoin, addr.into_parts().1);
        ser.serialize_entry("mainnet", &addr)?;
        addr = bitcoin::Address::new(bitcoin::Network::Testnet, addr.into_parts().1);
        ser.serialize_entry("testnet", &addr)?;
        addr = bitcoin::Address::new(bitcoin::Network::Regtest, addr.into_parts().1);
        ser.serialize_entry("regtest", &addr)?;
        ser.end()
    }
}

/// Starting the creation of a transaction proposal
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct StartTxProposal<'a> {
    /// Current feerate in sat/vkb
    pub fee_rate: u64,
    /// Amount available in the fee pool
    pub available_fees: i64,
    /// Amount below which UTXOs are ignored because it'd be more expensive
    /// to spend them than they are worth
    pub economical_amount: u64,
    /// Total number of UTXOs we control
    pub total_n_utxos: usize,
    /// Total number of pegout requests we are aware of
    pub total_n_pegouts: usize,
    /// Number of in-flight UTXOs (ones which have been spent by
    /// transactions which are not yet 100-blocks confirmed)
    pub in_flight_utxos: usize,
    /// Number of in-flight pegouts (ones which have been processed by
    /// transactions which are not yet 100-blocks confirmed)
    pub in_flight_pegouts: usize,
    /// The change address.
    #[serde(with = "serde_btc_addr")]
    pub change_address: bitcoin::Address,
    /// The change scriptPubkey.
    pub change_spk: &'a bitcoin::Script,
}

/// Created a transaction proposal
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct CompleteProposal<'a> {
    /// Set of inputs this proposal spends
    pub inputs: &'a [bitcoin::OutPoint],
    /// Set of pegout requests this proposal processes
    pub pegouts: &'a [elements::OutPoint],
    /// Set of change outputs
    pub change: &'a [u64],
    /// Transaction fee
    pub fee: u64,
}

/// Validating a transaction proposal which we either created
/// or received from the network
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ValidateProposal<'a> {
    /// Set of inputs this proposal spends
    pub inputs: &'a [bitcoin::OutPoint],
    /// Set of pegout requests this proposal processes
    pub pegouts: &'a [elements::OutPoint],
    /// Set of change outputs
    pub change: &'a [u64],
    /// The change address being used.
    #[serde(with = "serde_btc_addr")]
    pub change_address: bitcoin::Address,
    /// The change scriptPubkey being used.
    pub change_spk: &'a bitcoin::Script,
}

/// We received a precommit message from a peer
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ReceivedTxPrecommit {
    /// Peer that sent us the proposal
    pub peer: PeerId,
    /// Txid that the peer precommitted to
    pub txid: bitcoin::Txid,
}

/// A peer is precommitting to a tx that differs from the txid that
/// we precommitted to.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PrecommitWrongTxid {
    /// Peer that sent us the precommit
    pub peer: PeerId,
    /// Txid that we precommitted to
    pub our_txid: bitcoin::Txid,
    /// Txid that the peer precommitted to
    pub peer_txid: bitcoin::Txid,
}

/// Not using a UTXO because it would be uneconomical to spend (i.e. the cost
/// at the current feerate of including it as an input would exceed the value
/// of the UTXO)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct IgnoreUneconomicalUtxo {
    /// The UTXO under consideration
    pub outpoint: bitcoin::OutPoint,
    /// The value of the UTXO
    pub value: u64,
}

/// Starting the creation of a transaction proposal
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct UtxoNearExpiry {
    /// The UTXO under consideration
    pub outpoint: bitcoin::OutPoint,
    /// The value of the UTXO
    pub value: u64,
    /// Height at which the UTXO was confirmed
    pub height: u64,
    /// Height at which the UTXO will expire
    pub expiry_height: u64,
    /// Current height of the blockchain
    pub current_height: u64,
}

/// Explicitly sweep UTXO
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ExplicitlySweepUtxo {
    /// The UTXO under consideration
    pub outpoint: bitcoin::OutPoint,
    /// The value of the UTXO
    pub value: u64,
    /// Height at which the UTXO was confirmed
    pub height: u64,
    /// Current height of the blockchain
    pub current_height: u64,
}

/// Not sweeping UTXOs due to not meeting minimum requirements
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct NotSweepingUtxos {
    /// The value of the UTXOs
    pub value: u64,
    /// Number of UTXOs
    pub num_utxos: u64,
    /// Minimum sweep value threshold
    pub min_sweep_value_sats: u64,
    /// Minimum per-mille threshold
    pub min_sweep_per_mille: u64,
    /// Current total funds in watchman wallet
    pub total_funds: u64,
}

/// Reclaim a failed pegin UTXO
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ReclaimFailedPegin {
    /// The UTXO under consideration
    pub outpoint: bitcoin::OutPoint,
    /// The value of the UTXO
    pub value: u64,
    /// Height at which the UTXO was confirmed
    pub height: u64,
    /// Current height of the blockchain
    pub current_height: u64,
}

/// Read and validated a Failed Pegin from the config file
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct LoadedFailedPegin {
    /// Outpoint of failed pegin output
    pub outpoint: OutPoint,
    /// Value of failed pegin
    pub value: u64
}

/// Added a Failed Pegin to UTXO Table and Accounting to be swept
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct AddedFailedPegin {
    /// Outpoint of failed pegin output
    pub outpoint: OutPoint,
    /// Value of failed pegin
    pub value: u64
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct CantSignFailedPeginReclamation<'a> {
    /// Outpoint of failed pegin output
    pub outpoint: OutPoint,
    /// Available signers
    pub available_signers: &'a HashSet<PeerId>
}

/// Failed Peg In does not have enough confirmations to be swept
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct FailedPeginNotMature {
    /// Outpoint of failed pegin output
    pub outpoint: OutPoint,
}

/// Cannot find Failed Pegin outpoint in UTXO set, removing from config
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct FailedPeginNotInUtxoSet {
    /// Outpoint of failed pegin output
    pub outpoint: OutPoint,
    /// Stringified version of the bitcoind error
    pub error: String,
}

/// Failed Peg In could be claimed via normal claim
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct FailedPeginCanBeClaimed {
    /// Outpoint of failed pegin output
    pub outpoint: OutPoint,
}

/// Failed Peg In reclamation transaction is in the Mempool
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct FailedPeginReclamationInMempool {
    /// Outpoint of failed pegin output
    pub outpoint: OutPoint,
}


/// We are not spending a UTXO, despite needing to for expiry reasons,
/// because there are not enough fees or not enough room in the tx
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct NotSpendingUtxo {
    /// The input we are not spending,
    pub outpoint: bitcoin::OutPoint,
    /// Stringified version of the error that caused the pegout to be ignored
    pub error: String,
}

/// Ignoring a pegout request during proposal creation, because it doesn't
/// fit or we can't afford the fees
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IgnoringPegout {
    /// The outpoint on the sidechain of the pegout request
    pub outpoint: elements::OutPoint,
    /// The value of the UTXO
    pub value: u64,
    /// Stringified version of the error that caused the pegout to be ignored
    pub error: String,
}

/// Ignoring a pegout request during proposal creation, because it the
/// HSM has no more capacity for PAK proofs
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct IgnoringPegoutHsmFull {
    /// The outpoint on the sidechain of the pegout request
    pub outpoint: elements::OutPoint,
    /// The value of the UTXO
    pub value: u64,
}

/// Include a pegout request during proposal creation,
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct IncludingPegout {
    /// The outpoint on the sidechain of the pegout request
    pub outpoint: elements::OutPoint,
    /// The value of the UTXO
    pub value: u64,
}

/// An unsigned transaction was created from a concrete transaction proposal.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct CreatedUnsignedTx {
    /// The tx's txid.
    pub txid: bitcoin::Txid,
    /// The weight of the unsigned tx.
    pub unsigned_weight: usize,
    /// The estimated weight of the tx when signed.
    pub estimated_signed_weight: usize,
}

/// Signing given unsigned tx.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct SigningTx {
    pub unsigned_txid: bitcoin::Txid,
}

/// Ignoring a pegout request during proposal creation, because it the
/// HSM rejected its PaK proof. This should not happen and indicates a
/// situation that may require manual intervention
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct IgnoringPegoutBadPak {
    /// The outpoint on the sidechain of the pegout request
    pub outpoint: elements::OutPoint,
    /// The value of the UTXO
    pub value: u64,
    /// Stringified version of the HSM error
    pub error: String,
}

/// There were no pegout requests to process or expiring inputs to spend
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct EmptyProposal;

/// We refused master's proposal
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RefusedProposal<'a> {
    pub master: PeerId,
    pub error: Cow<'a, ProposalError>,
}

/// Update conflict requirements for a specific pegout request
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct UpdateConflictRequirements<'a> {
    /// TXID of the mainchain transaction for which we are updating
    /// the conflict set
    pub reason: bitcoin::Txid,
    /// Outpoint of the request on the sidechain
    pub request: elements::OutPoint,
    /// New set of requirements
    pub required_inputs: &'a HashSet<bitcoin::OutPoint>,
}

/// Clear conflict requirements for a specific pegout request
/// because the pegout has now been successfully processed
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ClearConflictRequirements {
    /// TXID of the finalized mainchain transaction which processes
    /// the pegout request
    pub reason: bitcoin::Txid,
    /// Outpoint of the request on the sidechain
    pub request: elements::OutPoint,
}

/// We saw an unconfirmed transaction which did not satisfy the
/// conflict requirements for some pegout. This likely means that
/// we are confused and have stricter requirements than everybody
/// else, which may mean that we have been signing transactions
/// that the majority of the network has rejected, or that our
/// view of the network is somehow compromised.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct UnconfirmedDoubleSpend<'a> {
    /// The guilty transaction
    pub txid: bitcoin::Txid,
    /// The pegout request whose conflict requirements were not
    /// respected
    pub request: elements::OutPoint,
    /// The conflicts that are required to be in the input list of said request.
    pub required_conflicts: &'a HashSet<bitcoin::OutPoint>,
}

/// A federation-produced transaction was detected but it had some
/// output that we don't recognize. This may mean a double-spend. It
/// may mean the federation is insolvent. This is a fatal error.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DetectedUnknownOutput<'a> {
    /// The guilty transaction
    pub txid: bitcoin::Txid,
    /// The output whose provenance we don't recognize
    pub output: &'a bitcoin::TxOut,
}

/// A federation-produced transaction was detected but it had some
/// input that we don't recognize. This is a fatal error.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DetectedUnknownInputs {
    /// The guilty transaction
    pub txid: bitcoin::Txid,
    /// The unknown inputs spent by the tx.
    pub unknown_inputs: Vec<bitcoin::OutPoint>,
}

/// Detected new change with a scriptPubKey matching a legacy
/// (no longer active) scriptPubKey.
///
/// This should only happen immediately after a transition, if the
/// originating pegout was made right before the transition. Otherwise,
/// this log indicates a problem.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DetectedLegacyChange<'a> {
    /// The guilty transaction
    pub txid: bitcoin::Txid,
    /// The scriptPubKey of the output
    pub spk: Cow<'a, bitcoin::Script>,
    /// The currently active change scriptPubKey
    pub active_change_spk: Cow<'a, bitcoin::Script>
}

/// Detected a donation to a legacy (no longer active) change scriptPubKey.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DetectedLegacyDonation<'a> {
    /// The guilty transaction
    pub txid: bitcoin::Txid,
    /// The scriptPubKey of the output
    pub spk: Cow<'a, bitcoin::Script>,
    /// The currently active change scriptPubKey
    pub active_change_spk: Cow<'a, bitcoin::Script>
}

/// A pegin claim referred to a mainchain block that we were not aware of.
/// This probably simply means the bitcoind is not synced, and requires
/// waiting until the bitcoind is fully synced before restarting the
/// functionary. See functionary bug #180.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct NoSuchBlock {
    /// The txid of the pegin claim that references the missing block
    pub claim_txid: elements::Txid,
    /// The outpoint that the pegin claim references
    pub bitcoin_outpoint: bitcoin::OutPoint,
    /// The hash of the missing block (where said outpoint should be)
    pub blockhash: bitcoin::BlockHash,
    /// Stringified version of the error we got from the mainchain daemon
    /// when requesting the block
    pub error: String,
}

/// A pegout request was made to the federation change address. To avoid
/// confusion, such pegout requests are treated as `OP_RETURN` outputs
/// and their value is directly added to the fee pool, rather than
/// processing the request as an ordinary pegout.
///
/// In production Liquid v1, it is impossible to trigger this bug because
/// there is no possible PAK proof for the federation change address.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PegoutToFederation {
    /// The outpoint of the pegout request
    pub outpoint: elements::OutPoint,
    /// The value of the request
    pub value: u64,
}

/// Round stage starting
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct WatchmanStartStage {
}

/// Alternate final stage starting
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WatchmanStartAlternateThirdStage;

/// Round completed successfully. This either means that we signed
/// and broadcast a transaction, or we were idle
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WatchmanRoundComplete<'a> {
    /// tx of the transaction we broadcast
    pub txid: bitcoin::Txid,
    pub inputs: &'a [bitcoin::OutPoint],
    pub nb_inputs: usize,
    pub pegouts: &'a [elements::OutPoint],
    pub nb_pegouts: usize,
    pub change: &'a [u64],
    pub nb_change: usize,
}

/// We skipped a round, since we just started up
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WatchmanRoundSkipped {
}

/// We skipped a round effectively, since there was no transaction to sign
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WatchmanRoundIdled {
}

/// A reason why a round failed.
#[derive(Debug, Copy, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum RoundFailedReason {
    /// No proposal sent by master.
    NoProposal,
    /// Failed to assemble tx using gathered signatures.
    TxAssembly,
    /// Tx was signed, but not accepted by the mempool.
    InvalidSignedTx,
}

/// Round failed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WatchmanRoundFailed {
    pub reason: RoundFailedReason,
    pub message: String,
}

/// Round did not complete because we were in some error state
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WatchmanRoundErrored {
    /// Stringified description of the error state
    pub error: String,
}

/// Received a transaction proposal from a peer we do not believe is master
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ProposalFromNonMaster {
    /// Peer that sent us the proposal
    pub peer: PeerId,
}

/// Received an `Idle` message from a peer we do not believe is master
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct IdleFromNonMaster {
    /// Peer that sent us the proposal
    pub peer: PeerId,
}

/// Failed to update our view of the blockchains' state from the RPC.
/// The location of this error depends on the round stage - in stage 1,
/// we run this command to update our state in preparation for the
/// new round. In stage 3, after broadcasting a transaction, we run
/// this to ensure we have a current view of the blockchains (in
/// in particular, the Bitcoin blockheight) so we record the correct
/// data along with the unconfirmed transaction.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RpcSyncFailed {
    /// Stringified version of the error that occured
    pub error: String,
}

/// Notes the number of unspendable UTXOs that were deleted from our records
/// at the start of this watchman round.
///
/// A recorded UTXO is unspendable if it was donated to an old fedpeg_program,
/// or if it was not swept to the new federation before the old one went offline,
/// following a dynafed transition.
///
/// This situation is expected to be uncommon; most rounds should have 0 utxos pruned.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct TotalPrunedUtxos {
    /// The total number of utxos that were pruned in this round
    pub n_utxos: usize,
}

/// We just broadcasted a new watchman transaction, but the blockchain
/// manager didn't pick it up.
/// This can be either because our sync failed (which should be
/// reported separately), or because the txindex didn't consider
/// the tx to be relevant and didn't store it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct TxUnknownAfterBroadcast {
    /// The txid of the tx.
    pub txid: bitcoin::Txid,
}

/// Used to debug the miniscript satisfier that combines the signature
/// to assemble the final tx.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CombineSigs<'a> {
    pub key: String,
    pub input_idx: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<PeerId>,
    pub sig_result: &'a str,
    pub msg: &'a str,
}

/// Work found for this round
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WatchmanProductiveRound {
    pub inputs: usize,
    pub outputs: usize,
    pub newstate: String,
}

/// Unable to locate block at expected location in specified chain
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WatchmanBlockCheckError {
    /// Peer reporting consensus info
    pub peer: PeerId,
    /// Which blockchain is being checked
    pub blockchain: &'static str,
    /// Hash of the block being checked. We use the underyling
    /// hash here so Bitcoin and Elements block hashes
    /// can be used.
    pub block_hash: sha256d::Hash,
    /// Failing result of check
    pub result: String,
}

/// Found a mainchain commitment.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MainchainCommitmentFound {
    pub sidechain_height: u64,
    pub sidechain_hash: elements::BlockHash,
    pub mainchain_hash: bitcoin::BlockHash,
    pub mainchain_height: Option<u64>,
}

/// Updated our latest mainchain commitment.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MainchainCommitmentUpdated {
    pub mainchain_height: u64,
    pub mainchain_hash: bitcoin::BlockHash,
    pub last_height: u64,
}

/// Detected fork in mainchain commitment.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MainchainCommitmentForked {
    pub sidechain_height: u64,
    pub sidechain_hash: elements::BlockHash,
    pub last_mainchain_height: u64,
    pub last_mainchain_hash: bitcoin::BlockHash,
    pub new_mainchain_height: u64,
    pub new_mainchain_hash: bitcoin::BlockHash,
}

/// Mainchain commitment went back in time.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MainchainCommitmentBackwards {
    pub sidechain_height: u64,
    pub sidechain_hash: elements::BlockHash,
    pub last_mainchain_height: u64,
    pub last_mainchain_hash: bitcoin::BlockHash,
    pub new_mainchain_height: u64,
    pub new_mainchain_hash: bitcoin::BlockHash,
}

/// Found mainchain commitment our mainchain node doesn't know.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MainchainCommitmentUnknown {
    pub sidechain_height: u64,
    pub sidechain_hash: elements::BlockHash,
    pub mainchain_hash: bitcoin::BlockHash,
}

/// Summary of statistics from the wallet printed every round.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WalletSummary<'a> {
    pub n_pending_txs: usize,
    pub n_pending_sweeponly_txs: usize,
    pub n_pending_pegout_delivery_txs: usize,
    pub current_signers: Cow<'a, HashSet<PeerId>>,
    pub n_non_federation_owned_utxos: usize,
    pub n_pending_pegouts: usize,
    pub n_pending_spent_utxos: usize,
    pub n_unprocessed_pegouts: usize,
    pub n_outputs_economical: usize,
    pub n_outputs_uneconomical: usize,
    pub n_outputs_available_economical: usize,
    pub n_outputs_available_uneconomical: usize,
    pub n_outputs_pending: usize,
    pub n_inputs_pending: usize,
    pub n_output_projected: usize,
    pub available_output_percentiles: [u64; 5],
    pub pending_input_value: u64,
    pub pending_output_value: u64,
    pub pending_change_value: u64,
    pub pending_donation_value: u64,
}

/// The consensus parameters have changed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WatchmanConsensusChanged<'a> {
    /// the dynafed root
    pub params_root: sha256::Midstate,
    /// fedpeg_program
    pub fedpeg_program: Cow<'a, bitcoin::Script>,
    /// fedpegscript
    pub fedpeg_script: String,
    /// the pak list
    pub pak_list: Cow<'a, PakList>,
}

/// Sending new block header to the HSM.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct HsmSendingHeader {
    /// The height of the header.
    pub height: u64,
    /// The hash of the header.
    pub hash: elements::BlockHash,
    /// The serialized header.
    pub header_hex: String,
}

/// We updated the Watchman HSM chain state with a new block header.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct HsmAcceptedHeader {
    /// The height of the header.
    pub height: u64,
    /// The hash of the header.
    pub hash: elements::BlockHash,
}

/// We sent a block header to the HSM and it was refused.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct HsmRefusedHeader {
    /// The height of the header.
    pub height: u64,
    /// The hash of the header.
    pub hash: elements::BlockHash,
    /// The error returned by the HSM.
    pub error: String,
}

/// We sent a block header to the HSM and it was refused.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct HsmErrorOnHeader {
    /// The height of the header.
    pub height: u64,
    /// The hash of the header.
    pub hash: elements::BlockHash,
    /// The error returned by the HSM.
    pub error: String,
}

/// Update of the HSM chain state failed
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct HsmUpdateFailed {
    /// The error returned by the HSM.
    pub error: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ProposalError {
    /// We tried to sign a transaction which conflicts with one that's pending
    ConflictsWithPendingTx(bitcoin::OutPoint),
    /// Too many change outputs on a tx to sign
    BadChangeCount {
        /// Number of change outputs in the transaction
        got: usize,
        /// Minimum number of change outputs
        min: usize,
        /// Maximum number of change outputs
        max: usize,
    },
    /// A change output's amount was too small
    BadChangeAmount {
        /// Value of the offending change output
        got: u64,
        /// Minimum change value
        min: u64,
    },
    /// A tx to sign is a non-conflicting double-spend of another tx we signed
    AttemptedDoubleSpend(elements::OutPoint),
    /// A transaction proposal included an input twice
    DuplicateInput(bitcoin::OutPoint),
    /// A tx proposal contained an unspendable utxo.
    UnspendableInput(bitcoin::OutPoint),
    /// A transaction proposal included a pegout twice
    DuplicatePegout(elements::OutPoint),
    /// Pegout cannot be included in a proposal since there are
    /// no available inputs which conflict with existing spends
    NoAvailableConflicts(elements::OutPoint),
    /// Transaction proposal exceeded maximum weight
    Oversize {
        /// Weight of the transaction
        got: usize,
        /// Maximim we allow
        max: usize,
    },
    /// Included a pegout to some destination without including the
    /// previous pegout to the same destination; indicates a non
    /// canonical proposal which may lead to inconsistent conflict
    /// trackers
    SkippedPegout {
        /// The request that was included
        request: elements::OutPoint,
        /// Previous request, which was not included
        previous: elements::OutPoint,
    },
    /// Transaction input value exceeded output value
    Unbalanced {
        /// Total value of all transaction inputs
        input_value: u64,
        /// Total value of all transaction outputs
        output_value: u64,
    },
    /// A transaction includes an output we can't identify either
    /// either as processing a pegout or as change
    UnknownOutput(bitcoin::TxOut),
    /// A transaction proposal includes a pegout we don't own
    UnknownPegout(elements::OutPoint),
    /// A federation tx confirmed on the blockchain contains inputs that
    /// we own and inputs that we don't know.
    UnknownInputs(Vec<bitcoin::OutPoint>),
    /// A transaction or proposal delivers a pegout more often than it was
    /// requested.
    DuplicatePegoutDelivery {
        /// The mainchain pegout delivery output.
        output: bitcoin::TxOut,
        /// The pegout requests to this address that have been delivered previously.
        requests: Vec<elements::OutPoint>,
    },
    /// A tx to sign has insufficient fee (minimum, got)
    FeeTooLow {
        /// Fee provided
        got: u64,
        /// Minimum fee required
        minimum: u64,
    },
    /// A tx to sign has excessive fee (maximum, got)
    FeeTooHigh {
        /// Fee provided
        got: u64,
        /// Maximum fee allowed
        maximum: u64,
    },
    /// We were unable to fund a transaction due to insufficient fees
    /// available in the fee pool
    InsufficientFees {
        /// Available fees
        available: i64,
        /// Amount we needed for the transaction
        needed: u64,
    },
    /// The HSM refused the PAK proof
    HsmRefusedPak {
        /// The binary code of the [NackReason]
        nack_code: u8,
        /// The name of the [NackReason]
        nack_name: String,
    },
    /// Non-economical reclamation proposal
    NonEconomicalReclamationProposal(Amount),
}

impl fmt::Display for ProposalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProposalError::ConflictsWithPendingTx(i) =>
                write!(f, "tried to sign a tx with input that conflicts with a pending tx: {}", i),
            ProposalError::BadChangeCount { got, min, max } =>
                write!(f, "tx change count {} (min {} max {})", got, min, max),
            ProposalError::BadChangeAmount { got, min } =>
                write!(f, "tx change amount {} (min {})", got, min),
            ProposalError::AttemptedDoubleSpend(x) =>
                write!(f, "tx processes pegout {} without required conflicts", x),
            ProposalError::DuplicateInput(outpoint) =>
                write!(f, "tx spent input {} twice", outpoint),
            ProposalError::UnspendableInput(outpoint) =>
                write!(f, "tx contains unspendable input {}", outpoint),
            ProposalError::DuplicatePegout(outpoint) =>
                write!(f, "tx processed pegout {} twice", outpoint),
            ProposalError::NoAvailableConflicts(claim) =>
                write!(f, "pegout {} cannot be processed (conflict requirements)", claim),
            ProposalError::Oversize { got, max } =>
                write!(f, "tx signed weight of {} exceeds max {}", got, max),
            ProposalError::SkippedPegout { request, previous } =>
                write!(f, "tx processes request {} without previous request {}", request, previous),
            ProposalError::Unbalanced { input_value, output_value } =>
                write!(f, "tx output value {} exceeds input value {}", output_value, input_value),
            ProposalError::UnknownOutput(ref x) =>
                write!(f, "tx spends to unknown transaction output {:?}", x),
            ProposalError::UnknownPegout(outpoint) =>
                write!(f, "tx processed unknown pegout {}", outpoint),
            ProposalError::UnknownInputs(ref inputs) =>
                write!(f, "tx spends unknown inputs: {:?}", inputs),
            ProposalError::DuplicatePegoutDelivery{ ref output, ref requests } => write!(f,
                "tx delivers a pegout more often than it was requested: \
                output: {:?}, requests: {:?}", output, requests,
            ),
            ProposalError::FeeTooLow { got, minimum } => write!(f,
                "we were asked to sign a tx with fee {}, but our minimum for it is {}", got, minimum,
            ),
            ProposalError::FeeTooHigh { got, maximum } => write!(f,
                "we were asked to sign a tx with fee {}, but our maximum for it is {}", got, maximum,
            ),
            ProposalError::InsufficientFees { needed, available } => write!(f,
                "insufficient fees available: needed {} sats but only had {}", needed, available,
            ),
            ProposalError::HsmRefusedPak { nack_code, nack_name } => write!(f,
                "the HSM refused PAK proof: {} (0x{:x})", nack_name, nack_code,
            ),
            ProposalError::NonEconomicalReclamationProposal(amount) =>
                write!(f, "reclamation proposal of amount {} was not economical", amount),
        }
    }
}

impl std::error::Error for ProposalError {}

