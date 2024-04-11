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


//! Blockchain Management
//!
//! Keeps track of the state of the mainchain and sidechain; identifies pegins
//! and pegouts; identifies "fee pool donations" (burned sidechain coins and
//! mainchain spends directly to the untweaked functionary address); tracks
//! watchman transactions as they are signed, seen on the network, and
//! confirmed.
//!

pub mod fee;
pub mod accounting;
pub mod consensus;
pub mod txindex;
pub mod utxotable;

use std::{cmp, error, fmt, fs, io, thread};
use std::borrow::Cow;
use std::collections::{HashSet, HashMap};
use std::io::Read;
use std::time::{Duration, Instant, SystemTime};

use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint};
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use elements::confidential::Asset;
use common::blockchain::extract_commitment;
use elements::PeginData;

use common::{constants, rollouts, BlockHeight, PeerId, network};
use descriptor::{self, LiquidDescriptor, TweakableDescriptor};
use common::hsm;
use common::rollouts::ROLLOUTS;
use logs::ProposalError;
use peer;
use rpc::{self, BitcoinRpc, ElementsRpc};
use utils::{self, HeightIterator};
use watchman::config::Configuration;
use self::accounting::Account;
use self::consensus::ConsensusTracker;
use self::utxotable::{PegoutRequest, SpendableUtxo, Utxo, UtxoTable};
use self::txindex::OutputMeta;
use watchman::transaction::{self, TransactionUtil};
use watchman::utils::mainchain_block_height;

/// Blockchain manager error
#[derive(Debug)]
pub enum Error {
    /// A problem with a proposal
    BadProposal(ProposalError),
    /// A block should've been in some blockchain but it wasn't
    BlockNotFound(bitcoin::BlockHash),
    /// Import/export error (parsing)
    Json(serde_json::Error),
    /// Import/export error (filesystem)
    Io(io::Error),
    /// JSONRPC communication
    Rpc(jsonrpc::Error),
    /// Tx index error.
    TxIndex(txindex::Error),
    /// Utxo-tracker error
    Utxo(utxotable::Error),
    /// A problem with the HSM
    Hsm(hsm::Error),
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::BadProposal(ref e) => Some(e),
            Error::Json(ref x) => Some(x),
            Error::Io(ref x) => Some(x),
            Error::Rpc(ref x) => Some(x),
            Error::TxIndex(ref x) => Some(x),
            Error::Utxo(ref x) => Some(x),
            Error::Hsm(ref e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::BadProposal(ref e) => write!(f, "bad proposal: {}", e),
            Error::Json(ref x) => write!(f, "json: {}", x),
            Error::BlockNotFound(hash) => write!(f, "block {} not found in chain", hash),
            Error::Io(ref x) => write!(f, "io: {}", x),
            Error::Rpc(ref x) => write!(f, "jsonrpc: {}", x),
            Error::TxIndex(ref x) => write!(f, "txindex: {}", x),
            Error::Utxo(ref x) => write!(f, "utxotable: {}", x),
            Error::Hsm(ref x) => write!(f, "HSM error: {}", x),
        }
    }
}

impl From<ProposalError> for Error {
    fn from(e: ProposalError) -> Error { Error::BadProposal(e) }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error { Error::Json(e) }
}

impl From<jsonrpc::Error> for Error {
    fn from(e: jsonrpc::Error) -> Error { Error::Rpc(e) }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error { Error::Io(e) }
}

impl From<txindex::Error> for Error {
    fn from(e: txindex::Error) -> Error { Error::TxIndex(e) }
}

impl From<utxotable::Error> for Error {
    fn from(e: utxotable::Error) -> Error { Error::Utxo(e) }
}

impl From<hsm::Error> for Error {
    fn from(e: hsm::Error) -> Error {
        if let hsm::Error::ReceivedNack(nack) = e {
            Error::BadProposal(ProposalError::HsmRefusedPak {
                nack_code: nack as u8,
                nack_name: format!("{:?}", nack),
            })
        } else {
            Error::Hsm(e)
        }
    }
}

/// Information about the number of outputs owned by the watchman: current state, available outputs
/// and when pending transactions are confirmed.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct OutputCounter {
    current: usize,
    current_uneconomical: usize,
    available: usize,
    available_uneconomical: usize,
    pending_inputs: usize,
    pending_outputs: usize
}

impl OutputCounter {
    /// Create new OutputCounter
    pub fn new(current: usize, current_uneconomical: usize, available: usize, available_uneconomical: usize, pending_inputs: usize, pending_outputs: usize) -> OutputCounter {
        OutputCounter {
            current: current,
            current_uneconomical: current_uneconomical,
            available: available,
            available_uneconomical: available_uneconomical,
            pending_inputs: pending_inputs,
            pending_outputs: pending_outputs
        }
    }

    /// Number of outputs we currently control including outputs
    /// spent by unconfirmed transactions.
    pub fn current(&self) -> usize {
        self.current
    }

    /// Number of current outputs that are uneconomical to spend
    pub fn current_uneconomical(&self) -> usize {
        self.current_uneconomical
    }

    /// Number of economical outputs after pending transactions are confirmed.
    pub fn projection(&self) -> usize {
        self.available + self.pending_outputs
    }

    /// Number of currently available outputs. Available means all economic outputs currently
    /// controlled but without outputs spent in pending transactions.
    pub fn available(&self) -> usize {
        self.available
    }

    /// Number of currently available uneconomical outputs
    pub fn available_uneconomical(&self) -> usize {
        self.available_uneconomical
    }

    /// Number of outputs that are added by pending transactions
    pub fn pending_outputs(&self) -> usize {
        self.pending_outputs
    }

    /// Number of inputs that are spent by pending transactions
    pub fn pending_inputs(&self) -> usize {
        self.pending_inputs
    }
}

impl network::NetEncodable for OutputCounter {
    /// Serializes the output counter as a network message payload
    fn encode<W: io::Write>(&self, mut w: W) -> Result<usize, network::Error> {
        w.write_u64::<LittleEndian>(self.current as u64)?;
        w.write_u64::<LittleEndian>(self.current_uneconomical as u64)?;
        w.write_u64::<LittleEndian>(self.available as u64)?;
        w.write_u64::<LittleEndian>(self.available_uneconomical as u64)?;
        w.write_u64::<LittleEndian>(self.pending_inputs as u64)?;
        w.write_u64::<LittleEndian>(self.pending_outputs as u64)?;
        Ok(8 * 6)
    }

    /// Parses an output counter from a network message buffer
    fn decode<R: io::Read>(mut r: R) -> Result<Self, network::Error> {
        Ok(OutputCounter {
            current: r.read_u64::<LittleEndian>()? as usize,
            current_uneconomical: r.read_u64::<LittleEndian>()? as usize,
            available: r.read_u64::<LittleEndian>()? as usize,
            available_uneconomical: r.read_u64::<LittleEndian>()? as usize,
            pending_inputs: r.read_u64::<LittleEndian>()? as usize,
            pending_outputs: r.read_u64::<LittleEndian>()? as usize,
        })
    }
}

/// An object of interest in a sidechain transaction
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TxObject<'tx> {
    /// Pegin input
    Pegin(elements::PeginData<'tx>),
    /// Pegout request output
    Pegout(elements::OutPoint, elements::PegoutData<'tx>),
    /// "Donation", i.e. burned coins, which go to the fee pool
    Donation(elements::OutPoint, u64),
    /// Transaction network fee
    Fee(u64),
}

/// Iterator over the interesting parts of a sidechain transaction
pub struct TxIterator<'tx> {
    /// The underlying transaction
    tx: &'tx elements::Transaction,
    /// txid of the transaction
    txid: elements::Txid,
    /// Hash of the genesis block of the mainchain
    genesis_hash: bitcoin::BlockHash,
    /// The asset representing mainchain coins on the sidechain
    pegged_asset: elements::confidential::Asset,
    /// Index of next input/output to return
    idx: usize,
}

impl<'tx> TxIterator<'tx> {
    /// Create a new iterator over a transaction
    pub fn new(
        tx: &'tx elements::Transaction,
        txid: elements::Txid,
        genesis_hash: bitcoin::BlockHash,
        pegged_asset: elements::confidential::Asset,
    ) -> TxIterator {
        debug_assert_eq!(tx.txid(), txid);
        TxIterator {
            tx,
            txid,
            genesis_hash,
            pegged_asset,
            idx: 0,
        }
    }
}

impl<'tx> Iterator for TxIterator<'tx> {
    type Item = TxObject<'tx>;

    fn next(&mut self) -> Option<TxObject<'tx>> {
        loop {
            if self.idx >= self.tx.input.len() + self.tx.output.len() {
                return None;
            }
            let idx = self.idx;
            self.idx += 1;

            if idx < self.tx.input.len() {
                let input = &self.tx.input[idx];
                // This basically just checks the `is_pegin` flag on the input
                // we are trusting the consensus code to reject any such inputs
                // if they don't correspond to a valid yet-unused Bitcoin output
                if let Some(data) = input.pegin_data() {
                    if data.genesis_hash == self.genesis_hash && Asset::Explicit(data.asset) == self.pegged_asset {
                        return Some(TxObject::Pegin(data));
                    }
                }
            } else {
                let vout = idx - self.tx.input.len();
                let output = &self.tx.output[vout];
                if output.asset == self.pegged_asset && output.is_null_data() {
                    if let Some(data) = output.pegout_data() {
                        let outpoint = elements::OutPoint {
                            txid: self.txid,
                            vout: vout as u32,
                        };
                        if data.genesis_hash == self.genesis_hash {
                            return Some(TxObject::Pegout(outpoint, data));
                        } else {
                            // If we are here, it means the user did a "pegout" with the
                            // wrong genesis hash and somehow got this onto the chain.
                            // Log an error rather than treating it as a donation, because
                            // it's likely that they did intend to pegout, but because
                            // something funny has happened, it will require manual
                            // intervention for them to get their funds.
                            slog!(RequestBadGenesis, request: outpoint,
                                dest_script_pubkey: &data.script_pubkey, value: data.value,
                                genesis: data.genesis_hash
                            );
                        }
                    } else {
                        return Some(TxObject::Donation(
                            elements::OutPoint {
                                txid: self.txid,
                                vout: vout as u32,
                            },
                            output.minimum_value(),
                        ));
                    }
                } else if output.is_fee() {
                    return Some(TxObject::Fee(output.minimum_value()));
                }
            }
        }
    }
}

/// Extract the mainchain commitment from the coinbase tx.
/// It returns the commitment in the first OP_RETURN output with the
/// correct commitment prefix.
pub fn extract_mainchain_commitment<'a>(block: &'a elements::Block) -> Option<bitcoin::BlockHash> {
    let func = |script: &'a [u8], header: &'a [u8]| {
        if script.len() == 1 + 1 + 4 + 32
            && script[0] == bitcoin::blockdata::opcodes::all::OP_RETURN.to_u8()
            && script[1] == bitcoin::blockdata::opcodes::all::OP_PUSHBYTES_36.to_u8()
            && &script[2..6] == header
        {
            Some(&script[6..])
        } else {
            None
        }
    };
    let header = &constants::MAINCHAIN_COMMITMENT_HEADER;
    extract_commitment(block, header, func).map(|sl| bitcoin::BlockHash::from_slice(sl).unwrap())
}

/// A struct used to communicate some statistics about in-flight txs.
#[derive(Default)]
pub struct InFlightStats {
    /// The total number of in-flight transactions.
    pub n_txs: usize,
    /// The number of in-flight transactions that are sweep-only
    /// (i.e. don't handle any pegouts).
    pub n_sweeponly: usize,
    /// The total number of in-flight change.
    pub total_change: u64,
    /// The total value of in-flight fee donations.
    pub total_fee_donations: u64,
}

/// Mega-structure which keeps track of the current state of both
/// blockchains, including which coins we control, which pegouts
/// have been requested (and which have been processed).
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Manager {
    /// Secp256k1 verification context, for deriving tweaked pubkeys
    #[serde(skip)]
    #[serde(default = "Secp256k1::verification_only")]
    secp: Secp256k1<secp256k1::VerifyOnly>,
    /// Tracker of the consensus parameters in the network.
    #[serde(default)]
    consensus: ConsensusTracker,
    /// Transaction index.
    txindex: txindex::TxIndex,
    /// Fee pool
    fee_pool: fee::Pool,
    /// The UTXO table, which will be refactored into multiple objects
    /// over the next commits
    utxos: UtxoTable,
    /// Tracking iterator for the sidechain height
    side_height_iter: HeightIterator,
    /// The latest observed mainchain commitment on the sidechain.
    #[serde(default = "default_mainchain_commitment")]
    latest_mainchain_commitment: (BlockHeight, bitcoin::BlockHash),
    /// Hash of the genesis block of the mainchain
    genesis_hash: bitcoin::BlockHash,
    /// The asset representing mainchain coins on the sidechain
    pegged_asset: elements::confidential::Asset,
    /// Number of tracked outputs we should target
    target_n_outputs: usize,
    /// The mainchain blockhash at the most recently confirmed (i.e.
    /// deeply buried) blockheight
    last_confirmed_hash: Option<bitcoin::BlockHash>,
    /// Accounting data
    account: Account,
    /// The total round time of the watchman protocol.
    round_time: Duration,
    /// Filename of a file where we can writeout the blockchains' state
    cache_file: String,
}

fn default_mainchain_commitment() -> (BlockHeight, bitcoin::BlockHash) {
    (BlockHeight::default(), bitcoin::BlockHash::all_zeros())
}

impl Manager {
    /// Creates a new empty `blockchain::Manager`
    pub fn new(
        fallback_fee_rate: Amount,
        main_skip_height: BlockHeight,
        target_n_outputs: usize,
        our_public_key: PublicKey,
        sidechain_info: rpc::SidechainInfo,
        round_time: Duration,
        cache_file: String,
        n_mainchain_confirmations: BlockHeight,
        dynafed_epoch_length: BlockHeight,
    ) -> Manager {
        Manager {
            secp: Secp256k1::verification_only(),
            consensus: ConsensusTracker::new(dynafed_epoch_length),
            txindex: txindex::TxIndex::new(main_skip_height, n_mainchain_confirmations),
            account: Account::new(),
            fee_pool: fee::Pool::new(fallback_fee_rate),
            utxos: utxotable::UtxoTable::new(our_public_key),
            side_height_iter: HeightIterator::new(
                1,  // start from genesis of sidechain
                constants::SIDECHAIN_CONFIRMS,
            ),
            latest_mainchain_commitment: (Default::default(), bitcoin::BlockHash::all_zeros()),
            genesis_hash: sidechain_info.parent_genesis,
            pegged_asset: elements::confidential::Asset::Explicit(sidechain_info.pegged_asset),
            target_n_outputs: target_n_outputs,
            last_confirmed_hash: None,
            round_time: round_time,
            cache_file: cache_file,
        }
    }

    /// Potentially convert from an old schema if needed.
    pub fn ensure_schema(&mut self) {
        // NB remove this when all peers have adopted the new schema
        self.txindex.ensure_schema();
    }

    /// Get read access to the consensus tracker.
    pub fn consensus(&self) -> &ConsensusTracker {
        &self.consensus
    }

    /// Validate and fix available_funds based on non_user_funds and docked_fees
    pub fn fix_available_funds(&mut self) {
        let mut real_available_funds = self.account.non_user_funds().to_signed().expect("signed overflow");
        real_available_funds -= self.fee_pool.temporarily_docked().to_signed().expect("overflow");
        if self.fee_pool.available_funds() != real_available_funds {
            log!(Error, "Available funds doesn't match: {} vs {}", real_available_funds, self.fee_pool.available_funds());
            self.fee_pool.set(real_available_funds.to_sat());
        }
    }

    /// Shorthand for [Manager::tx_meta].
    #[cfg(test)]
    fn self_tx_meta(&mut self, tx: &bitcoin::Transaction) -> Result<Option<Vec<OutputMeta>>, ProposalError> {
        let self_utxos = &mut self.utxos;
        let self_feepool = &mut self.fee_pool;
        let self_consensus = &self.consensus;
        let self_height = self.latest_mainchain_commitment.0;
        Manager::tx_meta(self_utxos, self_feepool, self_consensus, tx, self_height)
    }

    /// This method returns the relevant tx info for the given
    /// confirmed transaction.
    ///
    /// Since we have to use this in a closure while having a mutable reference
    /// to the tx index, we can't take [self] but take references to the
    /// required members instead.
    ///
    /// The height of the transaction's block is needed to determine which parameters
    /// were active at the time.
    fn tx_meta(
        self_utxos: &mut utxotable::UtxoTable,
        self_feepool: &mut fee::Pool,
        self_consensus: &ConsensusTracker,
        tx: &bitcoin::Transaction,
        block_height: BlockHeight
    ) -> Result<Option<Vec<OutputMeta>>, ProposalError> {
        // Because this method is called for every tx in the chain, the vast
        // majority of calls will be for uninteresting txs.
        // To speed sync up, we first check whether the tx is interesting for
        // us without making any allocations. This means we might do a small
        // amount of duplicate work for interesting txs.

        // It's a federation tx as soon as we recognize an input as ours.
        // Reclaimable UTXOs are never considered as federation inputs
        let federation_tx = tx.input.iter().any(|input| {
            match self_utxos.lookup_utxo(&input.previous_output) {
                Some(Utxo::Spendable(_)) | Some(Utxo::Unspendable(_)) => true,
                _ => false,
            }
        });

        // If there's no federation inputs, it's not a federation tx.
        // Check if there's any fee donations.
        if !federation_tx {
            let mut ret = None;
            for (i, output) in tx.output.iter().enumerate() {
                if let Some(true) = self_consensus.is_activated_spk_at(&output.script_pubkey, block_height) {
                    // Lazily put a vec into ret on the first hit.
                    ret.get_or_insert_with(|| {
                        vec![OutputMeta::Irrelevant; tx.output.len()]
                    })[i] = OutputMeta::Donation;

                    let spk = &output.script_pubkey;
                    if !self_consensus.matches_active_spk(&spk) {
                        slog!(DetectedLegacyDonation,
                                txid: tx.txid(),
                                spk: Cow::Borrowed(&spk),
                                active_change_spk: Cow::Borrowed(self_consensus.active_change_spk()));
                    }
                }
            }

            // Check if this donation is spending a pending failed pegin reclamation. If it is, remove
            // that reclamation from the UtxoTable immediately so it is not included in any further proposals
            // If this transaction is not finalized in the future the reclamation will be re-added to the table
            if ret.is_some() {
                for input in tx.input.iter() {
                    if self_utxos.try_process_reclamation(&input.previous_output, tx.txid()) {
                        slog!(ForgetUtxo, utxo: input.previous_output, txid: tx.txid());
                    }
                }
            }
            return Ok(ret);
        }

        // At this point we know we have a federation tx, so let's make sure
        // we know all the inputs.
        let mut input_value = Amount::ZERO;
        let mut unknown_inputs = Vec::with_capacity(tx.input.len());
        for input in &tx.input {
            if let Some(utxo) = self_utxos.lookup_utxo(&input.previous_output) {
                input_value += utxo.value;
            } else {
                unknown_inputs.push(input.previous_output);
            }
        }
        if !unknown_inputs.is_empty() {
            return Err(ProposalError::UnknownInputs(unknown_inputs));
        }

        // Then finish federation tx metadata.
        let mut ret = Vec::with_capacity(tx.output.len());
        for (i, output) in tx.output.iter().enumerate() {
            // In order to account for duplicate pegout requests and corresponding
            // duplicate outputs, we count the number of times this output has
            // been passed before.
            // NB this is O(n^2) stack reads but only for federation tx with fairly small n
            let nth = tx.output.iter().take(i).filter(|o| *o == output).count();

            // We take the n'th pegout request for this output to fulfill.
            let rqs = self_utxos.pegout_lookup(output).map(|x| &x[..]).unwrap_or(&[]);
            ret.push(if let Some(req) = rqs.iter().nth(nth) {
                OutputMeta::Pegout(*req)
            } else {
                let spk = &output.script_pubkey;
                if self_consensus.lookup_spk(spk).is_ours() {
                    if !self_consensus.matches_active_spk(spk) {
                        // This should only happen immediately following a
                        // transition, if a pegout occurred right before.
                        slog!(DetectedLegacyChange, txid: tx.txid(), spk: Cow::Borrowed(&spk),
                            active_change_spk: Cow::Borrowed(self_consensus.active_change_spk()),
                        );
                    }
                    OutputMeta::Change
                } else if rqs.is_empty() {
                    return Err(ProposalError::UnknownOutput(output.clone()));
                } else {
                    return Err(ProposalError::DuplicatePegoutDelivery {
                        output: output.clone(),
                        requests: rqs.to_vec(),
                    });
                }
            })
        }

        // We currently expect always to have at least one change output.
        // We don't want to assert this because we might want to change this
        // later on and we want to comply when others make no-change txs.
        if !ret.iter().any(|m| *m == OutputMeta::Change) {
            log!(Warn, "found a federation tx without a change output: {}", tx.txid());
        }

        // Check/dock fees
        let output_value = tx.output.iter().map(|o| o.value).sum::<Amount>();
        let fee = input_value - output_value;
        self_feepool.temporarily_dock_tx(tx, fee);

        Ok(Some(ret))
    }

    /// Handle a finalized transaction.
    fn handle_finalized_tx(
        self_utxos: &mut utxotable::UtxoTable,
        self_fee_pool: &mut fee::Pool,
        self_account: &mut Account,
        self_consensus: &ConsensusTracker,
        tx: txindex::Tx,
    ) {
        let txid = tx.tx.txid();
        let height = tx.status.height().expect("tx is confirmed");

        // Handle peg-out related things.
        if tx.is_federation_tx() {
            let fee = {
                // We unwrap errors because these checks already happened
                // when the tx metadata was calculated.
                let input_value = tx.tx.input
                    .iter()
                    .map(|i| self_utxos.lookup_utxo(&i.previous_output).expect("canonical").value)
                    .sum::<Amount>();
                let output_value = tx.tx.output.iter().map(|out| out.value).sum::<Amount>();
                input_value.checked_sub(output_value).expect("canonical")
            };
            self_fee_pool.temporarily_dock_tx(&tx.tx, fee);
            self_fee_pool.confirm(&txid);


            // Each federation tx may have up to constants::MAXIMUM_CHANGE_OUTPUTS outputs, but
            // they will all have the same scriptPubKey, so we only have to check the first change output.
            let change_spk = tx.tx.output
                .iter()
                .find(|o| self_consensus.is_activated_spk_at(&o.script_pubkey, height)
                    .expect("finalizing a tx at a height beyond the last mainchain commitment"))
                .map(|o| &o.script_pubkey);
            self_account.finalize_federation_tx(&tx.tx, change_spk);

            let pegouts = tx.iter_pegouts().collect();
            self_utxos.finalize_federation_tx(txid, tx.iter_federation_inputs(), &pegouts);
        }

        // Track the newly available UTXOs (change and donations).
        for (outpoint, output, meta) in tx.iter_outputs() {
            match meta {
                OutputMeta::Change => {
                    let desc = self_consensus.matches_activated_descriptor(&output.script_pubkey).cloned();
                    self_utxos.finalize_untweaked_output(outpoint, output.value, height, desc);
                }
                OutputMeta::Donation => {
                    let desc = self_consensus.matches_activated_descriptor(&output.script_pubkey).cloned();
                    // Donation to the untweaked address.
                    self_utxos.finalize_untweaked_output(outpoint, output.value, height, desc);
                    let fee_bump = self_account.fee_donation(outpoint, output.value);
                    self_fee_pool.add(fee_bump);

                }
                OutputMeta::Pegout(_) => {},
                OutputMeta::Irrelevant => {},
            }
        }

        // Check to see if this transaction finalizes a reclamation
        if self_utxos.is_pending_reclamation_tx(&txid) {
            let reclamation_utxos = self_utxos.try_finalize_reclamation(&txid);

            // Some sanity checks
            if reclamation_utxos.is_empty() || tx.tx.input.len() != reclamation_utxos.len() {
                log!(Error, "Reclamation tx does not have the expected number of inputs. Expected: {} - Found: {}", reclamation_utxos.len(), tx.tx.input.len());
                return;
            }
            for input in tx.tx.input.iter() {
               if reclamation_utxos.iter().find(|utxo| input.previous_output == utxo.outpoint).is_none() {
                   log!(Error, "Reclamation contains unexpected input: {}", input.previous_output);
                   return;
               }
            }

            for reclaimed_utxo in reclamation_utxos.iter() {
                slog!(FinalizedReclamation, outpoint: reclaimed_utxo.outpoint, txid);
            }

            self_fee_pool.reclaim_conflicting_fees(&tx.tx);
        }
    }

    /// Scan the mainchain looking for fee donations and federation-created
    /// transactions.
    ///
    /// It's important to make sure the [target] Bitcoin block existed before the last entire
    /// sidechain sync was done.
    ///
    /// Returns `Ok(true)` on a complete chain sync, `Ok(false)` if only
    /// some blocks were processed and more remain.
    fn scan_mainchain(&mut self, bitcoind: &impl BitcoinRpc) -> Result<bool, Error> {
        // Update the txindex and get new relevant txs to process.
        let start_time = Instant::now();
        let (done, new_relevant) = {
            let mut last_discrepancy = self.account.discrepancy();

            let utxos = &mut self.utxos;
            let fee_pool = &mut self.fee_pool;
            let account = &mut self.account;
            let consensus = &self.consensus;

            self.txindex.update_from_rpc(bitcoind, self.latest_mainchain_commitment.0,
                |call| match call {
                    txindex::UpdateClosureCall::TxMeta(tx, height) => {
                        let ret = Manager::tx_meta(utxos, fee_pool, consensus, tx, height);
                        txindex::UpdateClosureResult::TxMeta(ret)
                    }
                    txindex::UpdateClosureCall::FinalizedTx(txid, tx) => {
                        Manager::handle_finalized_tx(utxos, fee_pool, account, consensus, tx);

                        let discrepancy = account.discrepancy();
                        if last_discrepancy != discrepancy {
                            slog!(DiscrepancyChanged, txid: txid.to_raw_hash(), old_discrepancy: last_discrepancy.to_sat(),
                                discrepancy: discrepancy.to_sat(), bitcoin_txid: Some(txid), elements_txid: None
                            );
                            last_discrepancy = discrepancy;
                        }
                        txindex::UpdateClosureResult::FinalizedTx
                    }
                }
            )?
        };

        // Detect conflicts for the newly found transactions.
        // It's OK if some transactions go directly into final_relevant without
        // passing this check because they should be fine since they got confirmed.
        for txid in new_relevant {
            let tx = self.txindex.get(txid).expect("txindex returned wrong txid");
            if tx.is_federation_tx() {
                let inputs = tx.iter_federation_inputs().collect();
                let pegouts = tx.iter_pegouts();
                self.utxos.record_conflicts(txid, &inputs, pegouts)?;
            }
        }

        self.log_main_sync_status(self.latest_mainchain_commitment.0, done, start_time.elapsed());
        Ok(done)
    }

    /// Helper function called on every finalized sidechain transaction that we see
    fn process_side_transaction(
        &mut self,
        bitcoind: &impl BitcoinRpc,
        tx: &elements::Transaction,
        side_height: BlockHeight,
    ) -> Result<(), Error> {
        let txid = tx.txid();
        let mut tx_fee = 0;
        let mut pegouts = vec![];

        for object in TxIterator::new(&tx, txid, self.genesis_hash, self.pegged_asset) {
            match object {
                TxObject::Pegin(data) => {
                    match mainchain_block_height(data.referenced_block, bitcoind) {
                        Ok(main_height) => {
                            self.account.pegin(data.outpoint, txid, Amount::from_sat(data.value));
                            let tx = bitcoin::consensus::deserialize::<bitcoin::Transaction>(
                                data.tx
                            ).expect("invalid pegin data: invalid mainchain tx");
                            let mainchain_utxo = tx.output.get(data.outpoint.vout as usize)
                                .expect("invalid pegin data: invalid outpoint");
                            let desc = self.consensus.find_pegin_descriptor(
                                &self.secp,
                                &mainchain_utxo.script_pubkey,
                                data.claim_script,
                                side_height,
                            );
                            self.utxos.finalize_pegin(data, main_height, desc, false);
                        },
                        Err(e) => {
                            // If we can't look up a block, just panic and force the user
                            // to restart the program; we don't have a facility to reconsider
                            // blocks, so if we attempt to continue, we will simply have a
                            // missing pegin that other functionaries may see, causing
                            // permanent mysterious non-local errors.
                            slog_fatal!(NoSuchBlock, claim_txid: txid,
                                bitcoin_outpoint: data.outpoint, blockhash: data.referenced_block,
                                error: e.to_string()
                            );
                        }
                    }
                },
                TxObject::Pegout(side_outpoint, data) => {
                    // Treat pegouts to the change address as donations, since
                    // it would be ambiguous what was happening if they were
                    // to be processed as pegouts (fixes #220)
                    if self.consensus.lookup_spk(&data.script_pubkey).is_ours() {
                        slog!(PegoutToFederation, outpoint: side_outpoint, value: data.value);
                        self.account.fee_burn(side_outpoint, Amount::from_sat(data.value));
                        self.fee_pool.add(Amount::from_sat(data.value));
                    } else {
                        pegouts.push((side_outpoint, data));
                    }
                },
                TxObject::Donation(side_outpoint, value) => {
                    if value > 0 {
                        self.account.fee_burn(side_outpoint, Amount::from_sat(value));
                        self.fee_pool.add(Amount::from_sat(value));
                    }
                },
                TxObject::Fee(fee) => {
                    tx_fee += fee;
                },
            }
        }

        if !pegouts.is_empty() {
            let fee_per_pegout = tx_fee / pegouts.len() as u64;

            for (outpoint, data) in pegouts {
                self.account.pegout(
                    outpoint,
                    bitcoin::TxOut {
                        script_pubkey: data.script_pubkey.clone(),
                        value: Amount::from_sat(data.value),
                    },
                );

                self.utxos.finalize_pegout_request(outpoint, data, side_height, fee_per_pegout);
            }
        }
        Ok(())
    }

    /// Scan the sidechain looking for all locking and unlocking outputs.
    fn scan_sidechain(
        &mut self,
        bitcoind: &impl BitcoinRpc,
        sidechaind: &impl ElementsRpc,
    ) -> Result<(), Error> {
        if self.consensus.active_params().is_none() && self.side_height_iter.last_finalized_height().is_some() {
            // This is the case where we restarted a watchman that didn't have a consensus tracker.
            // We're going to have to sync all params in the past into the tracker.
            // This block can be removed once all watchmen have ran this piece of code once.
            let _ = rollouts::CONSENSUS_TRACKER;

            log!(Info, "Initiating ConsensusTracker syncup for first startup...");

            // Since the tracker wants params in correct order, we're going to first collect them
            // manually in reverse order.
            let mut params = Vec::new();
            let epoch_length = self.consensus.epoch_length();
            let mut height = self.side_height_iter.last_finalized_height().unwrap();
            height = height.saturating_sub(height % epoch_length);
            while height > 0 {
                let blockhash = sidechaind.block_at(height)?;
                let block = sidechaind.raw_block(blockhash)?;
                let commit = if let Some(commit) = extract_mainchain_commitment(&block) {
                    bitcoind.block_height(commit)?
                } else {
                    log!(Warn, "dynafed block {} does not have mainchain commitment", height);
                    None
                };

                if let elements::BlockExtData::Dynafed { current, .. } = block.header.ext {
                    assert!(current.is_full());
                    if let Some((last_height, _, last)) = params.last_mut() {
                        if *last == current {
                            // As long as params are the same, update the start height.
                            *last_height = height;
                        } else {
                            params.push((height, commit, current));
                        }
                    } else {
                        params.push((height, commit, current));
                    }
                } else {
                    break;
                }
                height = height.saturating_sub(epoch_length); // shouldn't underflow, but well
            }

            // Then add params in chronological order.
            for (height, commit, params) in params.into_iter().rev() {
                self.consensus.register_sidechain_block(height, commit, Some(&params));
            }
        }

        let start_time = Instant::now();
        self.side_height_iter.rpc_update_max_height(sidechaind)?;
        let mut count = 0; // Use this to save regularly during initial sync.
        loop {
            // Loop through all blocks until the tip reported by the node.
            // nb awkward for-loop is so that we can call `self.save_to_disk()` while iterating
            while let Some(height) = self.side_height_iter.next() {
                let blockhash = sidechaind.block_at(height)?;
                let block = sidechaind.raw_block(blockhash)?;

                let comm_height = if let Some(commit) = extract_mainchain_commitment(&block) {
                    let comm_height = bitcoind.block_height(commit)?;
                    slog!(MainchainCommitmentFound,
                        sidechain_hash: blockhash, sidechain_height: height,
                        mainchain_hash: commit, mainchain_height: comm_height,
                    );
                    if let Some(comm_height) = comm_height {
                        // Only update if strict progress, but log in strange cases.
                        let latest = self.latest_mainchain_commitment.0;
                        match comm_height.cmp(&latest) {
                            cmp::Ordering::Greater => {
                                slog!(MainchainCommitmentUpdated,
                                    mainchain_hash: commit, mainchain_height: comm_height,
                                    last_height: self.latest_mainchain_commitment.0,
                                );
                                self.latest_mainchain_commitment = (comm_height, commit);
                            },
                            cmp::Ordering::Equal => {
                                if commit != self.latest_mainchain_commitment.1 {
                                    slog!(MainchainCommitmentForked,
                                        sidechain_hash: blockhash, sidechain_height: height,
                                        last_mainchain_height: self.latest_mainchain_commitment.0,
                                        last_mainchain_hash: self.latest_mainchain_commitment.1,
                                        new_mainchain_hash: commit, new_mainchain_height: comm_height,
                                    );
                                }
                                // If it's just exactly the same, no reason to do anything.
                            },
                            cmp::Ordering::Less => {
                                slog!(MainchainCommitmentBackwards,
                                    sidechain_hash: blockhash, sidechain_height: height,
                                    last_mainchain_height: self.latest_mainchain_commitment.0,
                                    last_mainchain_hash: self.latest_mainchain_commitment.1,
                                    new_mainchain_hash: commit, new_mainchain_height: comm_height,
                                );
                            },
                        }
                    } else {
                        slog!(MainchainCommitmentUnknown, mainchain_hash: commit,
                            sidechain_hash: blockhash, sidechain_height: height,
                        );
                    };
                    comm_height
                } else {
                    None
                };

                if let elements::BlockExtData::Dynafed { ref current, .. } = block.header.ext {
                    if current.is_full() {
                        // Must be start of an epoch.
                        if comm_height.is_none() {
                            log!(Error, "dynafed block without mainchain commitment");
                        }
                        self.consensus.register_sidechain_block(height, comm_height, Some(current));
                    } else {
                        self.consensus.register_sidechain_block(height, comm_height, None);
                    }
                    assert_eq!(
                        current.calculate_root(), self.consensus.active_params().unwrap().root,
                        "the block must always have the active current root",
                    );
                }

                let mut last_discrepancy = self.account.discrepancy();
                // Loop through all transactions, but processing the coinbase last!
                // We need to do this because the coinbase might burn funds that are only
                // pegged in in a later transaction.
                // Remember that not every block necessarily has a coinbase tx.
                let is_coinbase = |(idx, tx): &(usize, &elements::Transaction)| {
                    *idx == 0 && tx.is_coinbase()
                };
                let skip_coinbase = block.txdata.iter().enumerate().skip_while(is_coinbase);
                let only_coinbase = block.txdata.iter().enumerate().take_while(is_coinbase);
                for (_, tx) in skip_coinbase.chain(only_coinbase) {
                    self.process_side_transaction(bitcoind, tx, height)?;

                    let discrepancy = self.account.discrepancy();
                    let txid = tx.txid();
                    if last_discrepancy != discrepancy {
                        slog!(DiscrepancyChanged, txid: txid.to_raw_hash(), old_discrepancy: last_discrepancy.to_sat(),
                            discrepancy: discrepancy.to_sat(), elements_txid: Some(txid), bitcoin_txid: None
                        );
                        last_discrepancy = discrepancy;
                    }
                }

                // Output status
                count += 1;
                if count % 5000 == 0 {
                    count = 0;
                    self.log_side_sync_status(false, start_time.elapsed());
                    self.account.log_status();
                    self.save_to_disk();
                }
            }

            // Check if the tip progressed since we started.
            let last_height = self.side_height_iter.max_height();
            self.side_height_iter.rpc_update_max_height(sidechaind)?;
            if last_height == self.side_height_iter.max_height() {
                break;
            }
        }

        self.log_side_sync_status(true, start_time.elapsed());
        Ok(())
    }

    /// If there are any failed pegins to sweep check that they are valid in the mainchain and if so
    /// add them to UtxoTable to be swept
    pub fn check_for_failed_pegins(
        &mut self,
        config: &mut Configuration,
        n_mainchain_confirmations: BlockHeight,
        available_signers: &HashSet<PeerId>,
        sidechain_height: BlockHeight,
        bitcoind: &rpc::Bitcoin,
    ) {
        if let Some(failed_pegins) = config.consensus.failed_pegins.as_mut() {
            let mut failed_pegins_to_remove = Vec::new();

            for failed_pegin_tx in failed_pegins.iter() {
                let outpoint = OutPoint::new(failed_pegin_tx.mainchain_tx.txid(), failed_pegin_tx.vout);

                if let Some(reclamation_txid) = self.utxos.in_progress_reclamation_txid(&outpoint) {
                    if bitcoind.mempool_entry(reclamation_txid).is_ok() {
                        slog!(FailedPeginReclamationInMempool, outpoint);
                        continue;
                    }
                }

                match bitcoind.txout(failed_pegin_tx.mainchain_tx.txid(), failed_pegin_tx.vout, false) {
                    Ok(txout) => {
                        if txout.confirmations < n_mainchain_confirmations as u32 {
                            slog!(FailedPeginNotMature, outpoint);
                            continue;
                        } else {
                            log!(Debug, "Failed Pegin UTXO ({}) found in mainchain", outpoint);
                        }
                    }
                    Err(e) => {
                        slog!(FailedPeginNotInUtxoSet, outpoint, error: e.to_string());
                        failed_pegins_to_remove.push(failed_pegin_tx.clone());
                        continue;
                    }
                };

                let block_height = match mainchain_block_height(failed_pegin_tx.mainchain_blockhash, bitcoind) {
                    Ok(h) => h,
                    Err(e) => {
                        log!(Debug, "Failed to query block_height on mainchain: {}", e);
                        continue;
                    }
                };

                let output = match failed_pegin_tx.mainchain_tx.output.get(failed_pegin_tx.vout as usize) {
                    Some(o) => o.clone(),
                    None => {
                        log!(Error,"Failed pegin output index in Failed Pegin (txid: {}) does not exist", failed_pegin_tx.mainchain_tx.txid());
                        continue;
                    }
                };

                if let Some(_descriptor) = self.consensus().find_pegin_descriptor(
                    &self.secp,
                    &output.script_pubkey,
                    failed_pegin_tx.claim_script.as_bytes(),
                    sidechain_height,
                )   {
                    slog!(FailedPeginCanBeClaimed, outpoint);
                    continue;
                }

                let descriptor = self.consensus().find_historial_pegin_descriptor(
                    &self.secp,
                    &output.script_pubkey,
                    failed_pegin_tx.claim_script.as_bytes()
                );

                let descriptor = match descriptor {
                    None => {
                        log!(Error, "Cannot find federation descriptor matching Failed Pegin {}", outpoint);
                        continue;
                    }
                    Some(descriptor) => {
                        if !descriptor.can_sign(available_signers) {
                            slog!(CantSignFailedPeginReclamation, outpoint, available_signers);
                            continue;
                        }
                        descriptor
                    }
                };

                let mut tx_bytes = Vec::new();
                failed_pegin_tx.mainchain_tx.consensus_encode(&mut tx_bytes)
                    .expect("Encode bitcoin tx as bytes");

                match self.utxos.lookup_utxo(&outpoint) {
                    None => {
                        slog!(AddedFailedPegin, outpoint, value: output.value.to_sat());
                        let pegin_data = PeginData {
                            outpoint: outpoint,
                            value: output.value.to_sat(),
                            asset: Default::default(),
                            genesis_hash: bitcoin::BlockHash::all_zeros(),
                            claim_script: failed_pegin_tx.claim_script.as_bytes(),
                            tx: tx_bytes.as_slice(),
                            merkle_proof: &[],
                            referenced_block: bitcoin::BlockHash::all_zeros(),
                        };

                        self.utxos.finalize_pegin(pegin_data, block_height, Some(descriptor), true);
                    }
                    Some(_) => {
                        log!(Debug, "Failed pegin outpoint {} with value {} already in table", outpoint, output.value);
                    }
                }
            }

            // Remove any failed pegins that cannot be found in mainchain UTXO set from in-memory config so they are
            // not checked again
            for pegin_to_remove in failed_pegins_to_remove.iter() {
                if let Some(pos_to_remove) =
                        failed_pegins.iter().position(|fp| fp == pegin_to_remove)
                {
                    failed_pegins.remove(pos_to_remove);
                }
            }
        }
    }


    /// Queries the mainchain and sidechain RPC clients to determine the
    /// current state of the blockchains; updates internal state based
    /// on this information.
    ///
    /// It also ensures the updated state is saved to disk.
    pub fn update_from_rpc(
        &mut self,
        bitcoind: &impl BitcoinRpc,
        sidechaind: &impl ElementsRpc,
    ) -> Result<(), Error> {
        loop {
            self.scan_sidechain(bitcoind, sidechaind)?;

            if self.latest_mainchain_commitment.0 == 0 {
                log!(Debug, "sidechain still syncing, waiting 10s for mainchain commitment...");
                thread::sleep(Duration::from_secs(10));
                continue;
            }

            if self.scan_mainchain(bitcoind)? {
                break; // We save at the end of this method.
            }
            self.save_to_disk();
        }

        if let Err(e) = self.fee_pool.update_rate_rpc(bitcoind) {
            slog!(FeeEstimateFailed, error: e.to_string());
        }
        self.save_to_disk();
        Ok(())
    }

    /// Import all data from disk
    pub fn load_from_disk(&mut self) -> Result<(), Error> {
        // (Attempt to) read cached blockchain data to speedup startup
        match fs::File::open(&self.cache_file) {
            Ok(mut fh) => {
                let mut bytes = Vec::new();
                fh.read_to_end(&mut bytes)?;
                let raw = String::from_utf8(bytes).expect("state file not valid UTF8");
                // nb: https://gl.blockstream.io/liquid/functionary/-/issues/957
                let patched = raw.replace("thresh_m(", "multi(");
                let mut new_manager: Manager = match serde_json::from_str(&patched) {
                    Ok(m) => m,
                    Err(err) => {
                        let now = time::now();
                        let backup = format!("{}-corrupt-{}", self.cache_file, now.rfc3339());
                        if let Err(e) = fs::rename(&self.cache_file, &backup) {
                            log!(Error, "error creating backup of state file at {}: {}", backup, e);
                        }
                        slog!(CorruptCacheFile, cache_path: &self.cache_file, error: err.to_string(),
                            backup_path: &backup,
                        );
                        return Err(err.into());
                    }
                };
                if new_manager.txindex.skip_height() != self.txindex.skip_height() {
                    slog!(MainConfsChanged, cache_path: &self.cache_file,
                        old_requirement: new_manager.txindex.skip_height(),
                        new_requirement: self.txindex.skip_height()
                    );
                } else if new_manager.side_height_iter.confirm_count() !=
                    self.side_height_iter.confirm_count()
                {
                    slog!(SideConfsChanged, cache_path: &self.cache_file,
                        old_requirement: new_manager.side_height_iter.confirm_count(),
                        new_requirement: self.side_height_iter.confirm_count()
                    );
                } else {
                    // all good
                    new_manager.ensure_schema();
                    *self = new_manager;
                }
                Ok(())
            }
            Err(e) => {
                slog!(NoCacheFile, cache_path: &self.cache_file, error: e.to_string());
                Err(e.into())
            }
        }
    }

    /// Export all data to disk
    pub fn save_to_disk(&self) {
        let start_time = Instant::now();
        utils::export_to_file(
            &self.cache_file,
            |fh| serde_json::to_writer(fh, self).map_err(Error::Json),
        );
        slog!(SaveCacheFile, cache_path: &self.cache_file, duration: start_time.elapsed());
    }

    /// Read doc of [ConsensusTracker::set_epoch_length].
    pub fn set_epoch_length(&mut self, epoch_length: BlockHeight) {
        // remove this method when all nodes have a consensus tracker
        let _ = common::rollouts::CONSENSUS_TRACKER;
        self.consensus.set_epoch_length(epoch_length);
    }

    /// Update the configured descriptors.
    pub fn update_known_descriptors(
        &mut self,
        new_descriptors: impl IntoIterator<Item = (BlockHeight, descriptor::Cached)>,
    ) {
        self.consensus.update_known_descriptors(new_descriptors);
    }

    /// Get the dynafed epoch length.
    pub fn dynafed_epoch_length(&self) -> BlockHeight {
        self.consensus.epoch_length()
    }

    /// Accessor for the current height of the main chain
    pub fn main_height(&self) -> BlockHeight {
        self.txindex.max_height()
    }

    /// Accessor for the current height of the side chain
    pub fn side_height(&self) -> BlockHeight {
        self.side_height_iter.max_height().unwrap_or(0)
    }

    /// Accessor for the current deeply-buried height of the mainchain
    pub fn finalized_main_height(&self) -> BlockHeight {
        self.txindex.finalized_height()
    }

    /// Accessor for the current deeply-buried height of the sidechain
    pub fn finalized_side_height(&self) -> Option<BlockHeight> {
        self.side_height_iter.last_finalized_height()
    }

    /// Determine whether we have synced the mainchain to within `time_window` of the current time.
    pub fn is_main_synced(&self, bitcoind: &impl BitcoinRpc, time_window: Duration) -> Result<bool, jsonrpc::Error> {
        let last_block_hash = bitcoind.block_at(self.main_height())?;
        let last_block_header = bitcoind.raw_header(last_block_hash)?;
        let cur_time = SystemTime::now();
        let last_block_time = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(last_block_header.time as u64)).unwrap();

        let elapsed = cur_time.duration_since(last_block_time); // error if last_block_time > cur_time
        Ok(elapsed.is_err() || elapsed.unwrap() <= time_window)
    }

    /// Get the UTXOs that are not entirely owned by the current federation.
    pub fn non_federation_owned_utxos<'a>(
        &'a self,
        current_federation: &'a HashSet<peer::Id>,
    ) -> impl Iterator<Item = &'a SpendableUtxo> + 'a {
        self.utxos.non_federation_owned_utxos(current_federation)
    }

    /// The pubkey that is used to compute the secret key tweaks that we send to the HSM.
    pub fn tweak_pubkey(&self) -> PublicKey {
        self.utxos.tweak_pubkey()
    }

    /// Discard utxos that are no longer spendable (old dynafed params) from the transaction index
    /// and return the total number discarded.
    pub fn prune_unspendable_utxos(&mut self, peers: &HashSet<peer::Id>) -> usize {
        self.utxos.prune_unspendable_utxos(peers)
    }

    /// Construct a transaction, if there are pending pegouts and/or some
    /// inputs are near expiry and need to be spent.
    pub fn propose_transaction(
        &self,
        ongoing_pegouts: &HashSet<elements::OutPoint>,
        ongoing_inputs: &HashSet<bitcoin::OutPoint>,
        n_outputs_with_pending: usize,
        validate_pak_proof: &impl Fn(&utxotable::PegoutRequest) -> Result<(), hsm::Error>,
        available_signers: &HashSet<peer::Id>,
        explicit_utxos_to_sweep: &Vec<bitcoin::OutPoint>,
    ) -> Result<transaction::ConcreteProposal, Error> {
        let proposal = self.utxos.tx_proposal(
            &self.consensus,
            &self.fee_pool,
            ongoing_inputs,
            ongoing_pegouts,
            self.main_height(),
            self.side_height(),
            self.target_n_outputs,
            n_outputs_with_pending,
            validate_pak_proof,
            available_signers,
            explicit_utxos_to_sweep
        )?;
        let concrete = proposal.to_concrete();
        slog!(CompleteProposal, inputs: &concrete.inputs, pegouts: &concrete.pegouts,
            change: concrete.change.iter().map(|c| c.to_sat()).collect::<Vec<_>>().as_slice(), fee: (proposal.input_value() - proposal.output_value()).to_sat()
        );
        Ok(concrete)
    }

    #[cfg(test)]
    fn check_proposal(&mut self, proposal: &transaction::ConcreteProposal)
        -> Result<(bitcoin::Transaction, Vec<utxotable::SpendableUtxo>), Error>
    {
        let utxos = &self.utxos;
        let (tx, inputs) = proposal.to_unsigned_tx(
             |outpoint| utxos.lookup_utxo(outpoint),
             |outpoint| utxos.lookup_pegout(outpoint),
             self.consensus.active_change_spk(),
             transaction::FeeCheck::Validate(&self.fee_pool),
        )?;
        let mut without_scriptsigs = tx.clone();
        without_scriptsigs.input.iter_mut().for_each(|i| i.script_sig = bitcoin::ScriptBuf::new());
        let input_map = inputs.iter().map(|i| (i.outpoint, i)).collect::<HashMap<_, _>>();
        let weight = transaction::ConcreteProposal::signed_weight(&without_scriptsigs, &input_map);
        assert!(weight <= constants::MAX_PROPOSAL_TX_WEIGHT);

        self.self_tx_meta(&tx).expect("proposal is not recognized as our own");
        Ok((tx, inputs))
    }

    /// Validates the proposal for
    /// - conflicts
    /// - invalid PAK proofs
    /// - fee availability
    /// - failed pegin reclamations
    pub fn validate_proposal(&self,
        proposal: &transaction::ConcreteProposal,
        mut pak_validate: impl FnMut(&utxotable::PegoutRequest) -> Result<(), hsm::Error>,
        use_csv_tweaked_change: bool,
    ) -> Result<(bitcoin::Transaction, Vec<SpendableUtxo>), Error> {
        let change_spk = if self.consensus.wm_transition_made() {
            &self.consensus.active_descriptor().spk
        } else {
            let support_tweak = ROLLOUTS.hsm_csv_tweak != rollouts::HsmCsvTweak::DynafedTransitionMade;
            // active here will be the legacy one
            if support_tweak && use_csv_tweaked_change {
                self.consensus.active_descriptor().csv_tweaked_spk.as_ref().unwrap()
            } else {
                &self.consensus.active_descriptor().spk
            }
        };

        slog!(ValidateProposal, inputs: &proposal.inputs, pegouts: &proposal.pegouts,
            change: &proposal.change.iter().map(|c| c.to_sat()).collect::<Vec<_>>().as_slice(), change_spk: change_spk,
            change_address: bitcoin::Address::from_script(
                change_spk, bitcoin::Network::Bitcoin,
            ).expect("invalid change spk"),
        );

        // Before doing anything, check if this conflicts with any of our pending
        // transactions. If so, don't sign it, because it might not propagate (it
        // might even conflict with stuff that's in the blockchain!, as we wait
        // for many confirmations before acknowledging contents of the blockchain.)
        // Signing it would force us to add entries to our conflict tracker which
        // would in turn force us to make our *own* transactions conflict with
        // the our pending transactions, effectively importing our peers' confusion.
        // But we know what's right. Just say no.

        let in_flight_inputs = self.in_flight_inputs();
        for input in &proposal.inputs {
            if in_flight_inputs.contains(input) {
                return Err(Error::BadProposal(ProposalError::ConflictsWithPendingTx(*input)));
            }
        }


        let (unsigned_tx, inputs) = {
            let utxos = &self.utxos; // borrow outside of closures on next line
            proposal.to_unsigned_tx(
                |outpoint| utxos.lookup_utxo(outpoint),
                |outpoint| utxos.lookup_pegout(outpoint),
                change_spk,
                transaction::FeeCheck::Validate(&self.fee_pool),
            )?
        };

        for pegout in &proposal.pegouts {
            (&mut pak_validate)(self.utxos.lookup_pegout(pegout).unwrap())?;
        }

        Ok((unsigned_tx, inputs))
    }

    /// Records a transaction in the conflict enforcer and allocates funds
    /// for paying the fees.
    pub fn prepare_to_sign(
        &mut self,
        proposal: &transaction::ConcreteProposal,
        unsigned_tx: &bitcoin::Transaction,
        inputs: &[SpendableUtxo],
    ) -> Result<(), Error> {
        self.utxos.record_conflicts(
            unsigned_tx.txid(), &proposal.input_set(), proposal.pegouts.iter().copied(),
        )?;

        let fee = unsigned_tx.calculate_fee(inputs);
        self.fee_pool.temporarily_dock_tx(&unsigned_tx, fee);

        Ok(())
    }

    /// Get an iterator over all in-flight transactions.
    pub fn in_flight_txs(&self) -> impl Iterator<Item=(&bitcoin::Txid, &txindex::Tx)> {
        self.txindex.in_flight_txs()
    }

    /// Return the number of in-flight transactions.
    pub fn n_in_flight_txs(&self) -> usize {
        self.txindex.n_in_flight_txs()
    }

    /// Return the number of in-flight change outputs.
    pub fn n_in_flight_change_outputs(&self) -> usize {
        self.in_flight_txs().map(|(_, tx)| tx.iter_change().count()).sum()
    }

    /// Returns all the inputs used in in-flight transactions.
    pub fn in_flight_inputs(&self) -> HashSet<bitcoin::OutPoint> {
        self.in_flight_txs().map(|(_, tx)| tx.iter_federation_inputs()).flatten().collect()
    }

    /// Total change of the in-flight pegout transactions.
    pub fn total_in_flight_change(&self) -> Amount {
        self.in_flight_txs().map(|(_, tx)| tx.iter_change()).flatten().map(|o| o.value).sum()
    }

    /// Test if a transaction is known by the blockchain manager
    /// with the given txid.
    pub fn is_tx_known(&self, txid: bitcoin::Txid) -> bool {
        self.txindex.get(txid).is_some()
    }

    /// Return percentiles of the watchmen's outputs without the outputs
    /// spent in pending transactions and uneconomical outputs.
    pub fn available_output_percentiles(&self) -> Option<[u64; 5]> {
        let signed_input_weight = self.consensus.active_descriptor().signed_input_weight();
        self.utxos.main_output_percentiles(
            &self.in_flight_inputs(),
            self.fee_pool.economical_amount(signed_input_weight),
        )
    }

    /// Return the total input value of pending transactions
    /// and the total change value of pending transactions.
    pub fn pending_funds(&self) -> (Amount, Amount) {
        let mut total_inputs = Amount::ZERO;
        // Iterate over in-flight inputs and add their values.
        for outpoint in self.in_flight_inputs().iter() {
            if let Some(utxo) = self.lookup_utxo(outpoint) {
                total_inputs += utxo.value;
            } else {
                log!(Fatal, "There is a pending transaction for which we don't know input {}.", outpoint);
            }
        }
        let total_change = self.total_in_flight_change();
        return (total_inputs, total_change);
    }

    /// Counts the number of outputs controlled by the watchman distinguishing between available,
    /// economical and projected number of outputs. Assumes that pending transactions do not
    /// conflict.
    pub fn output_counter(&self) -> OutputCounter {
        let main_utxos = self.main_utxos();
        let signed_input_weight = self.consensus.active_descriptor().signed_input_weight();
        let min_input_amount =  self.fee_pool.economical_amount(signed_input_weight);
        log!(Debug, "Minimum economical input amount: {:?}", min_input_amount);
        let n_current_uneconomical = main_utxos
            .iter()
            .filter(|&(_, ref out)| out.value <= min_input_amount)
            .count();
        let n_current = main_utxos.len() - n_current_uneconomical;
        let pending_inputs = self.in_flight_inputs();
        let n_pending_inputs = pending_inputs.len();
        let n_pending_outputs = self.n_in_flight_change_outputs();
        let available_utxos = main_utxos
            .iter()
            .filter(|&(u,_)| !pending_inputs.contains(u));
        let n_available_with_uneconomical = available_utxos.clone().count();
        let n_available_utxos = available_utxos
            .filter(|&(_, ref out)| out.value > min_input_amount)
            .count();
        OutputCounter {
            current: n_current,
            current_uneconomical: n_current_uneconomical,
            available: n_available_utxos,
            available_uneconomical: n_available_with_uneconomical,
            pending_inputs: n_pending_inputs,
            pending_outputs: n_pending_outputs,
        }
    }

    /// Logs a comprehensive summary of the watchman wallet.
    ///
    /// In order to avoid duplicate calculation of some collections, it also returns:
    /// - the set of all pegouts present in pending txs
    /// - the set of all utxos present as inputs in pending txs
    /// - the `OutputCounter` used in the WatchmanStatus message
    pub fn log_wallet_summary(&self,
        current_consensus: &HashSet<peer::Id>,
    ) -> (
        HashSet<elements::OutPoint>,
        HashSet<bitcoin::OutPoint>,
        OutputCounter,
    ) {
        let mut n_pending_txs = 0;
        let mut n_pending_txs_sweeponly = 0;
        let mut pending_change_value = Amount::ZERO;
        let mut pending_donation_value = Amount::ZERO;
        let mut pending_input_value = Amount::ZERO;
        let mut ongoing_pegouts = HashSet::new();
        let mut ongoing_inputs = HashSet::new();
        for (_, tx) in self.in_flight_txs() {
            n_pending_txs += 1;
            if tx.iter_pegouts().next().is_none() {
                n_pending_txs_sweeponly += 1;
            }

            pending_change_value += tx.iter_change().map(|o| o.value).sum::<Amount>();
            pending_donation_value += tx.iter_donations().map(|o| o.value).sum::<Amount>();
            ongoing_pegouts.extend(tx.iter_pegouts());

            if tx.is_federation_tx() {
                for input in tx.iter_federation_inputs() {
                    ongoing_inputs.insert(input);

                    if let Some(utxo) = self.lookup_utxo(&input) {
                        pending_input_value += utxo.value;
                    } else {
                        log!(Fatal, "There is a pending tx with unknown input: {}.", input);
                    }
                }
            }
        }

        let output_counter = self.output_counter();

        slog!(WalletSummary,
            n_pending_txs: n_pending_txs,
            n_pending_sweeponly_txs: n_pending_txs_sweeponly,
            n_pending_pegout_delivery_txs: n_pending_txs - n_pending_txs_sweeponly,
            current_signers: Cow::Borrowed(&self.all_signers()),
            n_non_federation_owned_utxos: self.non_federation_owned_utxos(current_consensus).count(),
            n_pending_pegouts: ongoing_pegouts.len(),
            n_pending_spent_utxos: ongoing_inputs.len(),
            n_unprocessed_pegouts: self.n_unprocessed_pegouts(&ongoing_pegouts),
            n_outputs_economical: output_counter.current(),
            n_outputs_uneconomical: output_counter.current_uneconomical(),
            n_outputs_available_economical: output_counter.available(),
            n_outputs_available_uneconomical: output_counter.available_uneconomical(),
            n_outputs_pending: output_counter.pending_outputs(),
            n_inputs_pending: output_counter.pending_inputs(),
            n_output_projected: output_counter.projection(),
            available_output_percentiles: self.available_output_percentiles().unwrap_or_default(),
            pending_input_value: pending_input_value.to_sat(),
            pending_output_value: (pending_change_value + pending_donation_value).to_sat(),
            pending_change_value: pending_change_value.to_sat(),
            pending_donation_value: pending_donation_value.to_sat(),
        );

        return (ongoing_pegouts, ongoing_inputs, output_counter);
    }

    // The following is a giant list of ad-hoc accessors which will need to be refactored away

    /// Accessor for the locked outputs on the mainchain
    pub fn main_utxos(&self) -> &HashMap<bitcoin::OutPoint, utxotable::Utxo> {
        self.utxos.main_utxos()
    }

    /// Create a summary of the fee pool
    pub fn fee_pool_summary(&self) -> fee::PoolSummary {
        self.fee_pool.summary()
    }

    /// Obtains a reference to UTXO data given an outpoint
    pub fn lookup_utxo(&self, outpoint: &bitcoin::OutPoint) -> Option<&Utxo> {
        self.utxos.lookup_utxo(outpoint)
    }

    /// Obtains a reference to pegout request data given an outpoint
    pub fn lookup_pegout(&self, outpoint: &elements::OutPoint) -> Option<&PegoutRequest> {
        self.utxos.lookup_pegout(outpoint)
    }

    /// Checks whether all the inputs of a transaction are untracked,
    /// i.e. a spending transaction has been confirmed on the mainchain.
    /// This is used to determine when a tx is successful, to avoid
    /// logging spurious "inputs missing" RPC errors.
    pub fn any_main_outs_spent(&self, outs: impl Iterator<Item=bitcoin::OutPoint>) -> bool {
        self.utxos.any_main_outs_spent(outs)
    }

    /// Counts the number of pegouts found in the sidechain for which there doesn't exist a
    /// complete watchman transaction that processes them (yet).
    pub fn n_unprocessed_pegouts(&self, ongoing_pegouts: &HashSet<elements::OutPoint>) -> usize {
        self.utxos.n_unprocessed_pegouts(ongoing_pegouts)
    }

    /// Get all the signers of all the existing UTXOs.
    pub fn all_signers(&self) -> HashSet<peer::Id> {
        self.utxos.all_signers()
    }

    // Logging
    fn log_main_sync_status(&self, target: BlockHeight, sync_complete: bool, duration: Duration) {
        slog!(WatchmanSyncStatus, blockchain: "bitcoin", max_height: target,
            current_height: self.txindex.max_height(), sync_complete, duration,
        );
    }

    fn log_side_sync_status(&self, sync_complete: bool, duration: Duration) {
        slog!(WatchmanSyncStatus, blockchain: "sidechain",
            current_height: self.side_height_iter.last_finalized_height().unwrap_or(0),
            max_height: self.side_height_iter.max_height().unwrap_or(0), sync_complete, duration,
        );
    }

    /// Log statuses of blockchain subcomponents.
    pub fn log_statuses(&self) {
        self.account.log_status();
        self.fee_pool.log_status();
    }
}

#[cfg(test)]
pub mod tests {
    use std::{panic, time};
    use std::str::FromStr;

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::sha256d;
    use bitcoin::{CompactTarget, ScriptBuf, SignedAmount};
    use elements::AssetId;
    use elements::dynafed::FullParams;
    use elements::encode::deserialize;
    use miniscript::Descriptor;

    use super::*;

    use common::constants::Constants;
    use tweak;
    use utils::{BlockRef, empty_elements_block};
    use rpc::Rpc;

    /// Bitcoin genesis hash
    pub const BITCOIN_GENESIS_STR: &'static str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    /// Asset ID for Liquid-BTC;
    /// can be found by running `elements-cli -chain=liquidv1 getsidechaininfo`
    pub const LBTC_ASSET: &'static str = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

    pub fn test_descriptor_1() -> miniscript::Descriptor<tweak::Key> {
        format!("sh(wsh(or_d(\
            multi(\
                2,\
                [410000000001]02cad6834ae4f150eb8196ff3aba2503a41cba8db987ec6831ddb90929c65833b9,\
                [410000000010]02cd0a5378855888ff62dcafc6d7422124bf0f51b4c9cc21302a403407e27ba04d,\
                [410000000100]0398c4371ab8b0d7112eef4f9b64d5696f454f9f3fa8773d7cc7da477be2190c5e\
            ),\
            and_v(\
                v:older({}),\
                multi(\
                    1,\
                    [untweaked]023303dedc51b9d227b17c9fb4710f96b844e1ccdc2c776e1b7274bd4e246b6202,\
                    [untweaked]03024c3b4f830854d6d26d6e34d92aff4c703bf57e85cd42abe328d928e01d4286,\
                    [untweaked]03fe4e8c8d99b9dcbb529a87d54f606bae0149a34018325547fa0c2239e038a1c9))\
                )\
            )\
        )", dummy_csv()).parse().unwrap()
    }

    pub fn test_descriptor_2() -> miniscript::Descriptor<tweak::Key> {
        // Address 1: el1qqd39hteaylpq92s8s43q4cd877w7p4h2hzhz09z0lv0xhl9kxphmrzgzf50mlrptlewh4kn690ek39el9tac7xktlj54sg9vp
        //    - Private key: cVJ8NXsvsy1DgNXbmZ9cGAcGiqqNfFZAq1xqitYW96pSnDFTBAcq
        //    - Public key: 02a17c065dc81ec05d87d6a4ceb6576926b1796c14a05bb679aa617b3ff3f0f0ab
        //
        // Address 2: el1qq0lzvdu7688tz0qnpwfunqdpryqer2hd5px2lk53sqtgjm3qwpjprp50j3ev8zaq5xptdqcecwy8xxxt9qc3zcmehrh8q2h7t
        //     - Private key: cTgVY69QL9zH3UTGx4J2NpmCbLkhjKPSZQhGYsK6cneDJSUDdcsB
        //     - Public key: 039284b1425b0143e9a65e413daf72e6955e8091ae44f9a6a29b1cefd5d3f73fdd
        //
        // Address 3: el1qq23nzl50ef76ukdr87fqlkvf0ync30gzhrh7c8wnwfpngu8cxfxzsagkd8gx2hew0mkzs7gxdrpzrmh2p8d92gdrh5pn5cp95
        //     - Private key: cN8yK4CBCXJWUi9UwFBE3Vo1aRecoRmf7Tm2qBfRb5YtNfyEevgx
        //     - Public key: 022ba9315a62b17f31f393250ce3a1a9ea88c2a2b8aaa155fc49b3dab1787cc995
        format!("sh(wsh(or_d(\
            multi(\
                2,\
                [410000000001]02a17c065dc81ec05d87d6a4ceb6576926b1796c14a05bb679aa617b3ff3f0f0ab,\
                [410000000010]039284b1425b0143e9a65e413daf72e6955e8091ae44f9a6a29b1cefd5d3f73fdd,\
                [410000000100]022ba9315a62b17f31f393250ce3a1a9ea88c2a2b8aaa155fc49b3dab1787cc995\
            ),\
            and_v(\
                v:older({}),\
                multi(\
                    1,\
                    [untweaked]023303dedc51b9d227b17c9fb4710f96b844e1ccdc2c776e1b7274bd4e246b6202,\
                    [untweaked]03024c3b4f830854d6d26d6e34d92aff4c703bf57e85cd42abe328d928e01d4286,\
                    [untweaked]03fe4e8c8d99b9dcbb529a87d54f606bae0149a34018325547fa0c2239e038a1c9))\
                )\
            )\
        )", dummy_csv()).parse().unwrap()
    }

    pub fn test_descriptor_3() -> miniscript::Descriptor<tweak::Key> {
        // Address 1: el1qqgaflhvtcm343t9lnu6s3mepeerrp35uwmk2gdwjsauvj28f54jdxkn3uvdtqv49cys9vqhg9a5pfhu3uexmxzy028v6f2z6j
        //    - Private key: cU3pEE3EXQwsRVDKeALxmmBC4e2DCxKo1nRUdX35h1v15Lvh4QmN
        //    - Public key: 03ff17399b644abbef8af0583f9ba62bfc100a9e2afb108633d988778ccbd5ebee
        //
        // Address 2: el1qqtt8m2kpz9lvjh7p2nd25yvfyv9ufwkuzahmuksl99hed6mhp72sk33jehu8lnc9chc4pqv6vmd7aa907euws5pc2754w203p
        //     - Private key: cPZws4JwxoojPmBvtttAxFjCDkrAwiuAm5L5mAz2pF3KpuXk8Jf3
        //     - Public key: 02cac595ebfdcb7e39f903a430d0837c0a30fc5cf32509fbc6788d46ec34861eb2
        //
        // Address 3: el1qqwzvz26kd8n7dxg4lyw7p7z0uddk04fh2d6j64evghpd3jva5r7m8ff5egvvfkv297p93stz3vxr06httt64jcx5jpmwtw8rg
        //     - Private key: cR7dzJdkSpJNU59b4QU4gLZL9KeJYuQ9VRao6RnXfQyjnqyiaYwS
        //     - Public key: 030a48be7f003bcd919b05a9463a636249876029ba2cc495e148d8b124c44c9686
        format!("sh(wsh(or_d(\
            multi(\
                2,\
                [410000000001]03ff17399b644abbef8af0583f9ba62bfc100a9e2afb108633d988778ccbd5ebee,\
                [410000000010]02cac595ebfdcb7e39f903a430d0837c0a30fc5cf32509fbc6788d46ec34861eb2,\
                [410000000100]030a48be7f003bcd919b05a9463a636249876029ba2cc495e148d8b124c44c9686\
            ),\
            and_v(\
                v:older({}),\
                multi(\
                    1,\
                    [untweaked]023303dedc51b9d227b17c9fb4710f96b844e1ccdc2c776e1b7274bd4e246b6202,\
                    [untweaked]03024c3b4f830854d6d26d6e34d92aff4c703bf57e85cd42abe328d928e01d4286,\
                    [untweaked]03fe4e8c8d99b9dcbb529a87d54f606bae0149a34018325547fa0c2239e038a1c9))\
                )\
            )\
        )", dummy_csv()).parse().unwrap()
    }

    /// Pegin of a little under 1MM sat (0.01 BTC)
    /// Liquid tx ce2902f2cd68e55dbbdf5d9bdc29ca58237782a8d1c7f1b0011b99497af63616
    pub const SIDE_TX_PEGIN: [u8; 1197] = hex!("
        02000000010131f8a1e7c264b5d6a34c746996e6a3d57fd6cd49051a0a73de3d
        d8b3509548c50100004000ffffffff02016d521c38ec1ea15734ae22b7c46064
        412829c0d0579f0a713d1c04ede979026f0100000000000f4098001976a91460
        c83d9ff5a02a088bc7723e0c8d873d3ccffc7888ac016d521c38ec1ea15734ae
        22b7c46064412829c0d0579f0a713d1c04ede979026f0100000000000001a800
        0000000000000002483045022100ff7887a5bb9b93764fc8481937176c38207c
        3f9bf8f22aed51dc94042d343ba602207aefc9ffbf429637f86d00379ca042ad
        802a331dcbadb1ac3372ace0bea6a33401210268b84bb07da2b3501153948e3f
        ca5f2b4a8485d83a065ae5262bf3c8dce9cc23060840420f0000000000206d52
        1c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f206f
        e28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000016
        001468fd55b0ec3fa63e7d9344a2e9ebb52f62ea547efd740101000000000101
        c663d757c16d5cbb6625c90639ffc36da73a5619da79f8dd01b4e7d100c97308
        000000002322002084616b3f48f31453285967aa2799ba20864a572e56a2551d
        384866fc643a34a3fdffffff02b135df000000000017a914bce6030af86a618c
        90b1c6fcccdc1919a5b3b2698740420f000000000017a914222b8a32d5e3fdc5
        67d645c08c915745b109045d870400483045022100db1bc2dc2369718b4b0e7c
        b09b46960602a7978c8db873367e18d64f3d7cf1f9022009c3e2f9ec141033e3
        a500d03c264e99f488c652a56287f4d440a85f4b138e8d01483045022100dabb
        4635cc7ba3c71da5a2d5e90fd9616d4b2e7ebc3084152e872b41f88dc1580220
        23aed46626ae75594103ee034566933fb5a5354172a1c927f5f5c77a1a01782d
        014752210208bb4211958782355bc7e822a4f8f9f7131339796f870d23c833ef
        c975a8af3c21029fc2ea55b734923cb1dafeaee16936b487703ca159fc20a3fa
        030cbe11bb96c552ae6e4a0800fdb90100000020dd06c547464da48eac5f4d1c
        ab2e4bcc7628d61d5f4b25000000000000000000f80363bdeae2b2ee9814a6d7
        a6b3acaf7d42c21b1012d3407e77d258b8478e0c254ead5b1f5a2717bb6fe661
        660b00000baee36d712023fae2225b93cb0b0e0c680f2b3861c6bcbc0ab59726
        d58aeb88726abb79f918f1a49be64619ba1e4c86720ed61330314f6d92b56502
        d808fcb3e8627de8e7539a940474631b5a712b15cf1cf73a79463e4ee653ea08
        ab8affca0eafc81323e7e3c0c4f7c6ee6e7e6e4560f1c58b7a401c2c09654bd2
        2ae109b44b1f79621a7facb853ae46b40ac88f9ae34f52285989030f088958c2
        932759710241456103204660d874c1479c2093086c2c55d5443c34f6ea0638fe
        1e40ccdb13a0da9db37e560faa66d7eb90fcd859ccdba3778474aa356ce851c1
        dc40855022dabe014a4c245283bc6a457ebfd1c6a6865abf51bee5f26a6524ac
        581989944c31f8a1e7c264b5d6a34c746996e6a3d57fd6cd49051a0a73de3dd8
        b3509548c5ff5b63e4c6fc1c7bf8b5358d4aa2942f83247ada60fcb395241f1d
        c23c8a1cda63547e78c9b06ccab478e23ff583028ede28ec356350bb7618be3b
        b064c91f2703ad5d1500000000
    ");

    /// Pegout of 100k sat (0.001 BTC)
    /// Liquid tx eb372e0d6a427b91482af41af3aa9bd98e683dcdde487568e748d39ca81f1c45
    pub const SIDE_TX_PEGOUT: [u8; 704] = hex!("
        0200000000011636f67a49991b01b0f1c7d1a882772358ca29dc9b5ddfbb5de5
        68cdf20229ce000000006b483045022100cc5040d5604062b02c15b04676f040
        9833a4a9ffeb9d2709bf3a3542e34b823902206cfa508e1e3749fc1d270234f3
        c82107f5fad00768490ed0596c6c20c1396a25012103c985c2b7898fd4974951
        d1346842b59d7e533bea5dd8dd9f7e157fda979ae372feffffff03016d521c38
        ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f01000000
        00000186a000fd82016a206fe28c0ab6f1b372c1a6a246ae63f74f931e8365e1
        5a089c68d61900000000001976a914bd3432857da35ae7c93a05c911208aad0d
        6fa69588ac21032bc4eff4929ffa1c0ec8c8920d6e8d511825d9609774bd9a58
        c865b74ecc507c4d21010813c2d863b5a4c50f89c6f66087e126a3dc746ab050
        029e7087d54ed2cc5ad13b5faf589a80acf3adec9f0169f0960bcecf7afd01dc
        f3ea6efeadb529e7676ad27e164e4a965a515b17e3a74fde8fa5afef2ac68830
        909ac7100066f15e718756e6e1664490e87056f457663cf842f3b60d5fdf9318
        81c03847e40678d88715a118cfc4c53bc1cca4879da4c7565c34e4e30d296cc6
        0a7b3b5d8dd338fc166bbe51c61db39f35b8f8d91f29e3208d9f410c318ca2bd
        a15a9e8385b1f0e669739627d46eddb3dc93eb47a718eefa2f5c22f7d430a257
        3503483a26e3132824e24ae6e9e1932da482fd73b04b308d6db99ebb129a5782
        b36f5a8f224b6c9f2e4fd14c8f7ec260905a093b0f5425624e156ee9a5c93641
        00e6591abf6d4ea372e7b3016d521c38ec1ea15734ae22b7c46064412829c0d0
        579f0a713d1c04ede979026f0100000000000db738001976a9147214faff96d5
        39eb843cdbf79aca6a45e5bc60fd88ac016d521c38ec1ea15734ae22b7c46064
        412829c0d0579f0a713d1c04ede979026f0100000000000002c00000980a0000
    ");

    /// This is the CSV we use in these tests.
    fn dummy_csv() -> u64 {
        Constants::default().near_expiry_threshold + 280
    }

    fn single_desc_consensus(desc: miniscript::Descriptor<tweak::Key>) -> ConsensusTracker {
        let mut ret = ConsensusTracker::new(10);
        ret.update_known_descriptors(vec![(0, descriptor::Cached::from(desc.clone()))]);
        ret.register_sidechain_block(1, Some(1), Some(&elements::dynafed::Params::Full(FullParams::new(
            elements::Script::new(),
            0,
            desc.liquid_script_pubkey(),
            desc.liquid_witness_script().to_bytes(),
            vec![],
        ))));
        assert_eq!(ret.active_params().expect("no params").descriptor.as_ref().expect("no desc").inner, desc);
        ret
    }

    /// A structure to streamline different aspects of a unified test setup.
    #[derive(Debug)]
    pub struct TestSetup {
        pub descriptor: Descriptor<tweak::Key>,
    }

    impl TestSetup {
        pub fn new(descriptor: Descriptor<tweak::Key>) -> TestSetup {
            TestSetup {
                descriptor: descriptor,
            }
        }

        pub fn descriptor(&self) -> Descriptor<tweak::Key> {
            self.descriptor.clone()
        }

        pub fn csv(&self) -> u64 {
            dummy_csv()
        }

        pub fn utxotable(&self) -> utxotable::UtxoTable {
            let our_pk = self.descriptor().iter_signer_keys().next().unwrap().to_pubkey();
            utxotable::UtxoTable::new(our_pk)
        }

        pub fn manager(&self) -> Manager {
            let descriptor = self.descriptor();
            assert_eq!(descriptor.csv_expiry(), Some(dummy_csv()));
            let consensus = single_desc_consensus(descriptor.clone());

            let main_skip_height = 470000;
            let n_mainchain_confirms = 20;
            let asset_id = elements::AssetId::from_str(LBTC_ASSET).unwrap();
            Manager {
                secp: Secp256k1::verification_only(),
                consensus: consensus,
                txindex: txindex::TxIndex::new(main_skip_height, n_mainchain_confirms),
                account: Account::new(),
                fee_pool: fee::Pool::new(Amount::from_sat(20000)),
                utxos: self.utxotable(),
                side_height_iter: HeightIterator::new(1, 2),
                latest_mainchain_commitment: (0, bitcoin::BlockHash::all_zeros()),
                genesis_hash: bitcoin::BlockHash::from_str(BITCOIN_GENESIS_STR).unwrap(),
                pegged_asset: elements::confidential::Asset::Explicit(asset_id),
                target_n_outputs: 100,
                last_confirmed_hash: None,
                round_time: time::Duration::from_secs(10),
                cache_file: String::new(),
            }
        }

        pub fn peers(&self) -> HashSet<peer::Id> {
            self.descriptor().signers()
        }

        /// Fee donation of 2^36 sat (~687 BTC) to the test descriptor.
        pub fn main_tx_donation(&self) -> bitcoin::Transaction {
            bitcoin::Transaction {
                version: bitcoin::transaction::Version::ONE,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: "5426c3899d136c5c398045e694b0c01052b990d5bf903ecc0eeeb919b0c1237f:1".parse().unwrap(),
                    script_sig: ScriptBuf::from_hex("47304402202be21fff8b3afb4b30a8f844ac3098f9b08b8b7545278d31c689dffa4f00186002207b39c703ede9f94118e27c9d979b7a55b485fbab89f3a2111f23884c90775cda012102cb202b000dde09b96dfffd672616aa3235fed9d34399ecfb63a2581b0e17340b").unwrap(),
                    sequence: bitcoin::Sequence::from_consensus(4294967295),
                    witness: bitcoin::Witness::default(),
                }],
                output: vec![bitcoin::TxOut {
                    value: Amount::from_sat(68719476736),
                    script_pubkey: self.descriptor().liquid_script_pubkey(),
                }],
            }
        }
    }

    struct DummyBitcoind;

    impl Rpc for DummyBitcoind {
        fn jsonrpc_query<T: serde::de::DeserializeOwned>(
            &self,
            query: &str,
            args: &[jsonrpc::serde_json::Value],
        ) -> Result<T, jsonrpc::Error> {
            println!("dummy rpc called: {}({:?})", query, args);
            if query == "getblockhash" {
                Ok(jsonrpc::serde_json::from_str(
                    "\"00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048\""
                )?)
            } else if query == "getblockheader" {
                Ok(jsonrpc::serde_json::from_str("{
                    \"confirmations\": 572529,
                    \"height\": 1
                }")?)
            } else {
                panic!("dummy bitcoin does not understand RPC call {}", query);
            }
        }

        fn is_warming_up(&self, _: &str) -> Result<bool, jsonrpc::Error> {
            Ok(true)
        }
    }
    impl rpc::BitcoinRpc for DummyBitcoind {}

    fn craft_pegin_tx(wm_desc: &Descriptor<tweak::Key>, pegin_values: &[u64]) -> elements::Transaction {
        // chosen randomly 20 bytes
        let claim_script = hex!("dd918c8d61810546e69f05951fef4fcda95ab4f0");
        let lock_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::non_standard(0),
            lock_time: LockTime::ZERO,
            input: vec![],
            output: pegin_values.iter().map(|value| {
                bitcoin::TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: wm_desc
                        .tweak(&secp256k1::Secp256k1::new(), &claim_script[..])
                        .liquid_script_pubkey()
                }
            }).collect(),
        };
        let lock_txid = lock_tx.txid();
        println!("crafted pegin lock tx with txid {}", lock_txid);
        let lock_tx_serialized = bitcoin::consensus::serialize(&lock_tx);
        let pegin_datas = pegin_values.iter().enumerate().map(|(i, value)| {
            elements::PeginData {
                outpoint: bitcoin::OutPoint::new(lock_txid, i as u32),
                value: *value,
                asset: AssetId::from_str(LBTC_ASSET).unwrap(),
                genesis_hash: BITCOIN_GENESIS_STR.parse().unwrap(),
                claim_script: &claim_script[..],
                tx: &lock_tx_serialized,
                merkle_proof: &[0u8; 80][..],
                referenced_block: bitcoin::BlockHash::hash(&[0u8; 80][..]),
            }
        });
        let ret = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: pegin_datas.clone().map(|pegin| {
                elements::TxIn {
                    previous_output: pegin.outpoint.to_string().parse().unwrap(),
                    is_pegin: true,
                    script_sig: elements::Script::new(),
                    sequence: elements::Sequence::from_consensus(4294967295),
                    asset_issuance: Default::default(),
                    witness: elements::TxInWitness {
                        pegin_witness: pegin.to_pegin_witness(),
                        ..Default::default()
                    },
                }
            }).collect(),
            output: vec![
                elements::TxOut {
                    asset: elements::confidential::Asset::Explicit(LBTC_ASSET.parse().unwrap()),
                    value: elements::confidential::Value::Explicit(pegin_values.iter().sum()),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: elements::Address::from_str(
                        "ert1qg2ln89hcmw8e60qs0n8uhc40spcqwdl3z9j2mg"
                    ).unwrap().script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                }
            ],
        };
        for (i, pegin) in pegin_datas.enumerate() {
            assert_eq!(ret.input[i].pegin_data().as_ref(), Some(&pegin));
        }
        println!("crafted pegin tx with txid {}", ret.txid());
        ret
    }

    #[test]
    fn prepare_to_sign_simple() {
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();
        let empty_manager = manager.clone();
        serialization_roundtrip(&manager);

        let mut proposal = transaction::ConcreteProposal {
            inputs: vec![],
            pegouts: vec![],
            change: vec![],
        };

        // Empty proposal will be rejected for having no change
        let res = manager.validate_proposal(&proposal, |_| Ok(()), false);
        if let Err(Error::BadProposal(
            ProposalError::BadChangeCount { got, min, max }
        )) = res {
            assert_eq!(got, 0);
            assert_eq!(min, 1);
            assert_eq!(max, constants::MAXIMUM_CHANGE_OUTPUTS);
        } else {
            panic!("unexpected {:?}", res);
        }

        // Zero change will be rejected for having too small change
        proposal.change.push(Amount::ZERO);
        let res = manager.validate_proposal(&proposal, |_| Ok(()), false);
        if let Err(Error::BadProposal(
            ProposalError::BadChangeAmount { got, min }
        )) = res {
            assert_eq!(got, 0);
            assert_eq!(min, constants::MINIMUM_DUST_CHANGE);
        } else {
            panic!("unexpected {:?}", res);
        }

        // If we add an input, it will then be rejected because the input is unrecognized
        let value = 1000000;
        let pegin_tx = craft_pegin_tx(&setup.descriptor(), &[value]);

        proposal.change[0] = Amount::from_sat(constants::MINIMUM_DUST_CHANGE);
        proposal.inputs.push(pegin_tx.input[0].pegin_data().expect("pegin tx").outpoint);

        let res = manager.validate_proposal(&proposal, |_| Ok(()), false);
        if let Err(Error::BadProposal(ProposalError::UnknownInputs(inputs))) = res {
            assert_eq!(inputs, vec![proposal.inputs[0]]);
        } else {
            panic!("unexpected {:?}", res);
        }
        assert_eq!(manager, empty_manager);

        // If we recognize it, we will then complain about burning everything to fees,
        // when the feepool is empty
        manager.process_side_transaction(&DummyBitcoind, &pegin_tx, 0).unwrap();
        let funded_manager = manager.clone();
        let res = manager.validate_proposal(&proposal, |_| Ok(()), false);
        if let Err(Error::BadProposal(ProposalError::InsufficientFees { available, needed })) = res {
            assert_eq!(available, 0);
            assert_eq!(needed, value - constants::MINIMUM_DUST_CHANGE);
        } else {
            panic!("unexpected {:?}", res);
        }
        assert_eq!(manager, funded_manager);
        serialization_roundtrip(&manager);

        // If we fill the feepool, it will *still* complain because the feerate is too high
        process_main_transaction(&mut manager, &setup.main_tx_donation(), 0, 1);
        let funded_manager2 = manager.clone();
        let res = manager.validate_proposal(&proposal, |_| Ok(()), false);
        if let Err(Error::BadProposal(ProposalError::FeeTooHigh { got, maximum })) = res {
            assert_eq!(got, value - constants::MINIMUM_DUST_CHANGE);
            assert_eq!(maximum, 21075);
        } else {
            panic!("expected fee too high (tx which burns all coins), got {:?}", res);
        }
        assert_eq!(manager, funded_manager2);
        serialization_roundtrip(&manager);

        // If we add a sane change output, it will go through
        proposal.change[0] = Amount::from_sat(990_000);
        manager.validate_proposal(&proposal, |_| Ok(()), false).expect("prepare ok");

        // Attempt an actual pegout
        let pegout_tx = deserialize::<elements::Transaction>(&SIDE_TX_PEGOUT).unwrap();
        let mut tx_iter = TxIterator::new(
            &pegout_tx,
            pegout_tx.txid(),
            manager.genesis_hash,
            manager.pegged_asset,
        );
        let pegout_ref;
        if let Some(TxObject::Pegout(outpoint, _)) = tx_iter.next() {
            assert_eq!(tx_iter.next(), Some(TxObject::Fee(704)));
            assert_eq!(tx_iter.next(), None);
            pegout_ref = outpoint;
        } else {
            panic!("expected pegout");
        };
        manager.process_side_transaction(&DummyBitcoind, &pegout_tx, 0).unwrap();

        // If we just add the tx so that the fee is negative, it will error out
        proposal.pegouts.push(pegout_ref);
        let res = manager.validate_proposal(&proposal, |_| Ok(()), false);
        if let Err(Error::BadProposal(ProposalError::Unbalanced { input_value, output_value })) = res {
            assert_eq!(input_value, value);
            assert_eq!(output_value, 1090000);
        } else {
            panic!("expected negative fee");
        }

        // Shrink the change output to make room for the pegout
        proposal.change[0] = Amount::from_sat(899000);
        let res = manager.validate_proposal(&proposal, |_| Ok(()), false);
        assert!(res.is_ok());

        // Trying to process the same output twice in one shot will cause an error
        proposal.change[0] = Amount::from_sat(798000); // make room for more outputs + fee
        let copy = proposal.pegouts[0];
        proposal.pegouts.push(copy);
        let res = manager.validate_proposal(&proposal, |_| Ok(()), false);
        if let Err(Error::BadProposal(ProposalError::DuplicatePegout(outpoint))) = res {
            assert_eq!(outpoint, pegout_ref);
        } else {
            panic!("unexpected {:?}", res);
        }

        let discrepancy = manager.account.discrepancy();
        assert_eq!(discrepancy.to_sat(), 0);
        serialization_roundtrip(&manager);
    }

    /// Helper function for processing a mainchain tx in the Manager
    /// by skipping the tx index.
    fn process_main_transaction(
        man: &mut Manager,
        tx: &bitcoin::Transaction,
        target_mainchain_height: BlockHeight,
        last_sidechain_height: BlockHeight
    ) {
        if let Some(meta) = man.self_tx_meta(tx).expect("tx_meta error") {
            // I don't think anything cares about the block hash for now..
            let status =  txindex::TxStatus::ConfirmedIn(BlockRef::new(target_mainchain_height, bitcoin::BlockHash::all_zeros()));
            let tx = txindex::tests::new_tx(tx.clone(), status, meta);
            man.txindex.insert_dummy_blocks_until(target_mainchain_height);
            man.consensus.register_sidechain_block(last_sidechain_height, Some(target_mainchain_height + 1), None);
            Manager::handle_finalized_tx(&mut man.utxos, &mut man.fee_pool, &mut man.account,
                &man.consensus, tx,
            );
        }
    }

    #[test]
    fn prepare_to_sign_2_pegs_1_dest() {
        //! Tests multiple simultaneous pegouts to the same destination. Tries docking fees
        //! for each and/or seeing the final transaction(s) posted to the blockchain. Checks
        //! that no discrepancy occurs. See https://gl.blockstream.io/liquid/functionary/issues/187

        // Create manager with a pile of pegged-in coins and fees
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();
        let value = 1000000;
        let pegin_tx = craft_pegin_tx(&setup.descriptor(), &[value]);
        manager.process_side_transaction(&DummyBitcoind, &pegin_tx, 0).unwrap();
        process_main_transaction(&mut manager, &setup.main_tx_donation(), 2, 1);

        // Create a pegout transaction that tries to peg twice to the same destination
        let mut pegout_tx = deserialize::<elements::Transaction>(&SIDE_TX_PEGOUT).unwrap();
        let pegout = pegout_tx.output[0].clone();
        pegout_tx.output.push(pegout);

        let mut tx_iter = TxIterator::new(
            &pegout_tx,
            pegout_tx.txid(),
            manager.genesis_hash,
            manager.pegged_asset,
        );

        let pegout_ref1;
        let pegout_ref2;
        let pegout_out1;
        let pegout_out2;
        if let Some(TxObject::Pegout(side_ref, pegout_data)) = tx_iter.next() {
            pegout_ref1 = side_ref;
            pegout_out1 = bitcoin::TxOut {
                script_pubkey: pegout_data.script_pubkey.clone(),
                value: Amount::from_sat(pegout_data.value),
            };
        } else {
            panic!("expected pegout");
        };
        if let Some(TxObject::Fee(704)) = tx_iter.next() {
        } else {
            panic!("expected fee");
        }
        if let Some(TxObject::Pegout(side_ref, pegout_data)) = tx_iter.next() {
            assert_eq!(tx_iter.next(), None);
            pegout_ref2 = side_ref;
            pegout_out2 = bitcoin::TxOut {
                script_pubkey: pegout_data.script_pubkey.clone(),
                value: Amount::from_sat(pegout_data.value),
            };
        } else {
            panic!("expected pegout");
        };

        manager.process_side_transaction(&DummyBitcoind, &pegout_tx, 0).unwrap();
        assert!(pegout_ref1 != pegout_ref2);
        assert_eq!(pegout_out1, pegout_out2);

        // Attempt to process this pegout in one transaction
        let pegin_out = bitcoin::OutPoint {
            txid: pegin_tx.input[0].pegin_data().expect("pegin tx").outpoint.txid,
            vout: pegin_tx.input[0].previous_output.vout,
        };

        let mut proposal = transaction::ConcreteProposal {
            inputs: vec![pegin_out],
            pegouts: vec![pegout_ref1, pegout_ref2],
            change: vec![Amount::from_sat(790000)],
        };

        let manager_copy = manager.clone();

        // Sign the tx
        let tx = manager.validate_proposal(&proposal, |_| Ok(()), false).unwrap().0;
        let discrepancy = manager.account.discrepancy();
        assert_eq!(discrepancy.to_sat(), 0);

        // Confirm the tx
        process_main_transaction(&mut manager, &tx, 1, 1);
        let discrepancy = manager.account.discrepancy();
        assert_eq!(discrepancy.to_sat(), 0);

        // Try without marking signed first
        manager = manager_copy.clone();
        process_main_transaction(&mut manager, &tx, 1, 1);
        let discrepancy = manager.account.discrepancy();
        assert_eq!(discrepancy.to_sat(), 0);

        // Try with only the first pegout being processed
        proposal.pegouts = vec![pegout_ref1];
        proposal.change[0] = Amount::from_sat(890000);
        manager = manager_copy.clone();

        manager.validate_proposal(&proposal, |_| Ok(()), false).unwrap();
        let discrepancy = manager.account.discrepancy();
        assert_eq!(discrepancy.to_sat(), 0);

        // Try with only the second pegout being processed - should error
        manager = manager_copy.clone();
        proposal.pegouts = vec![pegout_ref2];
        if let Err(Error::BadProposal(
            ProposalError::SkippedPegout { request, previous }
        )) = manager.validate_proposal(&proposal, |_| Ok(()), false) {
            assert_eq!(request, pegout_ref2);
            assert_eq!(previous, pegout_ref1);
        } else {
            panic!("should not allow skipping outputs");
        }
        let discrepancy = manager.account.discrepancy();
        assert_eq!(discrepancy.to_sat(), 0);

        process_main_transaction(&mut manager, &tx, 1, 1);
        let discrepancy = manager.account.discrepancy();
        assert_eq!(discrepancy.to_sat(), 0);

        // Try with only the one pegout being confirmed (indistinguishable which one)
        // without either being seen at signing-time
        manager = manager_copy.clone();
        process_main_transaction(&mut manager, &tx, 1, 1);
        let discrepancy = manager.account.discrepancy();
        assert_eq!(discrepancy.to_sat(), 0);
    }

    #[test]
    fn consolidation_confirm() {
        // Create manager with a pile of donation outputs
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();
        let mut donation_tx = setup.main_tx_donation();
        let donation_output = bitcoin::TxOut {
            script_pubkey: donation_tx.output[0].script_pubkey.clone(),
            value: Amount::from_sat(10000),
        };
        donation_tx.output = vec![donation_output; 50];
        process_main_transaction(&mut manager, &donation_tx, 1, 1);
        let mut m_copy = vec![manager.clone(); 3];

        let starting_pool = manager.fee_pool.available_funds();

        // Create "consolidation" proposal which has 50 inputs,
        // 5 change outputs, and no pegouts
        let proposal = transaction::ConcreteProposal {
            inputs: (0..50).map(|n| bitcoin::OutPoint {
                txid: donation_tx.txid(),
                vout: n,
            }).collect(),
            pegouts: vec![],
            change: vec![Amount::from_sat(90_000); 5],
        };
        let (unsigned_tx, inputs) = manager.validate_proposal(&proposal, |_| Ok(()), false).unwrap();

        assert_eq!(manager.fee_pool.available_funds(), starting_pool);
        manager.prepare_to_sign(&proposal, &unsigned_tx, &inputs).unwrap();
        assert_eq!(manager.fee_pool.available_funds(), starting_pool - SignedAmount::from_sat(50_000));
        process_main_transaction(&mut manager, &unsigned_tx, 100, 1);
        assert_eq!(manager.fee_pool.available_funds(), starting_pool - SignedAmount::from_sat(50_000));

        // regression test for #225
        process_main_transaction(&mut m_copy[0], &unsigned_tx, 100, 1);
        assert_eq!(m_copy[0].fee_pool.available_funds(), starting_pool - SignedAmount::from_sat(50_000));

        m_copy[1].prepare_to_sign(&proposal, &unsigned_tx, &inputs).unwrap();
        assert_eq!(manager.fee_pool.available_funds(), starting_pool - SignedAmount::from_sat(50_000));
        process_main_transaction(&mut m_copy[1], &unsigned_tx, 100, 1);
        assert_eq!(m_copy[1].fee_pool.available_funds(), starting_pool - SignedAmount::from_sat(50_000));

        process_main_transaction(&mut m_copy[2], &unsigned_tx, 100, 1);
        assert_eq!(m_copy[2].fee_pool.available_funds(), starting_pool - SignedAmount::from_sat(50_000));
    }

    /// Helper function to create a sidechain transaction that'll endow
    /// a blockchain manager with a bunch of pegins, pegout requests,
    /// and available feepool
    fn setup_sidechain_tx(
        descriptor: &Descriptor<tweak::Key>,
        available_inputs: &[u64],
        desired_outputs: &[u64],
        op_return_fee_donation: u64,
    ) -> elements::Transaction {
        // NB the order of the outputs here is determined by a previous version
        // of this impl that some tests depend on, so it's kept

        let mut pegout = deserialize::<elements::Transaction>(&SIDE_TX_PEGOUT).unwrap().output.remove(0);
        let mut ret = craft_pegin_tx(descriptor, available_inputs);

        // Balance the tx.
        let leftover = available_inputs.iter().sum::<u64>().checked_sub(
            desired_outputs.iter().sum::<u64>() + op_return_fee_donation
        );
        if leftover.is_none() || leftover == Some(0) {
            ret.output.pop();
        } else {
            ret.output[0].value = elements::confidential::Value::Explicit(leftover.unwrap());
        }

        // Encode `desired_outputs` as pegout outputs
        for amount in desired_outputs {
            pegout.value = elements::confidential::Value::Explicit(*amount);
            ret.output.push(pegout.clone());
        }

        // Encode `available_fees` as an OP_RETURN output
        ret.output.push(elements::TxOut {
            asset: elements::confidential::Asset::Explicit(LBTC_ASSET.parse().unwrap()),
            value: elements::confidential::Value::Explicit(op_return_fee_donation),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: elements::Script::from(vec![0x6a]), // OP_RETURN
            witness: elements::TxOutWitness::default(),
        });

        println!("crafted sidechain tx with txid {}", ret.txid());
        ret
    }

    pub fn fund_transaction(
        available_inputs: &[u64],
        desired_outputs: &[u64],
        ongoing_input_idxs: &[usize],
        ongoing_pegout_idxs: &[usize],
        available_fees: u64,
    ) -> Result<bitcoin::Transaction, utxotable::Error> {
        // Create manager with `available_inputs` provided as pegins, followed
        // by a sidechain-burn of `available_fees` many coins to fund the fee
        // pool.
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();
        manager.target_n_outputs = 0;  // disable change-splitting logic

        let setup_tx = setup_sidechain_tx(
            &setup.descriptor(),
            available_inputs,
            desired_outputs,
            available_fees,
        );
        manager.process_side_transaction(&DummyBitcoind, &setup_tx, 0)
            .expect("processing the sidechain-funding transaction");

        let ongoing_inputs: HashSet<_> = ongoing_input_idxs.iter()
            .map(|index| setup_tx.input[*index].pegin_data().unwrap().outpoint)
            .collect();

        let ongoing_pegouts: HashSet<_> = ongoing_pegout_idxs.iter()
            .map(|index| elements::OutPoint { txid: setup_tx.txid(), vout: *index as u32 })
            .collect();

        // Create the transaction outputs corresponding to the pegouts
        let proposal = manager.propose_transaction(
            &ongoing_pegouts,
            &ongoing_inputs,
            setup_tx.input.len(),
            &|_| Ok(()),
            &setup.peers(),
            &vec![],
        );

        match proposal {
            Ok(proposal) => Ok(manager.check_proposal(&proposal).unwrap().0),
            Err(Error::Utxo(err)) => Err(err),
            _ => unreachable!()
        }
    }

    #[test]
    fn fund_behavior() {
        // Try funding without fees. Make sure it fails.
        match fund_transaction(&[10000], &[8000], &[], &[], 0) {
            Err(utxotable::Error::CouldNotFund{ available, needed })
                if available == 0 && needed == 1520 => {},
            res => panic!("unexpected result {:?}", res),
        }

        // Try funding with sufficient fees to cover a change output, but
        // not enough for any inputs
        match fund_transaction(&[10000], &[8000], &[], &[], 2000) {
            Err(utxotable::Error::CouldNotFund{ available, needed })
                if available == 2000 && needed == 4895 => {},
            res => panic!("unexpected result {:?}", res),
        }

        // Funding with sufficient fees should work, and should fund the pegout
        let tx = fund_transaction(&[20000], &[8000], &[], &[], 12000).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);

        // With sufficient fees for only one pegout, only one pegout should be processed
        let tx = fund_transaction(&[20000], &[8000, 6000], &[], &[], 4895).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);

        // With sufficient fees for both, both get processed
        let tx = fund_transaction(&[30000], &[8000, 6000], &[], &[], 8000).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 3);

        // Exclude all but one input. Make sure only that one is used.
        let tx = fund_transaction(
            &[10000, 15000, 20000, 25000, 30000],
            &[5000],
            &[0, 1, 2, 3],
            &[],
            50000,
        ).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);

        // Exclude all the inputs. Should not be able to add any pegouts.
        match fund_transaction(
            &[10000, 15000, 20000, 25000, 30000],
            &[5000],
            &[0, 1, 2, 3, 4],
            &[],
            50000,
        ) {
            Err(utxotable::Error::EmptyProposal) => {},
            res => panic!("unexpected result {:?}", res),
        }

        // Exclude all inputs except one which is too small. Same result.
        match fund_transaction(
            &[5000, 15000, 20000, 25000, 30000],
            &[5000],
            &[1, 2, 3, 4],
            &[],
            50000,
        ) {
            Err(utxotable::Error::EmptyProposal) => {},
            res => panic!("unexpected result {:?}", res),
        }

        // Given only dust, should get the same error, even if in total we can
        // afford the output (and all the dust would fit)
        match fund_transaction(
            &vec![100; 1000],
            &[2000],
            &[1, 2, 3, 4],
            &[],
            50000,
        ) {
            Err(utxotable::Error::EmptyProposal) => {},
            res => panic!("unexpected result {:?}", res),
        }

        match fund_transaction(
            &vec![100; 1000],
            &vec![100; 500],
            &[1, 2, 3, 4],
            &[],
            50000,
        ) {
            Err(utxotable::Error::EmptyProposal) => {},
            res => panic!("unexpected result {:?}", res),
        }

        // Transaction size test
        let tx = fund_transaction(
            &vec![5000; 500],
            &vec![2000; 300],
            &[1, 2, 3, 4],
            &[],
            1_000_000,
        ).unwrap();
        assert!(tx.input.len() < 500);
        assert!(tx.output.len() < 253);
        assert!(tx.weight().to_wu() <= constants::MAXIMUM_TX_WEIGHT as u64);

        let tx = fund_transaction(
            &vec![100_000; 500],
            &vec![2000; 800],
            &[1, 2, 3, 4],
            &[],
            1_000_000,
        ).unwrap();
        assert!(tx.input.len() < 253);
        assert!(tx.output.len() >= 253);
        assert!(tx.output.len() < 800);
        assert!(tx.weight().to_wu() <= constants::MAXIMUM_TX_WEIGHT as u64);
    }

    #[test]
    fn fund_transaction_ct_restrictions() {
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();
        let signers = setup.peers();
        let mut utxos = vec![];
        let mut pegout_requests = vec![];

        // Setup a sidechain with five 100ksat claims, a big pegout request
        // that'll force them all to be spent, a small pegout request that
        // we'll use to create smaller transactions (which will obey certain
        // conflict requirements), and sufficient fees to make as many transactions
        // as we want.
        let setup_tx = setup_sidechain_tx(
            &setup.descriptor(),
            &[100_000, 100_000, 100_000, 100_000, 100_000],
            &[400_000, 10_000],
            90_000,
        );
        manager.process_side_transaction(&DummyBitcoind, &setup_tx, 0)
            .expect("processing the setup tx");

        // Extract data from the setup tx
        let tx_iter = TxIterator::new(
            &setup_tx,
            setup_tx.txid(),
            manager.genesis_hash,
            manager.pegged_asset,
        );
        for object in tx_iter {
            match object {
                TxObject::Pegout(outpoint, _) => {
                    pegout_requests.push(outpoint);
                },
                TxObject::Pegin(data) => {
                    utxos.push(data.outpoint);
                },
                _ => {}
            }
        }

        // Spend all outputs for the single pegout
        let proposal = manager.propose_transaction(
            &HashSet::new(),
            &HashSet::new(),
            manager.target_n_outputs,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).expect("pegout processing tx to work");
        assert_eq!(proposal.inputs.len(), 5);
        assert_eq!(proposal.pegouts.len(), 2);
        assert_eq!(proposal.change.len(), 1);

        // Notice it in the mempool, to record conflict requirements
        manager.check_proposal(&proposal).expect("created invalid proposal");

        // 1. Simple transaction processing only the small pegout
        //    (big one is excluded). It will succeed, and of course
        //    conflict because the first tx used every input.
        let proposal = manager.propose_transaction(
            &Some(pegout_requests[0]).into_iter().collect(),
            &HashSet::new(),
            100,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).expect("pegout processing tx to work");
        assert_eq!(proposal.inputs.len(), 2);
        assert_eq!(proposal.pegouts.len(), 1);
        assert_eq!(proposal.change.len(), 1);
        assert!(manager.check_proposal(&proposal).is_ok());
        // (Don't record as unconfirmed, so conflict tracker will be unchanged)

        // 2. Transaction where excluded inputs forces choice of conflict
        let proposal = manager.propose_transaction(
            &Some(pegout_requests[0]).into_iter().collect(),
            &utxos[0..4].iter().cloned().collect(),
            100,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).expect("pegout processing tx to work");
        assert_eq!(proposal.inputs.len(), 1);
        assert_eq!(proposal.inputs[0], utxos[4]);
        assert_eq!(proposal.pegouts.len(), 1);
        assert_eq!(proposal.change.len(), 1);
        let (tx, _) = manager.check_proposal(&proposal).expect("created invalid proposal");
        manager.utxos.record_conflicts(
            tx.txid(), &proposal.input_set(), proposal.pegouts.iter().copied(),
        ).unwrap();

        // 3. After doing this, *every* transaction that processes this
        //    pegout must use utxos[4], regardless of excluded inputs
        manager.propose_transaction(
            &Some(pegout_requests[0]).into_iter().collect(),
            &HashSet::new(),
            100,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).expect("pegout processing tx to work");
        assert_eq!(proposal.inputs.len(), 1);
        assert_eq!(proposal.inputs[0], utxos[4]);
        assert_eq!(proposal.pegouts.len(), 1);
        assert_eq!(proposal.change.len(), 1);
        assert!(manager.check_proposal(&proposal).is_ok());

        // 4. And if we try to exclude that output, we'll be unable to
        //    process the pegout
        let err = manager.propose_transaction(
            &Some(pegout_requests[0]).into_iter().collect(),
            &Some(utxos[4]).into_iter().collect(),
            100,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).unwrap_err();
        if let Error::Utxo(utxotable::Error::EmptyProposal) = err {
        } else {
            panic!("unexpected error {:?}", err);
        }
    }

    #[test]
    fn change_splitting() {
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();
        let signers = setup.peers();

        // Setup a sidechain with a bunch massive claims, each individually
        // able to create the maximum number of change outputs. (We make
        // them uniform to make the tests easier, as we choose coins randomly.)
        let pegin_size = constants::MAXIMUM_CHANGE_OUTPUTS as u64
            * constants::MINIMUM_OPPORTUNISTIC_CHANGE;
        let setup_tx = setup_sidechain_tx(
            &setup.descriptor(),
            &[pegin_size, pegin_size, pegin_size, pegin_size],
            &[pegin_size],
            250_000,
        );
        manager.process_side_transaction(&DummyBitcoind, &setup_tx, 0)
            .expect("processing the setup tx");

        // 1. We have enough change outputs. Only one should be created
        let proposal = manager.propose_transaction(
            &HashSet::new(),
            &HashSet::new(),
            manager.target_n_outputs,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).unwrap();
        assert_eq!(proposal.inputs.len(), 2);
        assert_eq!(proposal.pegouts.len(), 1);
        assert_eq!(proposal.change.len(), 1);
        manager.check_proposal(&proposal).expect("proposal ok");

        // 2. We don't have enough, but are within the radius
        let proposal = manager.propose_transaction(
            &HashSet::new(),
            &HashSet::new(),
            // +2 because the logic further subtracts proposal.inputs.len()
            manager.target_n_outputs - constants::N_MAIN_OUTPUTS_RADIUS + 2,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).unwrap();
        assert_eq!(proposal.inputs.len(), 2);
        assert_eq!(proposal.pegouts.len(), 1);
        assert_eq!(proposal.change.len(), 1);
        manager.check_proposal(&proposal).expect("proposal ok");

        // 3. Outside the radius, we create one more than the radius
        let proposal = manager.propose_transaction(
            &HashSet::new(),
            &HashSet::new(),
            manager.target_n_outputs - constants::N_MAIN_OUTPUTS_RADIUS + 1,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).unwrap();
        assert_eq!(proposal.inputs.len(), 2);
        assert_eq!(proposal.pegouts.len(), 1);
        assert_eq!(proposal.change.len(), 1 + constants::N_MAIN_OUTPUTS_RADIUS);
        manager.check_proposal(&proposal).expect("proposal ok");

        // 4. Missing more than the maximum number of change outputs...in
        //    response we only create the maximum, not more
        let proposal = manager.propose_transaction(
            &HashSet::new(),
            &HashSet::new(),
            manager.target_n_outputs - constants::MAXIMUM_CHANGE_OUTPUTS,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).unwrap();
        assert_eq!(proposal.inputs.len(), 2);
        assert_eq!(proposal.pegouts.len(), 1);
        assert_eq!(proposal.change.len(), constants::MAXIMUM_CHANGE_OUTPUTS);
        manager.check_proposal(&proposal).expect("proposal ok");

        // 4. If we claim to have 0 outputs available, we create the maximum
        //    number of change outputs, since our target is 100 for the test
        //    manager
        let proposal = manager.propose_transaction(
            &HashSet::new(),
            &HashSet::new(),
            3,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).unwrap();
        assert_eq!(proposal.inputs.len(), 2);
        assert_eq!(proposal.pegouts.len(), 1);
        assert_eq!(proposal.change.len(), constants::MAXIMUM_CHANGE_OUTPUTS);
        manager.check_proposal(&proposal).expect("proposal ok");

        // 5. Redo the maximum test, but with smaller claims such that we
        //    cannot add max-many outputs even after adding an input.
        //    We should have 4 change outputs - we fund enough for 6, but
        //    2's worth are used for the pegout and fee.
        let mut manager = setup.manager();
        let pegin_size = 2 * constants::MINIMUM_OPPORTUNISTIC_CHANGE;
        let setup_tx = setup_sidechain_tx(
            &setup.descriptor(),
            &[pegin_size, pegin_size, pegin_size, pegin_size],
            &[pegin_size],
            250_000,
        );
        manager.process_side_transaction(&DummyBitcoind, &setup_tx, 0)
            .expect("processing the setup tx");

        let proposal = manager.propose_transaction(
            &HashSet::new(),
            &HashSet::new(),
            3,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).unwrap();
        assert_eq!(proposal.inputs.len(), 3); // add an extra input
        assert_eq!(proposal.pegouts.len(), 1);
        assert_eq!(proposal.change.len(), 4);
        manager.check_proposal(&proposal).expect("proposal ok");

        // 6. Redo the maximum test with so many expired pegins that we
        //    have no room for change.
        let mut manager = setup.manager();
        manager.target_n_outputs = 10000;  // try to force change to be made
        let pegin_size = constants::MAXIMUM_CHANGE_OUTPUTS as u64
            * constants::MINIMUM_OPPORTUNISTIC_CHANGE;
        let setup_tx = setup_sidechain_tx(
            &setup.descriptor(),
            &vec![pegin_size; 500],
            &vec![pegin_size / 10; 50],
            pegin_size * 95,
        );
        manager.process_side_transaction(&DummyBitcoind, &setup_tx, 0)
            .expect("processing the setup tx");
        // expire all the outputs so they must be spent, leaving little
        // room for pegouts and change
        manager.txindex.insert_dummy_blocks_until(10000);

        let proposal = manager.propose_transaction(
            &HashSet::new(),
            &HashSet::new(),
            1000,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).unwrap();
        assert_eq!(proposal.inputs.len(), 222);
        assert_eq!(proposal.pegouts.len(), 3);
        assert_eq!(proposal.change.len(), 1);
        manager.check_proposal(&proposal).expect("proposal ok");

        // 7. Redo the maximum test limited by feepool, not weight
        let mut manager = setup.manager();
        manager.target_n_outputs = 10000;  // try to force change to be made
        let pegin_size = constants::MAXIMUM_CHANGE_OUTPUTS as u64
            * constants::MINIMUM_OPPORTUNISTIC_CHANGE;
        let setup_tx = setup_sidechain_tx(
            &setup.descriptor(),
            &vec![pegin_size; 500],
            &vec![pegin_size / 10; 50],
            100_000,
        );
        manager.process_side_transaction(&DummyBitcoind, &setup_tx, 0)
            .expect("processing the setup tx");
        // expire all the outputs so they must be spent, leaving little
        // room for pegouts and change
        manager.txindex.insert_dummy_blocks_until(10000);

        let proposal = manager.propose_transaction(
            &HashSet::new(),
            &HashSet::new(),
            1000,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).unwrap();
        assert_eq!(proposal.inputs.len(), 29);
        assert_eq!(proposal.pegouts.len(), 2);
        assert_eq!(proposal.change.len(), 1);
        manager.check_proposal(&proposal).expect("proposal ok");
    }

    fn serialization_roundtrip(m: &Manager) {
        let mut w: Vec<u8> = vec![];

        serde_json::to_writer(&mut w, m)
            .expect("serializing");
        let new_m = serde_json::from_reader(&w[..])
            .expect("deserializing");

        assert_eq!(*m, new_m);
    }

    #[test]
    fn coin_selection_fee_sorting() {
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();
        let signers = setup.peers();

        // Peg in 300k sat across two inputs which are each only large enough
        // to fund one pegout.
        let pegin_tx = setup_sidechain_tx(
            &setup.descriptor(),
            &[150_000, 150_000],
            &[],
            100_000,
        );
        let tx_iter = TxIterator::new(
            &pegin_tx,
            pegin_tx.txid(),
            manager.genesis_hash,
            manager.pegged_asset,
        );
        let pegins: Vec<bitcoin::OutPoint> = tx_iter
            .filter_map(|obj| if let TxObject::Pegin(data) = obj {
                Some(data.outpoint)
            } else {
                None
            })
            .collect();
        // Make a couple pegout transactions of value 100k but with different fees
        // and different ages.
        let pegout_tx = deserialize::<elements::Transaction>(&SIDE_TX_PEGOUT).unwrap();
        // check that this is the pegout tx we think it is
        assert_eq!(pegout_tx.output[0].minimum_value(), 100_000);
        assert!(pegout_tx.output[0].is_pegout());
        assert!(!pegout_tx.output[1].is_pegout());
        assert!(pegout_tx.output[2].is_fee());
        assert_eq!(pegout_tx.output[2].minimum_value(), 704);
        // create an alternate version with a higher fee
        let mut pegout_tx_high_fee = pegout_tx.clone();
        if let elements::confidential::Value::Explicit(x) = pegout_tx.output[0].value {
            pegout_tx_high_fee.output[0].value
                = elements::confidential::Value::Explicit(x - 1000);
        }
        if let elements::confidential::Value::Explicit(x) = pegout_tx.output[2].value {
            pegout_tx_high_fee.output[2].value
                = elements::confidential::Value::Explicit(x + 1000);
        }

        let rq_age = elements::OutPoint {
            txid: pegout_tx.txid(),
            vout: 0,
        };
        let rq_fee = elements::OutPoint {
            txid: pegout_tx_high_fee.txid(),
            vout: 0,
        };

        manager.process_side_transaction(&DummyBitcoind, &pegin_tx, 0).unwrap();
        manager.process_side_transaction(
            &DummyBitcoind,
            &pegout_tx,
            0,
        ).unwrap();
        manager.process_side_transaction(
            &DummyBitcoind,
            &pegout_tx_high_fee,
            10,  // 10 blocks younger than low-fee one
        ).unwrap();

        // Proposing at side_height 100 means the higher-fee one will win
        let proposal = manager.utxos.tx_proposal(
            &manager.consensus,
            &manager.fee_pool,
            &Some(pegins[1]).into_iter().collect(),
            &HashSet::new(),
            0,
            100,
            1000,
            1000,
            &|_| Ok(()),
            &signers,
            &vec![],
        ).unwrap().to_concrete();
        assert_eq!(proposal.pegouts, &[rq_fee]);

        // Proposing at side_height 10000 (or greater) means the older one
        // will win. Also, crazy-high heights will not cause overflows or
        // other panics.
        for height in &[10000, 10080, 12000, 25000, 1_000_000][..] {
            let proposal = manager.utxos.tx_proposal(
                &manager.consensus,
                &manager.fee_pool,
                &Some(pegins[1]).into_iter().collect(),
                &HashSet::new(),
                0,
                *height,
                1000,
                1000,
                &|_| Ok(()),
                &signers,
                &vec![],
            ).unwrap().to_concrete();
            assert_eq!(proposal.pegouts, &[rq_age]);
        }
    }

    #[test]
    fn multiple_pegouts_same_output_one_tx() {
        let mut input = bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::default(),
            sequence: bitcoin::Sequence::ZERO,
            script_sig: bitcoin::ScriptBuf::new(),
            witness: bitcoin::Witness::default(),
        };

        for count in [1, 2, 5, 10, 20].iter().cloned() {
            println!("running multiple_pegouts_same_output_one_tx with count {}", count);
            // Setup
            let setup = TestSetup::new(test_descriptor_1());
            let mut manager = setup.manager();

            let setup_tx = setup_sidechain_tx(
                &setup.descriptor(),
                &[1_000_000],
                &vec![5000; count],
                100_000,
            );
            manager.process_side_transaction(&DummyBitcoind, &setup_tx, 0).unwrap();

            let mut requests = vec![];
            let mut txouts = vec![];
            let tx_iter = TxIterator::new(
                &setup_tx,
                setup_tx.txid(),
                manager.genesis_hash,
                manager.pegged_asset,
            );
            for obj in tx_iter {
                match obj {
                    TxObject::Pegin(data) => {
                        input.previous_output = data.outpoint;
                    },
                    TxObject::Donation(..) => {},
                    TxObject::Fee(..) => {},
                    TxObject::Pegout(outpoint, data) => {
                        requests.push(outpoint);
                        txouts.push(bitcoin::TxOut {
                            value: Amount::from_sat(data.value),
                            script_pubkey: data.script_pubkey,
                        });
                    }
                }
            }

            // Single pegout
            let one_tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version::ONE,
                lock_time: LockTime::ZERO,
                input: vec![input.clone()],
                output: vec![txouts[0].clone()],
            };
            assert!(manager.self_tx_meta(&one_tx).unwrap().is_some(), "can't confirm tx");
            manager.utxos.record_conflicts(
                one_tx.txid(),
                &vec![input.previous_output].into_iter().collect(),
                vec![requests[0]].into_iter(),
            ).unwrap();

            // Record conflicts for the first pegout, but not any of the following ones
            assert_eq!(
                manager.lookup_pegout(&requests[0]).unwrap().required_conflicts,
                Some(input.previous_output).into_iter().collect::<HashSet<_>>()
            );
            for i in 1..count {
                assert_eq!(
                    manager.lookup_pegout(&requests[i]).unwrap().required_conflicts,
                    HashSet::new()
                );
            }

            // Many pegouts
            let mut n_tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version::ONE,
                lock_time: LockTime::ZERO,
                input: vec![input.clone()],
                output: vec![txouts[0].clone(); count],
            };
            assert!(manager.self_tx_meta(&n_tx).unwrap().is_some(), "can't confirm tx");
            manager.utxos.record_conflicts(
                n_tx.txid(),
                &vec![input.previous_output].into_iter().collect(),
                requests.iter().copied(),
            ).unwrap();

            // No change to conflicttracker state; we don't distinguish between transactions
            for outpoint in &requests {
                assert_eq!(
                    manager.lookup_pegout(outpoint).unwrap().required_conflicts,
                    Some(input.previous_output).into_iter().collect::<HashSet<_>>()
                );
            }

            // Too many pegouts
            n_tx.output.push(txouts[0].clone());
            assert_eq!(
                manager.self_tx_meta(&n_tx),
                Err(ProposalError::DuplicatePegoutDelivery {
                    output: txouts[0].clone(),
                    requests: requests.clone(),
                }),
            );

            // Check that a (single) unknown input means that this tx
            // is not a federation tx.
            n_tx.input[0].previous_output = Default::default();
            assert!(manager.self_tx_meta(&n_tx).unwrap().is_none());

            // No change to conflicttracker state
            for outpoint in &requests {
                assert_eq!(
                    manager.lookup_pegout(outpoint).unwrap().required_conflicts,
                    Some(input.previous_output).into_iter().collect::<HashSet<_>>()
                );
            }

            // Check that if the inputs are mixed known and unknown, the right
            // error is returned.
            let bad_tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version::ONE,
                lock_time: LockTime::ZERO,
                input: vec![
                    input.clone(),
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::default(),
                        sequence: bitcoin::Sequence::ZERO,
                        script_sig: bitcoin::ScriptBuf::new(),
                        witness: bitcoin::Witness::default(),
                    },
                ],
                output: vec![txouts[0].clone(); count],
            };
            assert_eq!(
                manager.self_tx_meta(&bad_tx),
                Err(ProposalError::UnknownInputs(vec![bad_tx.input[1].previous_output])),
            );
        }
    }

    #[test]
    fn multiple_pegouts_same_output_multiple_txes() {
        // Setup
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();

        let setup_tx = setup_sidechain_tx(
            &setup.descriptor(),
            &[200_000, 200_000],
            &vec![50_000; 5],
            150_000,
        );
        manager.process_side_transaction(&DummyBitcoind, &setup_tx, 0).unwrap();

        let mut inputs = vec![];
        let mut requests = vec![];
        let tx_iter = TxIterator::new(
            &setup_tx,
            setup_tx.txid(),
            manager.genesis_hash,
            manager.pegged_asset,
        );
        for obj in tx_iter {
            match obj {
                TxObject::Pegin(data) => {
                    inputs.push(data.outpoint);
                },
                TxObject::Donation(..) => {},
                TxObject::Fee(..) => {},
                TxObject::Pegout(outpoint, _) => {
                    requests.push(outpoint);
                }
            }
        }

        // Process 5 pegouts to the same destination across 2 transactions
        let first = transaction::ConcreteProposal {
            inputs: vec![inputs[0]],
            pegouts: vec![requests[0], requests[1], requests[2]],
            change: vec![Amount::from_sat(40_000)],
        };
        let second = transaction::ConcreteProposal {
            inputs: vec![inputs[1]],
            pegouts: vec![requests[3], requests[4]],
            change: vec![Amount::from_sat(90_000)],
        };

        // Refuse to sign second as it skips the first 3 requests
        if let Err(Error::BadProposal(
            ProposalError::SkippedPegout { request, previous }
        )) = manager.validate_proposal(&second, |_| Ok(()), false) {
            assert_eq!(request, requests[3]);
            assert_eq!(previous, requests[2]);
        } else {
            panic!("signed second tx");
        }

        // Sign first tx
        let first_tx = manager.validate_proposal(&first, |_| Ok(()), false)
            .expect("accept first proposal")
            .0;

        // Still refuse to sign second
        let manager_checkpoint = manager.clone();
        if let Err(Error::BadProposal(
            ProposalError::SkippedPegout { request, previous }
        )) = manager.validate_proposal(&second, |_| Ok(()), false) {
            assert_eq!(request, requests[3]);
            assert_eq!(previous, requests[2]);
        } else {
            panic!("signed second tx");
        }
        assert_eq!(manager, manager_checkpoint);

        manager.utxos.record_conflicts(
            first_tx.txid(), &first.input_set(), first.pegouts.iter().copied(),
        ).expect("error recording conflicts");

        // Confirm the first transaction
        process_main_transaction(&mut manager, &first_tx, 0, 1);

        // Now signing the second one should work
        let second_tx = manager.validate_proposal(&second, |_| Ok(()), false)
            .expect("accept second proposal")
            .0;
        manager.utxos.record_conflicts(
            second_tx.txid(), &second.input_set(), second.pegouts.iter().copied(),
        ).expect("error recording conflicts");
    }

    #[test]
    fn pegout_to_federation() {
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();

        // Set up a manager with a single pegout request whose destination
        // is the change address of the federation. We have no PAK proof
        // on this, which simulates a potential future network where PAK
        // proofs are not required.
        let mut setup_tx = setup_sidechain_tx(
            &setup.descriptor(),
            &[100_000],
            &[50_000],
            50_000,
        );

        let fed_spk = &manager.consensus.initial_permanent_descriptor().spk;
        println!("federation spk: {}", fed_spk);
        assert_eq!(setup_tx.output.len(), 2);
        setup_tx.output[0].script_pubkey = elements::script::Builder::new()
            .push_opcode(elements::opcodes::all::OP_RETURN)
            .push_slice(&manager.genesis_hash[..])
            .push_slice(fed_spk.as_bytes())
            .into_script();

        println!("new setup tx txid: {}", setup_tx.txid());
        assert_eq!(
            setup_tx.txid().to_string(),
            "953bf08976b05c82844db6cb250ad9cab89f2fd6f4cb0375650aa5be8ada9d44",
            "setup tx changed somehow",
        );
        manager.process_side_transaction(&DummyBitcoind, &setup_tx, 0).unwrap();

        // 1. Try proposing a transaction and ensure that the "change pegout"
        //    does not appear
        let error = manager.propose_transaction(
            &HashSet::new(),
            &HashSet::new(),
            100,
            &|_| Ok(()),
            &setup.peers(),
            &vec![],
        ).unwrap_err();
        if let Error::Utxo(utxotable::Error::EmptyProposal) = error {
            // good
        } else {
            panic!("produced a proposal without any valid pegouts");
        }

        // 2. Send the manager a proposal where the change pegout appears and
        //    ensure it's rejected
        let mut tx_iter = TxIterator::new(
            &setup_tx,
            setup_tx.txid(),
            manager.genesis_hash,
            manager.pegged_asset,
        );
        let utxo_outpoint;
        let request_outpoint;
        match tx_iter.next().unwrap() {
            TxObject::Pegin(data) => utxo_outpoint = data.outpoint,
            o => panic!("expected pegin, got {:?}", o),
        }
        match tx_iter.next().unwrap() {
            TxObject::Pegout(outpoint, request) => {
                assert_eq!(request.value, 50_000);
                let change_spk = &manager.consensus.initial_permanent_descriptor().spk;
                assert_eq!(request.script_pubkey, *change_spk);
                request_outpoint = outpoint;
            }
            o => panic!("expected pegout, got {:?}", o),
        }

        let proposal_pegout = transaction::ConcreteProposal {
            inputs: vec![utxo_outpoint],
            pegouts: vec![request_outpoint],
            change: vec![Amount::from_sat(40_000)],
        };
        if let Err(Error::BadProposal(
            ProposalError::UnknownPegout(outpoint)
        )) = manager.validate_proposal(&proposal_pegout, |_| Ok(()), false) {
            assert_eq!(outpoint, request_outpoint);
        } else {
            panic!("manager recognized pegout to change address")
        }

        // 3. Send the manager a proposal with an equivalent output, marked
        //    as change rather than a pegout, and ensure it's accepted
        let proposal_change = transaction::ConcreteProposal {
            inputs: vec![utxo_outpoint],
            pegouts: vec![],
            change: vec![Amount::from_sat(50_000), Amount::from_sat(40_000)],
        };
        let tx_change = manager.validate_proposal(&proposal_change, |_| Ok(()), false)
            .expect("accept change proposal")
            .0;
        assert!(manager.self_tx_meta(&tx_change).unwrap().is_some());
    }

    #[test]
    fn test_burn_fees_from_pegin() {
        //! We're going to have a chain with 0 BTC and a block with a pegin
        //! of which the fee is burned in the coinbase.

        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();
        let mut setup_tx = setup_sidechain_tx(
            &setup.descriptor(),
            &[10_000],
            &[4_000],
            5_000,
        );
        // Add fee output.
        setup_tx.output.push(elements::TxOut {
            asset: manager.pegged_asset,
            value: elements::confidential::Value::Explicit(1_000),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: elements::Script::new(),
            witness: elements::TxOutWitness::default(),
        });

        let coinbase = elements::Transaction {
            version: 0,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::default(),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::ZERO,
                asset_issuance: elements::AssetIssuance::default(),
                witness: elements::TxInWitness::default(),
            }],
            output: vec![elements::TxOut {
                asset: manager.pegged_asset,
                value: elements::confidential::Value::Explicit(1_000),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: elements::script::Builder::new()
                    .push_opcode(elements::opcodes::all::OP_RETURN)
                    .push_slice(&[42])
                    .into_script(),
                witness: elements::TxOutWitness::default(),
            }],
        };

        let block = elements::Block {
            header: elements::BlockHeader {
                version: 0,
                prev_blockhash: elements::BlockHash::all_zeros(),
                merkle_root: elements::TxMerkleNode::all_zeros(),
                time: 0,
                height: 1,
                ext: elements::BlockExtData::Proof {
                    challenge: elements::Script::new(),
                    solution: elements::Script::new(),
                },
            },
            txdata: vec![ coinbase, setup_tx ],
        };
        let tip = elements::BlockHeader {
            version: 0,
            prev_blockhash: block.block_hash(),
            merkle_root: elements::TxMerkleNode::all_zeros(),
            // Set tip time so the test doesn't wait for 5 seconds
            time: time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs() as u32,
            height: 1,
            ext: elements::BlockExtData::Proof {
                challenge: elements::Script::new(),
                solution: elements::Script::new(),
            },
        };

        /// A specific elements RPC for his test.
        struct SyncElements<'a> {
            block: &'a elements::Block,
            tip: &'a elements::BlockHeader,
        }

        impl<'a> Rpc for SyncElements<'a> {
            fn jsonrpc_query<T: serde::de::DeserializeOwned>(&self, query: &str,
                args: &[jsonrpc::serde_json::Value],
            ) -> Result<T, jsonrpc::Error> {
                println!("dummy elements rpc: {} args: {:?}", query, args);
                let response = match query {
                    "getblockhash" => {
                        assert_eq!(args[0].as_u64().expect("arg must be int"), 1);
                        format!("\"{}\"", self.block.block_hash())
                    }
                    "getbestblockhash" => {
                        format!("\"{}\"", self.tip.block_hash())
                    }
                    "getblock" => {
                        let hash = elements::BlockHash::from_str(args[0].as_str().unwrap()).unwrap();
                        assert_eq!(self.block.block_hash(), hash);
                        format!("\"{}\"", elements::encode::serialize_hex(self.block))
                    }
                    "getblockheader" => {
                        let hash = elements::BlockHash::from_str(args[0].as_str().unwrap()).unwrap();
                        assert_eq!(self.tip.block_hash(), hash);
                        format!("\"{}\"", elements::encode::serialize_hex(self.tip))
                    }
                    // Need to return 3 here to get block 1 to be processed.
                    "getblockcount" => "3".to_string(),
                    other => panic!("unexpected RPC command: {}", other),
                };
                println!("responding: {}", response);
                Ok(jsonrpc::serde_json::from_str(&response)?)
            }

            fn is_warming_up(&self, _: &str) -> Result<bool, jsonrpc::Error> {
                Ok(true)
            }
        }
        impl<'a> rpc::ElementsRpc for SyncElements<'a> {}

        let rpc = SyncElements {
            block: &block,
            tip: &tip,
        };
        manager.scan_sidechain(&DummyBitcoind, &rpc).expect("error scanning sidechain");
    }

    #[test]
    fn save_to_disk() {
        let cache_path = "/tmp/functionary_test_blockchain_save_to_disk";
        let _ = ::std::fs::remove_file(cache_path);

        // Quick test to test serialization to disk because serde_json has
        // some requirements that are not checked at compile-time.
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();
        manager.cache_file = cache_path.to_owned();
        manager.save_to_disk();

        let mut loaded_manager = setup.manager();
        loaded_manager.cache_file = cache_path.to_owned();
        loaded_manager.load_from_disk().expect("loading file from disk");
        assert_eq!(manager, loaded_manager);
    }

    #[test]
    fn deserialize_old_manager() {
        // regression test to ensure we can still deserialize old state file
        // test file from https://gl.blockstream.io/stevenroose/functionary/-/jobs/1135680
        let path = "sample_configs/blockchains-job1135680.json";
        let raw = std::fs::read_to_string(path).unwrap();
        let patched = raw.replace("thresh_m(", "multi(");
        let manager: Manager = serde_json::from_str(&patched).unwrap();
        assert_eq!(manager.genesis_hash.to_string(), "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206");
        assert_eq!(manager.utxos.main_utxos().len(), 2);
        assert_eq!(manager.txindex.n_in_flight_txs(), 1);
    }

    #[test]
    fn sample_cache_file() {
        use std::fs;

        let sample_file = "sample_configs/blockchains.json";
        let cache_path = "/tmp/functionary_test_blockchain_sample_cache_file";
        let _ = fs::remove_file(cache_path);

        // To regenerate this file, just run any of the integration tests, find a
        // `blockchains.json` file by searching the datadirs/ directory, and copy
        // that into functionary/sample_configs/
        let base_manager = {
            let mut m = TestSetup::new(test_descriptor_1()).manager();
            m.consensus = single_desc_consensus(miniscript::Descriptor::<tweak::Key>::from_str("\
                sh(wsh(or_d(multi(4,\
                     [46d14b1932e3]025438ba2c5597b58a72c14f604c5e7a62877208d4eb9214fec3f70ade3356b8db,\
                     [6ff19ed964fd]03567fc081d3e2a747cda66bcdb17f3ccb32651626f011c90e39c2c9122623c1be,\
                     [4a4043586028]039952df7a1f4de8a13d3a33e3f0164214d59af5582f875bcee01dca7f0fc5a6fd,\
                     [cf960f8414be]03a3a40fc66b7e38dc902194c8ab012b9cd5caf80685e7b7322e05db73b192a8cd,\
                     [c42ec540cf27]03ae894fda4822336520578b0ba5ad1d8c37c1a3195ca0f66847657c9148677a05),\
                     and_v(v:older(4032),multi(2,\
                         [untweaked]02aef2b8a39966d49183fdddaefdc75af6d81ea6d16f7aba745cc4855e88f83084,\
                         [untweaked]02141d452c3deeb937efff9f3378cd50bbde0543b77bbc6df6fc0e0addbf5578c5,\
                         [untweaked]03948d24a9622cb14b198aed0739783d7c03d74c32c05780a86b43429c65679def)))))\
            ").unwrap());
            m.txindex = txindex::TxIndex::new(0, 20);
            m
        };

        let first = {
            let mut manager = base_manager.clone();
            manager.cache_file = sample_file.to_owned();
            let manager_before_load = manager.clone();
            manager.load_from_disk().expect("loading file from disk");
            assert_ne!(manager, manager_before_load, "file failed to load");
            println!("Saving new loaded chains file to: {}", cache_path);
            manager.cache_file = cache_path.to_owned();
            manager.save_to_disk();
            manager
        };

        let second = {
            let mut manager = base_manager.clone();
            manager.cache_file = cache_path.to_owned();
            let manager_before_load = manager.clone();
            manager.load_from_disk().expect("loading file from disk");
            assert_ne!(manager, manager_before_load, "file failed to load");
            manager
        };

        assert_eq!(first, second);

        // In order to trigger on any unexpected change in the generated file,
        // do some rudimentary checks on the actual cache files.

        // We first create a file with a pretty JSON version of the cache file,
        // so that it can be looked at if either check fails.
        let created = fs::File::open(cache_path).unwrap();
        let created_len = created.metadata().unwrap().len();
        let created_pretty = {
            let mut path = std::path::PathBuf::from(cache_path);
            path.set_file_name("functionary_test_blockchain_sample_cache_file_pretty");
            let created_json = serde_json::from_reader::<_, serde_json::Value>(
                &mut io::BufReader::new(created),
            ).unwrap();
            let file = fs::File::create(&path).unwrap();
            serde_json::to_writer_pretty(&mut io::BufWriter::new(file), &created_json).unwrap();
            path
        };
        println!("Created cache file can be found at {}", cache_path);
        println!("Created cache file in pretty JSON can be found at {}", created_pretty.display());

        let original_len = fs::metadata(sample_file).unwrap().len();
        let diff = original_len as i64 - created_len as i64;
        assert_eq!((1087548, 23603), (created_len, diff));
        // NB can't use checksum because of randomness in hashmap ordering
    }

    #[test]
    fn error_on_unowned_input() {
        let unknown_input = bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::default(),
            sequence: bitcoin::Sequence::ZERO,
            script_sig: bitcoin::ScriptBuf::new(),
            witness: bitcoin::Witness::default(),
        };
        let mut known_input = unknown_input.clone();

        // Setup
        let setup = TestSetup::new(test_descriptor_1());
        let mut manager = setup.manager();
        let tx = setup_sidechain_tx(&setup.descriptor(), &[100_000], &[50_000], 50_000);
        manager.process_side_transaction(&DummyBitcoind, &tx, 0).unwrap();
        let tx_iter = TxIterator::new(&tx, tx.txid(), manager.genesis_hash, manager.pegged_asset);
        for obj in tx_iter {
            match obj {
                TxObject::Pegin(data) => {
                    known_input.previous_output = data.outpoint;
                },
                _ => {},
            }
        }
        let bad_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![known_input, unknown_input.clone()],
            output: vec![],
        };

        let utxos = &mut manager.utxos;
        let fee_pool = &mut manager.fee_pool;
        assert_eq!(
            Manager::tx_meta(utxos, fee_pool, &manager.consensus, &bad_tx, 0),
            Err(ProposalError::UnknownInputs(vec![unknown_input.previous_output])),
        );
    }

    #[test]
    fn test_extract_mainchain_commitment() {
        use std::str::FromStr;

        let hash = sha256d::Hash::hash(&[0]);
        let asset_id = AssetId::from_slice(hash.to_byte_array().as_slice()).unwrap();

        let op_return = |data: &[u8]| -> elements::TxOut {
            let script = elements::script::Builder::new()
                .push_opcode(elements::opcodes::all::OP_RETURN)
                .push_slice(data)
                .into_script();
            elements::TxOut {
                asset: elements::confidential::Asset::Explicit(asset_id),
                value: elements::confidential::Value::Explicit(1000),
                nonce: elements::confidential::Nonce::Null,
                witness: elements::TxOutWitness::default(),
                script_pubkey: script,
            }
        };

        let commitment = bitcoin::BlockHash::hash(&[1, 2, 3]);
        let block = elements::Block {
            header: empty_elements_block().header.clone(),
            txdata: vec![
                elements::Transaction {
                    version: 0,
                    lock_time: elements::LockTime::ZERO,
                    input: vec![elements::TxIn {
                        previous_output: elements::OutPoint::default(),
                        is_pegin: false,
                        script_sig: elements::Script::new(),
                        sequence: elements::Sequence::ZERO,
                        asset_issuance: elements::AssetIssuance::default(),
                        witness: elements::TxInWitness::default(),
                    }],
                    output: vec![
                        elements::TxOut {
                            asset: elements::confidential::Asset::Explicit(asset_id),
                            value: elements::confidential::Value::Explicit(0),
                            nonce: elements::confidential::Nonce::Null,
                            witness: elements::TxOutWitness::default(),
                            script_pubkey: elements::Address::from_str(
                                "PwiVCD8eumhW33Qztw5MXXxdu72xvjFnLX"
                            ).unwrap().script_pubkey(),
                        },
                        op_return(&[0]),
                        op_return(&constants::MAINCHAIN_COMMITMENT_HEADER),
                        op_return(
                            &constants::MAINCHAIN_COMMITMENT_HEADER.iter().copied()
                                .chain(sha256d::Hash::hash(&[3])[..].iter().copied())
                                .chain([0].iter().copied())
                                .collect::<Vec<_>>(),
                        ),
                        op_return(
                            &constants::MAINCHAIN_COMMITMENT_HEADER.iter().copied()
                                .chain(commitment.to_byte_array().iter().copied())
                                .collect::<Vec<_>>(),
                        ),
                        op_return(
                            &constants::MAINCHAIN_COMMITMENT_HEADER.iter().copied()
                                .chain(sha256d::Hash::hash(&[4])[..].iter().copied())
                                .collect::<Vec<_>>(),
                        ),
                    ],
                }
            ],
        };
        assert!(block.txdata[0].is_coinbase());
        assert_eq!(extract_mainchain_commitment(&block), Some(commitment));
    }

    #[test]
    pub fn test_is_main_synced() {
        use std::cell::Cell;

        use bitcoin;

        //use bitcoin::consensus::{deserialize, Decodable};
        //use jsonrpc::serde_json::{Number, Map, Value};

        // Define dummy bitcoind rpc with scripted rpc responses
        struct DummyBitcoind {
            prev_calls: Cell<u8>
        }

        impl DummyBitcoind {
            fn new() -> DummyBitcoind {
                DummyBitcoind {
                    prev_calls: Cell::new(0)
                }
            }
        }

        impl Rpc for DummyBitcoind {
            fn jsonrpc_query<T: serde::de::DeserializeOwned>(
                &self,
                query: &str,
                _args: &[jsonrpc::serde_json::Value],
            ) -> Result<T, jsonrpc::Error> {
                if query == "getblockhash" {
                    Ok(jsonrpc::serde_json::from_str(
                        "\"0000000000000000000000000000000000000000000000000000000000000000\""
                    )?)
                } else {
                    panic!("dummy bitcoin does not understand RPC call {}", query);
                }
            }

            fn is_warming_up(&self, _: &str) -> Result<bool, jsonrpc::Error> {
                Ok(true)
            }
        }

        impl rpc::BitcoinRpc for DummyBitcoind {
            fn raw_header(&self, _hash: bitcoin::BlockHash) -> Result<bitcoin::block::Header, jsonrpc::Error> {
                // This test uses the duration of 24 hours. So, all time diffs <=
                // 24 hrs +/- epsilon should be considered synced.
                // Anything else should be considered not synced
                let epsilon = 60; // wide enough for CI latency
                let system_block_time = match self.prev_calls.get() {
                    0 => SystemTime::now() - Duration::from_secs(10), // 10 seconds (synced)
                    1 => SystemTime::now() - Duration::from_secs(60 * 60), // 1 hour (synced)
                    2 => SystemTime::now() - Duration::from_secs((60 * 60 * 24) - 1 - epsilon), // almost one day (synced)
                    3 => SystemTime::now() - Duration::from_secs(60 * 60 * 25), // 25 hours (not synced)
                    4 => SystemTime::now() - Duration::from_secs(60 * 60 * 24 * 4), // 4 weeks (not synced)
                    5 => SystemTime::now() + Duration::from_secs(60 * 60), // 1 hour in the future (block time is ahead of our time) (synced)
                    _ => panic!("unexpected call to getblockheader rpc")
                };
                let unix_block_time = system_block_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
                self.prev_calls.set(self.prev_calls.get() + 1);

                // A header with dummy fields, except for the time field.
                Ok(bitcoin::block::Header {
                    version: bitcoin::block::Version::ONE,
                    prev_blockhash: bitcoin::BlockHash::from_str(&vec!["0"; 64].into_iter().collect::<String>()).unwrap(),
                    merkle_root: bitcoin::TxMerkleNode::from_str(&vec!["0"; 64].into_iter().collect::<String>()).unwrap(),
                    time: unix_block_time as u32,
                    bits: CompactTarget::from_consensus(0),
                    nonce: 0
                })
            }
        }

        // Run the test
        let setup = TestSetup::new(test_descriptor_1());
        let manager = setup.manager();

        let rpc = DummyBitcoind::new();
        let duration = Duration::from_secs(60 * 60 * 24);
        assert_eq!(manager.is_main_synced(&rpc, duration).unwrap(), true);
        assert_eq!(manager.is_main_synced(&rpc, duration).unwrap(), true);
        assert_eq!(manager.is_main_synced(&rpc, duration).unwrap(), true);
        assert_eq!(manager.is_main_synced(&rpc, duration).unwrap(), false);
        assert_eq!(manager.is_main_synced(&rpc, duration).unwrap(), false);
        assert_eq!(manager.is_main_synced(&rpc, duration).unwrap(), true);
    }
}
