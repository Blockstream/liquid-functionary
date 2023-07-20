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


//! # Withdraw Watcher
//! This implements a 5-of-7 rotating consensus for signing withdrawal transactions
//!

pub mod blockchain;
pub mod config;
pub mod transaction;
pub mod utils;

pub use self::blockchain::{fee, utxotable, txindex};

use std::{fmt, mem, thread};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use bitcoin;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{Hash, sha256, sha256d};
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};
use bitcoin::util::sighash::SighashCache;
use jsonrpc;

use common::{constants, rollouts, BlockHeight};
use common::hsm::WatchmanSignStatus;
use common::rollouts::ROLLOUTS;
use common::hsm as HsmCommon;
use descriptor::TweakableDescriptor;
use hsm;
use logs::ProposalError;
use message::{self, Message};
use network::{self, NetworkCtrl};
use peer::{self, PeerManager};
use rotator::{self, RoundStage};
use rpc::{self, Rpc, BitcoinRpc, ElementsRpc, RPC_VERIFY_ALREADY_IN_CHAIN};
use self::transaction::{assemble_tx, TransactionSignatures};
use self::utxotable::SpendableUtxo;
use utils::InChain;
use watchman::config::Configuration;

/// The current state of the watchman state machine
#[derive(Debug)]
pub enum State {
    /// We are scanning chains, etc., and have not yet joined consensus
    Starting,
    /// We are master this round, have no proposal, and will send an
    /// `Idle` message
    WillSendIdle,
    /// We are master this round and have a transaction to propose
    Proposing(transaction::ConcreteProposal),
    /// We have received (or created) and accepted a proposal
    HasProposal {
        /// The proposal we're working on. Currently mostly kept for logging.
        proposal: transaction::ConcreteProposal,
        /// The transaction corresponding to the proposal
        unsigned_tx: bitcoin::Transaction,
        /// Input data (descripter, value, etc) needed for signing
        inputs: Vec<SpendableUtxo>,
    },
    /// We have signed the proposal.
    Signed {
        /// The proposal we're working on. Currently mostly kept for logging.
        proposal: transaction::ConcreteProposal,
        /// The transaction corresponding to the proposal
        unsigned_tx: bitcoin::Transaction,
        /// Input data (descripter, value, etc) needed for signing
        inputs: Vec<SpendableUtxo>,
        /// My own signatures on the proposed tx
        my_sigs: TransactionSignatures,
    },
    /// We have not yet received a proposal
    NoProposal,
    /// We have nothing to do this round
    Idle,
    /// We errored out and are sitting out this round
    Error(Error)
}

/// Generic error enum
#[derive(Debug)]
pub enum Error {
    /// A problem with a proposal
    BadProposal(ProposalError),
    /// Syncing with the blockchains failed
    SyncFailed(blockchain::Error),
    /// Failed to validate a proposal
    FailedToValidate(blockchain::Error),
    /// Failed to sign a tx
    FailedToSign(blockchain::Error),
    /// Failed to sign a tx
    HsmFailedToSign(HsmCommon::Error),
    /// Failed to make a tx proposal for our round
    FailedToPropose(blockchain::Error),
    /// Not enough peers present to start a round.
    NotEnoughPeersPresent(usize, usize),
    /// Master sent a duplicate proposal.
    DuplicateProposal(peer::Id),
    /// We're not ready to do whatever was requested
    NotReady,
    /// Error while updating the HSM.
    UpdateHsm(common::hsm::Error),
    /// Error fetching any resource from any chain.
    ChainUnavailable(jsonrpc::Error),
}

impl Error {
    /// Converter for proposal validation errors.
    fn validating(e: blockchain::Error) -> Error {
        match e {
            blockchain::Error::BadProposal(e) => Error::BadProposal(e),
            blockchain::Error::Hsm(HsmCommon::Error::ReceivedNack(n))
                if n == HsmCommon::Command::NackBadData =>
            {
                Error::BadProposal(ProposalError::HsmRefusedPak {
                    nack_code: n as u8,
                    nack_name: format!("{:?}", n),
                })
            }
            e => Error::FailedToValidate(e),
        }
    }
    /// Converter for proposal signing errors.
    fn signing(e: blockchain::Error) -> Error {
        match e {
            blockchain::Error::BadProposal(e) => Error::BadProposal(e),
            e => Error::FailedToSign(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::BadProposal(ref e) => write!(f, "bad proposal: {}", e),
            Error::SyncFailed(ref e) => write!(f, "sync failed: {}", e),
            Error::FailedToValidate(ref e) => write!(f, "failed to validate: {}", e),
            Error::FailedToSign(ref e) => write!(f, "failed to sign: {}", e),
            Error::HsmFailedToSign(ref e) => write!(f, "HSM failed to sign: {}", e),
            Error::FailedToPropose(ref e) => write!(f, "failed to propose a tx: {}", e),
            Error::NotEnoughPeersPresent(m, n) => {
                write!(f, "only {} of {} peers present, can't start round", m, n)
            }
            Error::DuplicateProposal(p) => write!(f, "duplicate proposal from master {}", p),
            Error::NotReady => f.write_str("not yet ready to perform"),
            Error::UpdateHsm(ref e) => write!(f, "updating HSM: {}", e),
            Error::ChainUnavailable(ref e) => write!(f, "blockchain unavailable: {}", e),
        }
    }
}

impl std::error::Error for Error {}

/// The main watcher structure
pub struct Watchman {
    /// Global configuration
    config: Configuration,
    /// Secp context for verifying signatures
    secp: Secp256k1<secp256k1::VerifyOnly>,
    /// List of all peers
    peers: peer::List,
    /// The set of signers in all our existing UTXOs.
    signers: HashSet<peer::Id>,
    /// Handle to bitcoind
    bitcoind: rpc::Bitcoin,
    /// Handle to sidechaind
    sidechaind: rpc::Elements,
    /// The amount of confirmations needed for a mainchain tx
    /// to be considered finalized.
    n_mainchain_confirmations: BlockHeight,
    /// State of this peer
    state: State,
    /// Manager of the peers.
    peer_mgr: PeerManager<bitcoin::Txid, TransactionSignatures>,
    /// Number of rounds since we started
    round_count: u32,
    /// State of the blockchains and our coins on them
    blockchain_manager: blockchain::Manager,
    /// Newest half-confirmed block in the mainchain, as we see it
    /// If peers agree on this they must agree on last_confirmed_hash as well
    half_confirmed_mainchain_hash: bitcoin::BlockHash,
    /// Newest confirmed block of the sidechain, as we see it
    sidechain_hash: elements::BlockHash,
    /// The root of the dynafed params we last build the peer list for.
    /// This avoids doing the work every round.
    last_dynafed_root: sha256::Midstate,
    /// Security module used for signing
    hsm: Box<dyn hsm::SecurityModule>,
    /// Whether our HSM is dynafed-active or not.
    hsm_dynafed: bool,

    /// While we are in the process of rolling out HSM support for
    /// non-CSV-tweaked change outputs, we keep track of which script
    /// each peer is using.
    peer_uses_tweaked_change: HashMap<peer::Id, bool>,
}

impl Watchman {
    /// Create a new withdraw watcher
    pub fn new(config: Configuration, cache_file: String) -> Watchman {
        // Perform some sanity checks on the configuration.
        config.sanity_check().expect("invalid config (failed sanity check)");

        // Create RPC connections and check that they successfully warm up.
        let bitcoind = rpc::Bitcoin::new(
            config.local.bitcoind_rpc_url.clone(),
            Some(config.local.bitcoind_rpc_user.clone()),
            Some(config.local.bitcoind_rpc_pass.clone()),
        );
        let sidechaind = rpc::Elements::new(
            config.local.sidechaind_rpc_url.clone(),
            Some(config.local.sidechaind_rpc_user.clone()),
            Some(config.local.sidechaind_rpc_pass.clone()),
        );

        // Choose which security module to use
        let hsm = match config.local.hsm_socket {
            Some(ref path) => Box::new(hsm::LiquidHsm::new(path.clone())) as Box<dyn hsm::SecurityModule>,
            None => Box::new(hsm::LocalWatchman::new(
                PathBuf::from(&cache_file).parent().unwrap(),
                config.node.signing_secret_key.unwrap(),
            )) as Box<dyn hsm::SecurityModule>
        };

        // Check that both RPC ports work and that both daemons are warmed up.
        loop {
            let is_bitcoind_warming_up = bitcoind.is_warming_up("bitcoind").expect("bitcoind connection");
            let is_sidechaind_warming_up = sidechaind.is_warming_up("sidechaind").expect("sidechaind connection");
            if !(is_bitcoind_warming_up || is_sidechaind_warming_up) {
                break;
            }
            thread::sleep(Duration::from_secs(5));
        }

        //Wait until the tip of the sidechain is at least 1 as even in networks starting with dynafed
        //active it is only enabled after there is at least 1 block on top of the genesis block
        loop {
            match sidechaind.block_count() {
                Ok(count) => {
                    if count > 0 {
                        break;
                    }
                }
                Err(e) => {
                    slog!(Error, daemon: "sidechaind", action: "wait for first block".to_owned(),
                            error: &e
                        );
                }
            }
            thread::sleep(Duration::from_secs(5));
        }

        // `blockchain_info()` will return an error pre-dynafed because it expects there to be an
        // `epoch_length` field in the rpc response.
        let epoch_length = match sidechaind.blockchain_info() {
            Ok(info) => info.epoch_length,
            Err(_e) => {
                match config.consensus.predynafed_epoch_length {
                    None => panic!("Starting on pre-dynafed network, must provide `predynafed_epoch_length by config"),
                    Some(epoch_length) => {
                        log!(Info, "Setting a pre-dynafed epoch length from config of {}", epoch_length);
                        epoch_length
                    }
                }
            }
        };

        // Learn metadata about the sidechain
        let sidechain_info = sidechaind.sidechain_info()
            .expect("failed to get sidechain info from sidechain daemon");
        let n_mainchain_confirmations = sidechain_info.pegin_confirmation_depth
            .unwrap_or(config.consensus.fallback_mainchain_confirmations
                .expect("no fallback mainchain confirms provided")
            );
        log!(Info, "using n_mainchain_confirmations: {}", n_mainchain_confirmations);

        // Get public_key from HSM. Put this in a retry loop to deal with failed attempts.
        // loop time-out time is MAX_PUBKEY_RETRIES * (WAIT_TIME + public_key() return time)
        const MAX_PUBKEY_RETRIES: u32 = 20;
        const WAIT_TIME: Duration = Duration::from_secs(5);
        let mut tries = 0u32;
        let public_key = loop {
            match hsm.public_key() {
                Ok(t) => break t,
                Err(e) => {
                    tries += 1;
                    if tries == MAX_PUBKEY_RETRIES {
                        panic!("Could not retrieve public_key from HSM after {} tries, aborting!", MAX_PUBKEY_RETRIES)
                    }
                    slog!(PublicKeyRetrievalFailed, error: e.to_string());
                    thread::sleep(WAIT_TIME);
                    continue;
                }
            }
        };

        // Probe if we have an old or a new HSM.
        let hsm_dynafed = match hsm.set_witness_script(&bitcoin::Script::new()) {
            Ok(_) => panic!("this should not be possible with an empty script.."),
            Err(common::hsm::Error::ReceivedNack(common::hsm::Command::NackNotAllowed)) => {
                log!(Info, "our HSM supports dynafed");
                true
            }
            Err(common::hsm::Error::ReceivedNack(common::hsm::Command::NackBadData)) => {
                log!(Info, "our HSM doesn't support dynafed yet");
                false
            }
            Err(e) => {
                log!(Error, "Got an unexpected response from HSM version probe: {:?}", e);
                panic!("Got an unexpected response from HSM version probe: {:?}", e);
            }
        };

        // The code above causes two errors in the HSM and when all HSMs are
        // upgraded it can be removed, as should the whitelist entries for
        // these errors be removed:
        //   "buf_read_consume: buf_read_consume: Tried to read from empty buffer",
        //   "hsm_validate_change_script: CHECK failed: buf_read_consume"
        let _ = rollouts::HsmCsvTweak::FullHsmSupport;

        let mut blockchain_manager = blockchain::Manager::new(
            config.consensus.fallback_fee_rate,
            config.node.main_skip_height,
            config.node.n_main_outputs,
            public_key,
            sidechain_info,
            config.heartbeat(),
            cache_file,
            n_mainchain_confirmations,
            epoch_length,
        );
        // Throw away errors from `load_from_disk` as they are ultimately harmless,
        // they just cause a rescan,
        let _ = blockchain_manager.load_from_disk();
        blockchain_manager.set_epoch_length(epoch_length);

        // Add new descriptors from the config file to the consensus tracker.
        let descriptors = config.consensus.cpes.iter().map(|e| {
            (e.start as BlockHeight, config.typed_watchman_descriptor(&e.wm_descriptor).into())
        }).collect::<Vec<_>>();
        log!(Info, "Updating consensus tracker with descriptors from config: {:?}", descriptors);
        blockchain_manager.update_known_descriptors(descriptors);

        // Regression 2021-03-30: check that, after loading from disk, the public key
        //  we cached (and use for computing key tweaks) matches the one from the HSM
        if blockchain_manager.tweak_pubkey() != public_key {
            panic!(
                "The HSM public key {} does not match the blockchains.json public key {}. \
                 Please remove blockchains.json and restart the functionary (this will \
                 trigger a multi-hour rescan of both blockchains).",
                public_key,
                blockchain_manager.tweak_pubkey(),
            );
        }

        log!(Info, "current rollouts: {:?}", *ROLLOUTS);

        // Return
        Watchman {
            secp: Secp256k1::verification_only(),
            bitcoind,
            sidechaind,
            n_mainchain_confirmations,
            state: State::Starting,
            peer_mgr: PeerManager::new(config.my_id()),
            peers: peer::Map::empty(config.my_id()),
            signers: HashSet::new(),
            blockchain_manager,
            round_count: 0,
            half_confirmed_mainchain_hash: bitcoin::BlockHash::default(),
            sidechain_hash: elements::BlockHash::default(),
            last_dynafed_root: sha256::Midstate::default(),
            hsm: hsm,
            hsm_dynafed: hsm_dynafed,
            peer_uses_tweaked_change: HashMap::new(),
            config
        }
    }

    /// Do startup tasks (scanning both blockchains to learn current state)
    pub fn startup(&mut self) -> Result<(), Error> {
        slog!(WatchmanStartupStarted);

        loop {
            // Scan both blockchains to finish bringing us up to speed
            self.blockchain_manager.update_from_rpc(&self.bitcoind, &self.sidechaind)
                .map_err(Error::SyncFailed)?;
            // Once caught up, save state out
            self.blockchain_manager.save_to_disk();

            // Provide new data to the HSM.
            if self.update_hsm()? {
                // The HSM reports that it can sign txs.
                break;
            }

            thread::sleep(Duration::from_secs(10));
        }

        slog!(WatchmanStartupFinished);
        Ok(())
    }

    /// Count the number of peers that precommitted to the same hash.
    /// It only makes sense to call this for txids we also precommit to.
    pub fn tally_precommitments(&self, txid: bitcoin::Txid) -> (usize, Vec<peer::Id>) {
        let mut agreed = 1; // Include ourselves
        let mut bad_peers = vec![];

        // For precommits we only look at the consensus peers,
        // we don't care about the opinion of older signers.
        for (id, status) in self.peer_mgr.statuses().consensus_without_me() {
            match status.state {
                peer::State::Precommit(peer_txid) |
                peer::State::SentSignatures(peer_txid, _) => {
                    if peer_txid == txid {
                        agreed += 1;
                    } else {
                        bad_peers.push(id);
                    }
                }
                _ => {
                    bad_peers.push(id);
                }
            }
        }
        return (agreed, bad_peers)
    }

    /// Send new headers to the HSM.
    ///
    /// Returns true when the HSM reports it is ready to sign txs.
    fn update_hsm(&mut self) -> Result<bool, Error> {
        if !self.hsm_dynafed {
            // Do what we have to do for an old HSM.
            // Remove this section when HSM support is rolled out.
            assert_eq!(ROLLOUTS.hsm_csv_tweak, rollouts::HsmCsvTweak::Legacy);
            let change_desc = self.blockchain_manager.consensus().initial_permanent_descriptor();
            match self.hsm.set_witness_script(change_desc.csv_tweaked_witness_script.as_ref().unwrap()) {
                Ok(_)  => log!(Debug, "Set HSM witness script"),
                Err(e) => log!(Error, "Failed to set HSM witness script: {}", e)
            }
            let pak = self.sidechaind.pak_list().map_err(Error::ChainUnavailable)?;
            if let Err(e) = self.hsm.authorization_master_keys_replace(&pak) {
                log!(Warn, "Failed to set authorization master keys: {}",  e);
            }
            return Ok(true);
        }

        let state = self.hsm.get_watchman_state().map_err(Error::UpdateHsm)?;
        log!(Debug, "HSM state: {:?}", state);
        let current_height = self.sidechaind.block_count().map_err(Error::ChainUnavailable)?;

        let next_height = if let Some(last) = state.last_header {
            let ret = self.sidechaind.block_confirm_status(last).map_err(Error::ChainUnavailable)?;
            let (height, confirmations) = unwrap_opt_or!(ret, {
                log!(Info, "HSM has newer headers than our sidechain daemon, still syncing. \
                    Last header known by hsm: {}", last,
                );
                return Ok(false);
            });

            if confirmations < 1 {
                panic!("HSM has a header that is no longer in the chain: {}", last);
            }
            height + 1
        } else {
            // We haven't sent any headers yet, so we are going to send the first header.
            // The first header needs to be an epoch multiple, but since the HSM needs to have at
            // least one full epoch before it can be operational, we're going to try start sending
            // one epoch before that.

            let epoch_length = self.blockchain_manager.dynafed_epoch_length();

            let epoch_start = (current_height / epoch_length) * epoch_length;

            // Make sure dynafed is active.
            let header = self.sidechaind.raw_header_at(epoch_start).map_err(Error::ChainUnavailable)?;
            if !header.is_dynafed() {
                log!(Info, "Can't send headers to HSM yet, dynafed is not yet active...");
                return Ok(false);
            }

            // Try to go one epoch earlier if possible.
            let start = if epoch_start > epoch_length {
                let prev = epoch_start - epoch_length;

                // Only if dynafed is already active at this height.
                let header = self.sidechaind.raw_header_at(prev).map_err(Error::ChainUnavailable)?;
                if header.is_dynafed() {
                    prev
                } else {
                    epoch_start
                }
            } else {
                epoch_start
            };
            log!(Info, "Going to send header for block {} as HSM's first block header", start);
            start
        };

        log!(Debug, "Syncing HSM headers {}..={}", next_height, current_height);
        for height in next_height ..= current_height {
            let header = self.sidechaind.raw_header_at(height).map_err(Error::ChainUnavailable)?;
            let hash = header.block_hash();

            // If somehow we're not yet at dynafed, just return and come back later.
            if !header.is_dynafed() {
                log!(Error, "dynafed is not active yet, can't sync HSM");
                return Ok(false);
            }

            slog!(HsmSendingHeader, height: height, hash: hash,
                header_hex: elements::encode::serialize_hex(&header),
            );
            if let Err(e) = self.hsm.send_header(&header) {
                match e {
                    common::hsm::Error::ReceivedNack(common::hsm::Command::NackInvalid) |
                        common::hsm::Error::ReceivedNack(common::hsm::Command::NackNotAllowed) =>
                    {
                        slog!(HsmRefusedHeader, height: height, hash: hash, error: e.to_string());
                    }
                    common::hsm::Error::ReceivedNack(_) => {
                        slog!(HsmErrorOnHeader, height: height, hash: hash, error: e.to_string());
                    }
                    _ => log!(Error, "error sending to HSM: {}", e),
                }
                return Err(Error::UpdateHsm(e));
            } else {
                slog!(HsmAcceptedHeader, height: height, hash: hash);
            }
        }

        // If the state before syncing was not CanSign, ask state again.
        if state.sign_status != WatchmanSignStatus::CanSign {
            let new_state = self.hsm.get_watchman_state().map_err(Error::UpdateHsm)?;
            if new_state.sign_status != WatchmanSignStatus::CanSign {
                log!(Info, "HSM reports non-ready state '{:?}'", new_state.sign_status);
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check if we have enough pre-committed peers to sign.
    /// If `me` is present in the peer status list, it adds 1 regardless
    /// of the peer's state.
    pub fn sufficient_precommitments(&self, txid: bitcoin::Txid) -> bool {
        let (agreed, _) = self.tally_precommitments(txid);
        agreed >= self.config.node.precommit_threshold
    }

    fn validate_proposal(
        &self,
        proposal: &transaction::ConcreteProposal,
        check_pak: bool,
        master: peer::Id,
    ) -> Result<(bitcoin::Transaction, Vec<SpendableUtxo>), Error> {
        let hsm = &*self.hsm; // Need to borrow `self.hsm` outside the following
                              // closure to avoid conflict with lifetime of
                              // borrow of `self.blockchain_manager`

        // If I am the master then suggest `blockchain_manager` use it and let `blockchain_manager.validate_proposal(...)`
        // decide if I support it. Otherwise check the master against our `peer_uses_tweaked_change` list
        let use_csv_tweaked_change = (master == self.peers.my_id() && ROLLOUTS.hsm_csv_tweak == rollouts::HsmCsvTweak::Legacy)
            || self.peer_uses_tweaked_change.get(&master).copied().unwrap_or(false);

        self.blockchain_manager.validate_proposal(proposal,
            |pegout| {
                if check_pak {
                    hsm.authorized_addresses_add(
                        &pegout.dest_pubkey,
                        &pegout.authorization_proof,
                    )
                } else {
                    Ok(())
                }
            },
            use_csv_tweaked_change,
        ).map_err(Error::validating)
    }

    fn try_commit(&mut self,
        round_stage: RoundStage,
        proposal: &transaction::ConcreteProposal,
        unsigned_tx: &bitcoin::Transaction,
        inputs: &Vec<SpendableUtxo>,
    ) -> Result<Option<TransactionSignatures>, Error> {
        let txid = unsigned_tx.txid();

        // NB Because we might have received some signatures from old peers and
        // stored those with the zero txid, let's replace those.
        self.peer_mgr.replace_empty_commits(txid);

        if !self.sufficient_precommitments(txid) {
            return Ok(None);
        }

        log!(Info, "Comitting to tx {}", txid);

        self.blockchain_manager.prepare_to_sign(proposal, unsigned_tx, &inputs)
            .map_err(Error::signing)?;
        // Once tx is marked, write state to disk
        self.blockchain_manager.save_to_disk();

        slog!(SigningTx, unsigned_txid: unsigned_tx.txid());
        let our_sigs = self.hsm.sign_segwit_transaction(&unsigned_tx, &inputs)
            .map_err(Error::HsmFailedToSign)?;

        log!(Info, "Signed tx.");

        log!(Debug, "Sending tx signatures to peers.");
        self.peer_mgr.broadcast_tx_signatures(round_stage, &our_sigs);
        Ok(Some(our_sigs))
    }

    fn broadcast_valid_transaction(&self, tx: &bitcoin::Transaction) -> bool {
        match self.bitcoind.send_tx(tx) {
            Ok(_) => true,
            Err(jsonrpc::Error::Rpc(jsonrpc::error::RpcError{code, ..})) if code == RPC_VERIFY_ALREADY_IN_CHAIN => {
                log!(Debug, "Re-broadcasted tx that was already confirmed: {}", tx.txid());
                true
            },
            Err(e) => {
                log!(Error, "Broadcasting failed (sendraw): {}", e);
                false
            },
        }
    }

    /// Finish the round by constructing a tx from the proposal and
    /// the signatures, and broadcasting it to the network.
    fn finish_and_submit_proposal(
        &mut self,
        proposal: transaction::ConcreteProposal,
        unsigned_tx: bitcoin::Transaction,
        inputs: Vec<SpendableUtxo>,
        my_sigs: TransactionSignatures,
    ) {
        // Collect the signatures of ourself and peers.
        let sigs = {
            let mut ret = HashMap::with_capacity(self.peers.len() + 1);
            // Add our own signature.
            ret.insert(self.peers.my_id(), &my_sigs);
            // Add peers' signatures.
            for (peer, status) in self.peer_mgr.statuses().without_me() {
                if let peer::State::SentSignatures(_, ref sigs) = status.state {
                    ret.insert(peer, sigs);
                }
            }
            log!(Trace, "collected signatures: {:?}", ret);
            ret
        };

        let mut shc = SighashCache::new(&unsigned_tx);
        let signed_tx = match assemble_tx(&self.secp, &unsigned_tx, &mut shc, &inputs, &sigs) {
            Ok(signed_tx) => signed_tx,
            Err(sig_results) => {
                slog!(WatchmanRoundFailed, reason: logs::RoundFailedReason::TxAssembly,
                    message: format!("sig results: {:?}", sig_results),
                );
                return;
            }
        };
        let signed_tx_hex = serialize_hex(&signed_tx);

        log!(Info, "Signed tx: {}", signed_tx_hex);
        // Call signrawtransaction on the transaction, but not to sign it (the hsm has
        // signed it) but to get more detailed error messages when there is
        // something wrong with the transaction (f.e. it tells you which input is
        // missing).
        match self.bitcoind.check_signed_tx(&signed_tx) {
            Ok(None) => {},
            Ok(Some(errors)) => {
                slog!(WatchmanRoundFailed, message: errors,
                    reason: logs::RoundFailedReason::InvalidSignedTx,
                );
                return;
            },
            Err(e) => {
                slog!(WatchmanRoundErrored, error: format!("Failed to check signed tx: {}.", e));
                return;
            }
        }

        // Broadcast the tx and check if it was processed correctly.
        let txid = signed_tx.txid();
        if !self.broadcast_valid_transaction(&signed_tx) {
            return;
        }
        slog!(WatchmanRoundComplete, txid: txid,
            inputs: &proposal.inputs, nb_inputs: proposal.inputs.len(),
            pegouts: &proposal.pegouts, nb_pegouts: proposal.pegouts.len(),
            change: &proposal.change, nb_change: proposal.change.len(),
        );

        if let Err(e) = self.blockchain_manager.update_from_rpc(&self.bitcoind, &self.sidechaind) {
            slog!(RpcSyncFailed, error: e.to_string());
        }
        if !self.blockchain_manager.is_tx_known(txid) {
            slog!(TxUnknownAfterBroadcast, txid: txid);
        }
    }

    fn block_in_chain_check(&self,
        chain: &impl Rpc,
        chain_name: &'static str,
        peer: peer::Id,
        chain_hash: sha256d::Hash,
        confirmations: u64
    ) -> Result<(), String> {
        match chain.block_is_in_chain(chain_hash, confirmations) {
            InChain::Yes => Ok(()),
            InChain::NotFound => {
                slog!(WatchmanBlockCheckError, peer, blockchain: chain_name,
                    block_hash: chain_hash, result: format!("NotFound"),
                );
                Err(format!("block {} not found in {}", chain_hash, chain_name))
            }
            InChain::ForkedOff => {
                slog!(WatchmanBlockCheckError, peer, blockchain: chain_name,
                    block_hash: chain_hash, result: format!("ForkedOff"),
                );
                Err(format!("block {} is forked off in our {}", chain_hash, chain_name))
            }
            InChain::WrongDepth(n) => {
                // Only a warning
                log_peer!(Warn, self, peer,
                    "sees block {:x} in the main blockchain at depth {} but it's at depth {}.",
                    chain_hash, confirmations, n,
                );
                Ok(())
            }
            InChain::RpcError(e) => {
                slog!(WatchmanBlockCheckError, peer, blockchain: chain_name,
                    block_hash: chain_hash, result: format!("{:?}:{:?}", e, e),
                );
                Err(format!("error checking if block {} is in {}", chain_hash, chain_name))
            }
        }
    }

    /// Compare the consensus state of [peer] with our state.
    fn compare_consensus_state(&mut self,
        peer: peer::Id,
        peer_keys: Vec<(peer::Id, PublicKey, PublicKey)>,
        mainchain_hash: bitcoin::BlockHash,
        sidechain_hash: elements::BlockHash,
        change_spk_hash: sha256d::Hash,
        n_mainchain_confirms: u64,
        n_sidechain_confirms: u64,
    ) -> Result<(), String> {
        // Check peer's consensus state against our own
        if !self.peers.check_peer_keys(peer, &peer_keys) {
            return Err(format!("incompatible peer keys"));
        }

        let change_desc = self.blockchain_manager.consensus().active_descriptor();
        let change_pkh = sha256d::Hash::hash(&change_desc.spk[..]);
        if let Some(ref tweaked_spk) = change_desc.csv_tweaked_spk {
            assert_ne!(ROLLOUTS.hsm_csv_tweak, rollouts::HsmCsvTweak::DynafedTransitionMade);
            let tweaked_pkh = sha256d::Hash::hash(&tweaked_spk[..]);
            if change_spk_hash != change_pkh && change_spk_hash != tweaked_pkh {
                return Err(format!(
                    "incompatible watchman change script hash: {:x} instead of {:x}",
                    change_spk_hash, change_pkh,
                ));
            }
            let val = change_spk_hash == tweaked_pkh;
            log!(Debug, "setting peer_uses_tweaked_change for {} to {}", peer, val);
            *self.peer_uses_tweaked_change.entry(peer).or_default() = val;
        } else {
            if change_spk_hash != change_pkh {
                return Err(format!(
                    "incompatible watchman change script hash: {:x} instead of {:x}",
                    change_spk_hash, change_pkh,
                ));
            }
        }

        if n_mainchain_confirms != self.n_mainchain_confirmations {
            return Err(format!(
                "incompatible n_mainchain_confirmations: {} instead of {}",
                n_mainchain_confirms, self.n_mainchain_confirmations,
            ));
        }
        if n_sidechain_confirms != constants::SIDECHAIN_CONFIRMS {
            return Err(format!(
                "incompatible n_sidechain_confirms: {} instead of {}",
                n_sidechain_confirms, constants::SIDECHAIN_CONFIRMS,
            ));
        }

        // Check the blockchains for consistency
        self.block_in_chain_check(
            &self.bitcoind,
            "bitcoin",
            peer,
            mainchain_hash.as_hash(),
            self.n_mainchain_confirmations / 2
        )?;
        self.block_in_chain_check(
            &self.sidechaind,
            "elements",
            peer,
            sidechain_hash.as_hash(),
            constants::SIDECHAIN_CONFIRMS
        )?;

        Ok(())
    }

    /// Update the peer list using the active consensus params.
    fn update_peer_list(&mut self) -> Result<(), Error> {
        let active = match self.blockchain_manager.consensus().active_params() {
            Some(a) => a,
            None => {
                // This is for old watchmen without CPE config.
                self.peers = peer::List::from_slice(
                    &self.config.consensus.peers,
                    |_| true,
                    &self.config.node.name,
                );
                return Ok(());
            }
        };

        if active.root == self.last_dynafed_root {
            // Nothing new.
            return Ok(());
        }

        let descriptor = match active.descriptor {
            Some(ref d) => d,
            None => {
                // This means that the latest params are unknown, which suggests
                // we are still syncing and not ready to participate in
                // consensus.
                return Err(Error::NotReady);
            }
        };

        let mut consensus_keys = descriptor.iter_signer_keys().map(|k| k.to_pubkey()).collect::<HashSet<_>>();
        self.peers = peer::List::from_slice(
            &self.config.consensus.peers,
            |pk| consensus_keys.remove(&pk),
            &self.config.node.name,
        );

        if !consensus_keys.is_empty() {
            panic!("active wm descriptor contains keys we don't know");
        }
        self.last_dynafed_root = active.root;
        Ok(())
    }
}

impl rotator::Rotator for Watchman {
    fn dynafed_update<F>(&mut self, update_fn: F) where F: FnOnce(::dynafed::UpdateNotif) {
        if let Err(e) = self.update_peer_list() {
            log!(Error, "failed to update peer list: {}", e);
        }

        // Use legacy ordering as long as the legacy wm descriptor is active.
        let use_legacy_ordering = !self.blockchain_manager.consensus().wm_transition_made();
        log!(Debug, "use_legacy_ordering: {}", use_legacy_ordering);

        update_fn(::dynafed::UpdateNotif {
            use_legacy_ordering: use_legacy_ordering,
            peers: self.peers.clone(),
        });
    }

    fn stage_durations(&self) -> Vec<Duration> {
        vec![
            self.config.consensus.stage1,
            self.config.consensus.stage2,
            self.config.consensus.stage3,
        ]
    }

    fn setup_network(
        &mut self,
        tx_main: mpsc::SyncSender<rotator::MainCtrl>,
    ) -> mpsc::SyncSender<NetworkCtrl> {
        let router = network::Router::new(
            self.config.local.listen_addresses.clone(),
            self.peers.my_id(),
            2 * self.config.heartbeat(),
            self.config.node.communication_secret_key,
        );
        let tx_net = router.run(tx_main);
        self.peer_mgr.set_network_tx(tx_net.clone());
        tx_net
    }

    // React to start of a new round -- initialize state but don't do any network
    // activity since other nodes will be initializing at the same time and there
    // will be races if we try to communicate immediately.
    fn round_stage1(&mut self, round_stage: RoundStage) {
        slog!(WatchmanStartStage);

        // Log some general info every round so that log analysis can
        // pick it up from a log stream.
        slog!(SystemInfo,
            functionary_version: env!("CARGO_PKG_VERSION"),
            git_commit: constants::GIT_COMMIT_ID,
            our_id: self.peers.my_id(),
            network_addresses: &self.config.local.listen_addresses,
        );

        for peer in self.peers.values() {
            peer.log(self.peers.consensus_ids());
        }

        // ** Start this round **
        log!(Info, "Starting round.");

        // Reset round state
        self.peer_mgr.reset_for_new_round(&self.peers);

        // Update chain state
        if let Err(e) = self.blockchain_manager.update_from_rpc(&self.bitcoind, &self.sidechaind) {
            slog!(RpcSyncFailed, error: e.to_string());
            self.state = State::Error(Error::SyncFailed(e));
            return;
        }

        if let Err(e) = self.update_hsm() {
            log!(Error, "error updating HSM with new chain data: {}", e);
            self.state = State::Error(e);
            return;
        }

        self.blockchain_manager.log_statuses();

        // Check blockchains. We want to agree on what's been confirmed on the sidechain,
        // and agree on what's been *half* confirmed on the mainchain. The reason for
        // checking the halfway point is that if something has gone wrong consensus-wise,
        // we need early warning. Once there's a split at the "confirmed" depth it's too
        // late for recovery.
        match self.bitcoind.block_at_depth(self.n_mainchain_confirmations / 2) {
            Ok((_, hash)) => {
                log!(Info, "Mainchain is at tip {}", hash);
                self.half_confirmed_mainchain_hash = hash;
            }
            Err(e) => log!(Warn, "Failed to get mainchain block tip from RPC: {}", e)
        }
        match self.sidechaind.block_at_depth(constants::SIDECHAIN_CONFIRMS) {
            Ok((_, hash)) => {
                log!(Info, "Sidechain is at tip {}", hash);
                self.sidechain_hash = hash;
            }
            Err(e) => log!(Warn, "Failed to get sidechain block tip from RPC: {}", e)
        }
        // Increment round count (this is only for diagnostics)
        self.round_count += 1;

        self.signers = self.blockchain_manager.all_signers();
        let (pending_pegouts, pending_inputs, output_counter)
            = self.blockchain_manager.log_wallet_summary(self.peers.consensus_ids());

        // Broadcast any fully-signed transactions that are not yet confirmed.
        for (_, ref tx) in self.blockchain_manager.in_flight_txs() {
            if tx.status.is_mempool() {
                self.broadcast_valid_transaction(&tx.tx);
            }
        }

        // Clear peg-out authorization list
        if let Err(e) = self.hsm.authorized_addresses_clear() {
            log!(Warn, "Failed to clear peg-out authorized address cache: {}", e);
        }

        // Prune utxos that are no longer spendable (old dynafed params) from the utxo table.
        // Only do this once the initial sync is complete, to make sure that we aren't deleting any
        // temporary, historical utxos.
        //
        // If we are within 1 day of the most recent block's time, then we can assume that
        // all of our utxos should have known descriptors (and thus a known set of signers).
        let one_day = Duration::from_secs(60 * 60 * 24);
        if let Ok(true) = self.blockchain_manager.is_main_synced(&self.bitcoind, one_day) {
            let all_peers = self.peers.ids().collect::<HashSet<peer::Id>>();
            let n_pruned_utxos = self.blockchain_manager.prune_unspendable_utxos(&all_peers);
            slog!(TotalPrunedUtxos, n_utxos: n_pruned_utxos);
        }

        // If we're not master, we're done here.
        if round_stage.master != self.peers.my_id() {
            log!(Info, "{} is master.", self.peers[round_stage.master]);
            self.state = State::NoProposal;
            return;
        }

        // If we're master, we need to produce a transaction to pass around for signing.
        log!(Info, "I am master.");

        // Create a new transaction (or idle, or whatever)
        // Since this is stage 1, we can't know who will be part of this round,
        // but the peers present last round is a reasonable estimation.
        let available_signers = self.peer_mgr.peers_seen_last_round();
        log!(Info, "available signers this round: {:?}", available_signers);
        let tx_result = self.blockchain_manager.propose_transaction(
            &pending_pegouts,
            &pending_inputs,
            output_counter.projection(),
            &|pegout| {
                if self.config.consensus.validate_pegout_authorization_proof {
                    self.hsm.authorized_addresses_add(&pegout.dest_pubkey, &pegout.authorization_proof)
                } else {
                    Ok(())
                }
            },
            &available_signers,
            &self.config.local.explicit_sweep_utxos.as_ref().unwrap_or(&vec![]),
        );

        self.state = match tx_result {
            Ok(proposal) => {
                log!(Info, "Created a transaction with {} inputs and {} outputs.",
                    proposal.inputs.len(), proposal.pegouts.len() + proposal.change.len(),
                );
                State::Proposing(proposal)
            },
            Err(blockchain::Error::Utxo(utxotable::Error::EmptyProposal)) => {
                slog!(WatchmanRoundIdled);
                State::WillSendIdle
            },
            Err(e) => {
                slog!(WatchmanRoundErrored, error: format!("Failed to create tx: {}. Aborting round.", e));
                State::Error(Error::FailedToPropose(e))
            },
        };
    }

    // React to stage 2 of a round
    fn round_stage2(&mut self, round_stage: RoundStage) {
        slog!(WatchmanStartStage);

        if ROLLOUTS.status_ack_elim != common::rollouts::StatusAckElim::Phase3 {
            self.peer_mgr.broadcast_status_ack(round_stage);
        }

        // Broadcast some message depending on our current state
        self.state = match mem::replace(&mut self.state, State::Idle) {
            // Do nothing on our first round
            State::Starting => State::Starting,
            // If we're master and have no proposal, send an `Idle`
            State::WillSendIdle => {
                log!(Info, "Announcing that our state is Idle.");
                self.peer_mgr.broadcast_idle(round_stage);
                State::Idle
            },
            // If we're in error, and we're master, don't do anything.
            State::Error(reason) => {
                if round_stage.master == self.peers.my_id() {
                    log!(Info, "We're master but we errored. Skipping round.");
                }
                State::Error(reason)
            },
            // If we're master and have a proposal, send it
            State::Proposing(proposal) => {
                // Validate that our proposal is still valid, which also
                // computes unsigned tx and retrieves the input data.
                match self.validate_proposal(&proposal, false, round_stage.master) {
                    Ok((unsigned_tx, inputs)) => {
                        // If the threshold is 0, this suggests that the network may contain some older nodes.
                        // Don't broadcast precommits in this case, because older nodes will not recognize
                        // the precommit message, and this will cause some subsequent messages to be dropped
                        // (for reasons that we do not yet fully understand).
                        // More details: https://gl.blockstream.com/liquid/functionary/-/issues/878
                        if self.config.node.precommit_threshold > 0 {
                            let txid = unsigned_tx.txid();
                            log!(Debug, "Broadcasting precommit {}", txid);
                            self.peer_mgr.broadcast_tx_precommit(round_stage, txid);
                        }

                        log!(Info, "Broadcasting transaction proposal {:?}", proposal);
                        self.peer_mgr.broadcast_tx_proposal(round_stage, &proposal);

                        // Try to already commit when only one precommit is required.
                        match self.try_commit(round_stage, &proposal, &unsigned_tx, &inputs) {
                            Ok(Some(my_sigs)) => {
                                State::Signed { proposal, unsigned_tx, inputs, my_sigs }
                            }
                            Ok(None) => State::HasProposal { proposal, unsigned_tx, inputs },
                            Err(e) => State::Error(e),
                        }
                    },
                    Err(e) => {
                        log!(Error, "We failed to sign our own transaction: {}. Aborting round.", e);
                        State::Error(e)
                    },
                }
            },
            // If we're not master, do nothing
            x => {
                // When we're not master, do a quick resync to avoid race conditions with master.
                if let Err(e) = self.blockchain_manager.update_from_rpc(&self.bitcoind, &self.sidechaind) {
                    slog!(RpcSyncFailed, error: e.to_string());
                    self.state = State::Error(Error::SyncFailed(e));
                    return;
                }

                x
            },
        }
    }

    // React to a round ending
    fn round_stage3(&mut self, _: RoundStage) {
        // In stage 3, there is no longer really a "master". Everybody collects all the sigs
        // they've seen, puts together a transaction, and tries to send it on the network.
        slog!(WatchmanStartStage);

        // At this point there is no more communication, so dump the peers' status.
        for (id, status) in self.peer_mgr.statuses().consensus_without_me() {
            let name = self.peers.by_id(id).unwrap().name.as_ref();
            status.log(id, name);
        }

        match mem::replace(&mut self.state, State::Idle) {
            // These states were replaced in stage 2
            State::WillSendIdle | State::Proposing(..) => unreachable!(),
            // If we have a tx to work with, combine signatures and broadcast.
            State::HasProposal { unsigned_tx, .. } => {
                let (agreed, bad_peers) = self.tally_precommitments(unsigned_tx.txid());
                slog!(RoundFailedPrecommits,
                    threshold: self.config.node.precommit_threshold,
                    n_precommits: agreed, bad_peers: bad_peers
                );
            }
            State::Signed { proposal, unsigned_tx, inputs, my_sigs } => {
                self.finish_and_submit_proposal(proposal, unsigned_tx, inputs, my_sigs);
            },
            // If we weren't `HasProposal`, still log a completion message
            State::Starting => slog!(WatchmanRoundSkipped),
            State::Idle => slog!(WatchmanRoundIdled),
            State::NoProposal { .. } => slog!(
                WatchmanRoundFailed,
                reason: logs::RoundFailedReason::NoProposal,
                message: "no proposal".into(),
            ),
            State::Error(reason) => slog!(
                WatchmanRoundErrored,
                error: reason.to_string()
            ),
        }

        // Regardless of the outcome of the round,
        // do a sync to have less work next round.
        if let Err(e) = self.blockchain_manager.update_from_rpc(&self.bitcoind, &self.sidechaind) {
            slog!(RpcSyncFailed, error: e.to_string());
        }
        if let Err(e) = self.update_hsm() {
            log!(Error, "error updating HSM with new chain data: {}", e);
        }

        // Check for failed pegins to sweep
        let available_signers = self.peer_mgr.peers_seen_last_round();
        self.blockchain_manager.check_for_failed_pegins(
            &mut self.config,
            self.n_mainchain_confirmations,
            available_signers,
            self.blockchain_manager.side_height(),
            &self.bitcoind,
        );
    }

    // React to a network message
    fn handle_message(&mut self, msg: Message<message::Validated>, round_stage: RoundStage) {
        let peer = msg.header().sender;
        let header_time = msg.header().time;
        log!(Debug, "Received {:?} message from {}.", msg.header().command, peer);

        // If we have errored out or the peer misbehaved, just ignore.
        if let State::Error(_) = self.state {
            return;
        }
        if !self.peer_mgr.statuses()[peer].state.is_ok() {
            log!(Debug, "ignoring {:?} message from {} that is in a bad state", msg.header().command, peer);
            return;
        }

        if !self.peers.in_consensus(peer) && !self.signers.contains(&peer) {
            log!(Debug, "ignoring message from non-consensus peer {}: {:?}", peer, msg.header().command);
            return;
        }

        // NOTE: This is the last statement of the method, so it's OK to return
        // inside the match blocks.
        match msg.payload {
            // ** unsigned tx **
            message::Payload::TxProposal { proposal, .. } => {
                // If peer is not master, we don't want a tx from it.
                if peer != round_stage.master {
                    slog!(ProposalFromNonMaster, peer);
                    return;
                }

                // Otherwise all good, try to sign
                self.state = match mem::replace(&mut self.state, State::Idle) {
                    // Expecting transaction
                    State::NoProposal => {
                        let check_pak = self.config.consensus.validate_pegout_authorization_proof;
                        match self.validate_proposal(&proposal, check_pak, round_stage.master) {
                            Ok((unsigned_tx, inputs)) => {
                                if self.config.node.precommit_threshold > 0 {
                                    self.peer_mgr.broadcast_tx_precommit(
                                        round_stage, unsigned_tx.txid(),
                                    );
                                }
                                // Already try to commit in case low precommits.
                                match self.try_commit(round_stage, &proposal, &unsigned_tx, &inputs) {
                                    Ok(Some(my_sigs)) => {
                                        State::Signed { proposal, unsigned_tx, inputs, my_sigs }
                                    }
                                    Ok(None) => State::HasProposal { proposal, unsigned_tx, inputs },
                                    Err(e) => State::Error(e),
                                }
                            },
                            Err(Error::BadProposal(e)) => {
                                slog!(RefusedProposal, master: peer, error: Cow::Borrowed(&e));
                                State::Error(Error::BadProposal(e))
                            },
                            Err(e) => {
                                log!(Error, "error signing proposal: {}", e);
                                State::Error(e)
                            },
                        }
                    },
                    State::HasProposal { proposal: p, unsigned_tx, inputs } if p == proposal => {
                        log!(Error, "received two identical proposals from master {}", peer);
                        State::HasProposal { proposal: p, unsigned_tx, inputs }
                    },
                    State::Signed { proposal: p, unsigned_tx, inputs, my_sigs } if p == proposal => {
                        log!(Error, "received two identical proposals from master {}", peer);
                        State::Signed { proposal: p, unsigned_tx, inputs, my_sigs }
                    },
                    State::Idle => {
                        log!(Error, "received proposal while idle from {}, stopping round", peer);
                        State::Error(Error::NotReady)
                    },
                    State::HasProposal { .. } | State::Signed { .. } => {
                        log!(Error, "received two proposals from master {}, stopping round", peer);
                        State::Error(Error::DuplicateProposal(peer))
                    },
                    // Just started, can't handle transaction
                    State::Starting => State::Starting,
                    State::Error(e) => State::Error(e),
                    State::WillSendIdle | State::Proposing(_) => unreachable!("we are master"),
                }
            }

            message::Payload::TxPrecommit { txid } => {
                slog!(ReceivedTxPrecommit, peer, txid);

                self.peer_mgr.record_precommit(peer, txid);
                self.state = match mem::replace(&mut self.state, State::Starting) {
                    // If we have already committed, check if txids match.
                    State::Signed { proposal, unsigned_tx, inputs, my_sigs } =>{
                        let our_txid = unsigned_tx.txid();
                        if txid != our_txid {
                            slog!(PrecommitWrongTxid, peer, our_txid: our_txid, peer_txid: txid);
                        }
                        State::Signed { proposal, unsigned_tx, inputs, my_sigs }
                    }
                    // If we didn't commit yet, try to commit if precommit is to tx we like.
                    State::HasProposal { proposal, unsigned_tx, inputs } => {
                        // If the peer does not agree with us, log the discrepancy.
                        let our_txid = unsigned_tx.txid();
                        if txid != our_txid {
                            slog!(PrecommitWrongTxid, peer, our_txid: our_txid, peer_txid: txid);
                            State::HasProposal { proposal, unsigned_tx, inputs }
                        } else {
                            match self.try_commit(round_stage, &proposal, &unsigned_tx, &inputs) {
                                Ok(Some(my_sigs)) => {
                                    State::Signed { proposal, unsigned_tx, inputs, my_sigs }
                                }
                                Ok(None) => State::HasProposal { proposal, unsigned_tx, inputs },
                                Err(e) => State::Error(e),
                            }
                        }
                    }
                    s => s,
                };
            }

            // ** signed tx **
            message::Payload::TxSignatures { sigs } => {
                // Since messages are always processed in order, we won't receive signatures
                // before we receive a precommit. So we can extract the precommit from the state.
                if let peer::State::Precommit(txid) = self.peer_mgr.statuses()[peer].state {
                    // No need to check for transitions here because there's only one option.
                    self.peer_mgr.record_signatures(peer, txid, sigs);
                } else {
                    // This should only happen when talking with old peers
                    log_peer!(Warn, self, peer,
                        "got tx signatures from peer that didn't sent a precommit",
                    );
                    // NB Stored as a signature of the zero txid, we will replace it with the
                    // correct txid before we validate signatures.
                    self.peer_mgr.record_signatures(peer, Default::default(), sigs);
                }
            }

            // ** status **
            message::Payload::StatusWatchmanPreSeen {
                peer_keys,
                mainchain_hash,
                sidechain_hash,
                change_spk_hash,
                n_mainchain_confirms,
                n_sidechain_confirms,
                round_count,
                fee_pool_summary,
                n_pending_transactions,
                output_counter,
                percentiles,
                pending_input_value,
                pending_change_value,
                message,
            } => {
                log!(Debug,
                    "Got status message from {}. \
                    fee_pool_summary: {:?}, \
                    n_pending_transactions: {}, \
                    output_counter: {:?}, \
                    percentiles: {:?}, \
                    pending_input_value: {}, \
                    pending_change_value: {}, \
                    message: {}",
                    peer, fee_pool_summary, n_pending_transactions, output_counter, percentiles,
                    pending_input_value, pending_change_value, message,
                );

                let res = self.compare_consensus_state(
                    peer, peer_keys, mainchain_hash, sidechain_hash,
                    change_spk_hash, n_mainchain_confirms, n_sidechain_confirms,
                );
                if let Err(reason) = res {
                    log!(Warn, "state mismatch with peer {}: {}", peer, reason);
                    self.peer_mgr.status_mismatch(peer, reason);
                } else {
                    self.peer_mgr.update_from_status(peer, header_time, round_count, message);
                }
            }

            // ** status **
            message::Payload::StatusWatchman {
                peer_keys,
                mainchain_hash,
                sidechain_hash,
                change_spk_hash,
                n_mainchain_confirms,
                n_sidechain_confirms,
                round_count,
                fee_pool_summary,
                n_pending_transactions,
                output_counter,
                percentiles,
                pending_input_value,
                pending_change_value,
                peers_seen,
                message,
            } => {
                log!(Debug,
                    "Got status message from {}. \
                    fee_pool_summary: {:?}, \
                    n_pending_transactions: {}, \
                    output_counter: {:?}, \
                    percentiles: {:?}, \
                    pending_input_value: {}, \
                    pending_change_value: {}, \
                    peers_seen: {:?}, \
                    message: {}",
                    peer, fee_pool_summary, n_pending_transactions, output_counter, percentiles,
                    pending_input_value, pending_change_value, peers_seen, message,
                );

                // If the peer reports having received our messages, kick its watchdog.
                if peers_seen.contains(&self.peers.my_id()) {
                    slog!(KickWatchdogForInStatusAck, peer: peer);
                    self.peer_mgr.send_network_watchdog_kick(peer);
                }

                let res = self.compare_consensus_state(
                    peer, peer_keys, mainchain_hash, sidechain_hash,
                    change_spk_hash, n_mainchain_confirms, n_sidechain_confirms,
                );
                if let Err(reason) = res {
                    log!(Warn, "state mismatch with peer {}: {}", peer, reason);
                    self.peer_mgr.status_mismatch(peer, reason);
                } else {
                    self.peer_mgr.update_from_status(peer, header_time, round_count, message);
                }
            }

            // ** status ack **
            message::Payload::StatusAck => {
                if ROLLOUTS.status_ack_elim != common::rollouts::StatusAckElim::Phase3 {
                    slog!(KickWatchdogForStatusAck, peer: peer);
                    self.peer_mgr.send_network_watchdog_kick(peer);
                } else {
                    slog!(ReceivedStatusAck, peer: peer);
                }
            }

            // ** idle **
            message::Payload::Idle => {
                if peer != round_stage.master {
                    slog!(IdleFromNonMaster, peer);
                } else {
                    log!(Info, "Received Idle message from master ({}). Transitioning into Idle state.",
                        round_stage.master,
                    );
                    self.state = State::Idle;
                }
            }

            // ** nack **
            message::Payload::Nack { reason } => {
                log!(Debug, "peer {} sent nack: {}", peer, reason);
            }

            // ** blocksigner messages **
            message::Payload::UnsignedBlock { .. } |
            message::Payload::BlockPrecommit { .. } |
            message::Payload::BlockSignature { .. } |
            message::Payload::StatusBlocksignerPreSeen { .. } |
            message::Payload::StatusBlocksigner { .. } => {
                log!(Warn, "peer {} is sending blocksigner messages", peer);
            }
            message::Payload::Unknown => unreachable!(),
        }
    }

    // Broadcast Status messages
    fn send_status(&mut self, stage: RoundStage) {
        // Don't send a status message if we don't even know what block we're on,
        // it'll just cause the recipient to emit spurious errors
        match self.state {
            State::Starting => return,
            _ => {},
        }

        let mut peer_keys = Vec::with_capacity(self.peers.len());
        for (id, peer) in self.peers.iter() {
            peer_keys.push((id, peer.comm_pk_legacy.unwrap_or(peer.comm_pk), peer.sign_pk));
        }

        let (pending_input_value, pending_change_value) = self.blockchain_manager.pending_funds();
        let change_spk = self.blockchain_manager.consensus().active_change_spk();
        self.peer_mgr.broadcast_status_watchman(
            stage,
            peer_keys,
            self.half_confirmed_mainchain_hash,
            self.sidechain_hash,
            sha256d::Hash::hash(&change_spk[..]),
            self.n_mainchain_confirmations,
            constants::SIDECHAIN_CONFIRMS,
            self.round_count,
            self.blockchain_manager.fee_pool_summary(),
            self.blockchain_manager.n_in_flight_txs() as u64,
            self.blockchain_manager.output_counter(),
            self.blockchain_manager.available_output_percentiles().unwrap_or([0,0,0,0,0]),
            pending_input_value, pending_change_value,
            self.peer_mgr.peers_seen_last_round().into_iter().copied().collect(),
            format!("v{};git commit {}", message::MESSAGE_VERSION, constants::GIT_COMMIT_ID),
        );
    }
}
