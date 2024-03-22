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
//! This implements a 5-of-7 rotating consensus for signing blocks
//!

pub mod config;
pub mod dynafed;

use std::borrow::Cow;
use std::sync::mpsc;
use std::time::Duration;
use std::{fmt, mem, thread};

use bitcoin::hashes::{self, sha256, Hash, hex::DisplayHex};
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, ecdsa::Signature};
use common::{blockchain, util::ToBitcoinScript};
use elements::encode::serialize_hex;
use elements::BlockHash;
use elements::hex::ToHex;
use miniscript::{TranslatePk, Miniscript, Segwitv0};
use miniscript::policy::Liftable;

use blocksigner::config::Configuration;
use common::{constants, BlockHeight, SignState};
use common::rollouts::ROLLOUTS;
use hsm;
use message::{self, Message};
use network::{self, NetworkCtrl};
use peer::{self, PeerManager};
use rotator::{self, RoundStage};
use rpc::{self, BitcoinRpc, ElementsRpc, Rpc, RPC_VERIFY_ALREADY_IN_CHAIN};
use tweak;
use utils::empty_elements_block;

/// The current state of the blocksigning state machine
#[derive(Debug)]
pub enum State {
    /// Blocksigner has just started and is waiting for the next round
    Starting,
    /// We are master, it is stage 1, and at the start of stage 2 we
    /// will broadcast an unsigned block
    WillPropose,
    /// Waiting for unsigned block from master, not (yet) received
    ExpectingBlock,
    /// Precommitted to signing some block
    Precommitted(elements::Block),
    /// Sent a block signature to peers, expecting no reply
    SentSignature(elements::Block, Signature),
    /// An error occurred, we're waiting for the next round.
    Error(Error),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            State::Starting => f.write_str("Starting"),
            State::WillPropose => f.write_str("WillPropose"),
            State::ExpectingBlock => f.write_str("ExpectingBlock"),
            State::Precommitted(block) => write!(f, "Precommitted({})", block.header.height),
            State::SentSignature(_block, sig) => {
                write!(f, "SentSignature({})", sig)
            }
            State::Error(state) => write!(f, "Error({})", state)
        }
    }

}

/// Logs actions of the blocksigner $signer.
macro_rules! log_signer {
    ($level:ident, $signer:ident, $($arg:tt)+) => (
        $crate::rotator::log_rotator(
            file!(),
            line!(),
            $crate::logs::Severity::$level,
            $signer,
            $signer.peers.my_id(),
            &format!($($arg)+),
        )
    )
}

/// Blocksigner-related errors
#[derive(Debug)]
pub enum Error {
    /// Hex decoding error
    Hex(hashes::FromSliceError),
    /// A JSONRPC error
    Rpc(jsonrpc::Error),
    /// A miniscript error.
    Miniscript(miniscript::Error),
    /// Custom error.
    Custom(Cow<'static, str>),
    /// You hit the HSM rate limit.
    HsmSignRateLimit,
    /// Master sent a duplicate proposal.
    DuplicateProposal(peer::Id),
    /// Peer status report contained bad key for known host.
    ReportedPeerKeyMismatch,
    /// Peer sidechain tip is not the same as ours
    BlockchainMismatch{
        /// offending peer
        peer: peer::Id,
        /// offending peer's sidechain tip
        peer_tip: BlockHash,
        /// local sidechain tip
        our_tip: BlockHash,
    },
    /// Bad return from Sidechain preciousblock RPC
    SidechainPreciousFailed{
        /// Attempted tip
        master_tip: BlockHash,
        /// resulting error
        error: String,
    },
    /// Failure of Sidechain communication
    SidechainTransportFailure(jsonrpc::Error),
    /// No change after otherwise-successful Sidechain preciousblock RPC
    SidechainPostPreciousNotMaster{
        /// Attempted tip
        master_tip: BlockHash,
        /// Resulting tip
        actual_tip: BlockHash,
    },
}

impl Error {
    /// A custom error.
    pub fn custom<S: Into<Cow<'static, str>>>(e: S) -> Error {
        Error::Custom(e.into())
    }

    /// Provide any additional information associated with the Error
    pub fn extra(&self) -> Option<String> {
        match *self {
            Error::Hex(ref e) => Some(e.to_string()),
            Error::Rpc(ref e) => Some(e.to_string()),
            Error::Miniscript(ref e) => Some(e.to_string()),
            Error::Custom(_) => None,
            Error::HsmSignRateLimit => None,
            Error::DuplicateProposal(_) => None,
            Error::ReportedPeerKeyMismatch => None,
            Error::BlockchainMismatch{peer, peer_tip, our_tip} => Some(format!("{}, peer_tip: {}, our_tip: {}", peer, peer_tip, our_tip)),
            Error::SidechainPreciousFailed{master_tip: _, ref error} => Some(error.to_string()),
            Error::SidechainTransportFailure(ref e) => Some(e.to_string()),
            Error::SidechainPostPreciousNotMaster{master_tip, actual_tip} => Some(format!("master: {}, actual: {}", master_tip, actual_tip)),
        }
    }

    /// Provide a succinct representation of the Error
    pub fn succinct(&self) -> &str {
        match *self {
            Error::Hex(_) => "hex",
            Error::Rpc(_) => "rpc",
            Error::Miniscript(_) => "miniscript_error",
            Error::Custom(ref e) => e,
            Error::HsmSignRateLimit => "hsm_rate_limit",
            Error::DuplicateProposal(_) => "duplicate_proposal",
            Error::ReportedPeerKeyMismatch => "peer_key_mismatch",
            Error::BlockchainMismatch{..} => "blockchain_mismatch",
            Error::SidechainPreciousFailed{..} => "preciousblock",
            Error::SidechainTransportFailure(_) => "local_transport",
            Error::SidechainPostPreciousNotMaster{..} => "preciousblock_nochange",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Hex(ref e) => fmt::Display::fmt(e, f),
            Error::Rpc(ref e) => fmt::Display::fmt(e, f),
            Error::Miniscript(ref e) => write!(f, "miniscript error: {}", e),
            Error::Custom(ref e) => fmt::Display::fmt(e, f),
            Error::HsmSignRateLimit => write!(f, "hit HSM rate limit"),
            Error::DuplicateProposal(p) => write!(f, "duplicate proposal from master {}", p),
            Error::ReportedPeerKeyMismatch => write!(f, "bad key for known host"),
            Error::BlockchainMismatch{peer: _, peer_tip, our_tip: _} => write!(f, "peer tip mismatch: {}", peer_tip),
            Error::SidechainPreciousFailed{master_tip: _, ref error} => write!(f, "preciousblock: {}", error),
            Error::SidechainTransportFailure(ref e) => write!(f, "local transport: {}", e),
            Error::SidechainPostPreciousNotMaster{..} => write!(f, "preciousblock: local tip unswayed"),
        }
    }
}

impl From<hashes::FromSliceError> for Error {
    fn from(e: hashes::FromSliceError) -> Error { Error::Hex(e) }
}

impl From<jsonrpc::Error> for Error {
    fn from(e: jsonrpc::Error) -> Error { Error::Rpc(e) }
}

impl From<miniscript::Error> for Error {
    fn from(e: miniscript::Error) -> Error { Error::Miniscript(e) }
}

/// The main blocksigner structure
pub struct BlockSigner {
    /// Global configuration
    config: Configuration,
    /// Data needed for producing and verifying signatures
    secp: Secp256k1<secp256k1::VerifyOnly>,
    /// Set of consensus parameters entry sets (CPEs) that we understand
    cpe_set: dynafed::CpeSet,
    /// List of all peers
    peers: peer::List,
    /// Handle to bitcoind
    bitcoind: Option<rpc::Bitcoin>,
    /// Handle to sidechaind
    sidechaind: rpc::Elements,
    /// Tip of the sidechain, as we see it
    sidechain_tip: (BlockHeight, BlockHash),
    /// State of this peer
    state: State,
    /// State of the other peers (when we are master)
    peer_mgr: PeerManager<BlockHash, Signature>,
    /// Number of rounds since we started
    round_count: u32,
    /// The active dynafed params root.
    /// We cache this to prevent doing all the checking every round when the
    /// params don't change.
    active_dynafed_params: sha256::Midstate,
    /// Security module used for signing
    security_module: Box<dyn hsm::SecurityModule>,
    /// The last blocks created by this blocksigner.
    last_created_blocks: Vec<(RoundStage, BlockHeight, BlockHash)>,
}

impl BlockSigner {
    /// Create a new block signer
    pub fn new(config: Configuration) -> BlockSigner {
        log!(Info, "BlockSigner::new");
        // Choose which Hsm to use
        let security_module = match (&config.node.signing_secret_key, &config.local.hsm_socket) {
            (&Some(..), &Some(..)) => panic!("Cannot specify both `signing_secret_key` and `hsm_socket` in config file"),
            (&None, &None) => panic!("Must specify one of `signing_secret_key` or `hsm_socket` in config file"),
            (&None, &Some(ref path)) => Box::new(hsm::LiquidHsm::new(path.clone())) as Box<dyn hsm::SecurityModule>,
            (&Some(ref key), &None) => Box::new(hsm::LocalBlocksigner::new(*key)) as Box<dyn hsm::SecurityModule>,
        };

        // Create RPC connections and check that they successfully warm up.
        let bitcoind = config.local.bitcoind_rpc_url.as_ref().map(|url| {
            rpc::Bitcoin::new(
                url.to_owned(),
                Some(config.local.bitcoind_rpc_user.as_ref().expect("no bitcoin rpc user provided").clone()),
                Some(config.local.bitcoind_rpc_pass.as_ref().expect("no bitcoin rpc pass provided").clone()),
            )
        });
        let sidechaind = rpc::Elements::new(
            config.local.sidechaind_rpc_url.clone(),
            Some(config.local.sidechaind_rpc_user.clone()),
            Some(config.local.sidechaind_rpc_pass.clone()),
        );

        let mut cpe_set = match dynafed::CpeSet::from_config(&config) {
            Ok(s) => s,
            Err(e) => panic!("Invalid CPE in config: {}", e),
        };

        // Check that both RPC ports work and that both daemons are warmed up.
        loop {
            let is_bitcoind_warming_up = bitcoind.as_ref()
                .map(|rpc| rpc.is_warming_up("bitcoind").expect("bitcoind connection"))
                .unwrap_or(false);
            let is_sidechaind_warming_up = sidechaind.is_warming_up("sidechaind").expect("sidechaind connection");
            if !(is_bitcoind_warming_up || is_sidechaind_warming_up) {
                break;
            }
            thread::sleep(Duration::from_secs(5));
        }

        match sidechaind.blockchain_info() {
            Ok(info) => {
                // initialize the CPEs statuses
                let current_height = info.current_height;
                if current_height > 0 {
                    let start_height = current_height.saturating_sub(info.epoch_length);
                    for height in start_height..=current_height {
                        let header = sidechaind.raw_header_at(height).expect("to get sidechain header");
                        cpe_set.update_params_status(&header);
                    }
                }
            }
            Err(e) => {
                log!(Warn, "Elements reports that dynafed is NOT active: {}", e);
            }
        }

        log!(Info, "current rollouts: {:?}", *ROLLOUTS);

        // Return
        BlockSigner {
            secp: Secp256k1::verification_only(),
            cpe_set: cpe_set,
            bitcoind: bitcoind,
            sidechaind: sidechaind,
            sidechain_tip: (0, BlockHash::all_zeros()),
            state: State::Starting,
            peer_mgr: PeerManager::new(config.my_id()),
            peers: peer::Map::empty(config.my_id()),
            round_count: 0,
            security_module: security_module,
            active_dynafed_params: Default::default(),
            config: config,
            last_created_blocks: Vec::new(),
        }
    }

    /// Check if we have enough pre-committed peers to sign
    pub fn sufficient_precommitments(&self, hash: BlockHash) -> bool {
        let tally = BlockSigner::tally_precommitments(hash, self.peer_mgr.statuses()).0;
        tally >= self.config.node.precommit_threshold
    }

    /// Prepares a new block for proposal when we are master.
    fn prepare_block_proposal(&mut self) -> Result<elements::Block, Error> {
        log!(Debug, "Requesting hex block from sidechaind.");

        let mut commitments = Vec::new();

        let mut block = if let Some(ref bitcoind) = self.bitcoind {
            let mainchain_tip = bitcoind.tip()?;
            log!(Info, "Mainchain is at tip {}", mainchain_tip);
            blockchain::push_commitment(&mut commitments, &constants::MAINCHAIN_COMMITMENT_HEADER, &mainchain_tip);
            log_try!(Error, self.sidechaind.new_block_with_commitments(&commitments))
        } else {
            log_try!(Error, self.sidechaind.new_block())
        };

        let n_signers = self.peers.consensus().count();

        // Attach dynafed data if dynafed is active.
        if let elements::BlockExtData::Dynafed { proposed, current, .. } = block.header.ext.clone() {
            // Dynafed active, propose new parameters (unless they're already active)

            // Check the current parameters
            let current_root = current.calculate_root();
            let current_params = self.cpe_set.get_params(current_root).unwrap_or_else(|| {
                log!(Debug, "Unknown params: {:?}", current);
                slog_fatal!(UnknownParamsActivated, root: current_root);
            });

            let height = block.header.height as u64;
            if let Some(target) = self.cpe_set.target_params(current_root, height, n_signers) {
                self.cpe_set.audit_params(n_signers);
                assert!(target.start_height >= current_params.start_height, "target_params");

                let target_root = target.params.calculate_root();

                // prepare the OP_RETURN descriptors in case we're at CPE proposal/activation
                let (bs_descriptor, wm_descriptor) = target.normalized_descriptors();
                blockchain::push_descriptor_commitments(&mut commitments, bs_descriptor, wm_descriptor);

                if current_root != target_root {
                    if target.never_proposed() {
                        // proposal block
                        // replace the block template with the additional descriptor commitments for this CPE
                        block = log_try!(Error, self.sidechaind.new_block_with_commitments(&commitments));
                    }

                    if let elements::BlockExtData::Dynafed { ref mut proposed, ..} = block.header.ext {
                        // propose the new CPE
                        *proposed = elements::dynafed::Params::Full(target.params.clone());
                    } else {
                        // something has gone very wrong, the previous template header was dynafed
                        slog_fatal!(ExpectedDynafedHeader, height: height, block_hash: block.header.block_hash());
                    }

                    slog!(ProposingParams, root: target_root);
                    log!(Debug, "Proposed CPE contents: {:?}", proposed);
                } else {
                    // target params are current
                    if target.never_activated() {
                        // activation block
                        block = log_try!(Error, self.sidechaind.new_block_with_commitments(&commitments));
                    }
                }
            }
        } else {
            log!(Warn, "Dynafed is NOT active so not including dynafed data in header");
        }

        self.cpe_set.reset_signalling();

        log!(Info, "Created unsigned block.");
        log!(Debug, "Block header of unsigned block: {}", serialize_hex(&block.header));
        if let Err(e) = self.security_module.validate_block(&block.header) {
            log_signer!(Error, self, "HSM rejected our own block: {}", e);
            log!(Debug, "Offending block: {}", serialize_hex(&block));
            return Err(Error::custom("HSM rejected our block proposal"));
        }

        log!(Trace, "Done getting new block");
        return Ok(block);
    }

    /// Verify a block signature received from a peer
    pub fn validate_block_sig(&self, hash: BlockHash, peer: peer::Id, sig: &Signature) -> bool {
        let msg = secp256k1::Message::from_digest_slice(&hash[..]).expect("32-byte hash");
        self.secp.verify_ecdsa(&msg, &sig, &self.peers[peer].sign_pk).is_ok()
    }

    /// Try signing the block using the HSM and verify the signature.
    fn try_sign(&self, block: &elements::Block) -> Result<Signature, Error> {
        let sig = match self.security_module.sign_block(&block.header) {
            Ok(sig) => sig,
            Err(common::hsm::Error::ReceivedNack(common::hsm::Command::NackRateLimit)) => {
                return Err(Error::HsmSignRateLimit);
            }
            Err(e) => {
                return Err(Error::custom(format!("HSM refused to sign block: {}", e)));
            }
        };

        let blockhash = block.block_hash();
        if !self.validate_block_sig(blockhash, self.peers.my_id(), &sig) {
            let sig_hex = sig.serialize_der().to_hex();
            return Err(Error::custom(format!(
                "HSM signed block but got an invalid signature: {}", sig_hex,
            )));
        }

        Ok(sig)
    }

    /// Check which peers have precommitted to our block and submit our signature
    /// if enough have.
    fn try_commit(
        &self,
        round_stage: RoundStage,
        block: &elements::Block,
    ) -> Result<Option<Signature>, Error> {
        let blockhash = block.block_hash();
        if !self.sufficient_precommitments(blockhash) {
            return Ok(None);
        }

        match round_stage.stage {
            common::Stage::Stage1 | common::Stage::Stage2 => {},
            common::Stage::Stage3 | common::Stage::Stage3b => {
                if let Some(true) = self.config.node.allow_final_stage_signing {
                    log_signer!(Warn, self, "Allowing a late signing");
                } else {
                    log_signer!(Warn, self, "Avoiding a late signing");
                    return Ok(None);
                }
            }
        }

        let sig = match self.try_sign(block) {
            Ok(sig) => sig,
            Err(Error::HsmSignRateLimit) => {
                log_signer!(Warn, self,
                    "Hit the HSM rate-limit, not returning signature, should try later.",
                );
                return Ok(None);
            }
            Err(e) => {
                if self.peers.my_id() == round_stage.master {
                    log_signer!(Error, self, "Failed to sign our own block: {}", e);
                } else {
                    log_signer!(Error, self,
                        "Failed to sign block from master {}: {}", round_stage.master, e,
                    );
                }
                return Err(e);
            }
        };

        log!(Debug, "Sending block signature to peers (hash {})", blockhash);
        self.peer_mgr.broadcast_block_signature(round_stage, blockhash, sig);
        Ok(Some(sig))
    }

    /// Count the number of peers that precommitted to the same hash.
    /// If `me` is present in the peer status list, it adds 1 regardless
    /// of the peer's state.
    pub fn tally_precommitments(
        hash: BlockHash,
        peer_status: &peer::Map<peer::Status<BlockHash, Signature>>,
    ) -> (usize, Vec<peer::Id>) {
        let mut agreed = 1; // Include ourselves
        let mut bad_peers = vec![];
        for (id, status) in peer_status.consensus_without_me() {
            match status.state {
                peer::State::Precommit(peer_hash) |
                peer::State::SentSignatures(peer_hash, _) => {
                    if peer_hash == hash {
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

    /// Try submitting the new block to sidechaind and check if it was accepted.
    fn try_submit_block(&mut self, round_stage: RoundStage, block: &elements::Block) -> Result<(), Error> {
        // Submit to network
        if let Some(problem) = log_try!(Error, self.sidechaind.submit_block(block)) {
            log!(Warn, "Submit block returned result string: {}. \
                 The new block potentially did not advance the chain.", problem,
            );
        }

        // Check chaintip matches what we expect
        // We may have been beaten to the punch
        // in transmitting the newest block.
        let tip = log_try!(Warn, self.sidechaind.tip());
        let blockhash = block.block_hash();
        if tip == blockhash {
            slog!(BlocksignerRoundComplete, blockhash);
            let height = block.header.height as BlockHeight;
            self.last_created_blocks.push((round_stage, height, blockhash));
        } else {
            log!(Warn, "Submitted block {} but chaintip is {}; perhaps tied chaintip.",
                blockhash, tip,
            );
        }
        Ok(())
    }

    /// Compare the consensus state of [peer] with our state.
    fn compare_consensus_state(
        &mut self,
        round_stage: RoundStage,
        peer: peer::Id,
        peer_keys: Vec<(peer::Id, PublicKey, PublicKey)>,
        dynafed_params: Vec<elements::dynafed::Params>,
        sidechain_tip: BlockHash,
    ) -> Result<(), Error> {
        // Check peer's consensus state against our own.
        for params in &dynafed_params {
            let peer_root = params.calculate_root();
            if !self.cpe_set.record_param_support(peer_root, peer) {
                slog!(UnknownDynafedParamsSignalled, peer, root: peer_root);
                log!(Debug, "Unknown signalled CPE contents: {:?}", params);
            }
        }

        if !self.peers.check_peer_keys(peer, &peer_keys) {
            return Err(Error::ReportedPeerKeyMismatch);
        }

        // If we agree on the chain, we're all good.
        if sidechain_tip == self.sidechain_tip.1 {
            return Ok(());
        }

        // If we're master and our tip is different, don't error. The peer will either
        // switch to our tip or ignore us.
        if self.peers.my_id() == round_stage.master {
            log!(Debug, "peer {} thinks sidechain tip is {:x} but I think it's {:x}.",
                peer, sidechain_tip, self.sidechain_tip.1,
            );
            return Ok(());
        }

        // We're not master and peer is not master.
        if peer != round_stage.master {
            return Err(Error::BlockchainMismatch{peer, peer_tip: sidechain_tip, our_tip: self.sidechain_tip.1});
        }

        log!(Info, "peer {} (master) thinks sidechain tip is {:x} but I think it's {:x}",
            peer, sidechain_tip, self.sidechain_tip.1,
        );

        // If peer is master then try to switch to the master's block. This is
        // necessary to resolve 1-block forks. The preciousblock RPC will silently
        // switch to the master's block but only if it is at the same height as our
        // current tip. If the master's block is at a lower height, preciousblock
        // will silently do nothing.
        match self.sidechaind.precious_block(sidechain_tip) {
            Ok(None) => {},
            Ok(Some(e)) => return Err(Error::SidechainPreciousFailed{master_tip: sidechain_tip, error: e}),
            Err(e) => return Err(Error::SidechainTransportFailure(e)),
        }

        // Check if preciousblock worked
        match self.sidechaind.tip() {
            Ok(tip) if tip == sidechain_tip => {
                log!(Info, "Switched to master's ({}) tip: {}", peer, sidechain_tip);
                return Ok(());
            }
            Ok(tip) => return Err(Error::SidechainPostPreciousNotMaster{master_tip: sidechain_tip, actual_tip: tip}),
            Err(e) => return Err(Error::SidechainTransportFailure(e)),
        }
    }

    /// Update the peer list based on the active consensus params.
    fn update_peer_list(&mut self) -> Result<(), Error> {

        let params = match self.sidechaind.blockchain_info() {
            Ok(info) => {
                slog!(ConsensusManagementState,
                  epoch_age: info.epoch_age,
                  epoch_length: info.epoch_length,
                  size_on_disk: info.size_on_disk,
                );

                info.consensus_params
            },
            Err(e) => {
                log!(Warn, "Elements reports that dynafed is NOT active, using root params from config file: {}", e);
                elements::dynafed::Params::Full(self.cpe_set.pre_dynafed_params().cloned().expect("Must have pre-dynafed parameters available").params)
            }
        };

        let root = params.calculate_root();
        if root == self.active_dynafed_params {
            // Nothing to do, list didn't change.
            return Ok(());
        }

        let sb_script = params.signblockscript().unwrap();
        let params = self.cpe_set.get_params(root).unwrap_or_else(|| {
            log!(Debug, "Unknown params: {:?}", params);
            slog_fatal!(UnknownParamsActivated, root: root);
        });

        let mut pk_translator: tweak::KeyTranslator = tweak::KeyTranslator { };

        // Convert to a pubkey descriptor so that we can log it.
        // The log crate doesn't know the tweak::Key type.
        let keyed_descriptor = params.signblock_descriptor.translate_pk::<_, _>(
            &mut pk_translator
        ).unwrap();
        slog!(BlocksignerConsensusChanged,
            params_root: root,
            signblockscript: Cow::Borrowed(&sb_script),
            descriptor_named: Cow::Borrowed(&params.signblock_descriptor_named),
            descriptor_keys: Cow::Borrowed(&keyed_descriptor),
            policy: params.signblock_descriptor.lift().expect("descriptor can lift").to_string(),
            in_consensus: self.peers.in_consensus(self.peers.my_id()),
        );

        let mut keys = params.block_signing_keys();
        self.peers = peer::List::from_slice(
            &self.config.consensus.peers,
            |pk| keys.remove(pk),
            &self.config.node.name,
        );
        assert!(keys.is_empty(), "we already parsed all possible parameters on startup");

        self.active_dynafed_params = root;
        Ok(())
    }
}

impl rotator::Rotator for BlockSigner {
    fn dynafed_update<F>(&mut self, update_fn: F) where F: FnOnce(::dynafed::UpdateNotif) {
        if let Err(e) = self.update_peer_list() {
            log!(Error, "failed to update peer list: {}", e);
        }

        let use_legacy_ordering = match self.config.node.allow_pre_dynafed_ordering {
            Some(true) => {
                self.active_dynafed_params == Default::default() ||
                    self.cpe_set.legacy_params().is_none() ||
                    self.active_dynafed_params == self.cpe_set.legacy_params().unwrap().root
            },
            _ => false
        };
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
        slog!(BlocksignerStartStage);

        // Log some general info every round so that log analysis can
        // pick it up from a log stream.
        slog!(SystemInfo,
            functionary_version: env!("CARGO_PKG_VERSION"),
            git_commit: constants::GIT_COMMIT_ID,
            our_id: Some(self.peers.my_id()),
            network_addresses: Some(&self.config.local.listen_addresses),
        );

        for peer in self.peers.values() {
            peer.log(self.peers.consensus_ids())
        }

        // Reset signed state for all peers
        self.peer_mgr.reset_for_new_round(&self.peers);

        // Learn current tip
        match self.sidechaind.block_at_depth(1) {
            Ok((height, hash)) => {
                log!(Info, "Sidechain is at tip {}:{}", height, hash);
                self.sidechain_tip = (height, hash);
                match self.sidechaind.raw_header(hash) {
                    Ok(header) => self.cpe_set.update_params_status(&header),
                    Err(e) => log!(Warn, "Failed to get sidechain tip header from RPC: {}", e),
                }
            }
            Err(e) => log!(Warn, "Failed to get sidechain block tip from RPC: {}", e),
        }

        // Check what happened with the block from the previous rounds.
        // We only check blocks at least 2 deep because otherwise they can still be replaced.
        let sidechaind = &self.sidechaind; // borrowck trick
        let tip = self.sidechain_tip.0;
        self.last_created_blocks.retain(|(rs, height, hash)| {
            if tip.saturating_sub(*height) + 1 < constants::SIDECHAIN_CONFIRMS {
                return true; // block can still be replaced
            }
            match sidechaind.block_at(*height) {
                Ok(current_at_height) => {
                    if *hash != current_at_height {
                        slog!(BlockReplacedInChain, height: *height, our_block: *hash, error: None,
                            current: Some(current_at_height), round: rs.round, master: rs.master,
                        );
                    }
                    false
                }
                Err(jsonrpc::Error::Transport(_)) => true, // HTTP error; retry later
                Err(e) => {
                    slog!(BlockReplacedInChain, height: *height, our_block: *hash, current: None,
                        error: Some(e.to_string()), round: rs.round, master: rs.master,
                    );
                    false
                }
            }
        });

        // The first stage we send around status messages, nothing more needs to be done.
        self.state = if round_stage.master == self.peers.my_id() {
            log!(Info, "I, {}, am master.", &self.peers[round_stage.master]);
            State::WillPropose
        } else {
            log!(Info, "{} is master.", &self.peers[round_stage.master]);
            State::ExpectingBlock
        };
        self.round_count += 1;

        log!(Info, "Finished stage 1.");
    }

    // 1/3 through the round, announce unsigned block
    fn round_stage2(&mut self, round_stage: RoundStage) {
        slog!(BlocksignerStartStage);

        if ROLLOUTS.status_ack_elim != common::rollouts::StatusAckElim::Phase3 {
            self.peer_mgr.broadcast_status_ack(round_stage);
        }

        // Calculate and log the dynafed consensus voting based on the status
        // messages we received in stage 1.
        self.cpe_set.record_self_support(self.peers.my_id(), self.sidechain_tip.0 + 1);
        self.cpe_set.audit_params(self.peers.consensus().count());

        match self.state {
            State::WillPropose => {},
            // nothing to do, either errored or not master
            _ => return,
        }

        // If we are master, create an unsigned block
        let block = match self.prepare_block_proposal() {
            Ok(block) => block,
            Err(e) => {
               log_signer!(Error, self, "Error preparing block proposal: {:?}", e);
               self.state = State::Error(e);
               return;
            }
        };
        slog!(WillPropose, block_hash: block.block_hash(), block_height: block.header.height);
        if let elements::BlockExtData::Dynafed { ref current, ref proposed, .. } = block.header.ext {
            if *proposed != elements::dynafed::Params::Null {
                slog!(BlocksignerConsensusProposal,
                    current_params_root: current.calculate_root(),
                    proposed_params_root: proposed.calculate_root(),
                    current_fedpeg_program: current.fedpeg_program(),
                    proposed_fedpeg_program: proposed.fedpeg_program(),
                    current_fedpeg_script: current.fedpegscript().map(|x| x.to_lower_hex_string()),
                    proposed_fedpeg_script: proposed.fedpegscript().map(|x| x.to_lower_hex_string()),
                    descriptor_named: None,
                    descriptor_keys: None,
                    policy: None,
                    in_consensus: self.peers.in_consensus(self.peers.my_id()),
                );
            }
        }

        // Broadcast it to all peers.
        self.peer_mgr.broadcast_unsigned_block(round_stage, &block);

        // Update our own precommit state and send signature if only one
        // precommit required
        self.state = match self.try_commit(round_stage, &block) {
            Ok(Some(sig)) => State::SentSignature(block, sig),
            Ok(None) => State::Precommitted(block),
            Err(e) => State::Error(e),
        };
    }

    // 2/3 through the round, announce signed block
    fn round_stage3(&mut self, round_stage: RoundStage) {
        slog!(BlocksignerStartStage);

        // At this point there is no more communication, so dump the peers' status.
        for (id, status) in self.peer_mgr.statuses().consensus_without_me() {
            let name = self.peers.by_id(id).unwrap().name.as_ref();
            status.log(id, name);
        }

        // If we don't have a block or signature, sit this round out
        let (mut block, my_sig) = match self.state {
            State::Starting => {
                slog!(BlocksignerRoundSkipped);
                return;
            },
            State::ExpectingBlock => {
                slog!(RoundFailedNoBlock);
                return;
            },
            State::Precommitted(ref block) => {
                let (agreed, bad_peers) = BlockSigner::tally_precommitments(
                    block.block_hash(), &self.peer_mgr.statuses(),
                );
                slog!(RoundFailedPrecommits,
                    threshold: self.config.node.precommit_threshold,
                    n_precommits: agreed, bad_peers: bad_peers
                );
                return;
            },
            State::SentSignature(ref mut block, sig) => (
                // for borrowck reasons we can't maintain a borrow of `block`,
                // so we have to copy it and stick an empty block in its place

                // elements::Block no longer implements default
                {
                    let mut swap_block = empty_elements_block();
                    mem::swap(block, &mut swap_block);
                    swap_block
                },
                sig,
            ),
            State::Error(ref reason) => {
                slog!(BlocksignerRoundErrored, error: reason.to_string());
                return;
            },
            State::WillPropose => unreachable!(),
        };

        // Sign the block
        let block_hash = block.block_hash();
        let block_clone = block.clone();
        let signed = match block.header.ext {
            elements::BlockExtData::Proof { ref challenge, ref mut solution } => {
                // miniscript::parse expects a bitcoin Script
                let script = challenge.to_bitcoin_script();
                let miniscript: Miniscript<_, Segwitv0> = miniscript::Miniscript::parse(&script)
                    .expect("block challenge is a valid miniscript");
                let result = miniscript.satisfy(&Satisfier {
                    my_id: self.peers.my_id(),
                    my_sig,
                    blockhash: block_hash,
                    peer_status: &self.peer_mgr.statuses(),
                });

                if let Ok(witness) = result {
                    // Convert witness into a script, stripping the last byte off of all
                    // signatures to support Liquid Production's lack of sighashtypes.
                    let mut builder = elements::script::Builder::new();
                    for wit in witness {
                        if wit.is_empty() {
                            builder = builder.push_int(0);
                        } else {
                            builder = builder.push_slice(&wit[..wit.len() - 1]);
                        }
                    }
                    *solution = builder.into_script();
                    true
                } else {
                    slog!(RoundFailedSignatures, error: "could not satisfy".to_owned());
                    false
                }
            }
            elements::BlockExtData::Dynafed { ref current, ref mut signblock_witness, .. } => {
                let current_root = current.calculate_root();
                let params = self.cpe_set.get_params(current_root).expect("checked before precommit");

                let n_signers = self.peers.consensus().count();
                let height = block_clone.header.height as u64;
                let commitments_valid = if let Some(target) = self.cpe_set.target_params(current_root, height, n_signers) {
                    match check_descriptors(&block_clone, current_root, target) {
                        DescriptorCommitments::None => {
                            if should_contain_descriptors(current_root, target) {
                                slog!(CpeCommitmentsNotFound, height: height, block_hash: block_hash);
                                // didn't find the expected commitments
                                false
                            } else {
                                true
                            }
                        },
                        DescriptorCommitments::Mismatch => {
                            // the commitments don't match our expected CPE
                            false
                        },
                        DescriptorCommitments::Found => {
                            slog!(CpeCommitmentsFound, height: height, block_hash: block_hash);
                            true
                        },
                    }
                } else {
                    true
                };

                let mut dummy_txin = bitcoin::TxIn::default();
                let result = params.signblock_descriptor.satisfy(
                    &mut dummy_txin,
                    Satisfier {
                        my_id: self.peers.my_id(),
                        my_sig: my_sig,
                        blockhash: block_hash,
                        peer_status: self.peer_mgr.statuses(),
                    },
                );

                if result.is_ok() {
                    if commitments_valid {
                        assert!(dummy_txin.script_sig.is_empty());
                        *signblock_witness = dummy_txin.witness.to_vec();
                        true
                    } else {
                        false
                    }
                } else {
                    slog!(RoundFailedSignatures, error: "could not satisfy".to_owned());
                    false
                }
            }
        };

        if signed {
            if let Err(e) = self.try_submit_block(round_stage, &block) {
                log_signer!(Error, self, "Submitting block: FAILED: {}", e);
            }
        }

        log!(Info, "Finished round.");
    }

    // React to a network message
    fn handle_message(&mut self, msg: Message<message::Validated>, round_stage: RoundStage) {
        let peer = msg.header().sender;
        let header_time = msg.header().time;
        let command = msg.header().command;

        // If we have errored out, just ignore.
        if let State::Error(_) = self.state {
            return;
        }

        if !self.peers.in_consensus(peer) {
            log!(Debug, "ignoring message from non-consensus peer {}: {:?}", peer, msg.header().command);
            return;
        }
        if !self.peer_mgr.statuses()[peer].state.is_ok() {
            log!(Debug, "ignoring {:?} message from {} that is in a bad state", msg.header().command, peer);
            return;
        }

        // NOTE: This is the last statement of the method, so it's OK to return
        // inside the match blocks.
        match msg.payload {
            // ** unsigned block **
            message::Payload::UnsignedBlock { block } => {
                // If peer is not master, we don't want a block from it
                if peer != round_stage.master {
                    slog!(BlockFromNonMaster, peer);
                    return;
                }
                // If we aren't waiting for the block, we don't want it.
                match self.state {
                    State::ExpectingBlock => {}
                    State::Precommitted(_) | State::SentSignature(..) => {
                        slog!(BlockAtWrongTime, peer: peer,
                            self_state: Some(format!("self.state == {}", self.state)),
                            peer_state: None,
                        );
                        self.state = State::Error(Error::DuplicateProposal(peer));
                        return;
                    }
                    State::Starting | State::WillPropose => {
                        slog!(BlockAtWrongTime, peer: peer,
                            self_state: Some(format!("self.state == {}", self.state)),
                            peer_state: None,
                        );
                        return;
                    }
                    State::Error(_) => return,
                }

                // Send it to the daemon to check it
                match self.sidechaind.test_proposed_block(&block) {
                    Ok(_) => {},
                    Err(jsonrpc::Error::Rpc(jsonrpc::error::RpcError{code, message, ..})) if code == RPC_VERIFY_ALREADY_IN_CHAIN => {
                        slog!(DuplicateBlock, header: &block.header, error: message.to_string());
                        return;
                    }
                    Err(e) => {
                        slog!(DaemonRejectBlock, header: &block.header, error: e.to_string());
                        return;
                    }
                }

                // Count master's block as a precommit.
                let blockhash = block.block_hash();
                self.peer_mgr.record_precommit(peer, blockhash, elements::BlockHash::all_zeros());

                // Check that we understand the dynafed parameters
                if let elements::BlockExtData::Dynafed { ref current, ref proposed, .. } = block.header.ext {
                    let current_root = current.calculate_root();
                    let current_params = match self.cpe_set.get_params(current_root) {
                        Some(params) => params,
                        None => {
                            slog!(UnknownActiveCpe, peer: Some(peer), root: current_root,);
                            log!(Debug, "Unknown params: {:?}", current);
                            return;
                        }
                    };

                    if !proposed.is_null() {
                        let proposed_root = proposed.calculate_root();
                        if let Some(params) = self.cpe_set.get_params(proposed_root) {
                            if params.start_height < current_params.start_height {
                                slog!(OldCpeProposed, proposing_peer: peer,
                                      proposed_root: proposed_root,
                                      local_proposed_start: params.start_height,
                                      current_cpe_start: current_params.start_height,
                                      current_root: current_root,
                                );
                                log!(Debug, "Old params: {:?}", proposed);
                                return;
                            }
                            if params.start_height > block.header.height.into() {
                                slog!(CpeProposedEarly, peer: peer, root: proposed_root, expected_start_height: params.start_height,
                                );
                                log!(Debug, "Early parameters: {:?}", proposed);
                                return;
                            }
                        } else {
                            slog!(UnknownProposedCpe, peer: peer, root: proposed_root);
                            log!(Debug, "Unknown proposed CPE contents: {:?}", proposed);
                            return;
                        }
                    }
                }
                // Send it to the HSM to check it
                if let Err(e) = self.security_module.validate_block(&block.header) {
                    slog!(HsmRejectBlock, header: &block.header, error: e.to_string());
                    return;
                }
                // Otherwise, precommit to signing this block
                slog!(PrecommitDebug, blockhash, header: &block.header,
                    hex: serialize_hex(&block.header)
                );
                slog!(Precommit, blockhash);

                // Broadcast precommit to all peers -- note that we *don't* use a broadcast
                // message for this, to make auditing easier
                self.peer_mgr.broadcast_block_precommit(round_stage, blockhash);

                // Update our own precommit state and possibly sign
                self.state = match self.try_commit(round_stage, &block) {
                    Ok(Some(sig)) => State::SentSignature(block, sig),
                    Ok(None) => State::Precommitted(block),
                    Err(e) => State::Error(e),
                };
                log!(Debug, "Setting own state to: {}", self.state);
            }
            // ** precommit to signing a block **
            message::Payload::BlockPrecommit { blockhash } => {
                self.peer_mgr.record_precommit(peer, blockhash, elements::BlockHash::all_zeros());

                // If we have already committed, nothing more to do.
                if let State::SentSignature(..) = self.state {
                    return;
                }

                slog!(ReceivePrecommit, peer, blockhash);

                self.state = match mem::replace(&mut self.state, State::Starting) {
                    State::Precommitted(block) => {
                        // If the peer does not agree with us, log the discrepancy.
                        let our_hash = block.block_hash();
                        if blockhash != our_hash {
                            slog!(PrecommitWrongHash, peer,
                                our_hash: our_hash, peer_hash: blockhash,
                            );
                            State::Precommitted(block)
                        } else {
                            match self.try_commit(round_stage, &block) {
                                Ok(Some(sig)) => State::SentSignature(block, sig),
                                Ok(None) => State::Precommitted(block),
                                Err(e) => State::Error(e),
                            }
                        }
                    }
                    s => s,
                };
            }
            // ** block signature **
            message::Payload::BlockSignature { blockhash, signature } => {
                // If the signature is invalid, ignore it
                if !self.validate_block_sig(blockhash, peer, &signature) {
                    log_peer!(Warn, self, peer,
                        "Got invalid signature from {} for block {}: {}",
                        peer, blockhash, signature,
                    );
                    return;
                }

                // If the peer has precommitted, check they are consistent
                if let peer::State::Precommit(hash) = self.peer_mgr.statuses()[peer].state {
                    if blockhash != hash {
                        log_peer!(Warn, self, peer,
                            "Peer signature on {} does not match precommit to {}.",
                            blockhash, hash,
                        );
                    } else {
                        log_peer!(Info, self, peer, "Got signature on {}.", blockhash);
                        self.peer_mgr.record_signatures(peer, blockhash, signature);
                    }
                    return;
                }

                // Otherwise treat the signature as a precommit
                log_peer!(Info, self, peer,
                    "Got signature on {} from peer whose precommit we did not see.", blockhash,
                );
                self.peer_mgr.record_signatures(peer, blockhash, signature);
                // If we have already committed, nothing more to do.
                if let State::SentSignature(..) = self.state {
                    return;
                }

                self.state = match mem::replace(&mut self.state, State::Starting) {
                    State::Precommitted(block) => {
                        // If the peer does not agree with us, log the discrepancy.
                        let ourhash = block.block_hash();
                        if ourhash != blockhash {
                            log_peer!(Warn, self, peer,
                                "signed a block {:x} that disagreed with ours {:x}.",
                                blockhash, ourhash,
                            );
                            State::Precommitted(block)
                        } else {
                            match self.try_commit(round_stage, &block) {
                                Ok(Some(sig)) => State::SentSignature(block, sig),
                                Ok(None) => State::Precommitted(block),
                                Err(e) => State::Error(e),
                            }
                        }
                    }
                    s => s,
                };
            }

            // ** status **
            message::Payload::StatusBlocksignerPreSeen {
                peer_keys,
                dynafed_params,
                sidechain_tip,
                round_count,
                message,
            } => {
                // Compare the peers consensus state with our own and report the result.
                let res = self.compare_consensus_state(
                    round_stage, peer, peer_keys, dynafed_params, sidechain_tip,
                );
                if let Err(reason) = res {
                    slog!(PeerStatusMismatch, peer, command: command.text(), error: reason.succinct(), failure_info: reason.extra().as_ref().map(|info| info.as_str()));
                    self.peer_mgr.status_mismatch(peer, reason.to_string());
                } else {
                    self.peer_mgr.update_from_status(peer, header_time, round_count, message);
                }
            }

            // ** status **
            message::Payload::StatusBlocksigner {
                peer_keys,
                dynafed_params,
                sidechain_tip,
                round_count,
                peers_seen,
                message,
            } => {
                // If the peer reports having received our messages, kick its watchdog.
                if peers_seen.contains(&self.peers.my_id()) {
                    slog!(KickWatchdogForInStatusAck, peer: peer);
                    self.peer_mgr.send_network_watchdog_kick(peer);
                }

                // Compare the peers consensus state with our own and report the result.
                let res = self.compare_consensus_state(
                    round_stage, peer, peer_keys, dynafed_params, sidechain_tip,
                );
                if let Err(reason) = res {
                    slog!(PeerStatusMismatch, peer, command: command.text(), error: reason.succinct(), failure_info: reason.extra().as_ref().map(|info| info.as_str()));
                    self.peer_mgr.status_mismatch(peer, reason.to_string());
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
            // ** nack **
            message::Payload::Nack { reason } => {
                log!(Debug, "peer {} sent nack: {}", peer, reason);
            }
            // ** watchman messages **
            message::Payload::TxProposal { .. } |
            message::Payload::TxPrecommit { .. } |
            message::Payload::TxSignatures { .. } |
            message::Payload::Idle |
            message::Payload::StatusWatchmanPreSeen { .. } |
            message::Payload::StatusWatchman { .. } => {
                log!(Warn, "peer {} is sending watchman messages", peer);
            }
            message::Payload::Unknown => unreachable!(),
        }
    }

    // Broadcast Status messages
    fn send_status(&mut self, round_stage: RoundStage) {
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

        self.peer_mgr.broadcast_status_blocksigner(
            round_stage,
            peer_keys,
            self.cpe_set.params_at(self.sidechain_tip.0 + 1),
            self.sidechain_tip.1,
            self.round_count,
            self.peer_mgr.peers_seen_last_round().iter().copied().collect(),
            format!("v{};git commit {}", message::MESSAGE_VERSION, constants::GIT_COMMIT_ID),
        );
    }
}

/// The state of the signblock and fedpeg descriptor commitments found in a block.
enum DescriptorCommitments {
    /// Either one or both of the commitments were not found in the block.
    None,
    /// The commitments were found in the block, but don't match the expected descriptors.
    Mismatch,
    /// The expected commitments were found in the block.
    Found,
}

/// Determines if a block should contain the commitment descriptors.
fn should_contain_descriptors(current_root: sha256::Midstate, target: &dynafed::Params) -> bool {
    let target_root = target.params.calculate_root();

    if current_root != target_root {
        // block should contain the descriptors only if the target CPE has not been proposed before
        target.never_proposed()
    } else {
        // block should contain the descriptors only if the target CPE has not been activated before
        target.never_activated()
    }
}

/// Checks if the given block has the signblock and fedpeg descriptors.
fn check_descriptors(block: &elements::Block, current_root: sha256::Midstate, target: &dynafed::Params) -> DescriptorCommitments {
    if should_contain_descriptors(current_root, target) {
        has_target_descriptors(block, target)
    } else {
        DescriptorCommitments::None
    }
}

/// Returns true if the block has the expected signblock and watchman descriptors.
fn has_target_descriptors(block: &elements::Block, target: &dynafed::Params) -> DescriptorCommitments {
    let (signblock_expected, watchman_expected) = target.normalized_descriptors();

    match blockchain::extract_descriptor_strings(block) {
        (Some(signblock_found), Some(watchman_found)) => {
            if signblock_expected.to_string() == signblock_found && watchman_expected.to_string() == watchman_found {
                DescriptorCommitments::Found
            }
            else {
                // error: the commitments in the block proposal don't match the expected CPE descriptors
                slog!(CpeCommitmentsMismatch,
                    height: block.header.height,
                    block_hash: block.header.block_hash(),
                    signblock_found: signblock_found.into(),
                    signblock_expected: signblock_expected.to_string(),
                    watchman_found: watchman_found.into(),
                    watchman_expected: watchman_expected.to_string(),
                );
                DescriptorCommitments::Mismatch
            }
        },
        _ => {
            // either one or both of the descriptors were not found
            DescriptorCommitments::None
        }
    }
}

/// Temporary structure used to call Miniscript's `satisfy` function
struct Satisfier<'a> {
    my_id: peer::Id,
    my_sig: secp256k1::ecdsa::Signature,
    blockhash: BlockHash,
    peer_status: &'a peer::Map<peer::Status<BlockHash, Signature>>,
}

impl<'a, T: miniscript::ToPublicKey> miniscript::Satisfier<T> for Satisfier<'a> {
    fn lookup_ecdsa_sig(&self, signing_pk: &T) -> Option<bitcoin::ecdsa::Signature> {
        let sighash = bitcoin::sighash::EcdsaSighashType::All;
        let peer_id = peer::Id::from(signing_pk.to_public_key().inner);

        if !self.peer_status.in_consensus(peer_id) {
            return None;
        }

        let (sig_opt, result) = match self.peer_status[peer_id].state.clone() {
            peer::State::Awol => {
                if peer_id == self.my_id {
                    (
                        Some((self.my_sig, sighash)),
                        SignState::SelfSuccess(self.my_sig),
                    )
                } else {
                    (None, SignState::Missing)
                }
            },
            peer::State::Present => (None, SignState::NoPrecommit),
            peer::State::Precommit(hash) => {
                let log = if hash == self.blockhash {
                    SignState::NoSignature
                } else {
                    SignState::WrongPrecommitment(hash)
                };
                (None, log)
            },
            peer::State::SentSignatures(hash, sig) => {
                if hash == self.blockhash {
                    (Some((sig, sighash)), SignState::Success(sig))
                } else {
                    (
                        None,
                        SignState::WrongSignature {
                            hash,
                            sig,
                        },
                    )
                }
            }
            peer::State::StatusMismatch(_) => (None, SignState::Errored),
            peer::State::Errored => (None, SignState::Errored),
        };

        slog!(CombineSignature, peer: peer_id, result: result,);

        // transform the tuple into an EcdsaSig
        sig_opt.map(|(sig, hash_ty)| {
            bitcoin::ecdsa::Signature {
                sig,
                hash_ty,
            }
        })
    }
}
