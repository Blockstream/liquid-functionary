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

//! # Blocksigner logs
//!

use std::borrow::Cow;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use elements;
use miniscript;

use common::{BlockHeight, SignState, PeerId};

/// Blocksigner starting info
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct StartingBlocksigner<'a> {
    /// Path to the configuration file
    pub config_path: &'a str,
    /// git commit ID the software was compiled with, and config file path
    pub git_commit: &'a str,
    /// The semver version of the functionary software.
    pub functionary_version: &'a str,
}

/// Peer is master and will propose the given block.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WillPropose {
    /// The hash of the block we're proposing
    pub block_hash: elements::BlockHash,
    /// The height of the block we're proposing
    pub block_height: u32,
}

/// The peer's signature result
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CombineSignature {
    /// Name of the peer
    pub peer: PeerId,
    /// Whether the peer gave a valid signature
    pub result: SignState,
}

/// We are precommitting to signing a block
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Precommit {
    /// Blockhash that we precommitted to
    pub blockhash: elements::BlockHash,
}

/// We are precommitting to signing a block (debug version)
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PrecommitDebug<'a> {
    /// Blockhash that we precommitted to
    pub blockhash: elements::BlockHash,
    /// The block that was rejected
    pub header: &'a elements::BlockHeader,
    /// Hex encoded version of the block
    pub hex: String,
}

/// We received a precommit message from a peer
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ReceivePrecommit {
    /// Peer that sent us the proposal
    pub peer: PeerId,
    /// Blockhash that the peer precommitted to
    pub blockhash: elements::BlockHash,
}

/// Status of sync'ing a blockchain
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct BlocksignerSyncStatus<'a> {
    /// Which blockchain is being sync'd
    pub blockchain: &'a str,
    /// Current height that we are sync'd to
    pub current_height: u64,
    /// Maximum "finalized" height that we are aware of
    pub max_height: u64,
}

/// Round stage starting
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct BlocksignerStartStage {
}

/// Round completed successfully. We signed and broadcast a block
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct BlocksignerRoundComplete {
    /// hash of the block we broadcast
    pub blockhash: elements::BlockHash,
}

/// We skipped a round, since we just started up
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct BlocksignerRoundSkipped {
}

/// Didn't send signature to the peer.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct BlocksignerSignatureSkipped {
    // ID of peer that is skipped
    pub peer: PeerId,
    pub peer_state: String,
}

/// Round did not complete - master did not send a block
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RoundFailedNoBlock {
}

/// Round did not complete - not enough precommitments were
/// seen, so we didn't sign
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RoundFailedPrecommits {
    /// The number of precommitments required to produce a signature
    pub threshold: usize,
    /// The number of precommitments we actually got
    pub n_precommits: usize,
    /// The peers who did not commit to our block
    pub bad_peers: Vec<PeerId>,
}

/// Round did not complete - not enough signatures
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RoundFailedSignatures {
    /// Stringified version of the error Miniscript returned
    pub error: String,
}

/// Round did not complete because we were in some error state
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct BlocksignerRoundErrored {
    /// Stringified description of the error state
    pub error: String,
}

/// Received an unsigned block proposal from a peer we do not believe is
/// master
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct BlockFromNonMaster {
    /// Peer that sent us the proposal
    pub peer: PeerId,
}

/// Received an unsigned block proposal from master, but when we weren't
/// expecting one
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct BlockAtWrongTime {
    pub peer: PeerId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_state: Option<String>,
}

/// The HSM rejected a block
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct HsmRejectBlock<'a> {
    /// The block that was rejected
    pub header: &'a elements::BlockHeader,
    /// Stringified version of the HSM error
    pub error: String,
}

/// The daemon (through testproposedblock RPC) rejected a block
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DaemonRejectBlock<'a> {
    /// The block that was rejected
    pub header: &'a elements::BlockHeader,
    /// Stringified version of the HSM error
    pub error: String,
}

/// Received a precommit at the wrong time (likely, after having already
/// received a precommit or a signature), which we are rejecting for that
/// reason.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PrecommitAtWrongTime {
    /// Peer that sent us the precommit
    pub peer: PeerId,
    pub peer_state: String,
}

/// A peer is precommitting to a hash that differs from the hash that
/// we precommitted to.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PrecommitWrongHash {
    /// Peer that sent us the precommit
    pub peer: PeerId,
    /// Blockhash that we precommitted to
    pub our_hash: elements::BlockHash,
    /// Blockhash that the peer precommitted to
    pub peer_hash: elements::BlockHash,
}

/// Proposed change to consensus parameters
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct BlocksignerConsensusProposal<'a> {
    /// the current dynafed root
    pub current_params_root: sha256::Midstate,
    /// the proposed dynafed root
    pub proposed_params_root: sha256::Midstate,
    /// The current signblock scriptPubKey.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_fedpeg_program: Option<&'a bitcoin::Script>,
    /// The proposed signblock scriptPubKey.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_fedpeg_program: Option<&'a bitcoin::Script>,
    /// The current signblock script
    /// contains Option<&'a Vec<u8>>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_fedpeg_script: Option<String>,
    /// The proposed signblock scriptPubKey.
    /// contains Option<&'a Vec<u8>>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_fedpeg_script: Option<String>,
    /// The descriptor of the parameters using member names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor_named: Option<&'a miniscript::Descriptor<String>>,
    /// The descriptor of the parameters using actual pubkeys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor_keys: Option<&'a miniscript::Descriptor<PublicKey>>,
    /// the semantic policy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Whether we are part of consensus.
    pub in_consensus: bool,
}

/// The consensus parameters have changed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlocksignerConsensusChanged<'a> {
    /// the dynafed root
    pub params_root: sha256::Midstate,
    /// The signblock script.
    pub signblockscript: Cow<'a, elements::Script>,
    /// The descriptor of the parameters using member names.
    pub descriptor_named: Cow<'a, miniscript::Descriptor<String>>,
    /// The descriptor of the parameters using actual pubkeys.
    pub descriptor_keys: Cow<'a, miniscript::Descriptor<PublicKey>>,
    /// the semantic policy
    pub policy: String,
    /// Whether we are part of consensus.
    pub in_consensus: bool,
}

/// The block we created last round was replaced on chain.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlockReplacedInChain {
    /// The height of the block that was replaced.
    pub height: u64,
    /// The block we created at that height.
    pub our_block: elements::BlockHash,
    /// The block that block was replaced with at that height.
    /// If [None], our block just vanished, look at [error].
    pub current: Option<elements::BlockHash>,
    /// Error returned by the RPC when looking for block.
    pub error: Option<String>,
    /// The round this (our) block was created in.
    pub round: u64,
    /// The master that proposed the block.
    pub master: PeerId,
}

/// The consensus management state from getblockchaininfo
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConsensusManagementState {
    /// How many blocks have passed in the current epoch
    pub epoch_age: BlockHeight,
    /// How many blocks are in any epoch
    pub epoch_length: BlockHeight,
    /// Size in bytes of the Elements block and undo files
    pub size_on_disk: u64,
}

/// CPE statuses updated
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ParamsUpdated {
    /// The CPE root
    pub root: sha256::Midstate,
    /// The new CPE status
    pub status: String,
    /// Sidechain blockheight
    pub height: u64,
}

/// Submitted block contained descriptor strings
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlockIncludesDescriptors {
    /// Block height
    pub height: u32,
    /// Block hash
    pub hash: elements::BlockHash,
}

/// Special implementation to deal with SignState (since it can
/// either serialize into a single element or into an object --and
/// that polymorphism confuses something in the elk ingestion.
impl serde::ser::Serialize for CombineSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
        {
            #[derive(Serialize)]
            struct CombinedSigSerialize {
                peer: PeerId,
                result: String,
                #[serde(skip_serializing_if = "Option::is_none")]
                sig: Option<String>,
                #[serde(skip_serializing_if = "Option::is_none")]
                hash: Option<String>,
            }

            let (result, sig, hash) = match self.result {
                SignState::Success(sig) => ("success", Some(sig.to_string()), None),
                SignState::SelfSuccess(sig) => ("self_success", Some(sig.to_string()), None),
                SignState::Missing => ("missing", None, None),
                SignState::NoPrecommit => ("no_precommit", None, None),
                SignState::NoSignature => ("no_signature", None, None),
                SignState::WrongPrecommitment(hash) => ("wrong_precommitment", None, Some(hash.to_string())),
                SignState::WrongSignature{hash, sig} => ("wrong_signature", Some(sig.to_string()), Some(hash.to_string())),
                SignState::Errored => ("errored", None, None),
            };

            let sign_state_output = CombinedSigSerialize {
                peer: self.peer,
                result: result.to_string(),
                sig,
                hash,
            };

            serde::Serialize::serialize(&sign_state_output, serializer)
        }
}
