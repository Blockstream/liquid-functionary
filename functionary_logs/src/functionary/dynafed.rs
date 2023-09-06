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

//! # Dynamic Federations
//!

use std::collections::HashSet;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;

use common::PeerId;

/// A peer indicated in its status message support for a different
/// number of peers than we did
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PeerCountMismatch {
    /// Peer that sent us the status
    pub peer: PeerId,
    /// Number of peers that the other has configured
    pub other_n_peers: usize,
    /// Number of peers that we have configured
    pub our_n_peers: usize,
}

/// A peer described in its status message keys for a peer that we
/// don't recognize
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PeerUnknownPeer {
    /// Peer that sent us the status
    pub peer: PeerId,
    /// Peer that was described, which we have no support for
    pub unknown_peer: PeerId,
    /// Communication key of unrecognized peer
    pub comm_key: PublicKey,
    /// HSM signing key of unrecognized peer
    pub sign_key: PublicKey,
}

/// A peer described in its status message the incorrect communication
/// key for some other peer
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PeerCommKeyMismatch {
    /// Peer that sent us the status
    pub peer: PeerId,
    /// Communication key that we have for this peer
    pub expected_comm_key: PublicKey,
    /// Communication key that the other peer claimed for this peer
    pub claimed_comm_key: PublicKey,
}

/// A peer described in its status message the incorrect signing
/// key for some other peer. Since peer IDs are derived by hashing
/// signing keys, this error should be impossible unless there is
/// deliberately an ID collision. This indicates malicious behaviour
/// which will likely cause the network to malfunction.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PeerSignKeyMismatch {
    /// Peer that sent us the status
    pub peer: PeerId,
    /// Sign key that we have for this peer
    pub expected_sign_key: PublicKey,
    /// Sign key that the other peer claimed for this peer
    pub claimed_sign_key: PublicKey,
}

/// A peer supports some dynamic federation parameter set that we don't
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UnknownDynafedParamsSignalled {
    /// Peer that sent us the status
    pub peer: PeerId,
    /// Root of parameters that peer supports that we don't
    pub root: sha256::Midstate,
}

/// The blocksigner is proposing new consensus params.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ProposingParams {
    /// Root of parameters for referencing ConsensusParameterTally
    pub root: sha256::Midstate,
}

/// An unknown dynafed params activated on the network.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct UnknownParamsActivated {
    /// The root of the unrecognized parameters
    pub root: sha256::Midstate,
}

/// The expected descriptor commitments were not found in the block.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct CpeCommitmentsNotFound {
    pub height: u64,
    pub block_hash: elements::BlockHash,
}

/// Expected a Dynafed block header.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ExpectedDynafedHeader {
    pub height: u64,
    pub block_hash: elements::BlockHash,
}

/// The descriptor commitments in the block don't match the
/// descriptors from the target CPE.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CpeCommitmentsMismatch {
    pub height: u32,
    pub block_hash: elements::BlockHash,
    pub signblock_found: String,
    pub signblock_expected: String,
    pub watchman_found: String,
    pub watchman_expected: String,
}
/// The descriptor commitments were found in the block.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CpeCommitmentsFound {
    pub height: u64,
    pub block_hash: elements::BlockHash,
}

/// A block proposal had a "current" CPE that we don't understand. This
/// is a serious error and indicates that this functionary is unable to
/// participate in consensus
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UnknownActiveCpe {
    /// Peer that sent us the proposal; if this field is null, it means
    /// that this block came from the daemon `getnewblockhex` RPC
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<PeerId>,
    /// The root of the CPE.
    pub root: sha256::Midstate,
}

/// A block proposal had a "proposed" CPE that we don't understand. We
/// will refuse to sign it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UnknownProposedCpe {
    /// Peer that sent us the proposal
    pub peer: PeerId,
    /// The root of the unknown proposed CPE.
    pub root: sha256::Midstate,
}

/// A peer proposed a CPE that already passed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OldCpeProposed {
    /// Peer that sent us the proposal
    pub proposing_peer: PeerId,
    /// The root of the CPE.
    pub proposed_root: sha256::Midstate,
    /// Local "proposed" CPE start height
    pub local_proposed_start: u64,
    /// Local "current" CPE start height
    pub current_cpe_start: u64,
    /// The root of the active CPE.
    pub current_root: sha256::Midstate,
}

/// A peer proposed a CPE that we weren't expecting just yet
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CpeProposedEarly {
    /// Peer that sent us the proposal
    pub peer: PeerId,
    /// The root of the premature CPE.
    pub root: sha256::Midstate,
    /// The height we expect this CPE to be proposed
    pub expected_start_height: u64,
}

/// Dynamic federations are not yet active, and yet we are configured
/// to start proposing a transition. This probably indicates a bad
/// configuration. The only CPE with `start_height` before the dynafed
/// activation height should be the one with `start_height` 0; and this
/// should have parameters equivalent to the legacy parameters.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PrematureProposal {
    /// The current sidechain height
    pub current_height: u64,
    /// The height at which the CPE would activate.
    pub cpe_height: u64,
    /// Hash of premature CPE
    pub root: sha256::Midstate,
}

/// Tally of who has signalled support for what
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConsensusParameterTally<'a> {
    /// The height at which the CPE would activate.
    pub height: u64,
    /// Hash of CPE
    pub root: sha256::Midstate,
    /// Parameters that are being proposed
    pub signblock_descriptor: &'a str,
    /// Which peers support these parameters
    pub signalled: HashSet<PeerId>,
    /// Current total number of peers
    pub peer_count: usize,
}

/// What was parsed from the local config.toml
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ConsensusParameterParsed<'a> {
    /// The height at which the CPE would activate.
    pub height: u64,
    /// Hash of CPE
    pub root: sha256::Midstate,
    /// Proposed blocksigner consensus script
    pub signblock_descriptor: &'a str,
    /// Proposed watchman script
    pub watchman_descriptor: &'a str,
    /// The change address of the watchman federation.
    pub watchman_change_address_mainnet: &'a str,
    /// The change address of the watchman federation.
    pub watchman_change_address_regtest: &'a str,
    /// The tweaked change address of the watchman federation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchman_change_address_mainnet_tweaked: Option<String>,
    /// The tweaked change address of the watchman federation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchman_change_address_regtest_tweaked: Option<String>,
    /// Proposed PAK list vector
    pub watchman_pak_list: Vec<(PublicKey, PublicKey)>,
}

/// Update on our signalling for dynafed's BIP-9 activation.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ProposalDynafedActivationSignal<'a> {
    /// Whether we're signalling for dynafed's activation in our proposal.
    pub signalling: bool,
    /// The block version of our proposal's block.
    pub block_version: u32,
    /// Count of peers supporting activation
    pub supporting_count: usize,
    /// List of peers supporting activation
    pub supporting_peers: &'a HashSet<PeerId>,
}

/// Report a problem integrating a peer's status
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PeerStatusMismatch<'a> {
    /// Conflicting peer
    pub peer: PeerId,
    /// Offending message from peer
    pub command: &'a str,
    /// Offense (SignError)
    pub error: &'a str,
    /// Additional info about the error encountered
    pub failure_info: Option<&'a str>,
}
