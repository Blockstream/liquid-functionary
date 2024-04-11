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

//! # Peer
//! Functions and data structures to deal with peers
//!

use std::{fmt, mem, ops, time};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;

use bitcoin::hashes::sha256d;
use bitcoin::secp256k1::{self, PublicKey};
use time::{empty_tm, now_utc, Duration, Tm, Timespec};

use message::{self, Message};
use network::NetworkCtrl;
use rotator::RoundStage;
use running_avg::RunningAverage;
use watchman::{fee, transaction};
use watchman::blockchain::OutputCounter;

pub use common::PeerId as Id;

/// Data associated to a peer, obtained from the configuration file
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct Peer {
    /// The name of the peer. This is only used for local debug output and
    /// does not need to be canonicalized in any way.
    pub name: String,
    /// List of url:port strings indicating the addresses on which to connect
    /// to this peer
    #[serde(default)]
    pub addresses: Vec<String>,
    /// A public key used for authenticating messages to this peer
    #[serde(rename = "communication_public_key")]
    pub comm_pk: PublicKey,
    /// A public key used for authenticating messages to this peer
    #[serde(rename = "legacy_communication_public_key")]
    pub comm_pk_legacy: Option<PublicKey>,
    /// A public key used by this peer for signing blocks or transactions
    #[serde(rename = "signing_public_key")]
    pub sign_pk: PublicKey,
}

impl Peer {
    /// Log information about the peer
    pub fn log(&self, consensus: &HashSet<Id>) {
        slog!(PeerInfo, name: &self.name, id: self.id(), communication_pubkey: self.comm_pk,
            legacy_communication_pubkey: self.comm_pk_legacy,
            signing_pubkey: self.sign_pk, in_consensus: consensus.contains(&self.id()),
            network_addresses: &self.addresses,
        );
    }

    /// Calculate the peer's ID.
    pub fn id(&self) -> Id {
        Id::from(self.sign_pk)
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} (", self.name)?;
        for (i, addr) in self.addresses.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", addr)?;
        }
        f.write_str(")")
    }
}

impl VerifySig for Peer {
    fn verify_sig<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        msghash: &secp256k1::Message,
        signature: &secp256k1::ecdsa::Signature,
    ) -> Result<(), secp256k1::Error> {
        secp.verify_ecdsa(msghash, signature, &self.comm_pk)
    }
}

/// Trait describing the ability of some peer-related data
/// to verify a signature, e.g. on a network message
pub trait VerifySig {
    /// Verify a signature
    fn verify_sig<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        msghash: &secp256k1::Message,
        signature: &secp256k1::ecdsa::Signature,
    ) -> Result<(), secp256k1::Error>;
}

/// A list of peers which is indexed by a canonical ordering
#[derive(Debug, Clone)]
pub struct Map<T> {
    map: HashMap<Id, T>,
    /// The set of peer IDs that are part of consensus.
    consensus: HashSet<Id>,
    /// peer ID of this node
    me: Id,
}

/// Map from peer IDs to configuration data about those peers
pub type List = Map<Peer>;

impl List {
    /// Builds a peer map, starting from a list of peers read from the
    /// configuration file.
    ///
    /// Will panic if our name does not appear exactly once in the peer list.
    /// Though this should happen on startup right away.
    pub fn from_slice<F>(peers: &[Peer], mut in_consensus: F, myname: &str) -> List
        where F: FnMut(&PublicKey) -> bool
    {
        let mut map = HashMap::with_capacity(peers.len());
        let mut consensus = HashSet::with_capacity(peers.len());
        let mut me = None;
        for peer in peers {
            let id = Id::from(peer.sign_pk);
            if myname == peer.name {
                if me.is_some() {
                    panic!("Our name `{}` appeared in the peer list twice", myname);
                } else {
                    me = Some(id);
                }
            }
            if in_consensus(&peer.sign_pk) {
                consensus.insert(id);
            }
            map.insert(id, peer.clone());
        }
        List {
            map: map,
            consensus: consensus,
            me: me.expect(&format!("Our name `{}` did not appear in the peer list", myname)),
        }
    }

    /// Check the list of peer keys given in a status message against
    /// the peers in this list. Returns false if there is a serious
    /// discrepancy (i.e. we disagree about a specific peer's keys);
    /// otherwise returns true
    pub fn check_peer_keys(
        &self,
        sending_peer: Id,
        peer_keys: &[(Id, PublicKey, PublicKey)],
    ) -> bool {
        let mut ret = true;
        if peer_keys.len() != self.len() {
            // Log a warning but do not set the `ConfigMismatch` flag,
            // since this is not a fatal issue (only if we disagree on
            // the currently active set of peers, which is given by the
            // signblockscript in the block we're signing)
            slog!(PeerCountMismatch, peer: sending_peer,
                other_n_peers: peer_keys.len(), our_n_peers: self.len()
            );
        }
        for &(id, comm_key, sign_key) in peer_keys {
            match self.map.get(&id) {
                Some(known_peer) => {
                    if known_peer.comm_pk != comm_key && known_peer.comm_pk_legacy != Some(comm_key) {
                        slog!(PeerCommKeyMismatch, peer: sending_peer,
                            expected_comm_key: known_peer.comm_pk, claimed_comm_key: comm_key
                        );
                    }
                    if known_peer.sign_pk != sign_key {
                        slog!(PeerSignKeyMismatch, peer: sending_peer,
                            expected_sign_key: known_peer.sign_pk, claimed_sign_key: sign_key
                        );
                        ret = false;
                    }
                },
                None => {
                    slog!(PeerUnknownPeer, peer: sending_peer, unknown_peer: id, comm_key, sign_key);
                }
            }
        }
        ret
    }
}

impl<T> Map<T> {
    /// Creates an empty list with `my_id` set and nothing else
    pub fn empty(me: Id) -> Map<T> {
        Map {
            map: HashMap::new(),
            consensus: HashSet::new(),
            me: me,
        }
    }

    /// Update the list from another list of type `U`, given callbacks to handle
    /// added and deleted peers. Here `add_cb` converts a source object to the
    /// appropriate type for this list; `del_cb` simply runs for each deleted
    /// peer.
    pub fn update_from<F, G, U>(
        &mut self,
        new: &Map<U>,
        mut add_cb: F,
        mut del_cb: G,
    ) where
        F: FnMut(&U) -> T,
        G: FnMut(&mut T),
    {
        self.map.retain(|id, data| {
            if new.map.contains_key(id) {
                true
            } else {
                del_cb(data);
                false
            }
        });

        for (id, data) in &new.map {
            if !self.map.contains_key(id) {
                self.map.insert(*id, add_cb(data));
            }
        }

        self.consensus = new.consensus.clone();
    }

    /// Lookup a peer by its signing public key
    pub fn by_sign_pk(&self, sign_pk: &PublicKey) -> Option<&T> {
        self.by_id(Id::from(*sign_pk))
    }

    /// Lookup a peer by its ID
    pub fn by_id(&self, id: Id) -> Option<&T> {
        self.map.get(&id)
    }

    /// Lookup a peer by its ID and get a mutable reference.
    pub fn mut_by_id(&mut self, id: Id) -> Option<&mut T> {
        self.map.get_mut(&id)
    }

    /// Lookup the peer that represents this node
    pub fn my_id(&self) -> Id {
        self.me
    }

    /// Returns iterator over all peers.
    pub fn iter(&self) -> impl Iterator<Item=(Id, &T)> {
        self.map.iter().map(|(&id, v)| (id, v))
    }

    /// Returns an iterator over all values.
    pub fn values(&self) -> impl Iterator<Item=&T> {
        self.map.values()
    }

    /// Returns a mutable iterator over all peer values.
    pub fn values_mut(&mut self) -> impl Iterator<Item=&mut T> {
        self.map.values_mut()
    }

    /// Returns iterator over all peers that skips `me`.
    pub fn without_me(&self) -> impl Iterator<Item=(Id, &T)> {
        self.map.iter().filter(move |(id, _)| **id != self.me).map(|(&id, v)| (id, v))
    }

    /// Returns an iterator over all IDs.
    pub fn ids(&self) -> impl Iterator<Item=Id> + '_ {
        self.map.keys().copied()
    }

    /// Get the number of peers in the list
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns an iterator over consensus peers.
    pub fn consensus(&self) -> impl Iterator<Item=(Id, &T)> {
        self.iter().filter(move |(id, _)| self.consensus.contains(id))
    }

    /// Check whether the peer ID is in the consensus set.
    pub fn in_consensus(&self, id: Id) -> bool {
        self.consensus.contains(&id)
    }

    /// Returns an iterator over consensus peers that skips `me`.
    pub fn consensus_without_me(&self) -> impl Iterator<Item=(Id, &T)> {
        self.consensus().filter(move |(id, _)| *id != self.me)
    }

    /// Returns the set of the consensus peers' IDs.
    pub fn consensus_ids(&self) -> &HashSet<Id> {
        &self.consensus
    }

    /// Returns the set of consensus peer IDs in consensus order.
    pub fn consensus_ordered_ids(&self) -> Vec<Id> {
        let mut id_set: Vec<Id> = self.ids().filter(|i| self.consensus.contains(i)).collect();
        id_set.sort();
        id_set
    }

    /// (Testing only) override which peer is `me`
    #[cfg(test)]
    pub fn set_my_id(&mut self, me: Id) {
        self.me = me;
    }
}

// Indexing traits
impl<T> ops::Index<Id> for Map<T> {
    type Output = T;
    fn index(&self, index: Id) -> &T {
        &self.map[&index]
    }
}

impl<T> ops::IndexMut<Id> for Map<T> {
    fn index_mut(&mut self, index: Id) -> &mut T {
        self.map.get_mut(&index).expect("indexed peer ID that did not exist")
    }
}

/// Potential states that a peer can be in during a round. This enum is used to describe
/// the state of other peers as this peer sees them. It is unrelated to what is in the
/// peer's internal state machine
///
/// The generic types are the precommit type and the signatures type.
#[derive(Clone, PartialEq, Eq)]
pub enum State<P, S> {
    /// Peer has not participated in the round
    Awol,
    /// Peer has sent status message but otherwise not participated
    Present,
    /// Peer has precommitted
    Precommit(P),
    /// Peer has sent its signatures
    SentSignatures(P, S),
    /// There was a mismatch between the peer's status and ours, based
    /// on its status message.
    StatusMismatch(String),
    /// Peer errored, ignoring rest of the round.
    Errored,
}

impl<P, S> State<P, S> {
    /// Whether this peer is in an OK state and is still part of the round.
    pub fn is_ok(&self) -> bool {
        match self {
            State::Awol => true,
            State::Present => true,
            State::Precommit(_) => true,
            State::SentSignatures(..) => true,
            State::StatusMismatch(_) => false,
            State::Errored => false,
        }
    }
}

impl<P: fmt::Display, S: fmt::Debug> fmt::Debug for State<P, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            State::Awol => f.write_str("Awol"),
            State::Present => f.write_str("Present"),
            State::Precommit(hash) => write!(f, "Precommit({})", hash),
            State::SentSignatures(hash, ref sig) => {
                write!(f, "SentSignatures({}, {:?})", hash, sig)
            }
            State::StatusMismatch(ref e) => write!(f, "StatusMismatch({})", e),
            State::Errored => f.write_str("Errored"),
        }
    }
}

impl<P: fmt::Display, S: fmt::Debug> fmt::Display for State<P, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// The status of a peer, in our view
#[derive(Clone)]
pub struct Status<P, S> {
    /// The time of the last status message
    pub last_status_message: Tm,
    /// The difference between the time in that message and the real time
    pub clock_skew: Duration,
    /// The number of rounds this peer claims to have been up for
    pub n_rounds_up: u32,
    /// The message field of the last status message
    pub last_message: String,
    /// The peer's state in this round
    pub state: State<P, S>,
    /// The running average of clock skews
    avg_clock_skew: RunningAverage,
}

impl<P, S> Default for Status<P, S> {
    /// Create a blank Status for a new peer
    fn default() -> Status<P, S> {
        Status {
            last_status_message: empty_tm(),
            clock_skew: Duration::zero(),
            n_rounds_up: 0,
            last_message: String::new(),
            state: State::Awol,
            avg_clock_skew: RunningAverage::new(),
        }
    }
}

impl<P, S> Status<P, S> {
    /// the running average of clock skews
    pub fn avg_clock_skew(&self) -> f64 {
        self.avg_clock_skew.mean()
    }

    /// Reset a peer's state for a new round
    fn reset_for_new_round(&mut self) {
        self.state = State::Awol;
    }

    /// Update a peer's state from a status message
    pub fn update_from_status(&mut self, time: Timespec, round_count: u32, message: String) {
        self.last_status_message = now_utc();
        self.clock_skew = time - self.last_status_message.to_timespec();
        self.n_rounds_up = round_count;
        self.last_message = message;
        self.avg_clock_skew.sample(self.clock_skew.num_milliseconds() as f64);
        if let State::Awol = self.state {
            self.state = State::Present;
        }
    }
}

impl<P: fmt::Display, S: fmt::Debug> Status<P, S> {
    /// Log the status using a [PeerStatus] log.
    pub fn log(&self, self_id: Id, name: &str) {
        slog!(PeerStatus,
            peer: self_id,
            name: name,
            last_status_msg: time::UNIX_EPOCH.checked_add(
                time::Duration::from_secs(self.last_status_message.to_timespec().sec as u64)
            ).unwrap_or(time::UNIX_EPOCH),
            clock_skew: self.clock_skew.to_std().unwrap_or_default(),
            n_rounds_up: self.n_rounds_up,
            last_msg: &self.last_message,
            state: format!("{:?}", self.state),
        );
    }
}

impl<P: fmt::Display, S: fmt::Debug> fmt::Display for Status<P, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "Last status at: {}; Clock skew: {}ms; Up for {} rounds; state: {}; filtered skew: {:0}ms",
            self.last_status_message.rfc822z(), self.clock_skew.num_milliseconds(),
            self.n_rounds_up, self.state, self.avg_clock_skew.mean()
        )?;
        if !self.last_message.is_empty() {
            write!(f, ", message: {}", self.last_message)
        } else {
            f.write_str("")
        }
    }
}

/// Manager of the peers in the network.
pub struct PeerManager<P, S> {
    statuses: Map<Status<P, S>>,
    last_round_seen: HashSet<Id>,
    next_msgid: Cell<u32>,
    tx_net: Option<mpsc::SyncSender<NetworkCtrl>>,
}

impl<P: PartialEq, S> PeerManager<P, S> {
    /// Create a new peer manager.
    pub fn new(my_id: Id) -> PeerManager<P, S> {
        PeerManager {
            statuses: Map::empty(my_id),
            last_round_seen: HashSet::new(),
            next_msgid: Cell::new(0),
            tx_net: None,
        }
    }

    /// Get the status map.
    pub fn statuses(&self) -> &Map<Status<P, S>> {
        &self.statuses
    }

    /// Return the set of peers that were present since the start of the last round.
    pub fn peers_seen_last_round(&self) -> &HashSet<Id> {
        &self.last_round_seen
    }

    /// Reset all peers' statuses for a new round
    pub fn reset_for_new_round(&mut self, peers: &List) {
        // Keep track of the peers we've seen last round.
        let me = self.statuses.my_id();
        self.last_round_seen.clear();
        self.last_round_seen.extend(self.statuses.iter().filter_map(|(id, status)| {
            let present = match status.state {
                State::Awol => false,
                State::Present | State::Precommit(..) | State::SentSignatures(..)
                    | State::StatusMismatch(..) | State::Errored => true,
            };
            if id == me || present {
                Some(id)
            } else {
                None
            }
        }));

        // (this is a no-op and could potentially just be done once on init)
        self.statuses.update_from(
            peers,
            |_| Status::default(),
            |_| {},
        );

        self.next_msgid.set(0);

        for status in self.statuses.values_mut() {
            status.reset_for_new_round();
        }
    }

    /// Update a peer after receiving its status message.
    pub fn update_from_status(
        &mut self,
        peer: Id,
        time: Timespec,
        round_count: u32,
        message: String,
    ) {
        self.statuses[peer].update_from_status(time, round_count, message);
    }

    /// Record that the peer's status mismatched our state.
    pub fn status_mismatch(&mut self, peer: Id, reason: String) {
        self.statuses[peer].state = State::StatusMismatch(reason);
    }

    /// Record a precommit received by a peer.
    pub fn record_precommit(&mut self, peer: Id, precommit: P, default_precommit: P) {
        // we only don't want to go back from a signature to precommit
        if let State::SentSignatures(ref mut pc, ..) = self.statuses[peer].state {

            // NB Remove this once signatures are accompanied with commit hashes
            if *pc == default_precommit {
                *pc = precommit;
            }
        } else {
            self.statuses[peer].state = State::Precommit(precommit);
        }
    }

    /// Record signatures received by a peer.
    pub fn record_signatures(&mut self, peer: Id, commit: P, sigs: S) {
        self.statuses[peer].state = State::SentSignatures(commit, sigs);
    }

    /// Get the next msgid to use.
    fn next_msgid(&self) -> u32 {
        let ret = self.next_msgid.get();
        self.next_msgid.set(ret + 1);
        ret
    }

    /// Set the network thread handle.
    pub fn set_network_tx(&mut self, tx: mpsc::SyncSender<NetworkCtrl>) {
        assert!(self.tx_net.replace(tx).is_none());
    }

    /// Send a kick to the network watchdog for the peer.
    pub fn send_network_watchdog_kick(&self, peer: Id) {
        let tx = self.tx_net.as_ref().expect("peer manager is not yet ready to send messages");
        tx.send(NetworkCtrl::WatchdogKick(peer).into()).expect("error sending kick to network");
    }

    /// Send a message to the network thread.
    fn send_message(&self, msg: Message<message::Unsigned>) {
        let tx = self.tx_net.as_ref().expect("peer manager is not yet ready to send messages");
        tx.send(msg.into()).expect("failed to send msg on network channel");
    }

    /// Send a `StatusBlocksigner` to every peer
    pub fn broadcast_status_blocksigner(
        &self,
        stage: RoundStage,
        peer_keys: Vec<(Id, PublicKey, PublicKey)>,
        dynafed_params: Vec<elements::dynafed::Params>,
        sidechain_tip: elements::BlockHash,
        round_count: u32,
        peers_seen: Vec<Id>,
        message: String,
    ) {

        let msgid = self.next_msgid();

        self.send_message(Message::status_blocksigner(
            stage, msgid, peer_keys.clone(), dynafed_params.clone(),
            sidechain_tip, round_count, peers_seen.clone(), message.clone(),
        ));
    }

    /// Send a `StatusWatchman` to every peer
    pub fn broadcast_status_watchman(
        &self,
        stage: RoundStage,
        peer_keys: Vec<(Id, PublicKey, PublicKey)>,
        mainchain_hash: bitcoin::BlockHash,
        sidechain_hash: elements::BlockHash,
        change_spk_hash: sha256d::Hash,
        n_mainchain_confirms: u64,
        n_sidechain_confirms: u64,
        round_count: u32,
        fee_pool_summary: fee::PoolSummary,
        n_pending_transactions: u64,
        output_counter: OutputCounter,
        percentiles: [u64; 5],
        pending_input_value: u64,
        pending_change_value: u64,
        peers_seen: Vec<Id>,
        message: String,
    ) {
        let msgid = self.next_msgid();
        self.send_message(Message::status_watchman(
            stage, msgid, peer_keys.clone(), mainchain_hash,
            sidechain_hash, change_spk_hash, n_mainchain_confirms, n_sidechain_confirms,
            round_count, fee_pool_summary, n_pending_transactions, output_counter,
            percentiles, pending_input_value, pending_change_value, peers_seen.clone(),
            message.clone(),
        ));
    }

    /// Broadcast an unsigned block
    pub fn broadcast_unsigned_block(&self, stage: RoundStage, block: &elements::Block) {
        let msgid = self.next_msgid();
        self.send_message(Message::unsigned_block(stage, msgid, block.clone()));
    }

    /// Broadcast a precommitment to signing a block
    pub fn broadcast_block_precommit(&self, stage: RoundStage, blockhash: elements::BlockHash) {
        let msgid = self.next_msgid();
        self.send_message(Message::block_precommit(stage, msgid, blockhash));
    }

    /// Send a block signature to all other peers
    pub fn broadcast_block_signature(
        &self,
        stage: RoundStage,
        blockhash: elements::BlockHash,
        signature: secp256k1::ecdsa::Signature,
    ) {
        let msgid = self.next_msgid();
        self.send_message(Message::block_signature(stage, msgid, blockhash, signature));
    }

    /// Broadcast a transaction proposal
    pub fn broadcast_tx_proposal(
        &self,
        stage: RoundStage,
        proposal: &transaction::ConcreteProposal,
    ) {
        let msgid = self.next_msgid();
        self.send_message(Message::tx_proposal(stage, msgid, proposal.clone()));
    }

    /// Broadcast a precommitment to signing a transaction
    pub fn broadcast_tx_precommit(&self, stage: RoundStage, txid: bitcoin::Txid) {
        let msgid = self.next_msgid();
        self.send_message(Message::tx_precommit(stage, msgid, txid));
    }

    /// Broadcast signatures on a transaction proposal
    pub fn broadcast_tx_signatures(
        &self,
        stage: RoundStage,
        sigs: &transaction::TransactionSignatures,
    ) {
        let msgid = self.next_msgid();
        self.send_message(Message::tx_signatures(stage, msgid, sigs.clone()));
    }

    /// Broadcast an `Idle` message
    pub fn broadcast_idle(&self, stage: RoundStage) {
        let msgid = self.next_msgid();
        self.send_message(Message::idle(stage, msgid));
    }
}

impl<P, S> PeerManager<P, S> where P: Copy + PartialEq {
    /// This is a hacky way to replace signatures for an empty commitment.
    pub fn replace_empty_commits(&mut self, commit: P, empty_commit: P) {
        for peer in self.statuses.values_mut() {
            peer.state = match mem::replace(&mut peer.state, State::Awol) {
                State::SentSignatures(t, sigs) if t == empty_commit => {
                    State::SentSignatures(commit, sigs)
                }
                s => s,
            };
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use bitcoin::secp256k1::SecretKey;
    use std::str::FromStr;

    /// Test function to generate a signing context and peer list, for general use
    /// throughout unit tests even outside of this module.
    pub fn generate_peers(n: usize, index: usize)
        -> (message::SigningContext<secp256k1::SignOnly>, List)
    {
        use bitcoin::secp256k1::Secp256k1;

        let secp = Secp256k1::signing_only();

        if n > 4 {
            panic!("Please hardcode more keys (need {}, have 4)", n);
        }
        let secret_keys = [
            (
                SecretKey::from_str(
                    "a0f13d9076b8e0ad5386bd28405d6ae5a08ded1abdd219b88b770dc7a836efcc",
                ).unwrap(),
                SecretKey::from_str(
                    "5157488dda41597cb8d84a377724e03f1518a11c6a43b8f4b2ee6586c387b669",
                ).unwrap(),
            ),
            (
                SecretKey::from_str(
                    "5551387a9f07e7be732d080d98ba977c48e36569cb0f29a032ee7aed12c6533e",
                ).unwrap(),
                SecretKey::from_str(
                    "9ce64e4329b7217674d839d5d57133b0510afb4531ed1f284b794d6face10a1f",
                ).unwrap(),
            ),
            (
                SecretKey::from_str(
                    "63266ce12d09a0e61968a075ae7ed1087bd362c68e718e99a9a0b35db0c34634",
                ).unwrap(),
                SecretKey::from_str(
                    "1f7b5d0f01273768e458bc1e281e3afdc9cf94c073d2d31340a248f25ff37162",
                ).unwrap(),
            ),
            (
                SecretKey::from_str(
                    "d7b3566b1320a0583ed2bf0ad520daaafb852773c5b8b120b45c91a4c3639734",
                ).unwrap(),
                SecretKey::from_str(
                    "f8840d2e2dd4cb831062ac3fedb158136dcd18561f2cf8ff3167167ee86a1e6c",
                ).unwrap(),
            ),
        ];

        let mut list = vec![];
        let mut comm_sk = None;
        for i in 0..n {
            let sk_c = secret_keys[i].0;
            let pk_c = PublicKey::from_secret_key(&secp, &sk_c);
            let sk_s = secret_keys[i].1;
            let pk_s = PublicKey::from_secret_key(&secp, &sk_s);

            list.push(Peer {
                name: format!("Peer{}", i),
                addresses: vec![format!("peer{}:{}", i, i * 1111)],
                comm_pk: pk_c,
                comm_pk_legacy: None,
                sign_pk: pk_s,
            });
            if i == index {
                comm_sk = Some(sk_c);
            }
        }
        let list = List::from_slice(&list[..], |_| true, &list[index].name[..]);
        (
            message::SigningContext {
                secp: secp,
                comm_sk: comm_sk.unwrap(),
                my_id: list.my_id(),
            },
            list,
        )
    }

    /// Test if `me` is skipped when iterating using without_me
    #[test]
    fn without_me() {
        for n in 1..5 {
            let (_, mut list) = generate_peers(n, n - 1);
            assert_eq!(list.without_me().count(), n - 1);
            for (id, _) in list.without_me() {
                assert_ne!(id, list.me);
            }

            list.me = Id::default();
            assert_eq!(list.without_me().count(), n);
            for (id, _) in list.without_me() {
                assert_ne!(id, list.me);
            }
        }

    }

}
