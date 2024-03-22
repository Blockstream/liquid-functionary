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


//! # Network Messages
//! Parsing and validation of network messages
//!
//! ## Message Format
//!
//! Network messages take the following form:
//!
//! | Field   | Length | Description                                                   |
//! |---------|--------|---------------------------------------------------------------|
//! | Sig     | 64     | Signature on all the following data up to the payload         |
//! | Version | 4      | 4-byte network message version for incompatible peers         |
//! | Sender  | 6      | ID of the sender (this is a hash of her network pubkey)       |
//! | Recv'r  | 6      | ID of the receiver (this is a hash of her network pubkey)     |
//! | Round   | 4      | Round number (used in the rumoring protocol to avoid loops)   |
//! | Msgid   | 4      | Message ID used to re-order messages within a round           |
//! | Nonce   | 4      | Nonce (used in the relay mechanism to avoid loops)            |
//! | Command | 4      | The type of this message                                      |
//! | Time    | 12     | The time that the message was sent                            |
//! | Hash    | 32     | A hash of the payload (for sig-checking with only the header) |
//! | Length  | 4      | The length of the payload in bytes                            |
//! | Payload | ...    | The payload, if any                                           |
//!
//! Senders are identified by their peer ID, which is a 6-byte hash of their
//! signing public keys. Messages are authenticated by compact-encoded ECDSA
//! signatures which cover the entire non-signature portion of the message
//! header, including a hash of the full payload.
//!
//! Each message contains a `msgid`, which increments from 0 for each message
//! sent within a round. When the network layer sees an incoming message whose
//! `receiver` field is set to the peer's own ID, it caches and reorders (if
//! necessary) to ensure that the main loop only sees messages with correctly-
//! ordered `msgid`s with none skipped.
//!
//! Each message also contains a `nonce` field which must be monotonic within
//! each round. When the network layer sees an incoming message which is *not*
//! for the peer's own ID, it checks the `nonce` field. If the nonce is higher
//! than any nonce from that peer this round, the network layer forwards it to
//! the intended recepient; otherwise it drops it.
//!
//! This forward/drop behavior allows messages to reach peers even when some
//! direct links are down (or unusably slow), which happens sometimes on the Tor
//! network; on the other hand, it is why we may have reordered messages despite
//! using TCP.
//!

use bitcoin::{Amount, consensus};
use bitcoin::hashes::{self, Hash, sha256d};
use bitcoin::secp256k1::{self, PublicKey};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use time::{now_utc, Timespec};

use std::{fmt, mem, time};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use common::rollouts::ROLLOUTS;
use peer;

use rotator::RoundStage;
use watchman::blockchain::{fee, OutputCounter};
use watchman::transaction;

/// Nonce for outgoing messages
static NONCE: AtomicUsize = AtomicUsize::new(1);

/// Increment nonce for outgoing messages and return the old one
fn increment_nonce() -> u32 {
    NONCE.fetch_add(1, Ordering::SeqCst) as u32
}

/// The version of network messages
pub const MESSAGE_VERSION: u32 = 21;

/// Length of the message signature
pub const SIG_LEN: usize = 64;
/// Length of the header from signature through length
pub const HEADER_LEN: usize = 144;

/// The maximum size in bytes of message payloads.
pub const MAX_PAYLOAD_SIZE: u32 = 32_000_000;

/// Trait defining wire encoding for network messages
pub trait NetEncodable: Sized {
    /// Encode data into a writer, returning the number of bytes written
    fn encode<W: Write>(&self, w: W) -> Result<usize, Error>;
    /// Decode data from a reader
    fn decode<R: Read>(r: R) -> Result<Self, Error>;
}

/// Message type
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Command {
    /// A NAK, e.g. returned if a block request is sent to a non-master
    Nack,
    /// Legacy version of the StatusBlocksigner before the `peers_seen` field was added.
    StatusBlocksignerPreSeen,
    /// A message indicating the peer's health and clock time in UTC;
    /// also serves as a version message and contains the sender's
    /// beliefs about the state of the rotating consensus. Contains
    /// data the blocksigners must agree on.
    StatusBlocksigner,
    /// Legacy version of the StatusWatchman before the `peers_seen` field was added.
    StatusWatchmanPreSeen,
    /// Same as `StatusBlocksigner`, but with information the watchmen
    /// must agree on.
    StatusWatchman,
    /// An ACK to the Status message, used to confirm network connectivity
    StatusAck,
    /// An unsigned sidechain block (from master to peer)
    UnsignedBlock,
    /// A pre-commit to sign a block
    BlockPrecommit,
    /// Signature for a sidechain block (from peer to master)
    BlockSignature,
    /// A transaction proposal
    TxProposal,
    /// A pre-commit to sign a tx proposal
    TxPrecommit,
    /// A set of signatures for a mainchain watchman transaction
    TxSignatures,
    /// A command sent by the master to signal that there is
    /// nothing to do in this round.
    Idle,
    /// An unknown command.
    Unknown([u8; 4]),
}

impl Command {
    /// Output a text representation of the command, for logging
    pub fn text(&self) -> &'static str {
        // Remove the StatusAck command when cleaning up this rollout.
        let _ = common::rollouts::StatusAckElim::Phase3;

        match *self {
            Command::Nack => "nack",
            Command::StatusBlocksignerPreSeen => "status_blocksigner_pre_seen",
            Command::StatusBlocksigner => "status_blocksigner",
            Command::StatusWatchmanPreSeen => "status_watchman_pre_seen",
            Command::StatusWatchman => "status_watchman",
            Command::StatusAck => "status_ack",
            Command::UnsignedBlock => "unsigned_block",
            Command::BlockPrecommit => "block_precommit",
            Command::BlockSignature => "block_signature",
            Command::TxProposal => "tx_proposal",
            Command::TxPrecommit => "tx_precommit",
            Command::TxSignatures => "tx_signatures",
            Command::Idle => "idle",
            Command::Unknown(_) => "unknown",
        }
    }
}

impl NetEncodable for Command {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let bytes = match *self {
            Command::Nack => [0, 0, 0, 0],
            Command::StatusAck => [0, 0, 0, 1],
            Command::StatusBlocksignerPreSeen => [0, 0, 0, 2],
            Command::StatusWatchmanPreSeen => [0, 0, 0, 3],
            Command::StatusBlocksigner => [0, 0, 0, 4],
            Command::StatusWatchman => [0, 0, 0, 5],
            Command::UnsignedBlock => [0, 0, 1, 0],
            // Old message Command::SignedBlockHash was [0, 0, 1, 1]
            Command::BlockPrecommit => [0, 0, 1, 2],
            Command::BlockSignature => [0, 0, 1, 3],
            Command::TxProposal => [0, 0, 2, 0],
            Command::TxSignatures => [0, 0, 2, 1],
            Command::TxPrecommit => [0, 0, 2, 2],
            Command::Idle => [0, 0, 2, 3],
            Command::Unknown(b) => b,
        };
        w.write_all(&bytes[..])?;
        Ok(4)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut sl = [0; 4];
        r.read_exact(&mut sl[..])?;
        let command = match (sl[0], sl[1], sl[2], sl[3]) {
            (0, 0, 0, 0) => Command::Nack,
            (0, 0, 0, 1) => Command::StatusAck,
            (0, 0, 0, 2) => Command::StatusBlocksignerPreSeen,
            (0, 0, 0, 3) => Command::StatusWatchmanPreSeen,
            (0, 0, 0, 4) => Command::StatusBlocksigner,
            (0, 0, 0, 5) => Command::StatusWatchman,
            (0, 0, 1, 0) => Command::UnsignedBlock,
            (0, 0, 1, 2) => Command::BlockPrecommit,
            (0, 0, 1, 3) => Command::BlockSignature,
            (0, 0, 2, 0) => Command::TxProposal,
            (0, 0, 2, 1) => Command::TxSignatures,
            (0, 0, 2, 2) => Command::TxPrecommit,
            (0, 0, 2, 3) => Command::Idle,
            _ => Command::Unknown(sl),
        };
        Ok(command)
    }
}

/// Message-related error
#[derive(Debug)]
pub enum Error {
    /// byteorder de/serialization error
    ByteOrder(byteorder::Error),
    /// bitcoin_hashes de/serialization error
    BitcoinHashes(hashes::FromSliceError),
    /// Key error.
    Key(bitcoin::key::Error),
    /// Parse finished but more data was expected
    IncompleteRead(u64),
    /// I/O error reading from the network
    Io(io::Error),
    /// Received message from a peer we don't recognize
    UnknownPeerId(peer::Id),
    /// Bitcoin transaction couldn't be parsed, or something
    BadParse(bitcoin::consensus::encode::Error),
    /// Sidechain block couldn't be parsed, or something
    BadParseElements(elements::encode::Error),
    /// Payload hash did not match what was in the header
    BadMessageHash,
    /// Payload size was invalid for the command we received
    BadPayloadSize(usize, &'static str),
    /// secp error
    Secp(secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ByteOrder(ref e) => write!(f, "byteorder: {}", e),
            Error::BitcoinHashes(ref e) => write!(f, "bitcoin_hashes: {}", e),
            Error::Key(ref e) => write!(f, "bitcoin key error: {}", e),
            Error::IncompleteRead(n) => write!(f, "{} more bytes expected", n),
            Error::Io(ref e) => write!(f, "io: {}", e),
            Error::BadParse(ref e) => write!(f, "bitcoin: {}", e),
            Error::BadParseElements(ref e) => write!(f, "elements: {}", e),
            Error::UnknownPeerId(ref id) => write!(f, "peer ID {:?} not known", id),
            Error::BadMessageHash => f.write_str("bad message hash"),
            Error::BadPayloadSize(n, tp) => write!(f, "size {} not supported for message type {}", n, tp),
            Error::Secp(ref e) => write!(f, "secp256k1: {}", e),
        }
    }
}

#[doc(hidden)]
impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(e: bitcoin::consensus::encode::Error) -> Error { Error::BadParse(e) }
}

#[doc(hidden)]
impl From<elements::encode::Error> for Error {
    fn from(e: elements::encode::Error) -> Error { Error::BadParseElements(e) }
}

#[doc(hidden)]
impl From<hashes::FromSliceError> for Error {
    fn from(e: hashes::FromSliceError) -> Error { Error::BitcoinHashes(e) }
}

#[doc(hidden)]
impl From<bitcoin::key::Error> for Error {
    fn from(e: bitcoin::key::Error) -> Error { Error::Key(e) }
}

#[doc(hidden)]
impl From<byteorder::Error> for Error {
    fn from(e: byteorder::Error) -> Error { Error::ByteOrder(e) }
}

#[doc(hidden)]
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error { Error::Io(e) }
}

#[doc(hidden)]
impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error { Error::Secp(e) }
}

/// Data needed to sign a network header. Not `Copy` or `Clone` to
/// prevent excessive copying of secret data
pub struct SigningContext<C: secp256k1::Signing> {
    /// Signing context
    pub secp: secp256k1::Secp256k1<C>,
    /// Secret communication key
    pub comm_sk: secp256k1::SecretKey,
    /// ID of this node
    pub my_id: peer::Id,
}

/// Dummy structure to parameterize an unsigned header
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Unsigned;

/// Dummy structure to parameterize a validated header
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Validated;

/// Network message header
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Header<S> {
    /// Signature over all the following data. During construction
    /// this type is `Unsigned` and the header cannot be encoded or
    /// decoded. After signing it is changed to `secp256k1::Signature`.
    pub signature: S,
    /// Verison
    pub version: u32,
    /// ID of the sender
    pub sender: peer::Id,
    /// ID of the receiver
    pub receiver: peer::Id,
    /// Round number the message was sent in
    pub round: u32,
    /// ID of this message within a round (must increment by exactly
    /// one each message, starting from zero, each round). Used for messages
    /// intended for this peer. The network layer maintains a (limited)
    /// cache of messages within a round, and will only propagate messages
    /// to the main loop in correct order without skipping any. If messages
    /// arrive out of order, i.e. one with higher msgid is received before
    /// one with lower msgid, the network layer cache will hold both and
    /// reorder them.
    pub msgid: u32,
    /// Message-specific nonce, which must be monotonic within a round.
    /// Used for messages that are *not* intended for this peer, which are
    /// relayed rather than propagated to the main loop. If a message is
    /// received whose nonce (or a higher nonce) has been seen before
    /// within a round from a given peer, it is dropped. Otherwise, the
    /// peer will forward the message.
    pub nonce: u32,
    /// What this message is
    pub command: Command,
    /// Sender's clock time in UTC
    pub time: Timespec,
    /// Hash of the payload
    pub hash: sha256d::Hash,
    /// Length of the payload
    pub length: u32,
}

impl Into<logs::functionary::network::Header> for Header<secp256k1::ecdsa::Signature> {
    fn into(self) -> logs::functionary::network::Header {
        logs::functionary::network::Header {
            version: self.version,
            sender: self.sender.to_string(),
            receiver: self.receiver.to_string(),
            round: self.round,
            msgid: self.msgid,
            nonce: self.nonce,
            command: self.command.text(),
            time: time::UNIX_EPOCH + time::Duration::from_secs(self.time.sec as u64) +
                time::Duration::from_nanos(self.time.nsec as u64),
            hash: self.hash.into(),
            length: self.length,
        }
    }
}

impl<S> Header<S> {
    /// Encode a header without its signature
    fn encode_unsigned<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.encode(&mut w)?;
        len += self.sender.encode(&mut w)?;

        // read rollouts docs for comment on receiver field
        let _ = common::rollouts::Broadcast::Phase3;
        len += self.receiver.encode(&mut w)?;

        len += self.round.encode(&mut w)?;
        len += self.msgid.encode(&mut w)?;
        len += self.nonce.encode(&mut w)?;
        len += self.command.encode(&mut w)?;
        len += self.time.encode(&mut w)?;
        len += self.hash.encode(&mut w)?;
        len += self.length.encode(&mut w)?;
        Ok(len)
    }
}

impl Header<Unsigned> {
    /// Create an unsigned header suitable for sending to a peer
    pub fn to_peer(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        payload: &Payload,
    ) -> Header<Unsigned> {
        let mut engine = sha256d::Hash::engine();
        let payload_len = payload.encode_payload(&mut engine).unwrap();
        let payload_hash = sha256d::Hash::from_engine(engine);

        Header {
            signature: Unsigned,
            version: MESSAGE_VERSION,
            sender: peer::Id::default(),
            receiver: recipient,
            round: stage.round as u32,
            msgid: msgid,
            nonce: 0, // dummy
            command: payload.command(),
            time: now_utc().to_timespec(),
            hash: payload_hash,
            length: payload_len as u32,
        }
    }

    /// Signs the header, incrementing its nonce and updating its
    /// timestamp in the process
    pub fn sign<C: secp256k1::Signing>(mut self, sc: &SigningContext<C>)
        -> Header<secp256k1::ecdsa::Signature>
    {
        // Update timestamp to make diagnostics less difficult
        self.sender = sc.my_id;
        self.nonce = increment_nonce();
        self.time = now_utc().to_timespec();
        // Sign it
        let mut engine = sha256d::Hash::engine();
        assert_eq!(
            self.encode_unsigned(&mut engine).unwrap(),
            HEADER_LEN - SIG_LEN
        );
        let msghash = secp256k1::Message::from_digest_slice(
            &sha256d::Hash::from_engine(engine)[..]
        ).unwrap(); // unwrap OK for 32-byte hash

        // "Cast" the `Header<Unsigned>` to a `Header<Signature>`
        Header {
            signature: sc.secp.sign_ecdsa(&msghash, &sc.comm_sk),
            version: self.version,
            sender: self.sender,
            receiver: self.receiver,
            round: self.round,
            msgid: self.msgid,
            nonce: self.nonce,
            command: self.command,
            time: self.time,
            hash: self.hash,
            length: self.length,
        }
    }
}

impl Header<secp256k1::ecdsa::Signature> {
    /// Drop the signature from the header.
    pub fn drop_signature(self) -> Header<Validated> {
        Header {
            signature: Validated,
            version: self.version,
            sender: self.sender,
            receiver: self.receiver,
            round: self.round,
            msgid: self.msgid,
            nonce: self.nonce,
            command: self.command,
            time: self.time,
            hash: self.hash,
            length: self.length,
        }
    }
}

impl NetEncodable for Header<secp256k1::ecdsa::Signature> {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.signature.encode(&mut w)?;
        len += self.encode_unsigned(&mut w)?;
        Ok(len)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let signature = NetEncodable::decode(&mut r)?;
        let version = NetEncodable::decode(&mut r)?;
        let sender = NetEncodable::decode(&mut r)?;

        // read rollouts docs for comment on receiver field
        let _ = common::rollouts::Broadcast::Phase3;
        let receiver = NetEncodable::decode(&mut r)?;

        let round = NetEncodable::decode(&mut r)?;
        let msgid = NetEncodable::decode(&mut r)?;
        let nonce = NetEncodable::decode(&mut r)?;
        let command = NetEncodable::decode(&mut r)?;
        let time = NetEncodable::decode(&mut r)?;
        let hash = NetEncodable::decode(&mut r)?;
        let length = NetEncodable::decode(&mut r)?;

        Ok(Header {
            signature: signature,
            version: version,
            sender: sender,
            receiver: receiver,
            round: round,
            msgid: msgid,
            nonce: nonce,
            command: command,
            time: time,
            hash: hash,
            length: length,
        })
    }
}

/// Network message payload
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Payload {
    /// A NAK, e.g. returned if a block request is sent to a non-master
    Nack {
        /// Reason for the NAK
        reason: NackReason,
    },
    /// Health and status (blocksigner)
    StatusBlocksignerPreSeen {
        // Consensus
        /// List mapping peers' IDs to their communication and signing keys
        peer_keys: Vec<(peer::Id, PublicKey, PublicKey)>,
        /// Dynafed parameter sets that we understand/will sign proposals for
        dynafed_params: Vec<elements::dynafed::Params>,
        /// Tip of the sidechain
        sidechain_tip: elements::BlockHash,
        // Health
        /// Number of rounds the peer has been online for
        round_count: u32,
        /// A free-form message
        message: String
    },
    /// Health and status (blocksigner)
    StatusBlocksigner {
        // Consensus
        /// List mapping peers' IDs to their communication and signing keys
        peer_keys: Vec<(peer::Id, PublicKey, PublicKey)>,
        /// Dynafed parameter sets that we understand/will sign proposals for
        dynafed_params: Vec<elements::dynafed::Params>,
        /// Tip of the sidechain
        sidechain_tip: elements::BlockHash,
        // Health
        /// Number of rounds the peer has been online for
        round_count: u32,
        /// The ids of the peers we received a message from last round.
        peers_seen: Vec<peer::Id>,
        /// A free-form message
        message: String
    },
    /// Health and status (watchman)
    StatusWatchmanPreSeen {
        // Consensus
        /// List mapping peers' IDs to their communication and signing keys
        peer_keys: Vec<(peer::Id, PublicKey, PublicKey)>,
        /// Hash of a block in the mainchain
        mainchain_hash: bitcoin::BlockHash,
        /// Hash of a block in the sidechain
        sidechain_hash: elements::BlockHash,
        /// Untweaked scriptpubkey setting
        change_spk_hash: sha256d::Hash,
        /// Number of confirmations required for mainchain activity
        n_mainchain_confirms: u64,
        /// Number of confirmations required for sidechain activity
        n_sidechain_confirms: u64,
        // Health
        /// Number of rounds the peer has been online for
        round_count: u32,
        /// Fee rate from bitcoind estimatesmartfee
        fee_pool_summary: fee::PoolSummary,
        /// Number of in pending transactions
        n_pending_transactions: u64,
        /// Bunch of stats about the watchman's outputs
        output_counter: OutputCounter,
        /// Available output percentiles
        percentiles: [u64; 5],
        /// Pending input value
        pending_input_value: u64,
        /// Pending change value
        pending_change_value: u64,
        /// A free-form message
        message: String
    },
    /// Health and status (watchman)
    StatusWatchman {
        // Consensus
        /// List mapping peers' IDs to their communication and signing keys
        peer_keys: Vec<(peer::Id, PublicKey, PublicKey)>,
        /// Hash of a block in the mainchain
        mainchain_hash: bitcoin::BlockHash,
        /// Hash of a block in the sidechain
        sidechain_hash: elements::BlockHash,
        /// Untweaked scriptpubkey setting
        change_spk_hash: sha256d::Hash,
        /// Number of confirmations required for mainchain activity
        n_mainchain_confirms: u64,
        /// Number of confirmations required for sidechain activity
        n_sidechain_confirms: u64,
        // Health
        /// Number of rounds the peer has been online for
        round_count: u32,
        /// Fee rate from bitcoind estimatesmartfee
        fee_pool_summary: fee::PoolSummary,
        /// Number of in pending transactions
        n_pending_transactions: u64,
        /// Bunch of stats about the watchman's outputs
        output_counter: OutputCounter,
        /// Available output percentiles
        percentiles: [u64; 5],
        /// Pending input value
        pending_input_value: u64,
        /// Pending change value
        pending_change_value: u64,
        /// The ids of the peers we received a message from last round.
        peers_seen: Vec<peer::Id>,
        /// A free-form message
        message: String
    },
    /// An ACK to the Status message, used to confirm network connectivity
    StatusAck,
    /// An unsigned sidechain block (from master to peer)
    UnsignedBlock {
        /// The data
        block: elements::Block,
    },
    /// A pre-commit to sign a block
    BlockPrecommit {
        /// The block that's being committed to
        blockhash: elements::BlockHash,
    },
    /// Signature for a sidechain block (from peer to master)
    BlockSignature {
        /// The block that's being committed to
        blockhash: elements::BlockHash,
        /// A compact-encoded signature on the blockhash
        signature: secp256k1::ecdsa::Signature,
    },
    /// A transaction proposal
    TxProposal {
        /// The actual proposal
        proposal: transaction::ConcreteProposal,
    },
    /// A pre-commit to sign a transaction
    TxPrecommit {
        /// The tx that's being committed to
        txid: bitcoin::Txid,
    },
    /// A set of signatures for a mainchain watchman transaction
    TxSignatures {
        /// Signatures
        sigs: transaction::TransactionSignatures,
    },
    /// A command sent by the master to signal that there is
    /// nothing to do in this round.
    Idle,
    /// An unknown message.
    Unknown,
}

impl Payload {
    /// Obtains the `Command` for use in a message header
    pub fn command(&self) -> Command {
        match *self {
            Payload::Nack { .. } => Command::Nack,
            Payload::StatusBlocksignerPreSeen { .. } => Command::StatusBlocksignerPreSeen,
            Payload::StatusBlocksigner { .. } => Command::StatusBlocksigner,
            Payload::StatusWatchmanPreSeen { .. } => Command::StatusWatchmanPreSeen,
            Payload::StatusWatchman { .. } => Command::StatusWatchman,
            Payload::StatusAck => Command::StatusAck,
            Payload::UnsignedBlock { .. } => Command::UnsignedBlock,
            Payload::BlockPrecommit { .. } => Command::BlockPrecommit,
            Payload::BlockSignature { .. } => Command::BlockSignature,
            Payload::TxProposal { .. } => Command::TxProposal,
            Payload::TxPrecommit { .. } => Command::TxPrecommit,
            Payload::TxSignatures { .. } => Command::TxSignatures,
            Payload::Idle { .. } => Command::Idle,
            Payload::Unknown => panic!("shouldn't call this on unknown payload"),
        }
    }

    /// Encodes the payload. Not done with the `NetEncodable` trait since
    /// there is no corresponding `decode` method (as we need extra context
    /// from the header to know what to decode)
    fn encode_payload<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let mut len = 0;
        match *self {
            Payload::Nack { ref reason } => {
                len += reason.encode(&mut w)?;
            },
            Payload::StatusBlocksignerPreSeen {
                ref peer_keys,
                ref dynafed_params,
                ref sidechain_tip,
                ref round_count,
                ref message,
            } => {
                len += peer_keys.encode(&mut w)?;
                len += dynafed_params.encode(&mut w)?;
                len += sidechain_tip.encode(&mut w)?;
                len += round_count.encode(&mut w)?;
                w.write_all(message.as_bytes())?;
                len += message.len();
            },
            Payload::StatusBlocksigner {
                ref peer_keys,
                ref dynafed_params,
                ref sidechain_tip,
                ref round_count,
                ref peers_seen,
                ref message,
            } => {
                len += peer_keys.encode(&mut w)?;
                len += dynafed_params.encode(&mut w)?;
                len += sidechain_tip.encode(&mut w)?;
                len += round_count.encode(&mut w)?;
                len += peers_seen.encode(&mut w)?;
                w.write_all(message.as_bytes())?;
                len += message.len();
            },
            Payload::StatusWatchmanPreSeen {
                ref peer_keys,
                ref mainchain_hash,
                ref sidechain_hash,
                ref change_spk_hash,
                ref n_mainchain_confirms,
                ref n_sidechain_confirms,
                ref round_count,
                ref fee_pool_summary,
                ref n_pending_transactions,
                ref output_counter,
                ref percentiles,
                ref pending_input_value,
                ref pending_change_value,
                ref message,
            } => {
                len += peer_keys.encode(&mut w)?;
                len += mainchain_hash.encode(&mut w)?;
                len += sidechain_hash.encode(&mut w)?;
                len += change_spk_hash.encode(&mut w)?;
                len += n_mainchain_confirms.encode(&mut w)?;
                len += n_sidechain_confirms.encode(&mut w)?;
                len += round_count.encode(&mut w)?;
                len += fee_pool_summary.encode(&mut w)?;
                len += n_pending_transactions.encode(&mut w)?;
                len += output_counter.encode(&mut w)?;
                len += percentiles.encode(&mut w)?;
                len += pending_input_value.encode(&mut w)?;
                len += pending_change_value.encode(&mut w)?;
                w.write_all(message.as_bytes())?;
                len += message.len();
            },
            Payload::StatusWatchman {
                ref peer_keys,
                ref mainchain_hash,
                ref sidechain_hash,
                ref change_spk_hash,
                ref n_mainchain_confirms,
                ref n_sidechain_confirms,
                ref round_count,
                ref fee_pool_summary,
                ref n_pending_transactions,
                ref output_counter,
                ref percentiles,
                ref pending_input_value,
                ref pending_change_value,
                ref peers_seen,
                ref message,
            } => {
                len += peer_keys.encode(&mut w)?;
                len += mainchain_hash.encode(&mut w)?;
                len += sidechain_hash.encode(&mut w)?;
                len += change_spk_hash.encode(&mut w)?;
                len += n_mainchain_confirms.encode(&mut w)?;
                len += n_sidechain_confirms.encode(&mut w)?;
                len += round_count.encode(&mut w)?;
                len += fee_pool_summary.encode(&mut w)?;
                len += n_pending_transactions.encode(&mut w)?;
                len += output_counter.encode(&mut w)?;
                len += percentiles.encode(&mut w)?;
                len += pending_input_value.encode(&mut w)?;
                len += pending_change_value.encode(&mut w)?;
                len += peers_seen.encode(&mut w)?;
                w.write_all(message.as_bytes())?;
                len += message.len();
            },
            Payload::StatusAck => {
                // Remove the StatusAck type when cleaning up this rollout
                let _ = common::rollouts::StatusAckElim::Phase3;
            },
            Payload::UnsignedBlock { ref block } => {
                len += elements::encode::Encodable::consensus_encode(block, &mut w)?;
            },
            Payload::BlockPrecommit { ref blockhash } => {
                len += blockhash.as_raw_hash().encode(&mut w)?;
            },
            Payload::BlockSignature { ref blockhash, ref signature } => {
                len += blockhash.as_raw_hash().encode(&mut w)?;
                len += signature.encode(&mut w)?;
            },
            Payload::TxProposal { ref proposal, .. } => {
                len += proposal.encode(&mut w)?;
            },
            Payload::TxPrecommit { ref txid } => {
                len += txid.as_raw_hash().encode(&mut w)?;
            },
            Payload::TxSignatures { ref sigs } => {
                len += sigs.encode(&mut w)?;
            },
            Payload::Idle => { },
            Payload::Unknown => { },
        }
        Ok(len)
    }
}

/// Network message
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message<S> {
    /// Description of message data
    header: Header<S>,
    /// Message data
    pub payload: Payload,
}

impl NetEncodable for Message<secp256k1::ecdsa::Signature> {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.header.encode(&mut w)?;
        len += self.payload.encode_payload(&mut w)?;
        Ok(len)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let header = Header::decode(&mut r)?;
        if header.length > MAX_PAYLOAD_SIZE {
            log!(Warn, "Size of payload is {:x} and exceeds max payload size {:x}",
                header.length, MAX_PAYLOAD_SIZE,
            );
            return Err(Error::BadPayloadSize(header.length as usize, "Message<Signature>"));
        }

        let mut payload_buffer = vec![0; header.length as usize];
        r.read_exact(&mut payload_buffer)?;
        let mut cursor = io::Cursor::new(payload_buffer);
        let payload = match header.command {
            Command::Nack => Payload::Nack {
                reason: NetEncodable::decode(&mut cursor)?,
            },
            Command::StatusBlocksignerPreSeen => Payload::StatusBlocksignerPreSeen {
                peer_keys: NetEncodable::decode(&mut cursor)?,
                dynafed_params: NetEncodable::decode(&mut cursor)?,
                sidechain_tip: NetEncodable::decode(&mut cursor)?,
                round_count: NetEncodable::decode(&mut cursor)?,
                message: {
                    let bytes_left = header.length as u64 - cursor.position();
                    let mut s = String::with_capacity(bytes_left as usize);
                    cursor.read_to_string(&mut s)?;
                    s
                }
            },
            Command::StatusBlocksigner => Payload::StatusBlocksigner {
                peer_keys: NetEncodable::decode(&mut cursor)?,
                dynafed_params: NetEncodable::decode(&mut cursor)?,
                sidechain_tip: NetEncodable::decode(&mut cursor)?,
                round_count: NetEncodable::decode(&mut cursor)?,
                peers_seen: NetEncodable::decode(&mut cursor)?,
                message: {
                    let bytes_left = header.length as u64 - cursor.position();
                    let mut s = String::with_capacity(bytes_left as usize);
                    cursor.read_to_string(&mut s)?;
                    s
                }
            },
            Command::StatusWatchmanPreSeen => Payload::StatusWatchmanPreSeen {
                peer_keys: NetEncodable::decode(&mut cursor)?,
                mainchain_hash: NetEncodable::decode(&mut cursor)?,
                sidechain_hash: NetEncodable::decode(&mut cursor)?,
                change_spk_hash: NetEncodable::decode(&mut cursor)?,
                n_mainchain_confirms: NetEncodable::decode(&mut cursor)?,
                n_sidechain_confirms: NetEncodable::decode(&mut cursor)?,
                round_count: NetEncodable::decode(&mut cursor)?,
                fee_pool_summary: NetEncodable::decode(&mut cursor)?,
                n_pending_transactions: NetEncodable::decode(&mut cursor)?,
                output_counter: NetEncodable::decode(&mut cursor)?,
                percentiles: NetEncodable::decode(&mut cursor)?,
                pending_input_value: NetEncodable::decode(&mut cursor)?,
                pending_change_value: NetEncodable::decode(&mut cursor)?,
                message: {
                    let bytes_left = header.length as u64 - cursor.position();
                    let mut s = String::with_capacity(bytes_left as usize);
                    cursor.read_to_string(&mut s)?;
                    s
                },
            },
            Command::StatusWatchman => Payload::StatusWatchman {
                peer_keys: NetEncodable::decode(&mut cursor)?,
                mainchain_hash: NetEncodable::decode(&mut cursor)?,
                sidechain_hash: NetEncodable::decode(&mut cursor)?,
                change_spk_hash: NetEncodable::decode(&mut cursor)?,
                n_mainchain_confirms: NetEncodable::decode(&mut cursor)?,
                n_sidechain_confirms: NetEncodable::decode(&mut cursor)?,
                round_count: NetEncodable::decode(&mut cursor)?,
                fee_pool_summary: NetEncodable::decode(&mut cursor)?,
                n_pending_transactions: NetEncodable::decode(&mut cursor)?,
                output_counter: NetEncodable::decode(&mut cursor)?,
                percentiles: NetEncodable::decode(&mut cursor)?,
                pending_input_value: NetEncodable::decode(&mut cursor)?,
                pending_change_value: NetEncodable::decode(&mut cursor)?,
                peers_seen: NetEncodable::decode(&mut cursor)?,
                message: {
                    let bytes_left = header.length as u64 - cursor.position();
                    let mut s = String::with_capacity(bytes_left as usize);
                    cursor.read_to_string(&mut s)?;
                    s
                },
            },
            Command::StatusAck => Payload::StatusAck,
            Command::UnsignedBlock => Payload::UnsignedBlock {
                block: elements::encode::Decodable::consensus_decode(&mut cursor)?,
            },
            Command::BlockPrecommit => Payload::BlockPrecommit {
                blockhash: NetEncodable::decode(&mut cursor)?,
            },
            Command::BlockSignature => Payload::BlockSignature {
                blockhash: NetEncodable::decode(&mut cursor)?,
                signature: NetEncodable::decode(&mut cursor)?,
            },
            Command::TxProposal => Payload::TxProposal {
                proposal: NetEncodable::decode(&mut cursor)?,
            },
            Command::TxPrecommit => Payload::TxPrecommit {
                txid: NetEncodable::decode(&mut cursor)?,
            },
            Command::TxSignatures => Payload::TxSignatures {
                sigs: NetEncodable::decode(&mut cursor)?,
            },
            Command::Idle => Payload::Idle,
            Command::Unknown(_) => Payload::Unknown,
        };
        let bytes_left = header.length as u64 - cursor.position();
        if bytes_left == 0 {
            Ok(Message {
                header: header,
                payload: payload,
            })
        } else {
            Err(Error::IncompleteRead(bytes_left))
        }
    }
}

impl<S> Message<S> {
    /// Read-only accessor for the header
    pub fn header(&self) -> &Header<S> {
        &self.header
    }

    /// Check if the message is of an unknown command.
    pub fn is_unknown(&self) -> bool {
        match self.header.command {
            Command::Unknown(_) => true,
            _ => false,
        }
    }
}

impl Message<Unsigned> {
    /// Helper to create an unsigned message from a payload and context
    fn from_payload(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        payload: Payload,
    ) -> Message<Unsigned> {
        Message {
            header: Header::to_peer(stage, recipient, msgid, &payload),
            payload: payload,
        }
    }

    /// Sign the message
    pub fn sign<C: secp256k1::Signing>(self, sc: &SigningContext<C>)
        -> Message<secp256k1::ecdsa::Signature>
    {
        Message {
            header: self.header.sign(sc),
            payload: self.payload,
        }
    }

    /// Create a new blocksigner status message
    pub fn status_blocksigner_pre_seen(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        peer_keys: Vec<(peer::Id, PublicKey, PublicKey)>,
        dynafed_params: Vec<elements::dynafed::Params>,
        sidechain_tip: elements::BlockHash,
        round_count: u32,
        message: String,
    ) -> Message<Unsigned> {
        let payload = Payload::StatusBlocksignerPreSeen {
            peer_keys,
            dynafed_params,
            sidechain_tip,
            round_count,
            message,
        };
        Message::from_payload(stage, recipient, msgid, payload)
    }

    /// Create a new blocksigner status message
    pub fn status_blocksigner(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        peer_keys: Vec<(peer::Id, PublicKey, PublicKey)>,
        dynafed_params: Vec<elements::dynafed::Params>,
        sidechain_tip: elements::BlockHash,
        round_count: u32,
        peers_seen: Vec<peer::Id>,
        message: String,
    ) -> Message<Unsigned> {
        let payload = Payload::StatusBlocksigner {
            peer_keys,
            dynafed_params,
            sidechain_tip,
            round_count,
            peers_seen,
            message,
        };
        Message::from_payload(stage, recipient, msgid, payload)
    }

    /// Create a new watchman status message
    pub fn status_watchman_pre_seen(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        peer_keys: Vec<(peer::Id, PublicKey, PublicKey)>,
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
        message: String,
    ) -> Message<Unsigned> {
        let payload = Payload::StatusWatchmanPreSeen {
            peer_keys: peer_keys,
            mainchain_hash: mainchain_hash,
            sidechain_hash: sidechain_hash,
            change_spk_hash: change_spk_hash,
            n_mainchain_confirms: n_mainchain_confirms,
            n_sidechain_confirms: n_sidechain_confirms,
            round_count: round_count,
            fee_pool_summary: fee_pool_summary,
            n_pending_transactions: n_pending_transactions,
            output_counter: output_counter,
            percentiles: percentiles,
            pending_input_value: pending_input_value,
            pending_change_value: pending_change_value,
            message: message,
        };
        Message::from_payload(stage, recipient, msgid, payload)
    }

    /// Create a new watchman status message
    pub fn status_watchman(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        peer_keys: Vec<(peer::Id, PublicKey, PublicKey)>,
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
        peers_seen: Vec<peer::Id>,
        message: String,
    ) -> Message<Unsigned> {
        let payload = Payload::StatusWatchman {
            peer_keys: peer_keys,
            mainchain_hash: mainchain_hash,
            sidechain_hash: sidechain_hash,
            change_spk_hash: change_spk_hash,
            n_mainchain_confirms: n_mainchain_confirms,
            n_sidechain_confirms: n_sidechain_confirms,
            round_count: round_count,
            fee_pool_summary: fee_pool_summary,
            n_pending_transactions: n_pending_transactions,
            output_counter: output_counter,
            percentiles: percentiles,
            pending_input_value: pending_input_value,
            pending_change_value: pending_change_value,
            peers_seen,
            message: message,
        };
        Message::from_payload(stage, recipient, msgid, payload)
    }

    /// Create a new status-ACK message
    pub fn status_ack(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
    ) -> Message<Unsigned> {
        Message::from_payload(stage, recipient, msgid, Payload::StatusAck)
    }

    /// Create a new unsigned block
    pub fn unsigned_block(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        block: elements::Block,
    ) -> Message<Unsigned> {
        Message::from_payload(stage, recipient, msgid, Payload::UnsignedBlock { block })
    }

    /// Create a new block precommit message
    pub fn block_precommit(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        blockhash: elements::BlockHash,
    ) -> Message<Unsigned> {
        Message::from_payload(stage, recipient, msgid, Payload::BlockPrecommit { blockhash })
    }

    /// Create a new block signature message
    pub fn block_signature(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        blockhash: elements::BlockHash,
        signature: secp256k1::ecdsa::Signature,
    ) -> Message<Unsigned> {
        let payload = Payload::BlockSignature { blockhash, signature };
        Message::from_payload(stage, recipient, msgid, payload)
    }

    /// Create a new tx-proposal message
    pub fn tx_proposal(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        proposal: transaction::ConcreteProposal,
    ) -> Message<Unsigned> {
        Message::from_payload(stage, recipient, msgid, Payload::TxProposal { proposal })
    }

    /// Create a new tx precommit message
    pub fn tx_precommit(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        txid: bitcoin::Txid,
    ) -> Message<Unsigned> {
        Message::from_payload(stage, recipient, msgid, Payload::TxPrecommit { txid })
    }

    /// Create a new tx-signatures message
    pub fn tx_signatures(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
        sigs: transaction::TransactionSignatures,
    ) -> Message<Unsigned> {
        Message::from_payload(stage, recipient, msgid, Payload::TxSignatures { sigs })
    }

    /// Create a new idle message
    pub fn idle(
        stage: RoundStage,
        recipient: peer::Id,
        msgid: u32,
    ) -> Message<Unsigned> {
        Message::from_payload(stage, recipient, msgid, Payload::Idle)
    }
}

impl Message<secp256k1::ecdsa::Signature> {
    /// Check the signature and do other sanity checks on the message
    pub fn validate<C: secp256k1::Verification, T: peer::VerifySig>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        peers: &peer::Map<T>,
    ) -> Result<(), Error> {
        // Lookup sender to obtain public key; receiver to sanity-check
        let sender = match peers.by_id(self.header.sender) {
            Some(p) => p,
            None => return Err(Error::UnknownPeerId(self.header.sender)),
        };
        if ROLLOUTS.broadcast != common::rollouts::Broadcast::Phase3 {
            let rcvr = self.header.receiver;
            if rcvr != peer::Id::ZERO && peers.by_id(rcvr).is_none() {
                return Err(Error::UnknownPeerId(self.header.receiver));
            }
        }

        // Check signature
        let mut engine = sha256d::Hash::engine();
        assert_eq!(
            self.header.encode_unsigned(&mut engine).unwrap(),
            HEADER_LEN - SIG_LEN
        );
        let msghash = secp256k1::Message::from_digest_slice(
            &sha256d::Hash::from_engine(engine)[..]
        ).unwrap(); // unwrap OK for 32-byte hash
        sender.verify_sig(&secp, &msghash, &self.header.signature)?;

        // Check payload hash
        let mut engine = sha256d::Hash::engine();
        self.payload.encode_payload(&mut engine).unwrap();
        let payload_hash = sha256d::Hash::from_engine(engine);
        if self.header.hash != payload_hash {
            log!(
                Debug,
                "Bad message hash: header {}, payload {}",
                self.header.hash,
                payload_hash
            );
            return Err(Error::BadMessageHash);
        }

        Ok(())
    }

    /// Drop the signature on the message.
    pub fn drop_signature(self) -> Message<Validated> {
        Message {
            header: self.header.drop_signature(),
            payload: self.payload,
        }
    }
}

/// Reason for NAKing
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NackReason {
    /// Peers disagree on what the rotating consensus rules are
    ConfigurationMismatch,
    /// Peer received an unsigned block request when he was not master
    NotMaster,
    /// Peer has an internal error preventing him from processing the request
    InternalError,
    /// Peer sent an unsigned block we were not waiting for
    UnsolicitedBlock,
    /// Peer sent an invalid unsigned block
    InvalidBlock,
    /// Peer sent a block signature we were not waiting for
    UnsolicitedSignature,
    /// Peer sent a precommit we were not waiting for
    UnsolicitedPrecommit,
    /// Peer sent an unsigned tx we were not waiting for
    UnsolicitedUnsignedTx,
    /// Peer sent an signed tx we were not waiting for
    UnsolicitedTxSignatures,
    /// Peer sent an idle command but is not master
    UnsolicitedIdle,
    /// Peer sent a signature that didn't validate
    BadSignature,
    /// Peer sent a message which has no meaning in this protocol
    MessageUnknown,
    /// Watchman was out of fees and could not create a transaction
    InsufficientFees,
    /// Watchman was out of liquid funds and could not create a transaction
    InsufficientFunds,
    /// There are fewer peers online than the required number of signatures
    NotEnoughPeersPresent,
    /// Peers disagree on the state of one or both blockchains
    BlockchainMismatch,
    /// Peer previously received NAK from round master
    NackdByMaster,
    /// Peer sent a tx that conflicts with a pending transaction
    ConflictsWithPendingTx,
    /// Tried to sign two transactions in one round
    SignedTwoTxes,
    /// A JSONRPC error
    Rpc,
    /// A tx to sign is a non-conflicting double-spend of another tx we signed
    AttemptedDoubleSpend,
    /// Too many change outputs on a tx to sign
    BadChangeCount,
    /// An output we expect to be owned by us is not
    UnownedOutput,
    /// Too many outputs (more than we have sidecoin refs for) on a tx to sign (n sidecoins, n outputs)
    BadOutputCount,
    /// An input on a tx to sign does not belong to us
    UnownedInput,
    /// A tx to sign references a sidechain withdraw output that we don't know about
    MissingWithdraw,
    /// A tx to sign tries to unlock the same sidecoin twice (i.e. spend to the same mainchain output twice)
    DuplicateOutput,
    /// A tx to sign has insufficient fee (minimum, got)
    FeeTooLow,
    /// A tx to sign has excessive fee (maximum, got)
    FeeTooHigh,
    /// A tx to sign is too large, estimated after signing (maximum, got)
    SizeTooHigh,
    /// A tx to sign has negative fee
    NegativeFee,
    /// We did not receive a fee estimate
    NoFeeEstimate,
    /// Unable to fund a raw transaction due to conflicting fee requirements or something
    CouldNotFund,
    /// Security module error
    SecurityModule,

    /// Unrecognized reason
    Unknown([u8; 2])
}

impl NackReason {
    /// Interpret two bytes as a NAK reason
    pub fn from_bytes(data: &[u8]) -> NackReason {
        assert!(data.len() == 2);
        match (data[0], data[1]) {
            (0, 0) => NackReason::ConfigurationMismatch,
            (0, 1) => NackReason::NotMaster,
            (0, 2) => NackReason::InternalError,
            (0, 4) => NackReason::UnsolicitedBlock,
            (0, 6) => NackReason::UnsolicitedSignature,
            (0, 7) => NackReason::UnsolicitedPrecommit,
            (1, 0) => NackReason::InvalidBlock,
            (1, 1) => NackReason::UnsolicitedUnsignedTx,
            (1, 2) => NackReason::UnsolicitedTxSignatures,
            (1, 3) => NackReason::UnsolicitedIdle,
            (1, 5) => NackReason::BadSignature,
            (1, 6) => NackReason::ConflictsWithPendingTx,
            (1, 7) => NackReason::SignedTwoTxes,
            (2, 0) => NackReason::InsufficientFees,
            (2, 1) => NackReason::InsufficientFunds,
            (2, 2) => NackReason::NotEnoughPeersPresent,
            (3, 0) => NackReason::BlockchainMismatch,
            (3, 1) => NackReason::NackdByMaster,
            (4, 4) => NackReason::Rpc,
            (4, 11) => NackReason::AttemptedDoubleSpend,
            (4, 12) => NackReason::BadChangeCount,
            (4, 13) => NackReason::UnownedOutput,
            (4, 14) => NackReason::BadOutputCount,
            (4, 15) => NackReason::UnownedInput,
            (4, 16) => NackReason::MissingWithdraw,
            (4, 22) => NackReason::DuplicateOutput,
            (4, 23) => NackReason::FeeTooLow,
            (4, 24) => NackReason::FeeTooHigh,
            (4, 25) => NackReason::SizeTooHigh,
            (4, 26) => NackReason::NegativeFee,
            (4, 27) => NackReason::NoFeeEstimate,
            (4, 28) => NackReason::CouldNotFund,
            (4, 31) => NackReason::SecurityModule,
            (0xff, 0xff) => NackReason::MessageUnknown,
            (x, y) => NackReason::Unknown([x, y])
        }
    }

    /// Translate this reason into bytes
    pub fn to_bytes(&self) -> [u8; 2] {
        match *self {
            NackReason::ConfigurationMismatch => [0, 0],
            NackReason::NotMaster => [0, 1],
            NackReason::InternalError => [0, 2],
            NackReason::UnsolicitedBlock => [0, 4],
            NackReason::UnsolicitedSignature => [0, 6],
            NackReason::UnsolicitedPrecommit => [0, 7],
            NackReason::InvalidBlock => [1, 0],
            NackReason::UnsolicitedUnsignedTx => [1, 1],
            NackReason::UnsolicitedTxSignatures => [1, 2],
            NackReason::UnsolicitedIdle => [1, 3],
            NackReason::BadSignature => [1, 5],
            NackReason::InsufficientFees => [2, 0],
            NackReason::InsufficientFunds => [2, 1],
            NackReason::NotEnoughPeersPresent => [2, 2],
            NackReason::BlockchainMismatch => [3, 0],
            NackReason::NackdByMaster => [3, 1],
            NackReason::ConflictsWithPendingTx => [1, 6],
            NackReason::SignedTwoTxes => [1, 7],
            NackReason::Rpc => [4, 4],
            NackReason::AttemptedDoubleSpend => [4, 11],
            NackReason::BadChangeCount => [4, 12],
            NackReason::UnownedOutput => [4, 13],
            NackReason::BadOutputCount => [4, 14],
            NackReason::UnownedInput => [4, 15],
            NackReason::MissingWithdraw => [4, 16],
            NackReason::DuplicateOutput => [4, 22],
            NackReason::FeeTooLow => [4, 23],
            NackReason::FeeTooHigh => [4, 24],
            NackReason::SizeTooHigh => [4, 25],
            NackReason::NegativeFee => [4, 26],
            NackReason::NoFeeEstimate => [4, 27],
            NackReason::CouldNotFund => [4, 28],
            NackReason::SecurityModule => [4, 31],
            NackReason::MessageUnknown => [0xff, 0xff],
            NackReason::Unknown(x) => x
        }
    }
}

impl fmt::Display for NackReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// Primitives
impl NetEncodable for u64 {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_u64::<LittleEndian>(*self)?;
        Ok(8)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(r.read_u64::<LittleEndian>()?)
    }
}

impl NetEncodable for Amount {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_u64::<LittleEndian>(self.to_sat())?;
        Ok(8)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(Amount::from_sat(r.read_u64::<LittleEndian>()?))
    }
}

impl NetEncodable for [u64; 5] {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        for val in self.iter() {
            w.write_u64::<LittleEndian>(*val)?;
        }
        Ok(8 * 5)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok([
            r.read_u64::<LittleEndian>()?,
            r.read_u64::<LittleEndian>()?,
            r.read_u64::<LittleEndian>()?,
            r.read_u64::<LittleEndian>()?,
            r.read_u64::<LittleEndian>()?,
        ])
    }
}

impl NetEncodable for u32 {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_u32::<LittleEndian>(*self)?;
        Ok(4)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(r.read_u32::<LittleEndian>()?)
    }
}

impl NetEncodable for u16 {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_u16::<LittleEndian>(*self)?;
        Ok(2)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(r.read_u16::<LittleEndian>()?)
    }
}

impl NetEncodable for u8 {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_u8(*self)?;
        Ok(1)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(r.read_u8()?)
    }
}

impl NetEncodable for bitcoin::VarInt {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).encode(w)?;
                Ok(1)
            },
            0xFD..=0xFFFF => {
                0xFDu8.encode(&mut w)?;
                (self.0 as u16).encode(w)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                0xFEu8.encode(&mut w)?;
                (self.0 as u32).encode(w)?;
                Ok(5)
            },
            _ => {
                0xFFu8.encode(&mut w)?;
                self.0.encode(w)?;
                Ok(9)
            },
        }
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(consensus::Decodable::consensus_decode(&mut r)?)
    }
}

impl<T: NetEncodable> NetEncodable for Vec<T> {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let mut len = 0;
        len += bitcoin::VarInt(self.len() as u64).encode(&mut w)?;
        for c in self.iter() {
            len += c.encode(&mut w)?;
        }
        Ok(len)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        const MAX_LEN: u64 = 1_000_000;
        let len = bitcoin::VarInt::decode(&mut r)?.0;
        if len > MAX_LEN || len * mem::size_of::<T>() as u64 > MAX_LEN {
            return Err(Error::BadPayloadSize(len as usize, "Vec<T>"));
        }
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(NetEncodable::decode(&mut r)?);
        }
        Ok(ret)
    }
}

impl NetEncodable for elements::OutPoint {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        self.txid.encode(&mut w)?;
        self.vout.encode(&mut w)?;
        Ok(36)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(elements::OutPoint {
            txid: NetEncodable::decode(&mut r)?,
            vout: NetEncodable::decode(&mut r)?,
        })
    }
}

impl NetEncodable for bitcoin::OutPoint {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        self.txid.encode(&mut w)?;
        self.vout.encode(&mut w)?;
        Ok(36)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(bitcoin::OutPoint {
            txid: NetEncodable::decode(&mut r)?,
            vout: NetEncodable::decode(&mut r)?,
        })
    }
}

impl NetEncodable for Timespec {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_i64::<LittleEndian>(self.sec)?;
        w.write_i32::<LittleEndian>(self.nsec)?;
        Ok(12)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(Timespec {
            sec: r.read_i64::<LittleEndian>()?,
            nsec: r.read_i32::<LittleEndian>()?,
        })
    }
}

impl NetEncodable for NackReason {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let bytes = match *self {
            NackReason::ConfigurationMismatch => [0, 0],
            NackReason::NotMaster => [0, 1],
            NackReason::InternalError => [0, 2],
            NackReason::UnsolicitedBlock => [0, 4],
            NackReason::UnsolicitedSignature => [0, 6],
            NackReason::UnsolicitedPrecommit => [0, 7],
            NackReason::InvalidBlock => [1, 0],
            NackReason::UnsolicitedUnsignedTx => [1, 1],
            NackReason::UnsolicitedTxSignatures => [1, 2],
            NackReason::UnsolicitedIdle => [1, 3],
            NackReason::BadSignature => [1, 5],
            NackReason::InsufficientFees => [2, 0],
            NackReason::InsufficientFunds => [2, 1],
            NackReason::NotEnoughPeersPresent => [2, 2],
            NackReason::BlockchainMismatch => [3, 0],
            NackReason::NackdByMaster => [3, 1],
            NackReason::ConflictsWithPendingTx => [1, 6],
            NackReason::SignedTwoTxes => [1, 7],
            NackReason::Rpc => [4, 4],
            NackReason::AttemptedDoubleSpend => [4, 11],
            NackReason::BadChangeCount => [4, 12],
            NackReason::UnownedOutput => [4, 13],
            NackReason::BadOutputCount => [4, 14],
            NackReason::UnownedInput => [4, 15],
            NackReason::MissingWithdraw => [4, 16],
            NackReason::DuplicateOutput => [4, 22],
            NackReason::FeeTooLow => [4, 23],
            NackReason::FeeTooHigh => [4, 24],
            NackReason::SizeTooHigh => [4, 25],
            NackReason::NegativeFee => [4, 26],
            NackReason::NoFeeEstimate => [4, 27],
            NackReason::CouldNotFund => [4, 28],
            NackReason::SecurityModule => [4, 31],
            NackReason::MessageUnknown => [0xff, 0xff],
            NackReason::Unknown(x) => x
        };
        w.write_all(&bytes[..])?;
        Ok(2)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut sl = [0; 2];
        r.read_exact(&mut sl[..])?;
        Ok(match (sl[0], sl[1]) {
            (0, 0) => NackReason::ConfigurationMismatch,
            (0, 1) => NackReason::NotMaster,
            (0, 2) => NackReason::InternalError,
            (0, 4) => NackReason::UnsolicitedBlock,
            (0, 6) => NackReason::UnsolicitedSignature,
            (0, 7) => NackReason::UnsolicitedPrecommit,
            (1, 0) => NackReason::InvalidBlock,
            (1, 1) => NackReason::UnsolicitedUnsignedTx,
            (1, 2) => NackReason::UnsolicitedTxSignatures,
            (1, 3) => NackReason::UnsolicitedIdle,
            (1, 5) => NackReason::BadSignature,
            (1, 6) => NackReason::ConflictsWithPendingTx,
            (1, 7) => NackReason::SignedTwoTxes,
            (2, 0) => NackReason::InsufficientFees,
            (2, 1) => NackReason::InsufficientFunds,
            (2, 2) => NackReason::NotEnoughPeersPresent,
            (3, 0) => NackReason::BlockchainMismatch,
            (3, 1) => NackReason::NackdByMaster,
            (4, 4) => NackReason::Rpc,
            (4, 11) => NackReason::AttemptedDoubleSpend,
            (4, 12) => NackReason::BadChangeCount,
            (4, 13) => NackReason::UnownedOutput,
            (4, 14) => NackReason::BadOutputCount,
            (4, 15) => NackReason::UnownedInput,
            (4, 16) => NackReason::MissingWithdraw,
            (4, 22) => NackReason::DuplicateOutput,
            (4, 23) => NackReason::FeeTooLow,
            (4, 24) => NackReason::FeeTooHigh,
            (4, 25) => NackReason::SizeTooHigh,
            (4, 26) => NackReason::NegativeFee,
            (4, 27) => NackReason::NoFeeEstimate,
            (4, 28) => NackReason::CouldNotFund,
            (4, 31) => NackReason::SecurityModule,
            (0xff, 0xff) => NackReason::MessageUnknown,
            (x, y) => NackReason::Unknown([x, y])
        })
    }
}

impl NetEncodable for peer::Id {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_all(&self[..])?;
        Ok(self[..].len())
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut sl = [0; 6];
        r.read_exact(&mut sl[..])?;
        Ok(peer::Id::from(&sl[..]))
    }
}

macro_rules! net_encodable_hash {
    ($hash:ty) => {
        impl NetEncodable for $hash {
            fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
                w.write_all(&self[..])?;
                Ok(<$hash as Hash>::LEN)
            }

            fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
                let mut sl = [0; 32];
                r.read_exact(&mut sl[..])?;
                Ok(<$hash>::from_slice(&sl[..])?)
            }
        }
    };
}
net_encodable_hash!(bitcoin::BlockHash);
net_encodable_hash!(bitcoin::Txid);
net_encodable_hash!(sha256d::Hash);
net_encodable_hash!(elements::Txid);
net_encodable_hash!(elements::BlockHash);

impl NetEncodable for secp256k1::ecdsa::Signature {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let sig = self.serialize_compact();
        w.write_all(&sig[..])?;
        Ok(secp256k1::constants::COMPACT_SIGNATURE_SIZE)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut sl = [0; 64];
        r.read_exact(&mut sl[..])?;
        Ok(secp256k1::ecdsa::Signature::from_compact(&sl[..])?)
    }
}

impl NetEncodable for (secp256k1::ecdsa::Signature, bitcoin::EcdsaSighashType) {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let sig = self.0.serialize_der();
        let vi_len = bitcoin::VarInt(1 + sig.len() as u64).encode(&mut w)?;
        w.write_all(&sig)?;
        w.write_u8(self.1.to_u32() as u8)?;
        Ok(vi_len + sig.len() + 1)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut sl = [0; 74];
        let bitcoin::VarInt(len) = NetEncodable::decode(&mut r)?;
        let len = len as usize;
        if len == 0 || len > sl.len() {
            return Err(Error::BadPayloadSize(len, "(Signature, SigHashType)"));
        }
        r.read_exact(&mut sl[..len])?;

        Ok((
            secp256k1::ecdsa::Signature::from_der(&sl[..len - 1])?,
            bitcoin::EcdsaSighashType::from_consensus(sl[len - 1] as u32),
        ))
    }
}

impl NetEncodable for (peer::Id, PublicKey, PublicKey) {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.0.encode(&mut w)?;
        len += 33u8.encode(&mut w)?;
        w.write_all(&self.1.serialize())?;
        len += 33;
        len += 33u8.encode(&mut w)?;
        w.write_all(&self.2.serialize())?;
        len += 33;
        Ok(len)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let id = NetEncodable::decode(&mut r)?;
        let mut key_buf = [0; 65];
        let key1 = match r.read_u8()? {
            33 => {
                r.read_exact(&mut key_buf[..33])?;
                PublicKey::from_slice(&key_buf[..33])?
            },
            65 => {
                r.read_exact(&mut key_buf[..65])?;
                PublicKey::from_slice(&key_buf[..65])?
            },
            x => return Err(Error::BadPayloadSize(x as usize, "(Id, PublicKey, PublicKey)")),
        };
        let key2 = match r.read_u8()? {
            33 => {
                r.read_exact(&mut key_buf[..33])?;
                PublicKey::from_slice(&key_buf[..33])?
            },
            65 => {
                r.read_exact(&mut key_buf[..65])?;
                PublicKey::from_slice(&key_buf[..65])?
            },
            x => return Err(Error::BadPayloadSize(x as usize, "(Id, PublicKey, PublicKey)")),
        };
        Ok((id, key1, key2))
    }
}

#[cfg(test)]
pub mod tests {
    use bitcoin::secp256k1::ecdsa::Signature;
    use std::str::FromStr;

    use utils::empty_elements_block;
    use super::*;

    pub const CONST_HEADER: [u8; HEADER_LEN] = hex!("
        6c5b7dc587a156a6d7a4ba38183c589fbd4cf73d649f6f0a9b54b5cdf70ef223
        75b7ec1e34ddc618f6613c5f3e5321ecd05e1d7b54cf211b1aeec53de9a42d3f
        140000005fa52b1be4288bc04046a6f015cd5b07650000000000000000000000
        08baff5c00000000730fca15407feb4a4b8303baf4f84e29a209e0dcfd62e81f
        88c8edb7675c5a95d90e5c9002000000
    ");

    pub const CONST_BLOCK_PRECOMMIT: [u8; HEADER_LEN + 32] = hex!("
        337e7ed71da31daff249d6f02ff927109ec02c68c88c31225bed7ade5579517b
        7ba965dc4d53827d876f03019472c7048ac0c69ab07708ee3b7e701e8a1ae1b1
        150000005fa52b1be4288bc04046a6f015cd5b07650000000400000000000102
        0bc4c55d00000000f023991e1058090e438556067949f7a3c1e4f31aa11b9f0c
        6e719e3350b9525b969f651c20000000d250436c61f704840e5be0ca5229a2eb
        041d6ac40a2014d52ecd1617f9171ef8
    ");

    pub const CONST_TX_PROPOSAL: [u8; HEADER_LEN + 107] = hex!("
        9e00c7a30b80b359f5f47fea4644ef579fd513c607e77c73403910670490d16c
        20aebf33fa1e3c5b7372fc764f5d32f4d2bcf708052c180e1335fa14e0de109d
        150000005fa52b1be4288bc04046a6f015cd5b07650000000900000000000200
        0bc4c55d0000000061252d20742d77b7859f3d920807de287a129d577d094708
        2dcfb62f5de81b2a98febea46b00000001000000000000000000000000000000
        00000000000000000000000000000000000a0000000100000000000000000000
        0000000000000000000000000000000000000000000088130000040100000000
        000000020000000000000003000000000000000000020000000000
    ");

    pub const CONST_TX_PRECOMMIT: [u8; HEADER_LEN + 32] = hex!("
        ffd2521e108769a30f188d956cc9fcf42a3ad684b2427a20125fec9976ab5c51
        5476a837d6e630a3d9ebd1880692d8d45926e484e4b6fe99a32d210c4d4bbbd2
        150000005fa52b1be4288bc04046a6f015cd5b07650000000100000000000202
        42693b610000000037ebeb0f1058090e438556067949f7a3c1e4f31aa11b9f0c
        6e719e3350b9525b969f651c20000000d250436c61f704840e5be0ca5229a2eb
        041d6ac40a2014d52ecd1617f9171ef8
    ");

    pub const CONST_TX_SIGNATURES: [u8; HEADER_LEN + 145] = hex!("
        1b67e29ffbda18c9ecf89ebd6bde965ce091882fc04618763694efc6a150e784
        2ef9a46129cfc77ef7e995449a6dd3314dbc7e3da25fa963e41bfb6b7f6b12c0
        150000005fa52b1be4288bc04046a6f015cd5b07650000000800000000000201
        0bc4c55d00000000c62c27206ca67291a8f1d39fcd5a66dcdce8c8a98e95b0e1
        5ea4368de9a38b19e3b0517a910000000247304402206ac44d672dac41f9b00e
        28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe192900
        69cba53d096f44530e4f98acaa594810388cf7409a1870ce0147304402206ac4
        4d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220
        367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce
        01
    ");

    pub const CONST_NACK: [u8; HEADER_LEN + 2] = hex!("
        9e619d6e02916f9fc17ed0b680d681262ffdb14611b5dd781b5238d296f9d8d4
        2f886b94119ca4b77e69b21d06d104c61a1be4601e876cbf979f07958f36eeaf
        150000005fa52b1be4288bc04046a6f015cd5b07650000000500000000000000
        0bc4c55d000000005fdb9d1e407feb4a4b8303baf4f84e29a209e0dcfd62e81f
        88c8edb7675c5a95d90e5c90020000000000
    ");

    pub const CONST_STATUS_BLOCKSIGNER_PRE_SEEN: [u8; HEADER_LEN + 132] = hex!("
        04c243c31d433000ae0e30aa44c766b4f48ec6bb983824fb52d3d5eb10ad0b66
        5f9cfeadd1f7835a2f18f66349456caac13b604d02c19a98cad3b469a5611024
        150000005fa52b1be4288bc04046a6f015cd5b07650000000100000000000002
        b887d862000000005b844228ec5eec463e4885654fb69a7437b6ca05a0bf4447
        21bfb565b9147e7b5ed6b64a8400000001000000000000210202020202020202
        0202020202020202020202020202020202020202020202020221020202020202
        020202020202020202020202020202020202020202020202020202001cc3adea
        40ebfd94433ac004777d68150cce9db4c771bc7de1b297a7b795bbba3d000000
        7631343b74687265652064617973206772616365
    ");

    pub const CONST_STATUS_BLOCKSIGNER: [u8; HEADER_LEN + 145] = hex!("
        151e05071e3271c187bebba88a0bd886170e11f85a9c50788dbddbe2577d9c10
        36125fda160a4f58454b249bc60d0d3292d46b5cf44cd97c10c7f6a6e57203c1
        150000005fa52b1be4288bc04046a6f015cd5b07650000000100000000000004
        7d78fb62000000006f180131a89954a417526ea94a5677d1a6955cac240e1b93
        8ab6ac5f39c64f8ec617e50e9100000001000000000000210202020202020202
        0202020202020202020202020202020202020202020202020221020202020202
        020202020202020202020202020202020202020202020202020202001cc3adea
        40ebfd94433ac004777d68150cce9db4c771bc7de1b297a7b795bbba3d000000
        020102030405060506070809007631343b746872656520646179732067726163
        65
    ");

    pub const CONST_STATUS_WATCHMAN_PRE_SEEN: [u8; HEADER_LEN + 344] = hex!("
        861e29d9838f330a679157a6256e2978f4b269c082f5e139ff1cf1438c71281b
        4b1c7248f984e8a86cb571f30594452c6507cfe9201d01c32142190c4b488ed5
        150000005fa52b1be4288bc04046a6f015cd5b07650000000100000000000003
        7286d8620000000006521415b54fd844d6c9ee9bdf296c8682481494912f9dcd
        ec7d9b785bff758e85b3f3a45801000001000000000000210202020202020202
        0202020202020202020202020202020202020202020202020221020202020202
        0202020202020202020202020202020202020202020202020202025b955caf00
        5a9ca58b3df7a0432c686314222dabff5faea1abb169a1459374a135f6e7b760
        4aec1902ed918331a6d14322e7a2b8c581298aa33b3cb1f8f28bb8fc493f85c5
        8a9486a80f4457288e884bcd28dcf713372816644a587b5b4aa1847856341200
        0000002143658700000000bc000000feeedbbe00000000feeedbfa00000000fe
        feffc000000000210000000000000065000000000000000500000000000000ca
        0000000000000005000000000000001400000000000000280000000000000063
        0000000000000058000000000000004d00000000000000420000000000000037
        0000000000000015cd5b0700000000b168de3a000000007631343b62696c6c20
        63616c6c6168616e
    ");

    pub const CONST_STATUS_WATCHMAN: [u8; HEADER_LEN + 357] = hex!("
        07f6bf0c4a048c4cf7ec1b9da05b22be454f8c6a5424c337dd8e2cfd28fbac6c
        57a6576f4220911a1d8fb793778ccbc04a8638ab49e63e73fe19220eb098ace1
        150000005fa52b1be4288bc04046a6f015cd5b07650000000100000000000005
        4c79fb62000000009bbd201e5af2048b2ac8a2e4e5ca5ec7bf39a0aebeec2ba0
        96b71444e0672dcc5e90c9946501000001000000000000210202020202020202
        0202020202020202020202020202020202020202020202020221020202020202
        0202020202020202020202020202020202020202020202020202025b955caf00
        5a9ca58b3df7a0432c686314222dabff5faea1abb169a1459374a135f6e7b760
        4aec1902ed918331a6d14322e7a2b8c581298aa33b3cb1f8f28bb8fc493f85c5
        8a9486a80f4457288e884bcd28dcf713372816644a587b5b4aa1847856341200
        0000002143658700000000bc000000feeedbbe00000000feeedbfa00000000fe
        feffc000000000210000000000000065000000000000000500000000000000ca
        0000000000000005000000000000001400000000000000280000000000000063
        0000000000000058000000000000004d00000000000000420000000000000037
        0000000000000015cd5b0700000000b168de3a00000000020102030405060506
        070809007631343b62696c6c2063616c6c6168616e
    ");

    pub const CONST_BLOCK_SIGNATURE: [u8; HEADER_LEN + 96] = hex!("
        33e3b460fd667ecab52cf5a5ed2ecf57353886d288b8fcec69ec4339eec7ebb3
        3bfaafb9c84ca61394cf4a610d16ccd1cacda86136b36a1b05f319760abaeabc
        150000005fa52b1be4288bc04046a6f015cd5b07650000000300000000000103
        0bc4c55d00000000bb05981ebcd2ce0102c0d9dc1232d7f554b4369ec1287228
        7e93fa7ec00b1e083669799660000000761cf0bf52ae31f742fde8cd3bc032d6
        e696e0572bd7050783b96272dc749e436ac44d672dac41f9b00e28f4df20c52e
        eb087207e8d758d76d92c6fab3b73e2b367750dbbe19290069cba53d096f4453
        0e4f98acaa594810388cf7409a1870ce
    ");

    pub const CONST_STATUS_ACK: [u8; HEADER_LEN] = hex!("
        846a64624747d24843e5d0c65cb403f70613271d0ff387d9904df028b083a53b
        7fbb0698c599d2f2037fd12e48e2f7ebd798646f29b3c10035612a443ecc910f
        150000005fa52b1be4288bc04046a6f015cd5b07650000000000000000000001
        0bc4c55d000000006f28931e5df6e0e2761359d30a8275058e299fcc03815345
        45f55cf43e41983f5d4c945600000000
    ");

    pub const CONST_IDLE: [u8; HEADER_LEN] = hex!("
        def8facf50b880a8f3db3f14e0959053c9e4528f4141521cd978fad932e556f6
        43279d4c04be25f20484acd1e6c5230d322839cc59173c3a0049eaf2ae3f84d7
        150000005fa52b1be4288bc04046a6f015cd5b07650000000100000000000203
        0bc4c55d000000007628931e5df6e0e2761359d30a8275058e299fcc03815345
        45f55cf43e41983f5d4c945600000000
    ");

    pub const CONST_UNSIGNED_BLOCK: [u8; HEADER_LEN + 80] = hex!("
        d66f28783b284933f041454c8de401b5ba6c904a6d4a0286ff874c77a4466e13
        75bc66a2c2c0eca5c900aaf95b7509b68df53bb13e57eb69f32878542391fc6b
        150000005fa52b1be4288bc04046a6f015cd5b07650000000a00000000000100
        0bc4c55d000000002f2c0721fc9103149ddc9dba4483f60ff2768dcb05ee5644
        ba303006768877e07a378b865000000000000080000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
    ");

    macro_rules! message_roundtrip_test {
        ($test_name:ident, $test_const:ident, $command:expr) => {
            #[test]
            fn $test_name() {
                let secp = secp256k1::Secp256k1::verification_only();
                let (_sc, list) = peer::tests::generate_peers(2, 0);
                // Check incomplete parses
                assert!(Message::decode(&$test_const[1..]).is_err()
                    || Message::decode(&$test_const[1..]).unwrap().is_unknown()
                );
                assert!(
                    Message::decode(&$test_const[..$test_const.len() - 1]).is_err()
                    || Message::decode(&$test_const[..$test_const.len() - 1]).unwrap().is_unknown()
                );

                // Round trip
                let deser = Message::decode(&$test_const[..]).expect("decode");

                let mut reser = vec![];
                deser.encode(&mut reser).expect("encode");
                assert_eq!(&$test_const[..], &reser[..]);

                let mut payload_reser = vec![];
                deser.payload.encode_payload(&mut payload_reser).expect("encode");
                assert_eq!(&$test_const[HEADER_LEN..], &payload_reser[..]);

                // Check header values
                let mut engine = sha256d::Hash::engine();
                let payload_len = deser.payload.encode_payload(&mut engine).unwrap();
                let payload_hash = sha256d::Hash::from_engine(engine);

                // When creating a new test, use this code to sign messages.
                // let unsigned = {
                //     let new_payload = deser.payload.clone();
                //     let mut engine = sha256d::Hash::engine();
                //     let new_payload_len = new_payload.encode_payload(&mut engine).unwrap();
                //     let new_payload_hash = sha256d::Hash::from_engine(engine);
                //     Message {
                //         header: Header {
                //             signature: Unsigned,
                //             version: deser.header.version,
                //             sender: deser.header.sender,
                //             receiver: deser.header.receiver,
                //             round: deser.header.round,
                //             msgid: deser.header.msgid,
                //             nonce: deser.header.nonce,
                //             command: new_payload.command(),
                //             time: deser.header.time,
                //             hash: new_payload_hash,
                //             length: new_payload_len as u32,
                //         },
                //         payload: new_payload,
                //     }
                // };
                // let signed = unsigned.sign(&_sc);
                // let mut reser_signed = vec![];
                // signed.encode(&mut reser_signed).unwrap();
                // println!("signed message: {}", bitcoin::hashes::hex::ToHex::to_hex(&reser_signed[..]));

                deser.validate(&secp, &list).expect("validate header");
                assert_eq!(payload_hash, sha256d::Hash::hash(&payload_reser[..]));
                assert_eq!(deser.header.command, $command);
                assert_eq!(deser.header.version, MESSAGE_VERSION);
                assert_eq!(deser.header.length as usize, payload_len);
                assert_eq!(deser.header.hash, payload_hash);
            }
        }
    }

    #[test]
    fn header_rtt() {
        let mut reser = vec![];
        let deser = Header::decode(&CONST_HEADER[..]).unwrap();
        assert_eq!(deser.encode(&mut reser).unwrap(), HEADER_LEN);
        assert_eq!(&CONST_HEADER[..], &reser[..]);
    }

    message_roundtrip_test!(block_precommit_rtt, CONST_BLOCK_PRECOMMIT, Command::BlockPrecommit);
    message_roundtrip_test!(tx_proposal_rtt, CONST_TX_PROPOSAL, Command::TxProposal);
    message_roundtrip_test!(tx_precommit_rtt, CONST_TX_PRECOMMIT, Command::TxPrecommit);
    message_roundtrip_test!(tx_signatures_rtt, CONST_TX_SIGNATURES, Command::TxSignatures);
    message_roundtrip_test!(nack_rtt, CONST_NACK, Command::Nack);
    message_roundtrip_test!(status_blocksigner_ps_rtt, CONST_STATUS_BLOCKSIGNER_PRE_SEEN, Command::StatusBlocksignerPreSeen);
    message_roundtrip_test!(status_blocksigner_rtt, CONST_STATUS_BLOCKSIGNER, Command::StatusBlocksigner);
    message_roundtrip_test!(status_watchman_ps_rtt, CONST_STATUS_WATCHMAN_PRE_SEEN, Command::StatusWatchmanPreSeen);
    message_roundtrip_test!(status_watchman_rtt, CONST_STATUS_WATCHMAN, Command::StatusWatchman);
    message_roundtrip_test!(block_signature_rtt, CONST_BLOCK_SIGNATURE, Command::BlockSignature);
    message_roundtrip_test!(status_ack_rtt, CONST_STATUS_ACK, Command::StatusAck);
    message_roundtrip_test!(idle_rtt, CONST_IDLE, Command::Idle);
    message_roundtrip_test!(unsigned_block_rtt, CONST_UNSIGNED_BLOCK, Command::UnsignedBlock);

    macro_rules! check_message {
        ($you:ident, $msg:expr) => ({
            let secp = secp256k1::Secp256k1::verification_only();
            let (sc, list) = peer::tests::generate_peers(2, 0);
            let (_, mut other_list) = peer::tests::generate_peers(2, 0);

            let ids: Vec<_> = list.consensus_ordered_ids();
            let $you = if ids[0] == list.my_id() { ids[1] } else { ids[0] };
            other_list.set_my_id($you);

            let msg = $msg.sign(&sc);

            // Round-trip
            let mut ser = vec![];
            msg.encode(&mut ser).expect("encoding");
            // Uncomment these two lines to regenerate fixed test vectors
            //use bitcoin::hashes::hex::ToHex;
            //println!("{}: {}", &stringify!($msg)[..20], ser.to_hex());
            let decoded = Message::decode(&ser[..]).expect("decoding");
            assert_eq!(msg, decoded);

            // Check header
            let mut engine = sha256d::Hash::engine();
            let payload_len = msg.payload.encode_payload(&mut engine).unwrap();
            let payload_hash = sha256d::Hash::from_engine(engine);

            assert_eq!(msg.header.version, MESSAGE_VERSION);
            assert_eq!(msg.header.command, msg.payload.command());
            assert_eq!(msg.header.length as usize, payload_len);
            assert_eq!(msg.header.hash, payload_hash);

            // Check signature
            msg.validate(&secp, &list).expect("valid header");
            msg.validate(&secp, &other_list).expect("valid header");
        })
    }

    #[test]
    fn idle_round_trip() {
        check_message!(you, Message::idle(RoundStage::test_dummy(), you, 101));
    }

    #[test]
    fn status_ack_round_trip() {
        check_message!(
            you,
            Message::status_ack(RoundStage::test_dummy(), you, 101)
        );
    }

    #[test]
    fn unsigned_block_round_trip() {
        check_message!(
            you,
            Message::unsigned_block(
                RoundStage::test_dummy(),
                you,
                101, // msgid
                empty_elements_block(),
            )
        );
    }

    #[test]
    fn block_precommit_round_trip() {
        check_message!(
            you,
            Message::block_precommit(
                RoundStage::test_dummy(),
                you,
                101, // msgid
                elements::BlockHash::hash(b"block_precommit"),
            )
        );
    }

    #[test]
    fn tx_signatures_round_trip() {
        check_message!(
            you,
            Message::tx_signatures(
                RoundStage::test_dummy(),
                you,
                101, // msgid
                transaction::TransactionSignatures::from(vec![
                    (
                        Signature::from_str("\
                            304402206ac44d672dac41f9b00e28f4\
                            df20c52eeb087207e8d758d76d92c6fa\
                            b3b73e2b0220367750dbbe19290069cb\
                            a53d096f44530e4f98acaa594810388c\
                            f7409a1870ce\
                        ").unwrap(),
                        bitcoin::EcdsaSighashType::All,
                    ),
                    (
                        Signature::from_str("\
                            304402206ac44d672dac41f9b00e28f4\
                            df20c52eeb087207e8d758d76d92c6fa\
                            b3b73e2b0220367750dbbe19290069cb\
                            a53d096f44530e4f98acaa594810388c\
                            f7409a1870ce\
                        ").unwrap(),
                        bitcoin::EcdsaSighashType::All,
                    ),
                ]),
            )
        );
    }

    #[test]
    fn block_signature_round_trip() {
        check_message!(
            you,
            Message::block_signature(
                RoundStage::test_dummy(),
                you,
                101, // msgid
                elements::BlockHash::hash(b"block hash"),
                Signature::from_str("\
                    304402206ac44d672dac41f9b00e28f4\
                    df20c52eeb087207e8d758d76d92c6fa\
                    b3b73e2b0220367750dbbe19290069cb\
                    a53d096f44530e4f98acaa594810388c\
                    f7409a1870ce\
                ").unwrap(),
            )
        );
    }

    #[test]
    fn tx_proposal_round_trip() {
        let proposal = transaction::ConcreteProposal {
            inputs: vec![
                bitcoin::OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 10,
                },
            ],
            pegouts: vec![
                elements::OutPoint {
                    txid: elements::Txid::all_zeros(),
                    vout: 5000,
                },
            ],
            change: vec![
                bitcoin::Amount::from_sat(1),
                bitcoin::Amount::from_sat(2),
                bitcoin::Amount::from_sat(3),
                bitcoin::Amount::from_sat(0x20000)
            ],
        };
        check_message!(
            you,
            Message::tx_proposal(RoundStage::test_dummy(), you, 101, proposal)
        );
    }

    #[test]
    fn status_blocksigner_round_trip() {
        check_message!(
            you,
            Message::status_blocksigner_pre_seen(
                RoundStage::test_dummy(),
                you,
                101, // msgid
                vec![
                    (
                        peer::Id::default(),
                        PublicKey::from_slice(&[2; 33]).unwrap(),
                        PublicKey::from_slice(&[2; 33]).unwrap(),
                    ),
                ],
                vec![], // no dynafed params
                elements::BlockHash::hash(&[2]),
                0x3D,
                "v14;three days grace".to_owned(),
            )
        );
        check_message!(
            you,
            Message::status_blocksigner(
                RoundStage::test_dummy(),
                you,
                101, // msgid
                vec![
                    (
                        peer::Id::default(),
                        PublicKey::from_slice(&[2; 33]).unwrap(),
                        PublicKey::from_slice(&[2; 33]).unwrap(),
                    ),
                ],
                vec![], // no dynafed params
                elements::BlockHash::hash(&[2]),
                0x3D,
                vec![peer::Id::from([1,2,3,4,5,6]), peer::Id::from([5,6,7,8,9,0])],
                "three days grace".to_owned(),
            )
        );
    }

    #[test]
    fn status_watchman_round_trip() {
        check_message!(
            you,
            Message::status_watchman_pre_seen(
                RoundStage::test_dummy(),
                you,
                101, // msgid
                vec![
                    (
                        peer::Id::default(),
                        PublicKey::from_slice(&[2; 33]).unwrap(),
                        PublicKey::from_slice(&[2; 33]).unwrap(),
                    ),
                ],
                bitcoin::BlockHash::hash(b"main tip"),
                elements::BlockHash::hash(b"side tip"),
                sha256d::Hash::hash(b"scriptpubkey"),
                0x12345678,
                0x87654321,
                0xBC,
                fee::PoolSummary {
                    fee_rate: 0xbedbeefe,
                    available_funds: 0xfadbeefe,
                    temporarily_docked: 0xc0fffefe,
                },
                33, // pending transactions
                OutputCounter::new(101, 5, 202, 5, 20, 40),
                [99, 88, 77, 66, 55],
                123456789,
                987654321,
                "v14;bill callahan".to_owned(),
            )
        );
        check_message!(
            you,
            Message::status_watchman(
                RoundStage::test_dummy(),
                you,
                101, // msgid
                vec![
                    (
                        peer::Id::default(),
                        PublicKey::from_slice(&[2; 33]).unwrap(),
                        PublicKey::from_slice(&[2; 33]).unwrap(),
                    ),
                ],
                bitcoin::BlockHash::hash(b"main tip"),
                elements::BlockHash::hash(b"side tip"),
                sha256d::Hash::hash(b"scriptpubkey"),
                0x12345678,
                0x87654321,
                0xBC,
                fee::PoolSummary {
                    fee_rate: 0xbedbeefe,
                    available_funds: 0xfadbeefe,
                    temporarily_docked: 0xc0fffefe,
                },
                33, // pending transactions
                OutputCounter::new(101, 5, 202, 5, 20, 40),
                [99, 88, 77, 66, 55],
                123456789,
                987654321,
                vec![peer::Id::from([1,2,3,4,5,6]), peer::Id::from([5,6,7,8,9,0])],
                "bill callahan".to_owned(),
            )
        );
    }

    #[test]
    fn test_fuzzer_find() {
        let msg1 = hex!("
            8d4f8c803f4b09eb063d5b23358d7c4e67e8ebfbd8435f7f8d7c4e67e8eb
            fbd8435f7f8d7c4e5de6ebfbc8435f80baa0ce966cba5720a50a43000056
            4a448d9ae8239f75e0c8b048136352436e9ecf0000000000805720a50a43
            00e7805720a50a4300e7805720a50a4300e7eca2a8cdc26cba00000000c6
            67b073a13de58e472bfc26321b98755720a50a4300000000000000805720
            a50a430000
        ");
        let msg2 = hex!("
            8d4f8c803f4b09eb063d5b23358d7c4e67e8ebfbd8435f7f8d7c4e67e8eb
            fbd8435f7f8d7c4e67e8ebfbd8435f80baa0ce966cba5720a50a43000056
            4a448d9ae8239f75e0c8b048136352436e9ecf0000000000805720a50a43
            00e7eca2a8cdc26cba0000009c00805720a50a4300e7eca252056e9ecf00
            0000000080572020a50a4300e77fff52056e9ecf00000000008000
        ");

        for (i, msg) in [msg1.to_vec(), msg2.to_vec()].iter().enumerate() {
            println!("Checking msg idx {}", i);

            let mut cur = io::Cursor::new(msg);
            let decoded = Message::decode(&mut cur).expect("decoding err");

            println!("msg: {:?}", decoded);

            let mut buf = Vec::new();
            decoded.encode(&mut buf).expect("encoding err");
            let encoded = buf.clone();
            let mut cur = io::Cursor::new(buf);
            let decoded2 = Message::decode(&mut cur).expect("decoding err");

            assert_eq!(decoded, decoded2, "decoded roundtrip failed");

            let mut buf = Vec::new();
            decoded2.encode(&mut buf).expect("encoding err");
            let encoded2 = buf;

            assert_eq!(&encoded[..], &encoded2[..], "encoded roundtrip failed");
        }
    }
}
