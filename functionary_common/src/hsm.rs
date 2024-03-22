//{{ Liquid }}
//Copyright (C) {{ 2022 }}  {{ Blockstream }}

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

use std::{error, fmt, io};
use std::convert::TryFrom;
use std::fmt::Formatter;
use std::io::Write;

use bitcoin::hashes::{Hash, sha256d};
use elements::hex;
use bitcoin::secp256k1;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// Size of a fixed-size HSM message header
pub const HEADER_LEN: usize = 40;

/// Version of message format
pub const MESSAGE_VERSION: u8 = 2;

/// Address field for messages to the HSM
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Address {
    /// Message to/from the Rust blocksigner
    BlockSigner = 0,
    /// Message to/from the Rust watchman
    Watchman = 1,
    /// Query hsm address
    Query = 2,
    /// Update tool address
    Update = 3,
    /// Maintenance process address
    Maintenance = 4,
    /// ParallelPort itself
    ParallelPort = 0xff
}

/// Message identifier
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Command {
    /// Block header to validate and sign
    BlocksignerSignBlock = 0x00,
    /// Signature on a block
    BlocksignerBlockSig = 0x01,
    /// Block header to validate but not sign
    BlocksignerValidateBlock = 0x02,

    /// Request for unilateral withdraw address
    WatchmanGetUnilateralWithdrawPubkey = 0x14,
    /// Response
    WatchmanUnilateralWithdrawPubkey = 0x15,
    /// Request for unilateral withdraw locktime, in seconds
    WatchmanGetUnilateralWithdrawLocktime = 0x16,
    /// Response
    WatchmanUnilateralWithdrawLocktime = 0x17,
    /// Request for public signing key
    WatchmanGetPublicKey = 0x18,
    /// Response of public signing key
    WatchmanPublicKey = 0x19,

    /// Request to clear the list of authorized addresses
    WatchmanAuthorizedListReset = 0x1a,
    /// Request to add an address to the list of authorized ones
    WatchmanAuthorizationVerify = 0x1b,
    /// Request to replace the master authorization keys
    WatchmanAuthorizationMasterKeysReplace = 0x1c,

    /// Set the redeemscript used for change, given a signature
    WatchmanForeChangeScript = 0x1e,
    /// Request to set the untweaked (i.e. change) witness script
    WatchmanSetWitnessScript = 0x1f,

    /// Request to blocksigner to perform first-run initialization of HSM
    HSMInit = 0x21,
    /// Reply with data resulting from initialization, used to configure network
    HSMInitReply = 0x22,
    /// get time in epoch seconds from RTC
    HSMGetRtcTime = 0x23,
    /// response to GET_RTC_TIME
    HSMRtcTimeReply = 0x24,
    /// Get (generate if missing) HSM signing key
    HSMGetSigningKey = 0x25,
    /// Get HSM signing key result
    HSMGetSigningKeyResponse = 0x26,
    /// Add message payload to /dev/random
    HSMAddEntropy = 0x27,
    /// Reply to entropy-adding message
    HSMAddEntropyFailure = 0x28,
    /// v2+, Not set in v2 but will be in future versions
    HSMGetVersion = 0x29,
    /// v2+, GET_VERSION reply
    HSMGetVersionReply = 0x2a,
    /// Heartbeat message - message version 2+
    HSMHeartbeat = 0x2b,
    /// Heartbeat reply - message version 2+
    HSMHeartbeatReply = 0x2c,
    /// Requesting the public hsm restore key before initialization
    HSMGetRestoreKey = 0x2d,
    /// Replying to the public hsm restore key message before initialization
    HSMGetRestoreKeyReply = 0x2e,

    /// Request to watchman to sign a transaction
    WatchmanSignSegwitTx = 0x31,
    /// List of transaction signatures from the watchman
    WatchmanSegwitTxSignatures = 0x32,
    /// Used to send new block headers to the HSM.
    WatchmanHeader = 0x33,
    /// Used to ask the HSM about its chain state.
    WatchmanState = 0x34,
    /// Used to reply to [WatchmanState].
    WatchmanStateReply = 0x35,

    /// HSM Update packet
    HSMUpdate = 0x41,
    /// ACK reply for hsm update message
    HSMUpdateACK = 0x45,
    /// NACK reply for hsm update message
    HSMUpdateNACK = 0x46,

    /// Set the HSM to tamper-detect mode. CANNOT BE UNDONE BY THE FUNCTIONARY.
    TamperDetectEnable = 0xe0,
    /// A challenge nonce given by the HSM while in tamper detect mode
    TamperDetectChallenge = 0xe1,
    /// A signature of a tamper-detect nonce used to unlock the HSM
    TamperDetectResponse = 0xe2,

    /// Acknowledgement of correct data
    Ack = 0xf0,
    /// Rejection due communication failure
    NackRetry = 0xf1,
    /// Rejection due to bad data
    NackBadData = 0xf2,
    /// Rejection due to HSM error
    NackInternal = 0xf3,
    /// Rejection due to HSM authorization list being full already
    NackTooMany = 0xf4,
    /// NACK due to message being unsupported on remote, message version v2+
    NackUnsupported = 0xf5,
    /// NACK due to parallel_port failure to deliver to address v2+
    NackDeliveryFailed = 0xf6,
    /// Rejection due to rate-limiting; retry later
    NackRateLimit = 0xf7,
    /// Rejection due to not allowed in current state
    NackNotAllowed = 0xf8,
    /// Some validation failed. E.g. invalid block header.
    NackInvalid = 0xf9,
    /// HSM may be on fire
    HsmOnFire = 0xff,
}

impl Command {
    /// Parses a byte as a Command
    pub fn from_byte(b: u8) -> Result<Command, Error> {
        match b {
            0x00 => Ok(Command::BlocksignerSignBlock),
            0x01 => Ok(Command::BlocksignerBlockSig),
            0x02 => Ok(Command::BlocksignerValidateBlock),

            0x14 => Ok(Command::WatchmanGetUnilateralWithdrawPubkey),
            0x15 => Ok(Command::WatchmanUnilateralWithdrawPubkey),
            0x16 => Ok(Command::WatchmanGetUnilateralWithdrawLocktime),
            0x17 => Ok(Command::WatchmanUnilateralWithdrawLocktime),
            0x18 => Ok(Command::WatchmanGetPublicKey),
            0x19 => Ok(Command::WatchmanPublicKey),
            0x1a => Ok(Command::WatchmanAuthorizedListReset),
            0x1b => Ok(Command::WatchmanAuthorizationVerify),
            0x1c => Ok(Command::WatchmanAuthorizationMasterKeysReplace),
            0x1e => Ok(Command::WatchmanForeChangeScript),
            0x1f => Ok(Command::WatchmanSetWitnessScript),

            0x21 => Ok(Command::HSMInit),
            0x22 => Ok(Command::HSMInitReply),
            0x23 => Ok(Command::HSMGetRtcTime),
            0x24 => Ok(Command::HSMRtcTimeReply),
            0x25 => Ok(Command::HSMGetSigningKey),
            0x26 => Ok(Command::HSMGetSigningKeyResponse),
            0x27 => Ok(Command::HSMAddEntropy),
            0x28 => Ok(Command::HSMAddEntropyFailure),
            0x29 => Ok(Command::HSMGetVersion),
            0x2a => Ok(Command::HSMGetVersionReply),
            0x2b => Ok(Command::HSMHeartbeat),
            0x2c => Ok(Command::HSMHeartbeatReply),
            0x2d => Ok(Command::HSMGetRestoreKey),
            0x2e => Ok(Command::HSMGetRestoreKeyReply),

            0x31 => Ok(Command::WatchmanSignSegwitTx),
            0x32 => Ok(Command::WatchmanSegwitTxSignatures),
            0x33 => Ok(Command::WatchmanHeader),
            0x34 => Ok(Command::WatchmanState),
            0x35 => Ok(Command::WatchmanStateReply),

            0x41 => Ok(Command::HSMUpdate),
            0x45 => Ok(Command::HSMUpdateACK),
            0x46 => Ok(Command::HSMUpdateNACK),

            0xe0 => Ok(Command::TamperDetectEnable),
            0xe1 => Ok(Command::TamperDetectChallenge),
            0xe2 => Ok(Command::TamperDetectResponse),

            0xf0 => Ok(Command::Ack),
            0xf1 => Ok(Command::NackRetry),
            0xf2 => Ok(Command::NackBadData),
            0xf3 => Ok(Command::NackInternal),
            0xf4 => Ok(Command::NackTooMany),
            0xf5 => Ok(Command::NackUnsupported),
            0xf6 => Ok(Command::NackDeliveryFailed),
            0xf7 => Ok(Command::NackRateLimit),
            0xf8 => Ok(Command::NackNotAllowed),
            0xf9 => Ok(Command::NackInvalid),
            0xff => Ok(Command::HsmOnFire),
            _ => Err(Error::BadCommand(b))
        }
    }
}

impl Command {
    /// Output a text representation of the command, for logging
    pub fn text(&self) -> &'static str {

        match *self {
            Command::BlocksignerSignBlock => "bs_sign_block",
            Command::BlocksignerBlockSig => "bs_block_sig",
            Command::BlocksignerValidateBlock => "bs_validate_block",

            Command::WatchmanGetUnilateralWithdrawPubkey => "wm_get_unilateral_withdraw_pubkey",
            Command::WatchmanUnilateralWithdrawPubkey => "wm_unilateral_withdraw_pubkey",
            Command::WatchmanGetUnilateralWithdrawLocktime => "wm_get_unilateral_withdraw_locktime",
            Command::WatchmanUnilateralWithdrawLocktime => "wm_unilateral_withdraw_locktime",
            Command::WatchmanGetPublicKey => "wm_get_public_key",
            Command::WatchmanPublicKey => "wm_public_key",
            Command::WatchmanAuthorizedListReset => "wm_authorized_list_reset",
            Command::WatchmanAuthorizationVerify => "wm_authorization_verify",
            Command::WatchmanAuthorizationMasterKeysReplace => "wm_authorization_master_keys_replace",
            Command::WatchmanForeChangeScript => "wm_fore_change_script",
            Command::WatchmanSetWitnessScript => "wm_set_witness_script",

            Command::HSMInit => "hsm_init",
            Command::HSMInitReply => "hsm_init_reply",
            Command::HSMGetRtcTime => "hsm_get_rtc_time",
            Command::HSMRtcTimeReply => "hsm_rtc_time_reply",
            Command::HSMGetSigningKey => "hsm_get_signing_key",
            Command::HSMGetSigningKeyResponse => "hsm_get_signing_key_response",
            Command::HSMAddEntropy => "hsm_add_entropy",
            Command::HSMAddEntropyFailure => "hsm_add_entropy_failure",
            Command::HSMGetVersion => "hsm_get_version",
            Command::HSMGetVersionReply => "hsm_get_version_reply",
            Command::HSMHeartbeat => "hsm_heart_beat",
            Command::HSMHeartbeatReply => "hsm_heart_beat_reply",
            Command::HSMGetRestoreKey => "hsm_get_restore_key",
            Command::HSMGetRestoreKeyReply => "hsm_get_restore_key_reply",

            Command::WatchmanSignSegwitTx => "wm_sign_segwit_tx",
            Command::WatchmanSegwitTxSignatures => "wm_segwit_tx_signatures",
            Command::WatchmanHeader => "wm_header",
            Command::WatchmanState => "wm_state",
            Command::WatchmanStateReply => "wm_state_reply",

            Command::HSMUpdate => "hsm_update",
            Command::HSMUpdateACK => "hsm_update_ack",
            Command::HSMUpdateNACK => "hsm_update_nack",

            Command::TamperDetectEnable => "tamper_detect_enable",
            Command::TamperDetectChallenge => "tamper_detect_challenge",
            Command::TamperDetectResponse => "tamper_detect_response",

            Command::Ack => "ack",
            Command::NackRetry => "nack_retry",
            Command::NackBadData => "nack_bad_data",
            Command::NackInternal => "nack_internal",
            Command::NackTooMany => "nack_too_many",
            Command::NackUnsupported => "nack_unsupported",
            Command::NackDeliveryFailed => "nack_delivery_failed",
            Command::NackRateLimit => "nack_rate_limit",
            Command::NackNotAllowed => "nack_not_allowed",
            Command::NackInvalid => "nack_invalid",
            Command::HsmOnFire => "hsm_on_fire",
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.text())
    }
}

impl Address {
    /// Parses a byte as a Address
    pub fn from_byte(b: u8) -> Result<Address, Error> {
        match b & 0x0f {
            0x00 => Ok(Address::BlockSigner),
            0x01 => Ok(Address::Watchman),
            0x02 => Ok(Address::Query),
            0x03 => Ok(Address::Update),
            0x04 => Ok(Address::Maintenance),
            // unreachable 0xff retained for historical/searching reasons
            0x0f | 0xff => Ok(Address::ParallelPort),
            _ => Err(Error::BadAddress(b))
        }
    }
}

/// Message header to a real HSM
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Header {
    /// Message version
    pub version: u8,
    /// Who it is intended for
    pub address: Address,
    /// Who to reply to
    pub return_address: Address,
    /// What this message is
    pub command: Command,
    /// Length of the message
    pub length: u32,
    /// Sha256d hash of the full message contents
    pub hash: sha256d::Hash
}

impl Header {
    /// Constructs a new header, computing the length and hash from the given data
    pub fn for_data(version: u8, address: Address, return_address: Address, command: Command, data: &[u8]) -> Header {
        Header {
            version: version,
            address: address,
            return_address: return_address,
            command: command,
            length: data.len() as u32,
            hash: sha256d::Hash::hash(data)
        }
    }

    /// Parses a header from data on the wire
    pub fn parse(data: &[u8]) -> Result<Header, Error> {
        if data.len() != HEADER_LEN {
            return Err(Error::BadLength(data.len()));
        }

        let version = data[0] >> 2;
        if (version) != MESSAGE_VERSION {
            return Err(Error::BadVersion(version));
        }

        Ok(Header {
            version: version, //V2+ messages store version info in left 6 bits
            address: Address::from_byte(data[1])?,
            return_address: Address::from_byte(data[2])?,
            command: Command::from_byte(data[3])?,
            length: (&data[4..8]).read_u32::<LittleEndian>().unwrap(),
            hash: sha256d::Hash::from_slice(&data[8..40]).unwrap()
        })
    }

    /// Serializes a header into data that can be put on the wire
    pub fn serialize(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(HEADER_LEN);
        ret.push((self.version as u8) << 2); //V2+ messages store version info in left 6 bits
        ret.push(self.address as u8);
        ret.push(self.return_address as u8);
        ret.push(self.command as u8);
        ret.write_u32::<LittleEndian>(self.length).unwrap();
        ret.write_all(&self.hash[..]).unwrap();
        debug_assert_eq!(ret.len(), HEADER_LEN);
        ret
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "HSM Message Header - Version: {}, Address: {:04x}, Return Address: {:04x}, Command: {:04x}, len: {}", self.version, self.address as u8, self.return_address as u8, self.command as u8, self.length)
    }
}

/// HSM message header
/// A message that can be sent to/from the HSM
pub trait Message {
    /// Accessor for the message header
    fn header(&self) -> &Header;
    /// Accessor for the message data
    fn payload(&self) -> &[u8];
}

/// A nonce given by the HSM when it is in tamper-detect mode. To unlock it,
/// it requires a signature with this nonce.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TamperDetectNonce([u8; 32]);

impl fmt::Debug for TamperDetectNonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::format_hex(&self.0[..], f)
    }
}

impl fmt::Display for TamperDetectNonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::format_hex(&self.0[..], f)
    }
}

/// HSM-communication-related error
#[derive(Debug)]
pub enum Error {
    /// HSM sent us a nack
    ReceivedNack(Command),
    /// Header is not the correct length
    BadLength(usize),
    /// Header command not one we recognize
    BadCommand(u8),
    /// Header address not one we recognize
    BadAddress(u8),
    /// Header version does not mat current version
    BadVersion(u8),
    /// Tried to cache too many authorized keys between Reset calls
    AuthorizedKeyCacheFull,
    /// HSM is in tamper-detect mode and is not going to respond to any messages til it gets a nonce signature
    TamperDetect(TamperDetectNonce),
    /// Some bitcoin decoding error
    Bitcoin(bitcoin::consensus::encode::Error),
    /// Key error.
    Key(bitcoin::key::Error),
    /// Some crypto error
    Secp(secp256k1::Error),
    /// Some I/O error
    Io(io::Error),
    /// Other decoding error.
    Decoding(&'static str),
    /// Unknown
    Unknown
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ReceivedNack(ref c) => write!(f, "hsm replied NACK: {:?}", c),
            Error::BadLength(ref s) => write!(f, "hsm header wrong length {}", s),
            Error::BadCommand(ref c) => write!(f, "hsm header bad command {}", c),
            Error::BadAddress(ref a) => write!(f, "hsm header bad address {}", a),
            Error::TamperDetect(nonce) => write!(f, "HSM is in tamper detect mode (needs signature of nonce {} to unlock)", nonce),
            Error::Bitcoin(ref e) => write!(f, "bitcoin error: {}", e),
            Error::BadVersion(_) => write!(f, "hsm header wrong version"),
            Error::AuthorizedKeyCacheFull => write!(f, "tried to cache too many authorized keys. call reset."),
            Error::Key(ref e) => write!(f, "key error: {}", e),
            Error::Secp(ref e) => write!(f, "secp256k1 error: {}", e),
            Error::Io(ref e) => write!(f, "I/O error: {}", e),
            Error::Decoding(ref e) => write!(f, "decoding failed: {}", e),
            Error::Unknown => write!(f, "unknown error"),
        }
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(e: bitcoin::consensus::encode::Error) -> Error { Error::Bitcoin(e) }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error { Error::Io(e) }
}

impl From<bitcoin::key::Error> for Error {
    fn from(e: bitcoin::key::Error) -> Error { Error::Key(e) }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error { Error::Secp(e) }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Bitcoin(ref e) => Some(e),
            Error::Key(ref e) => Some(e),
            Error::Io(ref e) => Some(e),
            Error::Secp(ref e) => Some(e),
            _ => None
        }
    }

    fn description(&self) -> &str {
        "error::Error::description is deprecated, please use fmt::Display"
    }
}

impl Error {
    /// Converts a tamper detect nonce to an error object; a `TamperDetectNonce` error
    /// if it receives a 32-byte message, otherwise a `BadLength` error
    pub fn tamper_detect(data: &[u8]) -> Error {
        if data.len() == 32 {
            let mut ret = [0; 32];
            ret.copy_from_slice(data);
            Error::TamperDetect(TamperDetectNonce(ret))
        } else {
            Error::BadLength(data.len())
        }
    }
}

/// Reply status for HSMR_get_sign_status.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WatchmanSignStatus {
    /// Seen tip and know enough epochs to sign.
    CanSign = 0x01,
    /// Need more headers to be able to sign properly.
    NeedMoreHistory = 0x02,
}

impl TryFrom<u8> for WatchmanSignStatus {
    type Error = ();
    fn try_from(byte: u8) -> Result<WatchmanSignStatus, Self::Error> {
        match byte {
            0x01 => Ok(WatchmanSignStatus::CanSign),
            0x02 => Ok(WatchmanSignStatus::NeedMoreHistory),
            _ => Err(()),
        }
    }
}
