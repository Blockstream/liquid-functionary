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


//! # Networking logs
//!

use std::{fmt, str, time};
use std::borrow::Cow;

use bitcoin::hashes::{hex, sha256d};

use common::PeerId;

/// A message hash shortened to 12 hex digits.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortHash([u8; 5]);

impl From<sha256d::Hash> for ShortHash {
    fn from(h: sha256d::Hash) -> ShortHash {
        ShortHash([h[27], h[28], h[29], h[30], h[31]])
    }
}

impl fmt::Display for ShortHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[4], self.0[3], self.0[2], self.0[1], self.0[0],
        )
    }
}

impl fmt::Debug for ShortHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl hex::FromHex for ShortHash {
    type Err = hex::HexToArrayError;

    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::HexToArrayError>
        where I: Iterator<Item=Result<u8, hex::HexToBytesError>> + ExactSizeIterator + DoubleEndedIterator,
    {
        if iter.len() == 5 {
            let mut ret = [0; 5];
            for (n, byte) in iter.enumerate() {
                ret[n] = byte?;
            }
            Ok(ShortHash(ret))
        } else {
            Err(hex::HexToArrayError::InvalidLength(10, 2 * iter.len()))
        }
    }
}

impl serde::Serialize for ShortHash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for ShortHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<ShortHash, D::Error> {
        struct HexVisitor;

        impl<'de> serde::de::Visitor<'de> for HexVisitor {
            type Value = ShortHash;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an ASCII hex string")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if let Ok(hex) = str::from_utf8(v) {
                    Ok(hex::FromHex::from_hex(hex).map_err(E::custom)?)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(hex::FromHex::from_hex(v).map_err(E::custom)?)
            }
        }

        d.deserialize_str(HexVisitor)
    }
}

/// Format a nonce in fixed-width hex
fn serialize_nonce<S: serde::Serializer>(n: &u32, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&format_args!("{:08x}", n))
}

/// Format a nonce in fixed-width hex
fn deserialize_nonce<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    let hex: &'de str = serde::Deserialize::deserialize(d)?;
    u32::from_str_radix(hex, 16).map_err(serde::de::Error::custom)
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Header {
    pub version: u32,
    pub sender: String,
    pub _unused_field_1: String,
    pub round: u32,
    pub msgid: u32,
    pub nonce: u32,
    pub command: &'static str,
    pub time: time::SystemTime,
    pub hash: ShortHash,
    pub length: u32,
}

/// Log the functionary's own preferred protocol version on startup.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// the preferred protocol version of this peer
    pub version: u32,
}

/// Peer protocol version discovered by succesful handshake.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PeerHandshake {
    /// the peer
    pub peer: PeerId,
    /// the version
    pub version: u32,
}

/// Receive a network message to ourselves
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ReceiveForSelf {
    /// Sender of the message
    pub sender: PeerId,
    /// The protocol version of the message
    pub version: u32,
    /// Round number that the message was sent in
    pub round_no: u32,
    /// Message id
    pub msgid: u32,
    /// Message nonce
    #[serde(serialize_with = "serialize_nonce", deserialize_with = "deserialize_nonce")]
    pub nonce: u32,
    /// Time since the message was sent, in milliseconds
    pub skew_ms: i64,
    /// Message type
    pub command: Cow<'static, str>,
    /// Length of the message data
    pub length: u32,
    /// Hash of the message data
    pub hash: ShortHash,
}

/// Receive a network message for another peer
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ReceiveForRelay {
    /// Sender of the message
    pub sender: PeerId,
    /// Target destination for the message
    pub target: PeerId,
    /// Protocol version.
    pub version: u32,
    /// Round number that the message was sent in
    pub round_no: u32,
    /// Message nonce
    #[serde(serialize_with = "serialize_nonce", deserialize_with = "deserialize_nonce")]
    pub nonce: u32,
    /// Time since the message was sent, in milliseconds
    pub skew_ms: i64,
    /// Message type
    pub command: Cow<'static, str>,
    /// Length of the message data
    pub length: u32,
    /// Hash of the message data
    pub hash: ShortHash,
}

/// Receive a network message for another peer
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct QueuedMessagesCleared {
    /// Includes the destination information (peer name, IP address, port) for
    /// the connection associated with this queue.
    pub connection: String,
    /// Count of queued messages cleared by the associated operation
    pub cleared_count: usize,
    /// Count of messages remaining in the queue
    pub remaining_count: usize,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MessageDropped<'a> {
    pub connection: &'a str,
    pub message_type: &'static str,
    pub reason: &'static str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
}

/// Accounting entry for bytes queued on a given connection
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MessageSent {
    pub message_type: &'static str,
    pub bytes: usize,
}

/// Accounting entry for bytes received on a given connection
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MessageReceived {
    pub message_type: &'static str,
    pub bytes: usize,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ReceivedStatusAck {
    pub peer: PeerId,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct KickWatchdogForStatusAck {
    pub peer: PeerId,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct KickWatchdogForInStatusAck {
    pub peer: PeerId,
}