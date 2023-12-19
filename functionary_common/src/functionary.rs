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

use std::{fmt, ops, str};
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::time::{Duration, SystemTime};

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::hashes::hex::{self, FromHex};
use bitcoin::secp256k1::PublicKey;
#[cfg(feature = "serde")]
use serde::Deserialize;

/// A six-byte peer network ID based on the hash of the signing pubkey.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Default, Hash)]
pub struct PeerId([u8; 6]);

impl PeerId {
    /// The zeroed out peer ID.
    pub const ZERO: PeerId = PeerId([0, 0, 0, 0, 0, 0]);
}

impl From<[u8; 6]> for PeerId {
    fn from(data: [u8; 6]) -> PeerId {
        PeerId(data)
    }
}

impl<'a> From<&'a [u8]> for PeerId {
    /// Converts a slice (whose size must be correct) to an object
    fn from(data: &'a [u8]) -> PeerId {
        assert!(data.len() == 6);
        let mut ret = [0; 6];
        ret.copy_from_slice(&data[..]);
        PeerId(ret)
    }
}

impl fmt::LowerHex for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::format_hex(&self.0[..], f)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::format_hex(&self.0[..], f)
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl str::FromStr for PeerId {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_part = s.split("[").next().unwrap();
        Ok(PeerId(FromHex::from_hex(hex_part).map_err(|_| "invalid PeerId")?))
    }
}

impl FromHex for PeerId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
        where I: Iterator<Item=Result<u8, hex::Error>> +
            ExactSizeIterator +
            DoubleEndedIterator {
        Ok(PeerId(FromHex::from_byte_iter(iter)?))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PeerId, D::Error> {
        struct HexVisitor;

        impl<'de> serde::de::Visitor<'de> for HexVisitor {
            type Value = PeerId;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an ASCII hex string")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if let Ok(hex) = std::str::from_utf8(v) {
                    Ok(PeerId(FromHex::from_hex(hex).map_err(E::custom)?))
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(PeerId(FromHex::from_hex(v).map_err(E::custom)?))
            }
        }

        d.deserialize_str(HexVisitor)
    }
}

impl ops::Index<ops::RangeFull> for PeerId {
    type Output = [u8];

    fn index(&self, _: ops::RangeFull) -> &[u8] {
        &self.0[..]
    }
}

impl From<PublicKey> for PeerId {
    /// Create a peer ID from its config description
    fn from(pk: PublicKey) -> PeerId {
        let pk_hash = sha256d::Hash::hash(&pk.serialize());
        PeerId::from(&pk_hash[0..6])
    }
}

#[cfg(feature = "serde")]
fn serialize_duration_ms<S: serde::Serializer>(t: &Duration, s: S) -> Result<S::Ok, S::Error> {
    serde::Serialize::serialize(&t.as_millis(), s)
}

#[cfg(feature = "serde")]
pub fn deserialize_duration_ms<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let ms: u64 = serde::Deserialize::deserialize(d)?;
    Ok(Duration::from_millis(ms))
}

#[cfg(feature = "serde")]
pub fn deserialize_option_duration_ms<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
    let ms: Option<u64> = serde::Deserialize::deserialize(d)?;
    Ok(ms.map(|ms| Duration::from_millis(ms)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Stage1,
    Stage2,
    Stage3,
    /// Catchup sync
    Stage3b,
}

impl PartialOrd for Stage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        (i32::from(*self)).abs().partial_cmp(&(i32::from(*other)).abs())
    }
}

impl From<Stage> for i32 {
    fn from(stage: Stage) -> Self {
        match stage {
            Stage::Stage1 => 1,
            Stage::Stage2 => 2,
            Stage::Stage3 => 3,
            Stage::Stage3b => -3,
        }
    }
}

impl TryFrom<i32> for Stage {
    type Error = String;

    fn try_from(stage: i32) -> Result<Self, Self::Error> {
        match stage {
            1 => Ok(Stage::Stage1),
            2 => Ok(Stage::Stage2),
            3 => Ok(Stage::Stage3),
            -3 => Ok(Stage::Stage3b),
            _=> Err(format!("{} is not a valid stage number", stage))
        }
    }
}

impl Stage {
    /// Returns the index of the Stage that can be used to access the Duration array. This is also
    /// useful for comparing stages because it exploits the fact that the absolute value of
    /// Stage3 and Stage3b are equivalent.
    pub fn as_duration_index(&self) -> usize {
        (i32::from(*self).abs() - 1) as usize
    }
}

impl Display for Stage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", i32::from(*self))
    }
}

/// Round stage, which encodes a current round number, current master peer and
/// the stage within the round
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RoundStage {
    /// Time that this stage started
    pub start_time: SystemTime,
    /// Duration of this stage
    pub duration: Duration,
    /// Current round number
    pub round: u64,
    /// Current stage number within a round (0-indexed)
    pub stage: Stage,
    /// Current master
    pub master: PeerId,
}

impl Default for RoundStage {
    fn default() -> RoundStage {
        RoundStage {
            start_time: SystemTime::now(),
            duration: Default::default(),
            round: 0,
            stage: Stage::Stage1,
            master: Default::default(),
        }
    }
}

impl fmt::Display for RoundStage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let elapsed = &self.start_time.elapsed().unwrap_or_default().as_millis();
        write!(f, "{}.{} {}/{} ms", self.round, self.stage, elapsed, self.duration.as_millis())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for RoundStage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ret = SerializedRoundStage {
            elapsed: self.start_time.elapsed().unwrap_or_default(),
            duration: self.duration,
            round: self.round,
            stage: i32::from(self.stage),
            master: self.master,
        };
        serde::Serialize::serialize(&ret, serializer)
    }
}

impl RoundStage {
    /// Creates a `RoundStage` with arbitrary data for test cases that need one
    pub fn test_dummy() -> RoundStage {
        RoundStage {
            // Andrew's birthday
            start_time: SystemTime::UNIX_EPOCH
                + Duration::from_secs(7900 * 3600 * 24),
            duration: Duration::from_millis(25000),
            round: 123456789,
            stage: Stage::Stage3,
            master: PeerId::from(&b"andrew"[..]),
        }
    }

    /// Detect whether the stage has been overrun, and return the amount of
    /// the overrun if so
    pub fn is_overrun(&self) -> Option<Duration> {
        self.start_time
            .elapsed()
            .expect("start time in the past")
            .checked_sub(self.duration)
    }
}

/// A serialized [RoundStage] with the elapsed variable set.
#[cfg(feature = "serde")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SerializedRoundStage {
    /// Time time in ms elapsed since the stage started.
    #[serde(rename = "elapsed_ms")]
    #[serde(serialize_with = "serialize_duration_ms", deserialize_with = "deserialize_duration_ms")]
    pub elapsed: Duration,
    /// Duration of this stage, in ms
    #[serde(rename = "duration_ms")]
    #[serde(serialize_with = "serialize_duration_ms", deserialize_with = "deserialize_duration_ms")]
    pub duration: Duration,
    /// Current round number
    pub round: u64,
    /// Current stage number within a round
    pub stage: i32,
    /// Current master
    pub master: PeerId,
}