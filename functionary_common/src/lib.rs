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

#[cfg(feature = "serde")]
extern crate serde;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;

extern crate bitcoin;
extern crate byteorder;
extern crate elements;
#[cfg(test)]
extern crate miniscript;

pub mod constants;
pub use constants::CONSTANTS;

pub mod macros;

mod functionary;
pub use functionary::*;

mod blocksigner;
pub use blocksigner::SignState;

pub mod blockchain;
pub mod hsm;
pub mod rollouts;
pub mod util;

use std::fmt;
use std::io::Write;

use bitcoin::secp256k1::PublicKey;

/// A block height (or height delta, e.g. number of confirmations)
pub type BlockHeight = u64;

/// A PAK list entry.
///
/// Can be converted from and into a tuple of the offline and online key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PakEntry {
    /// The offline key part.
    pub offline: PublicKey,
    /// The online key part.
    pub online: PublicKey,
}

impl From<(PublicKey, PublicKey)> for PakEntry {
    fn from(pair: (PublicKey, PublicKey)) -> PakEntry {
        PakEntry {
            offline: pair.0,
            online: pair.1,
        }
    }
}

impl From<PakEntry> for (PublicKey, PublicKey) {
    fn from(entry: PakEntry) -> (PublicKey, PublicKey) {
        (entry.offline, entry.online)
    }
}

/// List of pegout authorization keys
#[derive(Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PakList {
    /// List of offline/online pubkey pairs.
    pairs: Vec<PakEntry>,
}

impl PakList {
    /// Construct a dynafed extension space from the PAK list.
    pub fn to_extension_space(&self) -> Vec<Vec<u8>> {
        let mut ret = Vec::with_capacity(self.len());
        for entry in self.pairs.iter() {
            let mut ser = Vec::with_capacity(2 * 65);
            ser.write_all(&entry.offline.serialize()).unwrap();
            ser.write_all(&entry.online.serialize()).unwrap();
            ret.push(ser);
        }
        ret
    }

    /// Construct a PAK list from a dynafed header's extension space.
    pub fn from_extension_space(ext: &[Vec<u8>]) -> Result<PakList, &'static str> {
        let mut pairs = Vec::with_capacity(ext.len());
        for pair in ext.iter() {
            if pair.len() != 66 {
                return Err("entry of invalid length, should be 66");
            }

            pairs.push(PakEntry {
                offline: PublicKey::from_slice(&pair[0..33]).map_err(|_| "invalid online key")?,
                online: PublicKey::from_slice(&pair[33..66]).map_err(|_| "invalid offline key")?,
            });
        }
        Ok(PakList { pairs })
    }

    /// Get an iterator of entries.
    pub fn iter(&self) -> std::slice::Iter<PakEntry> {
        self.pairs.iter()
    }

    /// Check the length of the PAK list.
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Check if the PAK list is empty.
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Get an iterator of pairs of offline/online pubkeys.
    pub fn pairs(&self) -> impl Iterator<Item = (&PublicKey, &PublicKey)> {
        self.pairs.iter().map(|entry| (&entry.offline, &entry.online))
    }

    /// Convert from a list of offline/online pubkey pairs.
    pub fn from_pairs(pairs: Vec<(PublicKey, PublicKey)>) -> PakList {
        PakList {
            pairs: pairs.into_iter().map(From::from).collect(),
        }
    }

    /// Iterate over the offline keys in order.
    pub fn iter_offline(&self) -> impl Iterator<Item = &PublicKey> {
        self.iter().map(|e| &e.offline)
    }

    /// Iterate over the online keys in order.
    pub fn iter_online(&self) -> impl Iterator<Item = &PublicKey> {
        self.iter().map(|e| &e.online)
    }
}

// the debug for PublicKey is quite bad, so let's make this more readable
impl fmt::Debug for PakList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PakList ({}) {{ {:?} }}", self.len(), self.pairs)
    }
}

/// The scriptint representation of 4032.
/// Can be constructed using `test::build_scriptint(4032)`.
const CSV_4032_SCRIPTINT: [u8; 2] = [192, 15];

/// Convert script into a variant of the script that has the mention of
/// 4032 replaced with 2016, assuming this would only apply to CSV pushes.
pub fn convert_into_csv_tweaked_change(script: &bitcoin::ScriptBuf) -> Option<bitcoin::ScriptBuf> {
    let mut converted = bitcoin::blockdata::script::Builder::new();
    let mut found_csv = false;

    // We're going to iterator through the instructions in the script and
    // just pass them into the builder, EXCEPT a byte push that is exactly
    // the number 4032, which we will assume is the CSV height push.
    // It will be replaced with a byte push for the number 2016.
    for res in script.instructions() {
        match res {
            Ok(bitcoin::blockdata::script::Instruction::PushBytes(b)) => {
                if b.as_bytes() == CSV_4032_SCRIPTINT {
                    if found_csv {
                        // double CSV.. doesn't seem good
                        return None;
                    }
                    found_csv = true;
                    converted = converted.push_int(2016);
                } else {
                    converted = converted.push_slice(b);
                }
            }
            Ok(bitcoin::blockdata::script::Instruction::Op(o)) => {
                converted = converted.push_opcode(o);
            }
            Err(_) => return None,
        }
    }

    if found_csv {
        Some(converted.into_script())
    } else {
        None
    }
}

/// Trait for more concisely printing types for logging.
pub trait ConcisePrintable<'a> {
    type Printable: fmt::Display;
    fn printable(&'a self) -> Self::Printable;
}

/// Type that implements concise logging for an elements header.
pub struct PrintableElementsHeader<'a>(&'a elements::BlockHeader);

impl<'a> fmt::Display for PrintableElementsHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut d = f.debug_struct("elements::BlockHeader");
        d.field("version", &self.0.version);
        d.field("prev_blockhash", &self.0.prev_blockhash);
        d.field("merkle_root", &self.0.merkle_root);
        d.field("time", &self.0.time);
        d.field("height", &self.0.height);
        if let elements::BlockExtData::Dynafed { ref current, ref proposed, .. } = self.0.ext {
            d.field("type", &"dynafed");
            d.field("current", &current.calculate_root());
            d.field("proposed", &proposed.calculate_root());
            // we skip the signblock witness
        } else {
            d.field("type", &"legacy");
            // we skip both the signblock challenge and solution
        }
        d.finish()
    }
}

impl<'a> ConcisePrintable<'a> for elements::BlockHeader {
    type Printable = PrintableElementsHeader<'a>;
    fn printable(&'a self) -> Self::Printable {
        PrintableElementsHeader(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::str::FromStr;

    use bitcoin::PublicKey;
    use miniscript::Descriptor;

    /// Helper to encode an integer in script format
    /// This method is borrowed from rust-bitcoin's script.rs
    fn build_scriptint(n: i64) -> Vec<u8> {
        if n == 0 { return vec![] }

        let neg = n < 0;

        let mut abs = if neg { -n } else { n } as usize;
        let mut v = vec![];
        while abs > 0xFF {
            v.push((abs & 0xFF) as u8);
            abs >>= 8;
        }
        // If the number's value causes the sign bit to be set, we need an extra
        // byte to get the correct value and correct sign bit
        if abs & 0x80 != 0 {
            v.push(abs as u8);
            v.push(if neg { 0x80u8 } else { 0u8 });
        }
        // Otherwise we just set the sign bit ourselves
        else {
            abs |= if neg { 0x80 } else { 0 };
            v.push(abs as u8);
        }
        v
    }

    #[test]
    fn test_csv_4032_scriptint() {
        assert_eq!(&CSV_4032_SCRIPTINT[..], &build_scriptint(4032)[..]);
    }

    #[test]
    fn test_convert_into_csv_tweaked_change() {
        // a liquid-looking descriptor
        let correct = {
            let desc = "sh(wsh(or_d(multi(3,025d8c3aa3e1689c20e58db2269b59f40764c699455ecaa61861115bc96c6037db,038b206b33de3bfdfa3cb79719209e360bf65b084aaf97264750864a8c2dcad9dc,02cde757c545d01b5f0d01257e60be9dffb0137b4bdf2942ea7a9b835063b61fab),and_v(v:older(4032),multi(1,023303dedc51b9d227b17c9fb4710f96b844e1ccdc2c776e1b7274bd4e246b6202,03024c3b4f830854d6d26d6e34d92aff4c703bf57e85cd42abe328d928e01d4286,03ff4e8c8d99b9dcbb529a87d54f606bae0149a34018325547fa0c2239e038a1c9)))))";
            let desc = Descriptor::<PublicKey>::from_str(desc).unwrap();
            desc.explicit_script().unwrap()
        };

        let broken = {
            let desc = "sh(wsh(or_d(multi(3,025d8c3aa3e1689c20e58db2269b59f40764c699455ecaa61861115bc96c6037db,038b206b33de3bfdfa3cb79719209e360bf65b084aaf97264750864a8c2dcad9dc,02cde757c545d01b5f0d01257e60be9dffb0137b4bdf2942ea7a9b835063b61fab),and_v(v:older(2016),multi(1,023303dedc51b9d227b17c9fb4710f96b844e1ccdc2c776e1b7274bd4e246b6202,03024c3b4f830854d6d26d6e34d92aff4c703bf57e85cd42abe328d928e01d4286,03ff4e8c8d99b9dcbb529a87d54f606bae0149a34018325547fa0c2239e038a1c9)))))";
            let desc = Descriptor::<PublicKey>::from_str(desc).unwrap();
            desc.explicit_script().unwrap()
        };

        assert_eq!(convert_into_csv_tweaked_change(&broken), None);
        assert_eq!(convert_into_csv_tweaked_change(&correct), Some(broken));
    }
}
