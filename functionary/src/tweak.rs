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

//! # Key Tweaks
//!
//! Utility functions to make pay-to-contract tweaks to public keys
//!

use std::{fmt, ops};
use std::str::FromStr;
use elements::secp256k1_zkp;
use miniscript;

use bitcoin::hashes::{hash160, Hmac, sha256, HmacEngine, Hash, HashEngine};
use bitcoin::hashes::hex::{self, FromHex, ToHex};
use bitcoin::secp256k1::{self, Secp256k1, PublicKey};

use common::PeerId;
use peer;
use utils;

/// A tweak to a secret key used to compute the signing key for a transaction
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct Tweak(
    #[serde(with = "utils::serialize::hex_bytes")]
    [u8; 32]
);

impl Tweak {
    /// Create a tweak which has no effect
    pub fn none() -> Tweak {
        Tweak([0; 32])
    }

    /// Create a tweak which tweaks one key by another
    pub fn some(s: &[u8]) -> Tweak {
        let mut ret = [0; 32];
        ret.copy_from_slice(s);
        Tweak(ret)
    }

    /// Tweaks a secret key by `self.0`. Will panic if the resulting secret key is invalid;
    /// it is assumed that all tweaks come from hashes, so this cannot happen except with
    /// negligible probability.
    pub fn tweak_secret(&self, s: &secp256k1::SecretKey) -> secp256k1::SecretKey {
        let mut key = *s;
        key.add_assign(&self.0[..]).expect("invalid tweak");
        key
    }
}

impl fmt::LowerHex for Tweak {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::format_hex(&self.0[..], f)
    }
}

impl ops::Index<ops::RangeFull> for Tweak {
    type Output = [u8];

    fn index(&self, _: ops::RangeFull) -> &[u8] {
        &self.0[..]
    }
}

impl Default for Tweak {
    fn default() -> Tweak {
        Tweak::none()
    }
}

/// An enum differentiating between "untweakable" (i.e. emergency withdrawal)
/// and "tweakable" (i.e. watchman) keys
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Key {
    /// A key associated to a functionary, which should be tweaked in
    /// a pay-to-contract mapping
    Tweakable(peer::Id, PublicKey),
    /// A key which, while not being a functionary key, should still be tweaked
    /// by the p2c mapping
    NonFunctionary(PublicKey),
    /// A tweaked key.
    Tweaked {
        /// The peer ID of the public key.
        peer: peer::Id,
        /// The public key with the given tweak already applied.
        tweaked_pk: PublicKey,
        /// The tweak used to have generated the tweaked key.
        tweak: Tweak,
    },
    /// A tweaked non-functionary key.
    TweakedNonFunc {
        /// The public key with the given tweak already applied.
        tweaked_pk: PublicKey,
        /// The tweak used to have generated the tweaked key.
        tweak: Tweak,
    },
    /// A key which should be unmodified in a p2c mapping
    Untweakable(PublicKey),
}

impl Key {
    /// Get the underlying pubkey this key represents.
    pub fn as_pubkey(&self) -> &PublicKey {
        match self {
            Key::Tweakable(_, ref pk) => pk,
            Key::NonFunctionary(ref pk) => pk,
            Key::Untweakable(ref pk) => pk,
            Key::Tweaked { ref tweaked_pk, .. } => tweaked_pk,
            Key::TweakedNonFunc { ref tweaked_pk, .. } => tweaked_pk,
        }
    }

    /// Get the underlying pubkey this key represents.
    #[inline]
    pub fn to_pubkey(&self) -> PublicKey {
        *self.as_pubkey()
    }

    /// Get the peer id associated with this key, if any.
    pub fn peer_id(&self) -> Option<PeerId> {
        match self {
            Key::Tweakable(id, _) => Some(*id),
            Key::NonFunctionary (..) => None,
            Key::Tweaked { peer, .. } => Some(*peer),
            Key::TweakedNonFunc { .. } => None,
            Key::Untweakable(..) => None,
        }
    }

    /// Do a pay-to-contract mapping on the key. Will always succeed;
    /// returns a `result` to make it easier to use in a closure for
    /// `Miniscript::translate`.
    pub fn p2c<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        contract: &[u8],
    ) -> Result<Key, String> {
        match *self {
            Key::Tweakable(id, pk) => {
                let (key, tweak) = tweak_key(secp, pk, contract);
                Ok(Key::Tweaked {
                    peer: id,
                    tweaked_pk: key,
                    tweak: tweak,
                })
            }
            Key::NonFunctionary(pk) => {
                let (key, tweak) = tweak_key(secp, pk, contract);
                Ok(Key::TweakedNonFunc {
                    tweaked_pk: key,
                    tweak: tweak,
                })
            }
            Key::Untweakable(pk) => Ok(Key::Untweakable(pk)),
            Key::Tweaked { .. } | Key::TweakedNonFunc { .. } => {
                panic!("trying to tweak a key twice");
            }
        }
    }

    /// Interprets a bitcoin public key as a tweak key
    pub fn from_public_key(pk: PublicKey) -> Result<Key, ()> {
        Ok(Key::Untweakable(pk))
    }
}

impl ops::Deref for Key {
    type Target = PublicKey;

    fn deref(&self) -> &Self::Target {
        self.as_pubkey()
    }
}

impl miniscript::MiniscriptKey for Key {
    // This is a common trick to not have to deal with key hashes when
    // you're not explicitly mixing key hashes and keys in descriptors.
    // So in order to easily extract keys from `Semantic` policies,
    // we can just proxy the key as the hash and get all keys like that.
    type Hash = Key;

    fn to_pubkeyhash(&self) -> Self::Hash {
        self.clone()
    }
}

impl miniscript::ToPublicKey for Key {
    /// Strip the metadata and return just the raw key
    fn to_public_key(&self) -> bitcoin::PublicKey {
        bitcoin::PublicKey {
            inner: self.to_pubkey(),
            compressed: true,
        }
    }

    fn hash_to_hash160(hash: &Key) -> hash160::Hash {
        miniscript::MiniscriptKey::to_pubkeyhash(hash.as_pubkey())
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Key::Untweakable(ref pk) => write!(f, "[untweaked]{}", pk),
            Key::NonFunctionary(ref pk) => write!(f, "[nonfunc]{}", pk),
            Key::Tweakable(id, ref pk) => write!(f, "[{}]{}", id.to_hex(), pk),
            Key::Tweaked { peer, ref tweaked_pk, tweak } => {
                write!(f, "[tweaked][{:x}][{:x}]{}", peer, tweak, tweaked_pk)
            }
            Key::TweakedNonFunc { ref tweaked_pk, tweak } => {
                write!(f, "[tweaked][nonfunc][{:x}]{}", tweak, tweaked_pk)
            }
        }
    }
}

use bitcoin::consensus::encode::Error as EncodeErr;

impl FromStr for Key {
    type Err = EncodeErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for ch in s.chars() {
            if !ch.is_alphanumeric() && ch != '[' && ch != ']' {
                return Err(EncodeErr::ParseFailed("invalid hex character"));
            }
        }

        // hex length shorthands
        const PK: usize = 2 * secp256k1::constants::PUBLIC_KEY_SIZE;
        const PID: usize = 2 * 6;
        const TWEAK: usize = 2 * 32;

        match s.len() {
            l if l == PK + 2 + 7 => {
                if &s[0..9] == "[nonfunc]" {
                    match PublicKey::from_str(&s[9..]) {
                        Ok(k) => Ok(Key::NonFunctionary(k)),
                        Err(_) => Err(EncodeErr::ParseFailed("invalid key")),
                    }
                } else {
                    Err(EncodeErr::ParseFailed("bad key"))
                }
            },
            l if l == PK + 2 + 9 => {
                if &s[0..11] == "[untweaked]" {
                    match PublicKey::from_str(&s[11..]) {
                        Ok(k) => Ok(Key::Untweakable(k)),
                        Err(_) => Err(EncodeErr::ParseFailed("invalid key")),
                    }
                } else {
                    Err(EncodeErr::ParseFailed("bad key"))
                }
            },
            l if l == PK + 2 + PID => {
                if s.as_bytes()[0] != b'[' {
                    Err(EncodeErr::ParseFailed("script key missing '['"))
                } else if s.as_bytes()[13] != b']' {
                    Err(EncodeErr::ParseFailed("script key missing ']'"))
                } else {
                    let bytes = <[u8; 6]>::from_hex(&s[1..13])
                        .map_err(|_| EncodeErr::ParseFailed("bad peer id"))?;
                    Ok(Key::Tweakable(
                        peer::Id::from(&bytes[..]),
                        match PublicKey::from_str(&s[14..]) {
                            Ok(k) => k,
                            Err(_) => return Err(EncodeErr::ParseFailed("invalid key")),
                        }
                    ))
                }
            }
            // `[tweaked][nonfunc][0102030405060708091011121314151617181920212223242526272829303132]<pubkey>
            //  ^ 0 pre          ^ 17
            //                    ^ 18          tweak                                              ^ 83
            l if l == PK + 2 + 7 + 2 + 7 + 2 + TWEAK => {
                if &s[0..18] == "[tweaked][nonfunc]" {
                    Ok(Key::TweakedNonFunc {
                        tweak: {
                            if s.as_bytes()[18] != b'[' {
                                return Err(EncodeErr::ParseFailed("tweak missing '['"));
                            }
                            if s.as_bytes()[83] != b']' {
                                return Err(EncodeErr::ParseFailed("tweak missing ']'"));
                            }

                            let bytes = <[u8; 32]>::from_hex(&s[19..83])
                                .map_err(|_| EncodeErr::ParseFailed("bad tweak"))?;
                            Tweak(bytes)
                        },
                        tweaked_pk: PublicKey::from_str(&s[84..])
                            .map_err(|_| EncodeErr::ParseFailed("invalid key"))?,
                    })
                } else {
                    Err(EncodeErr::ParseFailed("bad peer id"))
                }
            }
            // `[tweaked][010203040506][0102030405060708091011121314151617181920212223242526272829303132]<pubkey>
            //  ^ 0 pre ^ 8
            //           ^ 9  peerid  ^ 22
            //                         ^ 23          tweak                                              ^ 88
            l if l == PK + 2 + 7 + 2 + PID + 2 + TWEAK => {
                if &s[0..9] == "[tweaked]" {
                    Ok(Key::Tweaked {
                        peer: {
                            if s.as_bytes()[9] != b'[' {
                                return Err(EncodeErr::ParseFailed("script key missing '['"));
                            }
                            if s.as_bytes()[22] != b']' {
                                return Err(EncodeErr::ParseFailed("script key missing ']'"));
                            }

                            let bytes = <[u8; 6]>::from_hex(&s[10..22])
                                .map_err(|_| EncodeErr::ParseFailed("bad peer id"))?;
                            peer::Id::from(&bytes[..])
                        },
                        tweak: {
                            if s.as_bytes()[23] != b'[' {
                                return Err(EncodeErr::ParseFailed("tweak missing '['"));
                            }
                            if s.as_bytes()[88] != b']' {
                                return Err(EncodeErr::ParseFailed("tweak missing ']'"));
                            }

                            let bytes = <[u8; 32]>::from_hex(&s[24..88])
                                .map_err(|_| EncodeErr::ParseFailed("bad tweak"))?;
                            Tweak(bytes)
                        },
                        tweaked_pk: PublicKey::from_str(&s[89..])
                            .map_err(|_| EncodeErr::ParseFailed("invalid key"))?,
                    })
                } else {
                    Err(EncodeErr::ParseFailed("bad peer id"))
                }
            }
            _ => Err(EncodeErr::ParseFailed("script key with bad length"))
        }
    }
}

// These two functions are copied from elements-miniscript, which is not yet stabilised.
// Remove these and use them from elements-miniscript if/when that dependency is added.
// NB: https://gl.blockstream.io/liquid/functionary/-/issues/961

/// Tweak a MiniscriptKey to obtain the tweaked key
pub(super) fn tweak_key<C: secp256k1_zkp::Verification>(
    secp: &Secp256k1<C>,
    mut key: PublicKey,
    contract: &[u8],
) -> (PublicKey, Tweak) {
    let hmac_result = compute_tweak(&key, contract);
    key.add_exp_assign(secp, &hmac_result[..]).expect("HMAC cannot produce invalid tweak");
    (key, Tweak::some(&hmac_result[..]))
}

/// Compute a tweak from some given data for the given public key
pub(super) fn compute_tweak(pk: &PublicKey, contract: &[u8]) -> Hmac<sha256::Hash> {
    let mut hmac_engine = HmacEngine::<sha256::Hash>::new(&pk.serialize());
    hmac_engine.input(contract);
    Hmac::from_engine(hmac_engine)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::secp256k1::{self, rand, SecretKey};
    use miniscript::{Descriptor, ToPublicKey, TranslatePk};

    use peer;
    use super::*;

    #[test]
    fn p2c() {
        let secp = secp256k1::Secp256k1::new();
        let pk = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        ).unwrap();
        let tweaked_pk = PublicKey::from_str(
            "03029ac621b8ecaa2b3a6ea3dfe2f7c5d7dc6ac987d80537a2e235295495d7b11a",
        ).unwrap();
        let contract = b"stacy's mom has got it going on";
        let tweak = Tweak::some(&compute_tweak(&pk, contract)[..]);

        let id = peer::Id::from(&b"Andrew"[..]);

        assert_eq!(
            Key::Untweakable(pk).p2c(&secp, contract),
            Ok(Key::Untweakable(pk))
        );
        assert_eq!(Key::Untweakable(pk).to_pubkey(), pk);
        assert_eq!(
            Key::Untweakable(pk).to_public_key().inner,
            pk,
        );

        assert_eq!(
            Key::Tweakable(id, pk).p2c(&secp, contract),
            Ok(Key::Tweaked { peer: id, tweaked_pk, tweak })
        );
        assert_eq!(
            Key::NonFunctionary(pk).p2c(&secp, contract),
            Ok(Key::TweakedNonFunc { tweaked_pk, tweak })
        );
        assert_eq!(Key::Tweakable(id, pk).to_pubkey(), pk);
        assert_eq!(
            Key::Tweakable(id, pk).to_public_key().inner,
            pk,
        );

        assert_eq!(
            Key::Tweakable(id, pk).to_string(),
            "[416e64726577]\
            02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        );
        assert_eq!(
            Key::Untweakable(pk).to_string(),
            "[untweaked]02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        );

        assert_eq!(
            Key::from_str(
                "[416e64726577]\
                02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
            ).unwrap(),
            Key::Tweakable(id, pk),
        );
        assert_eq!(
            Key::from_str(
                "[untweaked]\
                02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            ).unwrap(),
            Key::Untweakable(pk)
        );
    }

    #[test]
    fn tweak_string_roundtrip() {
        let pk = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        ).unwrap();
        let id = peer::Id::from(&b"Andrew"[..]);

        let tweakable = Key::Tweakable(id, pk);
        let string = tweakable.to_string();
        let unstring = Key::from_str(&string).expect("parsing tweakable key");
        assert_eq!(unstring, tweakable);

        let untweak = Key::Untweakable(pk);
        let string = untweak.to_string();
        println!("string {}", string);
        let unstring = Key::from_str(&string).expect("parsing untweakable key");
        assert_eq!(unstring, untweak);

        let nonfunc = Key::NonFunctionary(pk);
        let string = nonfunc.to_string();
        println!("string {}", string);
        let unstring = Key::from_str(&string).expect("parsing nonfunc key");
        assert_eq!(unstring, nonfunc);

        let tweaked = tweakable.p2c(&secp256k1::Secp256k1::new(), &[1, 2, 3]).unwrap();
        let string = tweaked.to_string();
        println!("string {}", string);
        let unstring = Key::from_str(&string).expect("parsing tweaked key");
        assert_eq!(unstring, tweaked);

        let tweaked_nonfunc = nonfunc.p2c(&secp256k1::Secp256k1::new(), &[1, 2, 3]).unwrap();
        let string = tweaked_nonfunc.to_string();
        println!("string {}", string);
        let unstring = Key::from_str(&string).expect("parsing tweaked key");
        assert_eq!(unstring, tweaked_nonfunc);
    }

    #[test]
    fn tweak_string_bad_parse() {
        let err_str = Key::from_str(
            "[untweaked] 02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
        ).unwrap_err().to_string();
        assert_eq!(err_str, "parse failed: invalid hex character");

        let err_str = Key::from_str(
            "[untweaked]033333333333333333333333333333333333333333333333333333333333333322"
        ).unwrap_err().to_string();
        assert_eq!(err_str, "parse failed: invalid key");

        let err_str = Key::from_str(
            "[abcd]033333333333333333333333333333333333333333333333333333333333333333"
        ).unwrap_err().to_string();
        assert_eq!(err_str, "parse failed: script key with bad length");

        let err_str = Key::from_str(
            "[abcd]00000033333333333333333333333333333333333333333333333333333333333333333"
        ).unwrap_err().to_string();
        assert_eq!(err_str, "parse failed: bad key");

        let err_str = Key::from_str(
            "[untweeked]033333333333333333333333333333333333333333333333333333333333333333"
        ).unwrap_err().to_string();
        assert_eq!(err_str, "parse failed: bad key");

        let err_str = Key::from_str(
            "[untweakedXXX]033333333333333333333333333333333333333333333333333333333333333333"
        ).unwrap_err().to_string();
        assert_eq!(err_str, "parse failed: bad peer id");

        let err_str = Key::from_str(
            "[abcdef1234XX]033333333333333333333333333333333333333333333333333333333333333333"
        ).unwrap_err().to_string();
        assert_eq!(err_str, "parse failed: bad peer id");

        Key::from_str(
            "[abcdef123456]033333333333333333333333333333333333333333333333333333333333333333"
        ).unwrap();
    }

    #[test]
    fn test_roundtrip() {
        // create a descriptor with all the different variants of the tweak::Key type
        let mut rng = rand::thread_rng();
        let secp = secp256k1::Secp256k1::new();
        let dummy = Descriptor::<String>::from_str(
            "wsh(multi(2,Tweakable,Tweaked,TweakedNonFunc,Untweakable,NonFunctionary))",
        ).unwrap();
        let desc = dummy.translate_pk::<_, _, ()>(
            |s| {
                let key = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));
                let pid = peer::Id::from(key.clone());
                let tweak = Tweak::some(&sha256::Hash::hash(&pid[..]).into_inner()[..]);
                Ok(match s.as_str() {
                    "Tweakable" => Key::Tweakable(pid, key),
                    "Tweaked" => Key::Tweaked { peer: pid, tweaked_pk: key, tweak: tweak },
                    "TweakedNonFunc" => Key::TweakedNonFunc { tweaked_pk: key, tweak: tweak },
                    "Untweakable" => Key::Untweakable(key),
                    "NonFunctionary" => Key::NonFunctionary(key),
                    _ => panic!("variant '{}' not handled", s),
                })
            },
            |_hash| unimplemented!(),
        ).unwrap();

        // test that it roundtrips
        let s = desc.to_string();
        let decoded = Descriptor::<Key>::from_str(&s).unwrap();
        assert_eq!(decoded, desc);

        // then re-serialize simplified to make sure the types were kept
        // and also to have a match case over the variants to this test will
        // be added to when a new variant would be introduced
        let redummied = desc.translate_pk::<_, _, ()>(
            |key| Ok(match key {
                Key::Tweakable(_, _) => "Tweakable",
                Key::Tweaked { .. } => "Tweaked",
                Key::TweakedNonFunc { .. } => "TweakedNonFunc",
                Key::Untweakable(_) => "Untweakable",
                Key::NonFunctionary(_) => "NonFunctionary",
            }.to_owned()),
            |_hash| unimplemented!(),
        ).unwrap();
        assert_eq!(dummy, redummied);
    }
}

