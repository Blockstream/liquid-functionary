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


//! # Configuration
//! Support for parsing .toml configuration files
//!

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::PrivateKey;
use bitcoin::secp256k1::{SecretKey, PublicKey};
use miniscript::{Descriptor, TranslatePk};
use serde::{Deserialize, Deserializer};
use descriptor::{LiquidDescriptor, LiquidSanityCheck, SpendableDescriptor};

use peer;
use tweak;

/// Helper function to deserialize HSM sockets, which are expected
/// to be either a string or a boolean false
pub fn deserialize_hsm_socket<'de, D: Deserializer<'de>>(d: D)
    -> Result<Option<String>, D::Error>
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Socket { Present(bool), Named(String) }

    use serde::de::Error;

    match Socket::deserialize(d)? {
        Socket::Named(s) => Ok(Some(s)),
        Socket::Present(false) => Ok(None),
        Socket::Present(true) => Err(
            D::Error::custom("hsm_socket may not be «true»")
        ),
    }
}

/// Helper function to deserialize base58-encoded secret keys
pub fn deserialize_secret_key<'de, D: Deserializer<'de>>(d: D)
    -> Result<SecretKey, D::Error>
{
    use serde::de::Error;

    let s = String::deserialize(d)?;
    match PrivateKey::from_str(&s) {
        Ok(key) if key.compressed => Ok(key.inner),
        Ok(..) => Err(D::Error::custom("uncompressed keys are not allowed")),
        Err(e) => Err(D::Error::custom(e)),
    }
}

/// Helper function to deserialize base58-encoded secret keys.
/// Will also accept the literal `false` as a synonym for not being present
pub fn deserialize_secret_key_opt<'de, D: Deserializer<'de>>(d: D)
    -> Result<Option<SecretKey>, D::Error>
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Key { Present(bool), Named(Option<String>) }

    use serde::de::Error;

    match Key::deserialize(d)? {
        Key::Named(Some(s)) => {
            match PrivateKey::from_str(&s) {
                Ok(key) if key.compressed => Ok(Some(key.inner)),
                Ok(..) => Err(D::Error::custom("uncompressed keys are not allowed")),
                Err(e) => Err(D::Error::custom(e)),
            }
        },
        Key::Named(None) => Ok(None),
        Key::Present(false) => Ok(None),
        Key::Present(true) => Err(
            D::Error::custom("secret key may not be «true»")
        ),
    }
}

/// Helper function to deserialize hex-encoded ECIES blob
/// that is implemented in the HSM.
pub fn deserialize_ecies_blob<'de, D: Deserializer<'de>>(d: D)
    -> Result<Vec<u8>, D::Error>
{
    use serde::de::Error;

    let s = String::deserialize(d)?;

    use bitcoin::hashes::hex::FromHex;
    match Vec::<u8>::from_hex(&s) {
        Ok(ref data) if data.len() != 161 => Err(D::Error::custom("incorrect length")),
        Ok(data) => Ok(data),
        Err(e) => Err(D::Error::custom(e)),
    }
}

/// Helper function to deserialize durations encoded as milliseconds
pub fn deserialize_duration_ms<'de, D: Deserializer<'de>>(d: D)
    -> Result<Duration, D::Error>
{
    let ms = u64::deserialize(d)?;
    Ok(Duration::from_millis(ms))
}

/// Helper function to deserialize hex-encoded bitcoin::Transactions
pub fn deserialize_hex_bitcoin_tx<'de, D: Deserializer<'de>>(d: D)
                                                            -> Result<bitcoin::Transaction, D::Error>
{
    use serde::de::Error;

    let s = String::deserialize(d)?;

    use bitcoin::hashes::hex::FromHex;
    use bitcoin::consensus::Decodable;

    let tx_bytes = Vec::<u8>::from_hex(s.as_str())
        .map_err(|e| Error::custom(e))?;
    let tx = bitcoin::Transaction::consensus_decode(tx_bytes.as_slice())
        .map_err(|e| Error::custom(e))?;
    Ok(tx)
}

/// Helper function to serialize bitcoin::Transactions to a hex blob
pub fn serialize_bitcoin_tx_hex<S: serde::Serializer>(tx: &bitcoin::Transaction, s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::hex::ToHex;

    let mut tx_bytes: Vec<u8> = Vec::new();
    tx.consensus_encode(&mut tx_bytes).map_err(|e| Error::custom(e))?;

    s.collect_str(&tx_bytes.to_hex())
}

/// Helper function to translate a stringly-typed descriptor into
/// one with tweakable keys. Assumed to be called only on startup,
/// so it will panic on failure.
///
/// Also does sanity checks on the descriptor, which would preferably
/// have been done during deserialization, but there isn't an easy way
/// to hook into the serde pipeline to do that.
pub fn translate_descriptor(
    descriptor: &miniscript::Descriptor<String>,
    mut find_key: impl FnMut(&str) -> Option<(peer::Id, PublicKey)>,
) -> miniscript::Descriptor<tweak::Key> {
    let mut dupe_map = HashMap::new();

    let mut res = descriptor.translate_pk::<_, _, ()>(
        |key| {
            if let Ok(pk) = PublicKey::from_str(key) {
                Ok(tweak::Key::Untweakable(pk))
            } else {
                if let Some((peer_id, signing_key)) = find_key(key) {
                    // Store the whole key in the duplicate map, and link to its
                    // name, so we can provide a more helpful error message when
                    // sort-checking below
                    if dupe_map.insert(signing_key, key.to_owned()).is_none() {
                        log!(Debug, "inserted functionary/key «{}» ({}) in {}", key, signing_key, descriptor);
                        Ok(tweak::Key::Tweakable(peer_id, signing_key))
                    } else {
                        panic!("duplicate functionary/key «{}» ({}) in {}", key, signing_key, descriptor)
                    }
                } else {
                    panic!("unrecognized functionary/key «{}» in {}", key, descriptor)
                }
            }
        },
        |_hash| unimplemented!(),
    ).expect(&format!("parse keys in descriptor {}", descriptor));

    if let Some((_, _, keys)) = res.legacy_liquid_descriptor_components() {
        // In legacy applications we enforce the key ordering
        let mut keys_sorted = keys.clone();
        // nb `keys_sorted.sort()` does not do the right thing, which arguably is a rust-bitcoin bug
        keys_sorted.sort_by_cached_key(|key| key.serialize().to_vec());
        if keys != keys_sorted {
            // If there is an order mismatch, construct a correctly-ordered descriptor
            // so we can output this to the user, saving them the time of hex-sorting
            // the keys themselves.
            //
            // We use Descriptor::translate_pk for this; for each key, we look up its
            // index in the unsorted array, use the same index in the sorted array,
            // and return that key
            let resorted = descriptor.translate_pk::<_, _, ()>(
                |peer_name| {
                    if PublicKey::from_str(peer_name).is_ok() {
                        Ok(peer_name.to_owned())
                    } else {
                        let peer_key = find_key(peer_name).unwrap().1;
                        let kpos = keys.iter().position(|targ| *targ == peer_key).unwrap();
                        let new_peer_key = keys_sorted[kpos];
                        Ok(dupe_map.remove(&new_peer_key).unwrap())
                    }
                },
                |_hash| unimplemented!(),
            ).expect(&format!("reordering descriptor {}", descriptor));
            slog!(BadDescriptorOrder, bad_descriptor: descriptor.to_string(), reordered: resorted.to_string());
        }
    } else {
        // Outside of legacy applications (i.e. post-dynafed), all `Untweakable`
        // keys should actually be `NonFunctionary` keys
        res = res.translate_pk::<_, _, ()>(
            |key| match *key {
                tweak::Key::Untweakable(k) => Ok(tweak::Key::NonFunctionary(k)),
                x => Ok(x),
            },
            |_hash| unimplemented!(),
        ).expect("marking non-functionary keys as tweakable");
    }

    res
}

/// Configuration settings just for initializing HSM
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct InitHSM {
    /// Verbosity level of the logging syste
    pub log_level: logs::Severity,
    /// Path to a UNIX socket used to communicate with the HSM
    pub hsm_socket: String,
    /// User key to use in initializing the HSM, in base58
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_secret_key_opt")]
    pub user_key: Option<SecretKey>,
    /// DANGEROUS: Enable reinitializing an already-used HSM
    #[serde(default)]
    pub force_reinit_flag: bool,
    /// DANGEROUS: DEBUG_ONLY: used to restore an hsm from an already
    /// known keypair (like replacing a stub with a real hsm)
    #[serde(default)]
    pub plaintext_key_flag: bool,
    /// Restore backup keys onto an HSM: blocksign key in base58.
    /// Both restore_key options must be given together.
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_secret_key_opt")]
    pub blocksign_restore_key: Option<SecretKey>,
    /// Restore backup keys onto an HSM: watchman key in base58.
    /// Both restore_key options must be given together.
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_secret_key_opt")]
    pub watchman_restore_key: Option<SecretKey>,
    /// Restore encrypted backup keys onto an HSM. Payload is
    /// in hex. This is a replacement for blocksign_restore_key
    /// and watchman_restore_key
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_ecies_blob")]
    pub encrypted_restore_blob: Vec<u8>,
}


/// Perform various sanity checks on the watchman descriptors.
pub fn wm_desc_sanity_check(
    descriptors: impl Iterator<Item = Descriptor<tweak::Key>> + Clone
) -> Result<(), String> {
    let mut iter = descriptors.enumerate().peekable();

    // Can't be empty.
    if iter.peek().is_none() {
        return Err(format!("must have at least one CPE"));
    }

    // The first descriptor must be p2shwsh.
    let first = iter.peek().unwrap().1.clone();
    if first.desc_type() !=  miniscript::descriptor::DescriptorType::ShWsh {
        return Err(format!("first descriptor must have type p2shwsh"))
    }

    while let Some((i, desc)) = iter.next() {
        // Perform general sanity checks on each watchman descriptor.
        desc.liquid_sanity_check()?;

        if desc != first {
            if desc.desc_type() != miniscript::descriptor::DescriptorType::Wsh {
                return Err(format!("wm descriptor #{}: subsequent descriptors must have type p2wsh", i).into());
            }
        }

        // Make sure we never transition to a federation which cannot spend existing UTXOs
        if let Some((_, next)) = iter.peek() {
            if !next.can_spend(&desc) {
                return Err(format!(
                    "wm descriptor #{} unable to spend UTXOs from wm descriptor #{}", i, i + 1
                ));
            }
        }
    }

    Ok(())
}
