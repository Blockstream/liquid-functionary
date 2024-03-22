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

use bitcoin::PrivateKey;
use bitcoin::secp256k1::{SecretKey, PublicKey};
use miniscript::{Descriptor, TranslatePk, Translator, translate_hash_fail};
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

/// Helper function to deserialize hex-encoded bitcoin::Transactions
pub fn deserialize_hex_bitcoin_tx<'de, D: Deserializer<'de>>(d: D)
                                                            -> Result<bitcoin::Transaction, D::Error>
{
    use serde::de::Error;

    let s = String::deserialize(d)?;

    use bitcoin::hashes::hex::FromHex;
    use bitcoin::consensus::encode::deserialize;

    let tx_bytes = Vec::<u8>::from_hex(&s).map_err(|e| Error::custom(e))?;
    let tx: bitcoin::Transaction = deserialize(&tx_bytes).map_err(|e| Error::custom(e))?;
    Ok(tx)
}

/// Helper function to serialize bitcoin::Transactions to a hex blob
pub fn serialize_bitcoin_tx_hex<S: serde::Serializer>(tx: &bitcoin::Transaction, s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;
    use bitcoin::consensus::Encodable;
    use bitcoin::hex::DisplayHex;

    let mut tx_bytes: Vec<u8> = Vec::new();
    tx.consensus_encode(&mut tx_bytes).map_err(|e| Error::custom(e))?;

    s.collect_str(&tx_bytes.as_hex())
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

    struct KeyTranslator<'a, F> where F: FnMut(&str) -> Option<(peer::Id, PublicKey)> {
        find_key: &'a mut F,
        dupe_map: &'a mut HashMap<PublicKey, String>,
        descriptor: &'a miniscript::Descriptor<String>,
    }

    impl<'a, F> Translator<String, tweak::Key, ()> for KeyTranslator<'a, F>
    where
        F: FnMut(&str) -> Option<(peer::Id, PublicKey)>,
    {
        fn pk(&mut self, pk: &String) -> Result<tweak::Key, ()> {
            if let Ok(pk) = PublicKey::from_str(pk) {
                Ok(tweak::Key::Untweakable(pk))
            } else {
                if let Some((peer_id, signing_key)) = (self.find_key)(pk) {
                    // Store the whole key in the duplicate map, and link to its
                    // name, so we can provide a more helpful error message when
                    // sort-checking below
                    if self.dupe_map.insert(signing_key, pk.to_owned()).is_none() {
                        log!(Debug, "inserted functionary/key «{}» ({}) in {}", pk, signing_key, self.descriptor);
                        Ok(tweak::Key::Tweakable(peer_id, signing_key))
                    } else {
                        panic!("duplicate functionary/key «{}» ({}) in {}", pk, signing_key, self.descriptor)
                    }
                } else {
                    panic!("unrecognized functionary/key «{}» in {}", pk, self.descriptor)
                }
            }
        }

        // We don't need to implement these methods as we are not using them in the policy.
        // Fail if we encounter any hash fragments. See also translate_hash_clone! macro.
        translate_hash_fail!(String, tweak::Key, ());
    }

    let mut pk_translator = KeyTranslator {
        find_key: &mut find_key,
        dupe_map: &mut dupe_map,
        descriptor: &descriptor,
    };

    let mut res = descriptor.translate_pk::<_, _>(
        &mut pk_translator
    ).expect(&format!("parse keys in descriptor {}", descriptor));

    if let Some((_, _, keys)) = res.legacy_liquid_descriptor_components() {
        // In legacy applications we enforce the key ordering
        let mut keys_sorted = keys.clone();
        // nb `keys_sorted.sort()` does not do the right thing, which arguably is a rust-bitcoin bug
        keys_sorted.sort_by_cached_key(|key| key.serialize().to_vec());
        if keys != keys_sorted {

            struct ResortTranslator<'a, F> where F: FnMut(&str) -> Option<(peer::Id, PublicKey)> {
                find_key: &'a mut F,
                dupe_map: &'a mut HashMap<PublicKey, String>,
                keys: &'a [PublicKey],
                keys_sorted: &'a [PublicKey],
            }


            impl<'a, F> Translator<String, String, ()> for ResortTranslator<'a, F>
            where
                F: FnMut(&str) -> Option<(peer::Id, PublicKey)>,
            {
                fn pk(&mut self, pk: &String) -> Result<String, ()> {
                    if PublicKey::from_str(pk).is_ok() {
                        Ok(pk.clone())
                    } else {
                        let peer_key = (self.find_key)(pk).unwrap().1;
                        let kpos = self.keys.iter().position(|targ| *targ == peer_key).unwrap();
                        let new_peer_key = self.keys_sorted[kpos];
                        Ok(self.dupe_map.remove(&new_peer_key).unwrap())
                    }
                }

                translate_hash_fail!(String, String, ());
            }
            // If there is an order mismatch, construct a correctly-ordered descriptor
            // so we can output this to the user, saving them the time of hex-sorting
            // the keys themselves.
            //
            // We use Descriptor::translate_pk for this; for each key, we look up its
            // index in the unsorted array, use the same index in the sorted array,
            // and return that key
            let mut translator = ResortTranslator {
                find_key: &mut find_key,
                dupe_map: &mut dupe_map,
                keys: &keys,
                keys_sorted: &keys_sorted,
            };
            let resorted = descriptor.translate_pk::<_, _>(
                &mut translator
            ).expect(&format!("reordering descriptor {}", descriptor));
            slog!(BadDescriptorOrder, bad_descriptor: descriptor.to_string(), reordered: resorted.to_string());
        }
    } else {
        struct TweakTranslator;

        impl Translator<tweak::Key, tweak::Key, ()> for TweakTranslator {
            fn pk(&mut self, key: &tweak::Key) -> Result<tweak::Key, ()> {
                match key {
                    tweak::Key::Untweakable(k) => Ok(tweak::Key::NonFunctionary(*k)),
                    x => Ok(*x),
                }
            }

            translate_hash_fail!(tweak::Key, tweak::Key, ());
        }

        let mut translator = TweakTranslator;

        // Outside of legacy applications (i.e. post-dynafed), all `Untweakable`
        // keys should actually be `NonFunctionary` keys
        res = res.translate_pk::<_, _>(
            &mut translator
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
