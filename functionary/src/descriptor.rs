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

//! # Descriptors
//!
//! Liquid-specific tooling for managing output descriptors
//!

// This file exists because the Liquid production script pre-dates Miniscript,
// and therefore is not compatible with rust-miniscript or any other Miniscript tooling.
// Further, the script is not as efficient as the best Miniscript version we found
// (something the Miniscript authors are quite proud of, given that the Liquid prod
// script was heavily hand-optimized and used a novel trick).
// This is a problem because Miniscript was developed, among other things, to work in
// the functionary software.

// Miniscript is needed to:
// - compute maximum spend sizes, for fee estimation
// - construct optimal witnesses from an unordered set of signatures
// - allow the "watchman script" to be written in a human-understandable/editable form
// - (with some hacks) do the same for the blocksigner
// - Do some sanity checks, e.g. that we actually have a 2/3 threshold policy at time 0
// - Do all of the above, even with dynafed changing scripts out from under us
// - Do the dynafed-essential check that any new watchman script be spendable by the old
//   federation

// In other words, avoiding Miniscript is not an option. Moving to Miniscript saved us
// 1000s of lines of code, fixed some bugs, and gave us functionality (dynafed) that we
// otherwise couldn’t get. However we have a deployed system using this non-miniscript
// script and we need to support it somehow.

// As it turns out, our non-miniscript script has the same witness as the Miniscript
// `or_c(thresh_m(N, pks...), ...)`, at least when spending from the `thresh_m` branch.
// Further, this Miniscript would never be used in real production since a more
// efficient variant exists. Therefore, to handle the Liquid production case, we put
// this Miniscript into our config file, and in this source file we modify its encoding
// in Bitcoin Script (and the corresponding weights, derived address, etc) to match the
// production Liquid script rather than the correct Miniscript output. We leave all the
// witness-related logic alone.

// The result is that rust-miniscript thinks it is working with a certain kind of Miniscript,
// but actually it is working with a custom non-Miniscript legacy Liquid thing. This is
// guaranteed to work by the definition of `or_c`. So while it is a highly specific hack,
// it will not break in the future, and in any case, after a few watchman dynafed transitions
// we will be able to transition away from this entirely and forget it ever existed.

// Separately, Liquid production has a bug whereby the CSV value enforced for the Liquid script
// by the (non-field-upgradable) HSM did not match the CSV value configured in the network setup.
// However, as it turns out, the HSM only enforces this CSV value for change outputs, while the
// network logic only enforces CSV values for pegin outputs. So conveniently there is no direct
// conflict, provided that we treat change and pegins as using different legacy scripts.

// This is accomplished by the `csv_tweaked_descriptor` method which simply subs out one
// CSV value for another, for use in constructing change outputs for watchman transactions.
use std::{fmt, iter, ops};
use std::collections::HashSet;
use std::str::FromStr;

use bitcoin::ScriptBuf;
use bitcoin::blockdata::script;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};
use miniscript::{Descriptor, Miniscript, MiniscriptKey, TranslatePk, Translator, translate_hash_fail};
use miniscript::descriptor::{DescriptorType, ShInner, WshInner};
use miniscript::miniscript::decode::Terminal;
use miniscript::policy::{Liftable, Semantic};

use common::{BlockHeight, PeerId};
use tweak;

/// Trait to perform the descriptor sanity checks for use as a federation descriptor.
///
/// Currently this includes:
/// - must be of type p2wsh or p2shwsh
/// - at age 0, the descriptor must be a threshold
///   - of 2 out of 3 or stricter
///   - without any key used twice
pub trait LiquidSanityCheck {
    /// Perform the sanity check. See trait docs for more info.
    fn liquid_sanity_check(&self) -> Result<(), String>;
}

impl<P> LiquidSanityCheck for Descriptor<P>
where
    P: miniscript::MiniscriptKey<Sha256 = P, Hash256 = P, Ripemd160 = P, Hash160 = P>
        + fmt::Display + Eq + std::hash::Hash,
{
    fn liquid_sanity_check(&self) -> Result<(), String> {
        let tp = self.desc_type();
        match tp {
            DescriptorType::ShWsh | DescriptorType::Wsh => {},
            _ => return Err(format!(
                "invalid descriptor type: {:?}, only p2shwsh and p2wsh is allowed", tp,
            )),
        }

        let lifted = self.lift().map_err(|e| format!("can't lift descriptor: {}", e))?;
        match lifted.at_age(bitcoin::Sequence(0)) {
            miniscript::policy::Semantic::Threshold(k, subs) => {
                if k * 3 < subs.len() * 2 {
                    return Err(format!(
                        "Threshold {}/{} in descriptor is below 2/3", k, subs.len(),
                    ));
                }

                // check that all subs are keys and that there are no duplicates
                let mut keys = HashSet::with_capacity(subs.len());
                for semantic in &subs {
                    let key = match semantic {
                        Semantic::Key(key) => key,
                        s => return Err(format!("invalid policy inside threshold: {:?}", s)),
                    };
                    if !keys.insert(key) {
                        return Err(format!("duplicate key: {}", key));
                    }
                }
            },
            miniscript::policy::Semantic::Key(_) => {
                log!(Info, "Descriptor is for a network with a single signer");
            },
            _ => {
                panic!("valid liquid policies have a threshold at age 0");
            }
        }

        Ok(())
    }
}

/// Trait extending Miniscript to serialize as Script in a way that is
/// consensus-compatible with the production Liquid network
///
/// All the methods in this trait assume that the implementor passes the
/// sanity check of [LiquidSanityCheck].
pub trait LiquidDescriptor {
    /// Determines whether a given output descriptor represents the
    /// legacy Liquid network policy
    fn is_legacy_liquid_descriptor(&self) -> bool {
        self.legacy_liquid_descriptor_components().is_some()
    }

    /// Internal-use function which extracts the parts of the Liquid legacy
    /// descriptor needed to reconstruct the corresponding Script to match
    /// the deployed network (which Miniscript cannot produce directly)
    fn legacy_liquid_descriptor_components(&self)
        -> Option<(
            ScriptBuf,
            usize,
            Vec<PublicKey>,
        )>;

    /// Replacement for `Descriptor::witness_script` that hacks up scripts
    /// of a certain form to match Liquid prod
    fn liquid_witness_script(&self) -> ScriptBuf;

    /// Replacement for `Descriptor::script_pubkey` that hacks up scripts
    /// of a certain form to match the untweaked Liquid prod address
    fn liquid_script_pubkey(&self) -> ScriptBuf;

    /// Replacement for `Descriptor::address` that hacks up scripts
    /// of a certain form to match the untweaked Liquid prod address
    fn liquid_address_net(&self, net: bitcoin::Network) -> bitcoin::Address;

    /// Shorthand for [liquid_address_net] using mainnet.
    fn liquid_address(&self) -> bitcoin::Address {
        self.liquid_address_net(bitcoin::Network::Bitcoin)
    }

    /// The first nonzero locktime that affects the descriptor, if any
    fn csv_expiry(&self) -> Option<BlockHeight>;

    /// The number of signatures required to satisfy the script at time 0
    fn n_signatures(&self) -> usize;

    /// The weight of the scriptSig and input witness needed for this descriptor
    fn satisfaction_weight(&self) -> usize;

    /// The weight of a single TxIn that spends this descriptor.
    fn signed_input_weight(&self) -> usize {
        // txid:vout and sequence have 160 weight
        self.satisfaction_weight() + 160
    }

    /// Takes a descriptor that matches the Liquid prod template and replaces
    /// the CSV of 4032 with 2016.
    fn csv_tweaked_descriptor(&self) -> Self;
}

impl<P> LiquidDescriptor for Descriptor<P>
where
    P: Clone + miniscript::ToPublicKey + FromStr,
    P::Sha256: FromStr, P::Hash256: FromStr, P::Ripemd160: FromStr, P::Hash160: FromStr,
    <P as FromStr>::Err: fmt::Display,
    <P::Hash256 as FromStr>::Err: fmt::Display,
    <<P as MiniscriptKey>::Sha256 as FromStr>::Err: ToString,
    <<P as MiniscriptKey>::Ripemd160 as FromStr>::Err: ToString,
    <<P as MiniscriptKey>::Hash160 as FromStr>::Err: ToString
{
    fn legacy_liquid_descriptor_components(&self) -> Option<(ScriptBuf, usize, Vec<PublicKey>)> {
        use bitcoin::blockdata::opcodes;

        let ms = inner_sh_wsh_miniscript(self)?;
        let (left, right) = match ms.node {
            Terminal::OrD(ref left, ref right) => (left, right),
            _ => return None,
        };
        let (threshold, keys) = match &left.node {
            Terminal::Multi(threshold, keys) => (threshold, keys),
            _ => return None,
        };

        let lser = left.node.encode(script::Builder::new()).into_script();
        let mut rser = right.node.encode(script::Builder::new()).into_script().into_bytes();
        // ...and the rightmost "..." ends in OP_CHECKMULTISIG
        if lser.as_bytes()[lser.len() - 1] == rser[rser.len() - 1] {
            // ...and we have an OP_VERIFY style checksequenceverify, which in
            // Liquid production was encoded with OP_DROP instead...
            if rser[4] == opcodes::all::OP_VERIFY.to_u8() {
                rser[4] = opcodes::all::OP_DROP.to_u8();
                // ...then we should serialize it by sharing the OP_CMS across
                // both branches, and add an OP_DEPTH check to distinguish the
                // branches rather than doing the normal cascade construction
                Some((
                    ScriptBuf::from(rser),
                    *threshold,
                    keys.iter()
                        .map(|k| k.to_public_key().inner)
                        .collect(),
                ))
            } else {
                None
            }
        } else {
            None
        }
    }

    fn liquid_witness_script(&self) -> ScriptBuf {
        use bitcoin::blockdata::opcodes;

        if let Some((rser, threshold, keys)) = self.legacy_liquid_descriptor_components() {
            let mut builder = script::Builder::new()
                .push_opcode(opcodes::all::OP_DEPTH)
                .push_int(threshold as i64 + 1)
                .push_opcode(opcodes::all::OP_EQUAL)
                .push_opcode(opcodes::all::OP_IF)
                // manually serialize the left CMS branch, without the OP_CMS
                .push_int(threshold as i64);
            for key in &keys {
                builder = builder.push_key(&bitcoin::PublicKey {
                    inner: key.clone(),
                    compressed: true,
                });
            }
            let mut nearly_done = builder
                .push_int(keys.len() as i64)
                .push_opcode(opcodes::all::OP_ELSE)
                .into_script()
                .to_bytes();
            // Manually jam an OP_ENDIF before the final OP_CMS
            nearly_done.extend(rser.into_bytes());
            let insert_point = nearly_done.len() - 1;
            nearly_done.insert(insert_point, 0x68);
            ScriptBuf::from(nearly_done)
        } else {
            self.explicit_script().expect("witness script")
        }
    }

    fn liquid_script_pubkey(&self) -> ScriptBuf {
        if let Descriptor::Sh(sh) = self {
            if let &ShInner::Wsh(..)= sh.as_inner() {
                self.liquid_witness_script().to_p2wsh().to_p2sh()
            } else {
                self.script_pubkey()
            }
        } else {
            self.script_pubkey()
        }
    }

    fn liquid_address_net(&self, net: bitcoin::Network) -> bitcoin::Address {
        if let Descriptor::Sh(sh) = self {
            if let &ShInner::Wsh(..) = sh.as_inner() {
                bitcoin::Address::p2shwsh(&self.liquid_witness_script(), net)
            } else {
                self.address(net).expect("Liquid does not support bare descriptors")
            }
        } else {
            self.address(net).expect("Liquid does not support bare descriptors")
        }
    }

    fn csv_expiry(&self) -> Option<BlockHeight> {
        let timelocks = self.lift().expect("descriptor can lift").relative_timelocks();
        if timelocks.is_empty() {
            None
        } else {
            Some(timelocks[0] as BlockHeight)
        }
    }

    fn n_signatures(&self) -> usize {
        self.lift().expect("descriptor can lift")
            .at_age(bitcoin::Sequence(0))
            .minimum_n_keys().expect("policy to satisfy")
    }

    #[allow(deprecated)]
    fn satisfaction_weight(&self) -> usize {
        let offset = if self.is_legacy_liquid_descriptor() {
            2 // two wasted bytes in witness script
        } else {
            0
        };

        // This must be updated to the new `max_weight_to_satisfy` method during the new dynafed transition as per
        // https://gl.blockstream.io/liquid/functionary/-/issues/1340
        // When this is update remove the `#[allow(deprecated)]` above
        offset + self.max_satisfaction_weight().unwrap()
    }

    fn csv_tweaked_descriptor(&self) -> Descriptor<P> {
        let ms = if let Some(ms) = inner_sh_wsh_miniscript(self) {
            ms
        } else {
            return self.clone();
        };
        let (left, right) = match ms.node {
            Terminal::OrD(ref left, ref right) => (left, right),
            _ => return self.clone(),
        };
        let (land, rand) = match (&left.node, &right.node) {
            (&Terminal::Multi(..), &Terminal::AndV(ref land, ref rand)) => (land, rand),
            _ => return self.clone(),
        };
        let land_v = match land.node {
            Terminal::Verify(ref land_v) => land_v,
            _ => return self.clone(),
        };
        if land_v.node == Terminal::Older(bitcoin::Sequence(4032)) {
            let descriptor = format!("sh(wsh(or_d({},and_v(v:older(2016),{}))))", left, rand);
            Descriptor::<P>::from_str(&descriptor).unwrap()
        } else {
            self.clone()
        }
    }
}

/// Extract the inner Miniscript from a `sh(wsh(...))` descriptor.
fn inner_sh_wsh_miniscript<P: miniscript::ToPublicKey>(
    desc: &Descriptor<P>,
) -> Option<&Miniscript<P, miniscript::Segwitv0>> {
    if let Descriptor::Sh(ms) = desc {
        if let ShInner::Wsh(s) = ms.as_inner() {
            if let WshInner::Ms(ms) = s.as_inner() {
                Some(ms)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

/// An iterator over a set of functionary keys taken from a descriptor.
#[derive(Debug)]
pub struct FuncKeyIter {
    inner: std::vec::IntoIter<miniscript::policy::semantic::Policy<tweak::Key>>,
}

impl iter::Iterator for FuncKeyIter {
    type Item = tweak::Key;

    fn next(&mut self) -> Option<Self::Item> {
        if let miniscript::policy::Semantic::Key(pkh) = self.inner.next()? {
            Some(pkh)
        } else {
            panic!("valid liquid policies have keys in the threshold");
        }
    }
}

impl iter::FusedIterator for FuncKeyIter {}

/// Trait over descriptors using our internal [tweak::Key] type.
pub trait TweakableDescriptor {
    /// Tweak the descriptor with the hash of the given contract (p2c).
    fn tweak<C: secp256k1::Verification>(&self, secp: &Secp256k1<C>, contract: &[u8]) -> Self;

    /// Get an iterator over the functionary signers keys together with the
    /// signing threshold.
    ///
    /// This does not include keys in the emergency clause.
    fn iter_signing_keys_threshold(&self) -> (FuncKeyIter, usize);

    /// Get an iterator over the functionary signers keys.
    ///
    /// This does not include keys in the emergency clause.
    fn iter_signer_keys(&self) -> FuncKeyIter;

    /// Get the set of functionary signers.
    ///
    /// This does not include keys in the emergency clause.
    fn signers(&self) -> HashSet<PeerId>;

    /// Check whether the given set of signers can sign this descriptor.
    fn can_sign(&self, signers: &HashSet<PeerId>) -> bool;

    /// Translate this Descriptor's key from [tweak::Key] to [PublicKey]
    fn to_descriptor_publickey(&self) -> Descriptor<PublicKey>;
}

/// Translator that applies a pay-to-contract mapping to a key
pub struct TweakedKeyTranslator<'a, C: secp256k1::Verification> {
    secp: &'a Secp256k1<C>,
    contract: &'a [u8],
}

impl<'a, C: secp256k1::Verification> Translator<tweak::Key, tweak::Key, ()> for TweakedKeyTranslator<'a, C> {
    fn pk(&mut self, pk: &tweak::Key) -> Result<tweak::Key, ()> {
        pk.p2c(self.secp, &self.contract[..]).map_err(|_| ())
    }

    // We don't need to implement these methods as we are not using them in the policy.
    // Fail if we encounter any hash fragments. See also translate_hash_clone! macro.
    translate_hash_fail!(tweak::Key, tweak::Key, ());
}

/// Translator that maps tweak::Keys to PublicKeys
pub struct PublicKeyTranslator;

impl Translator<tweak::Key, PublicKey, ()> for PublicKeyTranslator {
    fn pk(&mut self, pk: &tweak::Key) -> Result<PublicKey, ()> {
        Ok(*pk.as_pubkey())
    }

    // We don't need to implement these methods as we are not using them in the policy.
    // Fail if we encounter any hash fragments. See also translate_hash_clone! macro.
    translate_hash_fail!(tweak::Key, PublicKey, ());
}

impl TweakableDescriptor for Descriptor<tweak::Key> {
    fn tweak<C: secp256k1::Verification>(&self, secp: &Secp256k1<C>, contract: &[u8]) -> Self {
        let mut translator = TweakedKeyTranslator {
            secp: secp,
            contract: contract
        };
        self.translate_pk(&mut translator).unwrap()
    }

    fn iter_signing_keys_threshold(&self) -> (FuncKeyIter, usize) {

        let policy = self.lift().expect("valid liquid policies are liftable").at_age(bitcoin::Sequence(0));

        match policy {
            miniscript::policy::Semantic::Threshold(k, subs) => {
                let iter = FuncKeyIter {
                    inner: subs.into_iter(),
                };
                (iter, k)
            },
            miniscript::policy::Semantic::Key(key) => {
                let iter = FuncKeyIter {
                    inner: vec![Semantic::Key(key)].into_iter().into(),
                };
                (iter, 1)
            },
            _ => {
                panic!("valid liquid policies have a threshold at age 0");
            }
        }
    }

    fn iter_signer_keys(&self) -> FuncKeyIter {
        self.iter_signing_keys_threshold().0
    }

    fn signers(&self) -> HashSet<PeerId> {
        self.iter_signer_keys().map(|key| {
            key.peer_id().expect("valid liquid policies have functionary keys in threshold")
        }).collect()
    }

    fn can_sign(&self, signers: &HashSet<PeerId>) -> bool {
        let (keys, mut threshold) = self.iter_signing_keys_threshold();
        for key in keys {
            let peer = key.peer_id().expect("keys in threshold are funcs");
            if signers.contains(&peer) {
                threshold -= 1;
                if threshold == 0 {
                    return true;
                }
            }
        }
        false
    }

    fn to_descriptor_publickey(&self) -> Descriptor<PublicKey> {
        let mut translator = PublicKeyTranslator;
        self.translate_pk(&mut translator).unwrap()
    }
}

/// Trait for computing whether a descriptor can spend another descriptor
pub trait SpendableDescriptor {
    /// Can these params spend UTXOs owned by the federation with the provided CPE.
    fn can_spend(&self, other: &Self) -> bool;
}

impl SpendableDescriptor for Descriptor<tweak::Key> {
    fn can_spend(&self, other: &Self) -> bool {
        let threshold = match other.lift().unwrap().at_age(bitcoin::Sequence(0)) {
            miniscript::policy::Semantic::Threshold(t, _) => t,
            miniscript::policy::Semantic::Key(_) => 1,
            ref other_policy => panic!("descriptor policy «{:?}» at time 0 is not a multisig", other_policy)
        };

        let signers = self.signers();
        let other_signers = other.signers();

        let count = signers.iter().filter(|&signer| other_signers.contains(&signer)).count();
        count >= threshold
    }
}

/// Cached descriptor data
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(from = "miniscript::Descriptor<tweak::Key>")]
#[serde(into = "miniscript::Descriptor<tweak::Key>")]
pub struct Cached {
    /// Inner descriptor for watchman-owned coins
    pub inner: Descriptor<tweak::Key>,
    /// witnessScript for the descriptor
    pub witness_script: ScriptBuf,
    /// scriptPubKey for the descriptor
    pub spk: ScriptBuf,
    /// Minimum number of signatures we need to combine to sign a transaction
    pub n_required_sigs: usize,

    /// CSV-tweaked descriptor for watchman-owned coins
    pub csv_tweaked: Option<Descriptor<tweak::Key>>,
    /// witnessScript for the CSV-tweaked descriptor
    pub csv_tweaked_witness_script: Option<ScriptBuf>,
    /// scriptPubKey for the CSV-tweaked descriptor
    pub csv_tweaked_spk: Option<ScriptBuf>,
}

impl Cached {
    /// Same as [matches], but returns the descriptor,
    /// regular or tweaked, that was matched.
    pub fn matches(&self, spk: &ScriptBuf) -> Option<&Descriptor<tweak::Key>> {
        if *spk == self.spk {
            Some(&self.inner)
        } else if self.csv_tweaked_spk.as_ref().map(|s| s == spk).unwrap_or(false) {
            Some(&self.csv_tweaked.as_ref().unwrap())
        } else {
            None
        }
    }
}

impl ops::Deref for Cached {
    type Target = Descriptor<tweak::Key>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<Descriptor<tweak::Key>> for Cached {
    fn from(d: Descriptor<tweak::Key>) -> Cached {
        let tweaked = if d.is_legacy_liquid_descriptor() {
            Some(d.csv_tweaked_descriptor())
        } else {
            None
        };

        Cached {
            spk: d.liquid_script_pubkey(),
            witness_script: d.liquid_witness_script(),
            n_required_sigs: d.n_signatures(),
            inner: d,

            csv_tweaked_spk: tweaked.as_ref().map(|d| d.liquid_script_pubkey()),
            csv_tweaked_witness_script: tweaked.as_ref().map(|d| d.liquid_witness_script()),
            csv_tweaked: tweaked,
        }
    }
}

impl From<Cached> for Descriptor<tweak::Key> {
    fn from(d: Cached) -> Descriptor<tweak::Key> {
        d.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liquid() {
        let desc = Descriptor::<bitcoin::PublicKey>::from_str(
            "\
            sh(wsh(or_d(multi(\
                11,\
                020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261,\
                02675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af99,\
                02896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d48,\
                029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c,\
                02a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc4010,\
                02f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf07,\
                03079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b,\
                03111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2,\
                0318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa0840174,\
                03230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de1,\
                035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a6,\
                03bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c,\
                03cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d17546,\
                03d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d424828,\
                03ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a\
            ),and_v(v:older(4032),multi(\
                2,\
                03aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79,\
                0291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807,\
                0386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb\
            )))))",
        )
        .unwrap();

        assert_eq!(desc.csv_expiry(), Some(4032));
        assert_eq!(desc.n_signatures(), 11);
        assert_eq!(desc.satisfaction_weight(), 1580);
        assert_eq!(desc.signed_input_weight(), 1740);

        assert_eq!(desc.csv_tweaked_descriptor().csv_expiry(), Some(2016));
        assert_eq!(desc.csv_tweaked_descriptor().n_signatures(), 11);
        assert_eq!(desc.csv_tweaked_descriptor().satisfaction_weight(), 1580);
        assert_eq!(desc.csv_tweaked_descriptor().signed_input_weight(), 1740);

        // Output from this code, manually verified
        assert_eq!(
            format!("{:?}", desc.explicit_script().unwrap()),
            "Script(\
                OP_PUSHNUM_11 \
                OP_PUSHBYTES_33 020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261 \
                OP_PUSHBYTES_33 02675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af99 \
                OP_PUSHBYTES_33 02896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d48 \
                OP_PUSHBYTES_33 029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c \
                OP_PUSHBYTES_33 02a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc4010 \
                OP_PUSHBYTES_33 02f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf07 \
                OP_PUSHBYTES_33 03079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b \
                OP_PUSHBYTES_33 03111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2 \
                OP_PUSHBYTES_33 0318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa0840174 \
                OP_PUSHBYTES_33 03230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de1 \
                OP_PUSHBYTES_33 035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a6 \
                OP_PUSHBYTES_33 03bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c \
                OP_PUSHBYTES_33 03cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d17546 \
                OP_PUSHBYTES_33 03d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d424828 \
                OP_PUSHBYTES_33 03ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a \
                OP_PUSHNUM_15 \
                OP_CHECKMULTISIG OP_IFDUP OP_NOTIF \
                    OP_PUSHBYTES_2 c00f OP_CSV OP_VERIFY \
                    OP_PUSHNUM_2 \
                    OP_PUSHBYTES_33 03aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79 \
                    OP_PUSHBYTES_33 0291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807 \
                    OP_PUSHBYTES_33 0386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb \
                    OP_PUSHNUM_3 \
                    OP_CHECKMULTISIG \
                OP_ENDIF)",
        );

        // Taken from `bitcoin decodescript` on the actual production Liquid script, renamed
        // numbers to `OP_PUSHNUM_` and `OP_CHECKSEQUENCEVERIFY` to `OP_NOP2`
        assert_eq!(
            format!("{:?}", desc.liquid_witness_script()),
            "Script(\
                OP_DEPTH \
                OP_PUSHNUM_12 \
                OP_EQUAL \
                OP_IF \
                    OP_PUSHNUM_11 \
                    OP_PUSHBYTES_33 020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261 \
                    OP_PUSHBYTES_33 02675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af99 \
                    OP_PUSHBYTES_33 02896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d48 \
                    OP_PUSHBYTES_33 029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c \
                    OP_PUSHBYTES_33 02a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc4010 \
                    OP_PUSHBYTES_33 02f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf07 \
                    OP_PUSHBYTES_33 03079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b \
                    OP_PUSHBYTES_33 03111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2 \
                    OP_PUSHBYTES_33 0318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa0840174 \
                    OP_PUSHBYTES_33 03230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de1 \
                    OP_PUSHBYTES_33 035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a6 \
                    OP_PUSHBYTES_33 03bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c \
                    OP_PUSHBYTES_33 03cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d17546 \
                    OP_PUSHBYTES_33 03d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d424828 \
                    OP_PUSHBYTES_33 03ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a \
                    OP_PUSHNUM_15 \
                OP_ELSE \
                    OP_PUSHBYTES_2 c00f OP_CSV OP_DROP \
                    OP_PUSHNUM_2 \
                    OP_PUSHBYTES_33 03aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79 \
                    OP_PUSHBYTES_33 0291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807 \
                    OP_PUSHBYTES_33 0386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb \
                    OP_PUSHNUM_3 \
                OP_ENDIF \
                OP_CHECKMULTISIG)",
        );

        // Also found by just running the code
        assert_eq!(
            format!("{:?}", desc.script_pubkey()),
            "Script(OP_HASH160 OP_PUSHBYTES_20 37a602781efd839dcc3e6b20877b978141e35c67 OP_EQUAL)",
        );

        // Also taken from production, eg
        // 0a6909b2eb793aa895c1cb0ea10bb2b5fbf931af8fea68829aa3339b459f9f83 input 2
        assert_eq!(
            format!("{:?}", desc.liquid_script_pubkey()),
            "Script(OP_HASH160 OP_PUSHBYTES_20 9e10aa3d2f248e0e42f9bab31e858240e7ed40e4 OP_EQUAL)",
        );
        assert_eq!(
            format!("{:?}", desc.liquid_address()),
            "3G6neksSBMp51kHJ2if8SeDUrzT8iVETWT"
        );

        // Also taken from production, eg
        // 0a6909b2eb793aa895c1cb0ea10bb2b5fbf931af8fea68829aa3339b459f9f83 output 3
        assert_eq!(
            format!("{:?}", desc.csv_tweaked_descriptor().liquid_script_pubkey()),
            "Script(OP_HASH160 OP_PUSHBYTES_20 8ed14f3b870f8d9012c423ec7a76148ba84f6505 OP_EQUAL)",
        );
        assert_eq!(
            format!("{:?}", desc.csv_tweaked_descriptor().liquid_address()),
            "3EiAcrzq1cELXScc98KeCswGWZaPGceT1d"
        );
    }
}
