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


//! # UTXO Table
//!
//! Tracks mainchain UTXOs (unsigned transaction outputs) controlled by the
//! federation as well as pegout requests on the sidechain. Is responsible
//! for coin selection and ensuring the different transactions which process
//! the same pegout request conflict, such that at most one can possibly
//! be included in the main blockchain.
//!
//! There are three ways that UTXOs can come into control of the federation:
//!     1. A user makes a pegin by transferring coins to the federation,
//!        then "claiming" them on the sidechain by revealing auxiliary
//!        information needed to recognize the coins as federation-owned.
//!     2. A user (or somebody) sends coins to the "untweaked federation
//!        address" which directly transfers coins to the watchmen.
//!     3. When the federation processes pegouts, it produces change outputs
//!        are similarly controlled by the federation without aux data.
//!
//! In all cases, an entry is created in the `main_utxos` map, mapping
//! the outpoint of the federation-controlled funds to a `Utxo` structure
//! containing everything the federation needs to know in order to spend
//! the coins.
//!
//! Money may also be transferred to the federation by burning coins on the
//! sidechain; but the effect of this is purely accounting (user funds
//! becoming non-user funds, available for use as transaction fees), and
//! therefore does not affect this module.
//!
//! When a user wants to move coins back to the mainchain, she creates a
//! "pegout request" which specifies a desired destination. The federation
//! sees these requests and records them in the `pegout_map` and `reverse_map`
//! structures. When creating transactions, the watchmen check these maps
//! to determine where coins need to go, and construct a transaction
//! accordingly.
//!
//! When such a transaction is either signed or seen on the network, the
//! federation records this in the `required_conflicts` map of each
//! processed `PegoutRequest` as well as the `conflict_map` of the UTXO
//! table. These maps link pegout requests to the sets of inputs in
//! transactions that process them, and are used to make sure that all
//! transcations that process the same pegouts are in conflict with each
//! other.
//!
//! Once a federation-constructed transaction is submitted to the mainchain
//! and buried by 100 blocks (or whatever the pegin confirmation depth is),
//! it is considered "finalized" and all associated entries in the
//! `main_utxos`, `pegout_map`, reverse_map` and `conflict_map` are deleted.
//!

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::{error, hash, fmt, i64, ops};

use bitcoin::Amount;
use bitcoin::hashes::{Hash, siphash24};
use bitcoin::secp256k1::{rand, PublicKey};

use common::BlockHeight;
use common::constants::{CONSTANTS, MAX_PROPOSAL_TOTAL_HSM_PAYLOAD, MAX_PROPOSAL_TX_WEIGHT, MAXIMUM_REQUIRED_INPUTS, MINIMUM_ECONOMICAL_SWEEP_FACTOR};
use descriptor::{LiquidDescriptor, TweakableDescriptor};
use common::hsm;
use logs::ProposalError;
use peer;
use tweak::{self, Tweak};
use utils;
use utils::serialize::ElementsOutpointSerdeWrapper;
use watchman::blockchain::{self, fee};
use watchman::blockchain::consensus::ConsensusTracker;
use watchman::transaction;

/// Basic info to identify a mainchain output.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct UtxoInfo {
    /// The outpoint of this UTXO
    pub outpoint: bitcoin::OutPoint,
    /// The amount of the output, in satoshis
    pub value: Amount,
    /// The block number that this output was confirmed in
    pub height: BlockHeight,
}

impl UtxoInfo {
    /// Create a new [UtxoInfo].
    pub fn new(outpoint: bitcoin::OutPoint, value: Amount, height: BlockHeight) -> UtxoInfo {
        UtxoInfo {
            outpoint: outpoint,
            value: value,
            height: height,
        }
    }
}

/// A description of a mainchain output which we are able to spend
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpendableUtxo {
    /// The basic info on this Utxo.
    pub info: UtxoInfo,
    /// The tweak needed to make to the secret key to spend the output. None
    /// for change or donation outputs
    pub tweak: Tweak,
    /// The output descriptor, with tweaked keys, for this output
    pub descriptor: miniscript::Descriptor<tweak::Key>,
}

impl SpendableUtxo {
    /// Create a new [SpendableUtxo].
    pub fn new(
        outpoint: bitcoin::OutPoint,
        value: Amount,
        height: BlockHeight,
        tweak: Tweak,
        descriptor: miniscript::Descriptor<tweak::Key>,
    ) -> SpendableUtxo {
        SpendableUtxo {
            info: UtxoInfo::new(outpoint, value, height),
            tweak: tweak,
            descriptor: descriptor,
        }
    }
    /// The size of the unsigned input that spends this UTXO.
    pub fn unsigned_input_size(&self) -> usize {
        32 + 4 // prevout outpoint
            + 4 // sequence
            + self.descriptor.unsigned_script_sig().len() // scriptsig
    }

    /// The weight of the signed input that spends this UTXO.
    pub fn signed_input_weight(&self) -> usize {
        self.descriptor.signed_input_weight()
    }

    /// The peers that are in the signer set of the script of this UTXO.
    pub fn signers(&self) -> HashSet<peer::Id> {
        self.descriptor.signers()
    }

    /// Check if this UTXO is entirely owned by the current federation.
    pub fn is_federation_owned(&self, current_federation: &HashSet<peer::Id>) -> bool {
        self.signers().iter().all(|s| current_federation.contains(s))
    }
}

impl ops::Deref for SpendableUtxo {
    type Target = UtxoInfo;
    fn deref(&self) -> &Self::Target {
        &self.info
    }
}

impl hash::Hash for SpendableUtxo {
    fn hash<H: hash::Hasher>(&self, hasher: &mut H) {
        hash::Hash::hash(&self.info.outpoint, hasher)
    }
}

/// General UTXO type that covers both unspendable and spendable UTXOs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Utxo {
    /// An unspendable UTXO.
    Unspendable(UtxoInfo),
    /// A spendable UTXO.
    Spendable(SpendableUtxo),
    /// A Reclaimable UTXO.
    OnlyReclaimable(SpendableUtxo),
}

impl Utxo {
    /// Create a new spendable [Utxo].
    pub fn new_spendable(
        outpoint: bitcoin::OutPoint,
        value: Amount,
        height: BlockHeight,
        tweak: Tweak,
        descriptor: miniscript::Descriptor<tweak::Key>,
    ) -> Utxo {
        Utxo::Spendable(SpendableUtxo::new(outpoint, value, height, tweak, descriptor))
    }

    /// Create a new reclaimable [Utxo].
    pub fn new_reclaimable(
        outpoint: bitcoin::OutPoint,
        value: Amount,
        height: BlockHeight,
        tweak: Tweak,
        descriptor: miniscript::Descriptor<tweak::Key>,
    ) -> Utxo {
        Utxo::OnlyReclaimable(SpendableUtxo::new(outpoint, value, height, tweak, descriptor))
    }

    /// Create a new unspendable [Utxo].
    pub fn new_unspendable(outpoint: bitcoin::OutPoint, value: Amount, height: BlockHeight) -> Utxo {
        Utxo::Unspendable(UtxoInfo::new(outpoint, value, height))
    }

    /// Get the [UtxoInfo] of this Utxo.
    pub fn info(&self) -> &UtxoInfo {
        match self {
            Utxo::Unspendable(ref info) => info,
            Utxo::Spendable(ref utxo) => &utxo.info,
            Utxo::OnlyReclaimable(ref utxo) => &utxo.info,
        }
    }

    /// Get the [SpendableUtxo] for [Utxo::Spendable].
    pub fn spendable(&self) -> Option<&SpendableUtxo> {
        match self {
            Utxo::Spendable(ref utxo) => Some(&utxo),
            Utxo::Unspendable(_) => None,
            Utxo::OnlyReclaimable(_) => None,
        }
    }

    /// Get the [SpendableUtxo] for [Utxo::OnlyReclaimable].
    pub fn reclaimable(&self) -> Option<&SpendableUtxo> {
        match self {
            Utxo::OnlyReclaimable(ref utxo) => Some(&utxo),
            Utxo::Unspendable(_) => None,
            Utxo::Spendable(_) => None,
        }
    }
}

impl AsRef<UtxoInfo> for Utxo {
    fn as_ref(&self) -> &UtxoInfo {
        self.info()
    }
}

impl ops::Deref for Utxo {
    type Target = UtxoInfo;
    fn deref(&self) -> &Self::Target {
        self.info()
    }
}

impl hash::Hash for Utxo {
    fn hash<H: hash::Hasher>(&self, hasher: &mut H) {
        hash::Hash::hash(&self.outpoint, hasher)
    }
}

/// Serialized version of the [Utxo] type, only used for serde.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
struct SerializedUtxo<'a> {
    outpoint: bitcoin::OutPoint,
    value: u64,
    height: BlockHeight,
    tweak: Option<Tweak>,
    descriptor: Option<Cow<'a, miniscript::Descriptor<tweak::Key>>>,
}

impl serde::Serialize for Utxo {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let ser = SerializedUtxo {
            outpoint: self.outpoint,
            value: self.value.to_sat(),
            height: self.height,
            tweak: self.spendable().map(|u| u.tweak),
            descriptor: self.spendable().map(|u| Cow::Borrowed(&u.descriptor)),
        };
        serde::Serialize::serialize(&ser, s)
    }
}

impl<'de> serde::Deserialize<'de> for Utxo {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        let ser = SerializedUtxo::deserialize(d)?;
        let info = UtxoInfo::new(ser.outpoint, Amount::from_sat(ser.value), ser.height);
        Ok(if let Some(desc) = ser.descriptor {
            Utxo::Spendable(SpendableUtxo {
                info: info,
                tweak: ser.tweak.ok_or_else(|| D::Error::custom("Utxo missing tweak"))?,
                descriptor: desc.into_owned(),
            })
        } else {
            Utxo::Unspendable(info)
        })
    }
}

/// A description of a sidechain peg-out output whose corresponding mainchain
/// output has yet to be unlocked.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PegoutRequest {
    /// The txid:vout on the sidechain
    pub request: elements::OutPoint,
    /// If there are multiple requests to the same destination, a
    /// reference to the most recent one before this one.
    pub previous_request: Option<elements::OutPoint>,
    /// The total number of previous requests
    pub n_previous_requests: usize,
    /// The destination on the mainchain for the requested peg-out
    pub dest_output: bitcoin::TxOut,
    /// The height of the output in the sidechain
    pub height: BlockHeight,
    /// Pubkey which is authorized for peg-out
    #[serde(with = "utils::serialize::hex_bytes")]
    pub dest_pubkey: Vec<u8>,
    /// Authorization proof of the above key
    #[serde(with = "utils::serialize::hex_bytes")]
    pub authorization_proof: Vec<u8>,
    /// We may sign multiple transactions processing the same pegouts. We need
    /// to ensure that these transactions conflict with each other. To do this
    /// we maintain a list of "required conflicts" associated to each pegout,
    /// which is the intersection of all transactions we're aware of that
    /// process the pegout request.
    ///
    /// We require that new transactions have nonzero intersection with this
    /// set to prevent double-pegouts and loss of funds.
    pub required_conflicts: HashSet<bitcoin::OutPoint>,
    /// Transaction fee of the pegout request (divided among all requests
    /// if there were multiple requests in the same transaction)
    pub fee: u64,
}

impl PegoutRequest {
    /// The size in bytes of the tx output to deliver this pegout.
    pub fn txout_size(&self) -> usize {
        let spk_len = self.dest_output.script_pubkey.len();
        8 + bitcoin::VarInt(spk_len as u64).size() + spk_len
    }
}

impl hash::Hash for PegoutRequest {
    fn hash<H: hash::Hasher>(&self, hasher: &mut H) {
        hash::Hash::hash(&self.request, hasher)
    }
}

impl<'de> serde::Deserialize<'de> for PegoutRequest {
    fn deserialize<D: serde::de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
        struct PegoutRequestStub {
            request: ElementsOutpointSerdeWrapper,
            previous_request: Option<ElementsOutpointSerdeWrapper>,
            n_previous_requests: usize,
            dest_output: bitcoin::TxOut,
            height: BlockHeight,
            #[serde(with = "utils::serialize::hex_bytes")]
            dest_pubkey: Vec<u8>,
            #[serde(with = "utils::serialize::hex_bytes")]
            authorization_proof: Vec<u8>,
            required_conflicts: HashSet<bitcoin::OutPoint>,
            fee: u64,
        }

        let ret = PegoutRequestStub::deserialize(d)?;
        Ok(PegoutRequest {
            request: ret.request.into(),
            previous_request: ret.previous_request.map(Into::into),
            n_previous_requests: ret.n_previous_requests,
            dest_output: ret.dest_output,
            height: ret.height,
            dest_pubkey: ret.dest_pubkey,
            authorization_proof: ret.authorization_proof,
            required_conflicts: ret.required_conflicts,
            fee: ret.fee,
        })
    }
}

/// The main UTXO tracking structure
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct UtxoTable {
    /// A map of locked outputs on the mainchain, indexed by (txid, vout)
    #[serde(with = "utils::serialize::hashmap")]
    main_utxos: HashMap<bitcoin::OutPoint, Utxo>,
    /// A map of peg-out outputs on the sidechain which unlock mainchain
    /// outputs, and are waiting on the functionaries to actually sign a transaction
    /// unlocking them. Indexed by (txid, vout) of the sidechain txes.
    #[serde(with = "utils::serialize::hashmap")]
    pegout_map: HashMap<elements::OutPoint, PegoutRequest>,
    /// A map from mainchain TxOut's to the entries in `pegout_map`
    /// that refer to them. Note that when looking them up, we just take the first
    /// -- so any attempt to withdraw to a previously-used output must wait for
    /// the first attempt to fully confirm. It is not clear that this limitation
    /// can be removed, since it is possible (e.g. if the signer was temporarily
    /// partitioned) that the first a signer hears about a withdrawal is when it
    /// appears in the mainchain. Then no matter how carefully it was tracking
    /// things, it would have only the txouts in the main transaction to go on
    /// when determining which pending sidechain output was actually unlocked.
    #[serde(with = "utils::serialize::hashmap")]
    reverse_map: HashMap<bitcoin::TxOut, Vec<elements::OutPoint>>,
    /// Map from Bitcoin outputs to the pegout requests processed in transactions
    /// that spend them. Used when finalizing transactions to look up which
    /// pegout requests need their `required_conflicts` map updated.
    #[serde(with = "utils::serialize::hashmap")]
    conflict_map: HashMap<bitcoin::OutPoint, HashSet<elements::OutPoint>>,
    /// List of in-progress failed peg-in output reclamation and the transaction they are being
    /// handled in
    #[serde(default, with = "utils::serialize::hashmap")]
    reclamation_map: HashMap<bitcoin::Txid, Vec<UtxoInfo>>,
    /// Our own public key
    our_pubkey: PublicKey,
}

impl<'de> serde::Deserialize<'de> for UtxoTable {
    fn deserialize<D: serde::de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
        struct UtxoTableStub {
            #[serde(with = "utils::serialize::hashmap")]
            main_utxos: HashMap<bitcoin::OutPoint, Utxo>,
            #[serde(with = "utils::serialize::hashmap")]
            pegout_map: HashMap<ElementsOutpointSerdeWrapper, PegoutRequest>,
            #[serde(with = "utils::serialize::hashmap")]
            reverse_map: HashMap<bitcoin::TxOut, Vec<ElementsOutpointSerdeWrapper>>,
            #[serde(with = "utils::serialize::hashmap")]
            conflict_map: HashMap<bitcoin::OutPoint, HashSet<ElementsOutpointSerdeWrapper>>,
            #[serde(default, with = "utils::serialize::hashmap")]
            reclamation_map: HashMap<bitcoin::Txid, Vec<UtxoInfo>>,
            our_pubkey: PublicKey,
        }

        let ret = UtxoTableStub::deserialize(d)?;
        Ok(UtxoTable {
            main_utxos: ret.main_utxos,
            pegout_map: ret.pegout_map.into_iter().map(|(k, v)| (k.into(), v)).collect(),
            reverse_map: ret.reverse_map.into_iter().map(
                |(k, v)| (k, v.into_iter().map(Into::into).collect())
            ).collect(),
            conflict_map: ret.conflict_map.into_iter().map(
                |(k, v)| (k, v.into_iter().map(Into::into).collect())
            ).collect(),
            reclamation_map: ret.reclamation_map,
            our_pubkey: ret.our_pubkey,
        })
    }
}

/// UTXO management error. Arguably most of these are not "errors"
/// in the sense that they are triggered by sidechain outputs which
/// appear to be withdrawal or lock outputs, but are somehow invalid.
/// This means they do not serve any fedpeg purpose, but of course
/// they are perfectly legal as sidechain outputs.
#[derive(Debug)]
pub enum Error {
    /// A tx to sign is a non-conflicting double-spend of another tx we signed
    AttemptedDoubleSpend(elements::OutPoint),
    /// Unable to fund a transaction at all (likely because the feepool is empty
    /// or all our utxos are tied up)
    CouldNotFund {
        /// The money available for fees
        available: i64,
        /// The money needed in fees for proposal
        needed: u64,
    },
    /// Not really an error - a transaction proposal resulted in no pegouts being
    /// processed or soon-expiring outputs being spent
    EmptyProposal,
    /// Non-economical reclamation proposal
    NonEconomicalReclamationProposal(Amount),
    /// unknown proposal error
    UnknownError(String)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AttemptedDoubleSpend(x) => write!(
                f, "tx processes pegout {} without required conflicts", x,
            ),
            Error::CouldNotFund { available, needed} => write!(f,
                "could not fund proposal: got {}; need {}", available, needed,
            ),
            Error::EmptyProposal => write!(f, "nothing to propose"),
            Error::NonEconomicalReclamationProposal(amount) =>
                write!(f, "reclamation proposal of amount {} was not economical", amount),
            Error::UnknownError(err) => write!(f, "unknown error: {}", err.as_str()),
        }
    }
}

impl error::Error for Error {}

impl UtxoTable {
    /// Creates a new empty UtxoTable
    pub fn new(our_pubkey: PublicKey) -> UtxoTable {
        UtxoTable {
            our_pubkey: our_pubkey,
            main_utxos: HashMap::new(),
            pegout_map: HashMap::new(),
            reverse_map: HashMap::new(),
            conflict_map: HashMap::new(),
            reclamation_map: HashMap::new(),
        }
    }

    /// Accessor for the number of locked outputs on the mainchain
    pub fn n_main_outputs(&self) -> usize {
        self.main_utxos.len()
    }

    /// Accessor for the locked outputs on the mainchain
    pub fn main_utxos(&self) -> &HashMap<bitcoin::OutPoint, Utxo> {
        &self.main_utxos
    }

    /// Obtains a reference to UTXO data given an outpoint
    pub fn lookup_utxo(&self, outpoint: &bitcoin::OutPoint) -> Option<&Utxo> {
        self.main_utxos.get(outpoint)
    }

    /// Obtains a reference to pegout request data given an outpoint
    pub fn lookup_pegout(&self, outpoint: &elements::OutPoint) -> Option<&PegoutRequest> {
        self.pegout_map.get(outpoint)
    }

    /// Returns percentiles of main output values excluding the `to_exclude` and uneconomical
    /// outputs. Returns None if there are no main outputs.
    pub fn main_output_percentiles(
        &self,
        to_exclude: &HashSet<bitcoin::OutPoint>,
        min_input_amount: Amount,
    ) -> Option<[u64; 5]> {
        let mut main_utxos = self.main_utxos.clone();
        for out in to_exclude {
            main_utxos.remove(out);
        }
        let mut main_utxos: Vec<_> = main_utxos.iter().filter(|&(_, ref out)| out.value > min_input_amount).collect();
        main_utxos.sort_by_key(|&(_, ref out)| out.value);
        if main_utxos.len() == 0 {
            return None
        }

        let min = main_utxos[0].1.value.to_sat();
        let max = main_utxos[main_utxos.len()-1].1.value.to_sat();
        let perc = |perc: f64| -> u64 {
            main_utxos[((perc as f64/100.0)*main_utxos.len() as f64).ceil() as usize - 1].1.value.to_sat()
        };
        return Some([min, perc(25.0), perc(50.0), perc(75.0), max])
    }

    /// Counts the number of pegouts found in the sidechain for which there doesn't exist a
    /// complete watchman transaction that processes them (yet).
    pub fn n_unprocessed_pegouts(&self, ongoing: &HashSet<elements::OutPoint>) -> usize {
        let mut ret = 0;
        for (side_out, _) in &self.pegout_map {
            if ongoing.contains(&side_out) {
                log!(Trace, "n_unprocessed_pegouts: Skipping ongoing output {}", side_out);
                continue;
            }
            ret += 1
        }
        ret
    }

    /// Make sure that if the pegout tx handles a pegout request that has been
    /// attempted before, at least one of the inputs used in that previous
    /// attempt is also used in this tx.
    fn check_conflicts(
        &mut self,
        txid: bitcoin::Txid,
        tx_inputs: &HashSet<bitcoin::OutPoint>,
        requests: impl IntoIterator<Item = elements::OutPoint>,
    ) -> Result<(), ProposalError> {
        for request in requests {
            let conflicts = &self.pegout_map[&request].required_conflicts;
            if !conflicts.is_empty() && conflicts.is_disjoint(tx_inputs) {
                slog!(UnconfirmedDoubleSpend, txid: txid, request: request,
                    required_conflicts: conflicts,
                );
                return Err(ProposalError::AttemptedDoubleSpend(request));
            }
        }
        Ok(())
    }

    /// Record a transaction which claims to process some set of pegouts
    /// in our conflict tracker
    pub fn record_conflicts(
        &mut self,
        txid: bitcoin::Txid,
        inputs: &HashSet<bitcoin::OutPoint>,
        pegouts: impl IntoIterator<Item = elements::OutPoint> + Clone,
    ) -> Result<(), ProposalError> {
        // Convert input array to hashset
        self.check_conflicts(txid, inputs, pegouts.clone())?;

        // The lookups below can be unwrapped because we assume internal consistency.
        for request in pegouts {
            let rq = &mut self.pegout_map.get_mut(&request).unwrap().required_conflicts;
            if rq.is_empty() {
                *rq = inputs.clone();
                for txin in inputs {
                    self.conflict_map.entry(*txin).or_insert(HashSet::new()).insert(request);
                }
            } else {
                let mut intersection = HashSet::with_capacity(rq.len());
                // Shrink the `required_conflicts` set associated to this
                // request. We don't delete the corresponding entries in the
                // conflict map, which is a minor inefficiency.
                for input in rq.drain() {
                    if inputs.contains(&input) {
                        intersection.insert(input);
                    } else {
                        self.conflict_map.get_mut(&input).unwrap().remove(&request);
                    }
                }
                *rq = intersection;
            }
            slog!(UpdateConflictRequirements, reason: txid, request: request, required_inputs: rq);
        }

        Ok(())
    }

    /// Clear all conflicts related to the given inputs from the conflict list.
    fn clear_conflicts(
        &mut self,
        txid: bitcoin::Txid,
        inputs: impl IntoIterator<Item = bitcoin::OutPoint>,
    ) {
        // The lookups below can be unwrapped because we assume internal consistency.
        for input in inputs.into_iter() {
            if let Some(requests) = self.conflict_map.remove(&input) {
                for request in requests {
                    let rq = &mut self.pegout_map.get_mut(&request).unwrap().required_conflicts;
                    // We confirmed a transaction spending one of the inputs
                    // that was required for this pegout request. By definition
                    // every transaction we signed included this input, and is
                    // therefore invalidated by the confirmed transaction. We
                    // can therefore clear the conflict list.
                    if !rq.is_empty() { // check it isn't already cleared
                        assert!(rq.contains(&input));
                        for other_input in rq.drain() {
                            if other_input != input {
                                self.conflict_map.get_mut(&other_input).unwrap().remove(&request);
                                if self.conflict_map[&other_input].is_empty() {
                                    self.conflict_map.remove(&other_input);
                                }
                            }
                        }
                        slog!(ClearConflictRequirements, reason: txid, request: request);
                    }
                }
            }
        }
    }

    /// Starts tracking an "untweaked output" which represents a fee donation
    pub fn finalize_untweaked_output(
        &mut self,
        txout_ref: bitcoin::OutPoint,
        value: Amount,
        height: BlockHeight,
        descriptor: Option<miniscript::Descriptor<tweak::Key>>,
    ) {
        slog!(RecordUtxo, utxo: txout_ref, value: value.to_sat(), height: height, claim_script: None);

        let utxo = if let Some(desc) = descriptor {
            Utxo::new_spendable(txout_ref, value, height, Tweak::none(), desc)
        } else {
            Utxo::new_unspendable(txout_ref, value, height)
        };
        if self.main_utxos.insert(txout_ref, utxo).is_some() {
            panic!("Finalized UTXO {} twice", txout_ref);
        }
    }

    /// Finalizes a mainchain transaction that we created to process some set
    /// of pegouts. Update the conflict tracker to reflect this.
    pub fn finalize_federation_tx(
        &mut self,
        txid: bitcoin::Txid,
        inputs: impl IntoIterator<Item = bitcoin::OutPoint> + Clone,
        pegouts: &HashSet<elements::OutPoint>,
    ) {
        self.clear_conflicts(txid, inputs.clone());

        // Run through the pending withdrawals and remove them
        for request in pegouts {
            log!(Debug, "removing pegout from utxotable: {}", request);
            let data = self.pegout_map.remove(&request).expect("BUG: pegout in map");
            let delete_reverse_entry = {
                // Delete all the entries from `reverse_map` for this
                // destination which appear in this transaction
                if let Some(requests) = self.reverse_map.get_mut(&data.dest_output) {
                    let mut len = requests.len();
                    requests.retain(|out| {
                        if pegouts.contains(out) {
                            len -= 1;
                            slog!(ForgetRequest, txid: txid, request: *request,
                                output: Cow::Borrowed(&data.dest_output), n_remaining: len
                            );
                            false
                        } else {
                            true
                        }
                    });
                    requests.is_empty()
                } else {
                    // already deleted the `reverse_map` entry
                    true
                }
            };
            if delete_reverse_entry {
                self.reverse_map.remove(&data.dest_output);
            } else {
                // Update `previous_request` and `n_previous_requests`
                // for every remaining pegout to this destination
                let mut previous = None;
                for (n, rq) in self.reverse_map[&data.dest_output].iter().enumerate() {
                    let pegout = self.pegout_map.get_mut(rq).unwrap();
                    pegout.previous_request = previous;
                    pegout.n_previous_requests = n;
                    previous = Some(*rq);
                }
            }
        }
        // Run through its inputs and remove from our locked output list
        for input in inputs.into_iter() {
            self.main_utxos.remove(&input).expect("was tracking utxo");
            slog!(ForgetUtxo, utxo: input, txid: txid);
        }
    }

    /// The pubkey that is used to compute the secret key tweaks that we send to the HSM
    pub fn tweak_pubkey(&self) -> PublicKey {
        self.our_pubkey
    }

    /// Process a peg-in by importing the "spent" main chain output into the watchmen's wallet.
    pub fn finalize_pegin(
        &mut self,
        data: elements::PeginData,
        mainchain_height: BlockHeight,
        tweaked_descriptor: Option<miniscript::Descriptor<tweak::Key>>,
        is_reclamation: bool
    ) {
        let tweak = tweak::compute_tweak(&self.our_pubkey, &data.claim_script[..]);

        slog!(RecordUtxo, utxo: data.outpoint, value: data.value, height: mainchain_height,
            claim_script: Some(&data.claim_script[..])
        );

        let utxo = if let Some(desc) = tweaked_descriptor {
            if is_reclamation {
                Utxo::new_reclaimable(data.outpoint, Amount::from_sat(data.value), mainchain_height, Tweak::some(&tweak[..]), desc)
            } else {
                Utxo::new_spendable(data.outpoint, Amount::from_sat(data.value), mainchain_height, Tweak::some(&tweak[..]), desc)
            }
        } else {
            Utxo::new_unspendable(data.outpoint, Amount::from_sat(data.value), mainchain_height)
        };
        self.main_utxos.insert(data.outpoint, utxo);
    }

    /// Initiates the mainchain peg-out process by adding data to the `pending_withdraws` data structure.
    pub fn finalize_pegout_request(
        &mut self,
        side_outpoint: elements::OutPoint,
        pegout_data: elements::PegoutData,
        sidechain_height: u64,
        fee: u64,
    ) {
        let dest_pubkey;
        let authorization_proof;
        if pegout_data.extra_data.len() >= 2 {
            dest_pubkey = pegout_data.extra_data[0].to_owned();
            authorization_proof = pegout_data.extra_data[1].to_owned();
        } else {
            dest_pubkey = vec![];
            authorization_proof = vec![];
        }

        let txout = bitcoin::TxOut {
            script_pubkey: pegout_data.script_pubkey,
            value: Amount::from_sat(pegout_data.value),
        };
        if self.pegout_map.contains_key(&side_outpoint) {
            panic!("Tried to process sidechain withdraw {} twice.", side_outpoint);
        } else {
            let previous_requests = self
                .reverse_map
                .entry(txout.clone())
                .or_insert(vec![]);

            slog!(RecordRequest, request: side_outpoint, output: Cow::Borrowed(&txout),
                n_remaining: 1 + previous_requests.len()
            );

            let prev_req = previous_requests.last().map(|x| *x);
            self.pegout_map.insert(side_outpoint, PegoutRequest {
                request: side_outpoint,
                previous_request: prev_req,
                n_previous_requests: previous_requests.len(),
                dest_output: txout,
                height: sidechain_height,
                dest_pubkey: dest_pubkey,
                authorization_proof: authorization_proof,
                required_conflicts: Default::default(),
                fee: fee,
            });
            previous_requests.push(side_outpoint);
        }
    }

    /// See if the provided output is an existing pending reclamation and remove it if it exists
    pub fn try_process_reclamation(&mut self, reclamation_outpoint: &bitcoin::OutPoint, txid: bitcoin::Txid) -> bool {
        if let Some(Utxo::OnlyReclaimable(utxo)) = self.main_utxos.remove(reclamation_outpoint) {
            if let Some(map) = self.reclamation_map.get_mut(&txid) {
                map.push(utxo.info);
            } else {
                self.reclamation_map.insert(txid, vec![utxo.info]);
            }
            return true;
        }
        false
    }

    /// See if the provided output is an existing pending reclamation and remove it if it exists
    pub fn try_finalize_reclamation(&mut self, txid: &bitcoin::Txid) -> Vec<UtxoInfo> {
        if let Some(reclamation_utxos) = self.reclamation_map.remove(txid) {
            return reclamation_utxos
        }
        vec![]
    }

    /// Check if transaction id corresponds to a pending reclamation
    pub fn is_pending_reclamation_tx(&self, txid: &bitcoin::Txid) -> bool {
        self.reclamation_map.contains_key(txid)
    }

    /// Checks whether all the inputs of a transaction are untracked,
    /// i.e. a spending transaction has been confirmed on the mainchain.
    /// This is used to determine when a tx is successful, to avoid
    /// logging spurious "inputs missing" RPC errors.
    pub fn any_main_outs_spent(&self, mut outs: impl Iterator<Item=bitcoin::OutPoint>) -> bool {
        outs.any(|out| !self.main_utxos.contains_key(&out))
    }

    /// Iterate all spendable UTXOs.
    ///
    /// If a set of signers is specified, will filter on UTXOs spendable by the
    /// signers. If not, any UTXO we have enough information about to spend it
    /// will be returned, regardless of whether we could successfully sign it.
    pub fn spendable_utxos<'a>(
        &'a self,
        signers: Option<&'a HashSet<peer::Id>>,
    ) -> impl Iterator<Item = &'a SpendableUtxo> + 'a {
        self.main_utxos.values()
            .filter_map(|u| u.spendable())
            .filter(move |u| signers.map(|s| u.descriptor.can_sign(s)).unwrap_or(true))
    }

    /// Iterate all unspent reclaimable UTXOs.
    ///
    /// If a set of signers is specified, will filter on UTXOs spendable by the
    /// signers. If not, any UTXO we have enough information about to spend it
    /// will be returned, regardless of whether we could successfully sign it.
    pub fn reclaimable_utxos<'a>(
        &'a self,
        signers: Option<&'a HashSet<peer::Id>>,
    ) -> impl Iterator<Item = &'a SpendableUtxo> {
        self.main_utxos.values()
            .filter_map(|u| u.reclaimable())
            .filter(move |u| signers.map(|s| u.descriptor.can_sign(s)).unwrap_or(true))
    }

    /// Return the txid of an in-progress reclamation if it exists
    pub fn in_progress_reclamation_txid(&self, reclamation_outpoint: &bitcoin::OutPoint) -> Option<&bitcoin::Txid> {
        for (txid, utxos) in self.reclamation_map.iter() {
            if utxos.iter().find(|u| &u.outpoint == reclamation_outpoint).is_some() {
                return Some(txid);
            }
        }
        None
    }

    /// Get all the signers of all the existing UTXOs.
    pub fn all_signers(&self) -> HashSet<peer::Id> {
        let mut ret = HashSet::new();
        self.spendable_utxos(None).for_each(|u| ret.extend(u.signers()));
        ret
    }

    /// Get the UTXOs that are not entirely owned by the current federation.
    pub fn non_federation_owned_utxos<'a>(
        &'a self,
        current_federation: &'a HashSet<peer::Id>,
    ) -> impl Iterator<Item = &'a SpendableUtxo> + 'a {
        self.spendable_utxos(None).filter(move |u| !u.is_federation_owned(current_federation))
    }

    /// Discard all outputs that are unspendable by the provided set of peers from the utxo table,
    /// and return the total number discarded.
    ///
    /// We will have such unspendable outputs if all utxos aren't swept in time following a dynafed transition,
    /// or if someone donates funds to an old federation which is no longer active
    ///
    /// Note: UTXOs whose descriptors are unknown will be pruned (because we don't know their signers),
    /// so make sure to only call this method once the initial sync has completed.
    pub fn prune_unspendable_utxos(
        &mut self,
        all_peers: &HashSet<peer::Id>
    ) -> usize {
        let n_utxos_initial = self.main_utxos.len();

        self.main_utxos.retain(|_, utxo| {
            let signers = match utxo {
                Utxo::Unspendable(_) => None,
                Utxo::Spendable(utxo) | Utxo::OnlyReclaimable(utxo) => {
                    if utxo.descriptor.can_sign(all_peers) {
                        return true;
                    }
                    Some(utxo.signers())
                }
            };

            // This should be a rare occurrence.
            slog!(DeleteUnspendableUtxo,
                utxo: utxo.outpoint,
                signers,
                peers: all_peers,
            );
            false
        });

        let n_utxos_final = self.main_utxos.len();
        n_utxos_initial - n_utxos_final
    }

    #[cfg(test)]
    fn proposal_sanity<'u, 'p>(
        &'u self,
        proposal: &transaction::Proposal<'u, 'p>,
        change_spk: &bitcoin::Script,
    ) {
        let concrete = proposal.to_concrete();

        use bitcoin::ScriptBuf;
        concrete.to_unsigned_tx(
            |outpoint| self.lookup_utxo(outpoint),
            |outpoint| self.lookup_pegout(outpoint),
            &ScriptBuf::from_bytes(change_spk.to_bytes()),
            transaction::FeeCheck::None,
        ).expect("proposal to unsigned tx");
    }

    #[cfg(not(test))]
    fn proposal_sanity<'a, 'b>(&self, _: &transaction::Proposal<'a, 'b>, _: &bitcoin::Script) {}

    /// Helper to add nearly-expired (or actually expired) inputs
    /// to a transaction proposal. Inputs that do not fit are simply not
    /// added, and a warning logged, rather than erroring.
    fn add_critical_inputs<'utxo, 'pegout>(
        &'utxo self,
        proposal: &mut transaction::Proposal<'utxo, 'pegout>,
        fee_pool: &fee::Pool,
        input_exclude: &HashSet<bitcoin::OutPoint>,
        economical_amount: Amount,
        current_height: BlockHeight,
        available_signers: &'utxo HashSet<peer::Id>,
    ) -> bool {
        let mut really_critical = false;
        for utxo in self.spendable_utxos(Some(available_signers)) {
            if utxo.value < economical_amount {
                slog!(IgnoreUneconomicalUtxo, outpoint: utxo.outpoint, value: utxo.value.to_sat());
                continue;
            }
            if let Some(expiry) = utxo.descriptor.csv_expiry() {
                if utxo.height + expiry < current_height + CONSTANTS.near_expiry_threshold &&
                    !input_exclude.contains(&utxo.outpoint)
                {
                    slog!(UtxoNearExpiry, outpoint: utxo.outpoint, value: utxo.value.to_sat(),
                        height: utxo.height, expiry_height: utxo.height + expiry,
                        current_height: current_height
                    );

                    if let Err(e) = proposal.add_input(fee_pool, utxo) {
                        slog!(NotSpendingUtxo, outpoint: utxo.outpoint, error: e.to_string());
                    } else {
                        if utxo.height + expiry < current_height + CONSTANTS.critical_expiry_threshold
                            && utxo.value.to_sat() >= MINIMUM_ECONOMICAL_SWEEP_FACTOR * economical_amount.to_sat()
                        {
                            really_critical = true;
                        }
                    }
                }
            }
        }
        really_critical
    }

    /// Helper to add nearly-expired (or actually expired) inputs
    /// to a transaction proposal. Inputs that do not fit are simply not
    /// added, and a warning logged, rather than erroring.
    fn check_and_add_explict_utxos_to_sweep<'utxo, 'pegout>(
        &'utxo self,
        proposal: &mut transaction::Proposal<'utxo, 'pegout>,
        fee_pool: &fee::Pool,
        input_exclude: &HashSet<bitcoin::OutPoint>,
        current_height: BlockHeight,
        available_signers: &'utxo HashSet<peer::Id>,
        explicit_utxos_to_sweep: &'utxo Vec<bitcoin::OutPoint>,
    ) -> bool {
        if !explicit_utxos_to_sweep.is_empty() {
            log!(Info, "Check if following UTXOs are available to be explicitly swept: {:?}", explicit_utxos_to_sweep);
        }
        let mut explicit_utxos = false;
        // This loop is the outer loop so that if there are no explicit sweeps this method will exit early.
        for explicitly_selected_utxo in explicit_utxos_to_sweep.iter() {
            for utxo in self.spendable_utxos(Some(available_signers)) {
                if &utxo.outpoint == explicitly_selected_utxo &&
                    !input_exclude.contains(&utxo.outpoint) {
                    slog!(ExplicitlySweepUtxo, outpoint: utxo.outpoint, value: utxo.value.to_sat(),
                        height: utxo.height,current_height: current_height
                    );
                    if let Err(e) = proposal.add_input(fee_pool, utxo) {
                        slog!(NotSpendingUtxo, outpoint: utxo.outpoint, error: e.to_string());
                    } else {
                        explicit_utxos = true;
                    }
                }
            }
        }
        explicit_utxos
    }

    /// Helper to add failed pegin UTXOs to a transaction proposal.
    /// Inputs that do not fit are simply not added, and a warning logged, rather than erroring.
    fn check_and_add_failed_pegin_reclamations<'utxo, 'pegout>(
        &'utxo self,
        proposal: &mut transaction::Proposal<'utxo, 'pegout>,
        fee_pool: &fee::Pool,
        current_height: BlockHeight,
        available_signers: &'utxo HashSet<peer::Id>,
    ) -> bool {
        let mut reclaim_found = false;
        for utxo in self.reclaimable_utxos(Some(available_signers)) {
            slog!(ReclaimFailedPegin, outpoint: utxo.outpoint, value: utxo.value.to_sat(),
                height: utxo.height,current_height: current_height
            );
            if let Err(e) = proposal.add_input(fee_pool, utxo) {
                slog!(NotSpendingUtxo, outpoint: utxo.outpoint, error: e.to_string());
            } else {
                reclaim_found = true;
            }
        }
        reclaim_found
    }

    /// Creates a transaction proposal
    pub fn tx_proposal<'out>(
        &'out self,
        consensus: &'out ConsensusTracker,
        fee_pool: &fee::Pool,
        input_exclude: &HashSet<bitcoin::OutPoint>,
        pegout_exclude: &HashSet<elements::OutPoint>,
        bitcoin_tip: BlockHeight,
        sidechain_height: BlockHeight,
        desired_n_main_outputs: usize,
        n_outputs_with_pending: usize,
        validate_pak_proof: &impl Fn(&PegoutRequest) -> Result<(), hsm::Error>,
        available_signers: &'out HashSet<peer::Id>,
        explicit_utxos_to_sweep: &'out Vec<bitcoin::OutPoint>,
    ) -> Result<transaction::Proposal<'out, 'out>, Error> {
        let mut fund_even_without_pegouts = false;

        // 0. Start with a single dust-valued change output
        let change_spk = consensus.active_change_spk();
        let mut proposal = transaction::Proposal::new(change_spk);
        let change_desc = consensus.active_descriptor();

        let max_satisfaction_weight = change_desc.satisfaction_weight();
        // Calculate the maximum number of inputs a proposal can support (assuming all are federation inputs) before
        // overflowing the MAX_PROPOSAL_TX_WEIGHT
        let max_inputs = MAX_PROPOSAL_TX_WEIGHT / max_satisfaction_weight;
        let three_quarters_max_inputs = 3 * max_inputs / 4;

        // Assume that the minimum economical weight is
        // 1 signed federation input + 1 change output x 4 + 4 (tx_in count)
        // + 4 (tx_out count) + 2 (segwit flags) + 16 (version) + 16 (locktime)
        let min_economical_weight = change_desc.signed_input_weight() + 4 * proposal.change_txout_size() + 42;
        let min_amount = fee_pool.economical_amount(min_economical_weight);

        slog!(StartTxProposal, fee_rate: fee_pool.summary().fee_rate,
            available_fees: fee_pool.summary().available_funds, economical_amount: min_amount.to_sat(),
            total_n_utxos: self.main_utxos.len(), total_n_pegouts: self.pegout_map.len(),
            in_flight_utxos: input_exclude.len(), in_flight_pegouts: pegout_exclude.len(),
            change_address: bitcoin::Address::from_script(
                change_spk, bitcoin::Network::Bitcoin,
            ).expect("invalid change spk"),
            change_spk: change_spk,
        );

        // We use this amount for determining if sweeps are economical as they will ideally share a single change output
        let min_economical_amount_input_only = fee_pool.economical_amount(change_desc.signed_input_weight());
        // 1. Add inputs that are near expiry
        let really_critical_added = self.add_critical_inputs(
            &mut proposal, fee_pool, input_exclude, min_economical_amount_input_only, bitcoin_tip, available_signers,
        );

        // Check if any of the explicitly selected UTXOs are spendable and if they are include them in the proposal
        let explicit_added = self.check_and_add_explict_utxos_to_sweep(
            &mut proposal, fee_pool, input_exclude, bitcoin_tip, available_signers, explicit_utxos_to_sweep
        );

        // If we added any, make sure this transaction is completed
        // even if it doesn't wind up processing any pegouts.
        if proposal.n_inputs() > 0 {
            if really_critical_added || explicit_added || proposal.input_value().to_sat() >= CONSTANTS.min_sweep_value_sats || proposal.n_inputs() >= MAXIMUM_REQUIRED_INPUTS {
                fund_even_without_pegouts = true;
            } else {
                let total_funds = self.spendable_utxos(Some(available_signers)).map(|u| u.value).sum::<Amount>();
                if (proposal.input_value().to_sat() * 1000) > (total_funds.to_sat() * CONSTANTS.min_sweep_permille) {
                    fund_even_without_pegouts = true;
                } else {
                    slog!(NotSweepingUtxos, value: proposal.input_value().to_sat(), num_utxos: proposal.n_inputs() as u64, min_sweep_value_sats: CONSTANTS.min_sweep_value_sats, min_sweep_per_mille: CONSTANTS.min_sweep_permille, total_funds: total_funds.to_sat());
                }
            }
        }

        // Randomly order remaining inputs but prioritize UTXOs of old federations.
        let active_desc = consensus.active_descriptor();
        let mut utxos = self.spendable_utxos(Some(available_signers))
            .filter(|utxo| utxo.value > min_amount && !input_exclude.contains(&utxo.outpoint))
            .collect::<Vec<_>>();
        // To generate deterministic but unpredictable randomness.
        let engine = siphash24::HashEngine::with_keys(rand::random(), rand::random());
        let hash_utxo = |utxo: &SpendableUtxo| {
            let mut engine = engine.clone();
            bitcoin::consensus::Encodable::consensus_encode(&utxo.info.outpoint, &mut engine).unwrap();
            siphash24::Hash::from_engine(engine)
        };
        utxos.sort_by_cached_key(|utxo|
            (
                // First sort by whether the utxo is from an old federation or not.
                utxo.descriptor == active_desc.inner,
                // Then sort randomly.
                hash_utxo(utxo),
            )
        );

        let utxos_len = utxos.len();
        if utxos_len > three_quarters_max_inputs {
            // After randomly sorting the UTXO set we will sort from 75% of the max allowable inputs onwards so that the largest
            // UTXOs are found from that index onwards. This means that the first 75% of max allowable inputs that can be added
            // to a proposal are still randomized but above 75% the max number of inputs we start choosing the largest UTXOs
            // to fund the proposal without overflowing the max allowable weight
            utxos[three_quarters_max_inputs..utxos_len].sort_by(
                |a, b| b.value.partial_cmp(&a.value).expect("value comparison")
            );
        }

        let utxo_count_before_pegouts_serviced = utxos.len();
        let mut utxos_iter = utxos.into_iter();

        // 2. Add pegouts
        let mut all_requests: Vec<&PegoutRequest> = self.pegout_map.values().filter(
            |p| !pegout_exclude.contains(&p.request)
        ).collect();
        // Sort by fee, but with an exponentially-increasing age factor to
        // ensure that old pegouts are eventually processed. This constant
        // 1.0043 was chosen such that it would not overflow i64 until over
        // 10080 blocks (which is one week on Liquid). Meanwhile, 1.0043^x
        // will reach a reasonable fee once x corresponds to 36 hours, an
        // unreasonable fee at 3 days (> 1BTC), and will overwhelm any fee
        // competition (hundreds of BTC) by 4 days.
        all_requests.sort_by_key(|p|
            (
                // First sort by how many previous requests there are, to
                // ensure that the oldest ones are always processed before
                // the later ones (and to penalize address reuse)
                p.n_previous_requests,
                // Then by age-adjusted fee
                if sidechain_height > p.height + 10080 {
                    i64::MIN
                } else {
                    (-(p.fee as i64)).saturating_sub(1.0043f64.powi(
                        (sidechain_height - p.height) as i32
                    ) as i64)
                },
                // Then by age alone
                p.height,
            )
        );

        // Counter for the number of HSM payload bytes we already sent.
        // See docs for MAX_PROPOSAL_TOTAL_HSM_PAYLOAD for more info.
        let mut total_hsm_payload = 0;

        for request in all_requests {
            let unsigned_proposal_tx_size = proposal.unsigned_size();
            if total_hsm_payload + unsigned_proposal_tx_size >= MAX_PROPOSAL_TOTAL_HSM_PAYLOAD {
                log!(Debug, "reached max hsm payload bytes (current: {}; tx size: {})",
                    total_hsm_payload, unsigned_proposal_tx_size,
                );
                break;
            }

            match proposal.add_pegout(
                request,
                fee_pool,
                input_exclude,
                &mut utxos_iter,
                |o| self.main_utxos[o].spendable().expect("conflicts are spendable"),
                validate_pak_proof,
            ) {
                Ok(()) => {
                    slog!(IncludingPegout, outpoint: request.request,
                        value: request.dest_output.value.to_sat()
                    );

                    total_hsm_payload +=
                        request.dest_pubkey.len() + request.authorization_proof.len();
                }
                Err(blockchain::Error::Hsm(hsm::Error::AuthorizedKeyCacheFull)) => {
                    slog!(IgnoringPegoutHsmFull, outpoint: request.request,
                        value: request.dest_output.value.to_sat()
                    );
                    break;
                }
                Err(blockchain::Error::Hsm(err)) => {
                    slog!(IgnoringPegoutBadPak, outpoint: request.request,
                        value: request.dest_output.value.to_sat(), error: err.to_string()
                    );
                    continue;
                }
                Err(blockchain::Error::BadProposal(ProposalError::InsufficientFees { available, needed })) => {
                    // We assume that handling pegouts will cost about the same fee.
                    if proposal.n_pegouts() == 0 && !fund_even_without_pegouts {
                        // Too few fees to even make a single pegout.
                        return Err(Error::CouldNotFund { available, needed });
                    }
                    log!(Debug, "finishing proposal because we don't have any more fees \
                        (available: {}, needed: {})", available, needed,
                    );
                    break;
                }
                Err(err) => {
                    slog!(IgnoringPegout, outpoint: request.request,
                        value: request.dest_output.value.to_sat(), error: err.to_string()
                    );
                    continue;
                }
            }
        }

        let utxo_count_after_pegouts_serviced = utxos_iter.len();
        let utxo_input_count = utxo_count_before_pegouts_serviced - utxo_count_after_pegouts_serviced;
        if utxo_input_count > three_quarters_max_inputs {
            log!(Info, "Overweight mitigation applied: threshold: {}, actual: {}", three_quarters_max_inputs, utxo_input_count);
        }

        let mut performing_reclamation = false;
        // The transaction is complete except for change/fee adjustment.
        // Check that it makes any sense.
        if proposal.n_pegouts() == 0 && !fund_even_without_pegouts {
            // clear the proposal before trying the failed pegins
            proposal = transaction::Proposal::new(change_spk);

            // Check if there are any failed pegin's marked for sweeping
            performing_reclamation = self.check_and_add_failed_pegin_reclamations(
                &mut proposal,
                fee_pool,
                bitcoin_tip,
                available_signers,
            );

            if proposal.n_inputs() == 0 {
                slog!(EmptyProposal);
                return Err(Error::EmptyProposal);
            }
        }

        // 3. Replace the phantom change output with multiple pegin-sized
        //    change outputs, if this is possible and desired
        self.proposal_sanity(&proposal, change_spk);
        match proposal.adjust_change(
            fee_pool,
            &mut utxos_iter,
            desired_n_main_outputs,
            n_outputs_with_pending,
            min_amount,
            performing_reclamation
        ) {
            Ok(_) => (),
            Err(ProposalError::NonEconomicalReclamationProposal(amount)) => {
                return Err(Error::NonEconomicalReclamationProposal(amount));
            },
            // Currently there are no other possible proposal errors this method can return but this will
            // catch future ones if they are missed.
            Err(e) => {
                log!(Error, "unhandled proposal error: {}", e);
                return Err(Error::UnknownError(e.to_string()));
            }
        }
        self.proposal_sanity(&proposal, change_spk);

        Ok(proposal)
    }

    /// Accessor for pegouts which have a given main output as their destination
    pub fn pegout_lookup(&self, output: &bitcoin::TxOut) -> Option<&Vec<elements::OutPoint>> {
        self.reverse_map.get(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryFrom;
    use std::fmt::Debug;
    use std::str::FromStr;

    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::secp256k1::rand::{thread_rng, Rng, RngCore};
    use bitcoin::blockdata::script::PushBytes;
    use elements::encode::deserialize;

    use watchman::blockchain::{TxIterator, TxObject};
    use watchman::blockchain::tests::{test_descriptor_1, TestSetup};

    fn random_outpoint() -> bitcoin::OutPoint {
        let mut inp = [0; 32];
        thread_rng().fill_bytes(&mut inp[..]);
        bitcoin::OutPoint {
            txid: bitcoin::Txid::hash(&inp[..]),
            vout: thread_rng().gen::<u32>() % 10000,
        }
    }

    fn random_main_utxo(value: u64, height: u64, descriptor: miniscript::Descriptor<tweak::Key>) -> (bitcoin::OutPoint, Utxo) {
        let mut inp = [0; 32];
        thread_rng().fill_bytes(&mut inp[..]);
        let txout_ref = bitcoin::OutPoint {
            txid: bitcoin::Txid::hash(&inp[..]),
            vout: thread_rng().gen::<u32>() % 10000,
        };
        let tweak = if thread_rng().gen() {
            let sk = SecretKey::new(&mut thread_rng());
            Tweak::some(&sk[..])
        } else {
            Tweak::none()
        };

        (
            txout_ref,
            Utxo::new_spendable(txout_ref, Amount::from_sat(value), height, tweak, descriptor),
        )
    }

    fn random_pending_withdraw(height: BlockHeight, value: Amount) -> (elements::OutPoint, PegoutRequest) {
        let mut inp = [0; 32];
        thread_rng().fill_bytes(&mut inp[..]);
        let txout_ref = elements::OutPoint {
            txid: elements::Txid::hash(&inp[..]),
            vout: thread_rng().gen::<u32>() % 10000,
        };
        let script = script::Builder::new()
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(<&PushBytes>::try_from(inp[0..20].as_ref()).expect("push bytes"))
            .push_opcode(opcodes::all::OP_EQUAL)
            .into_script();
        let arbitrary_pubkey_vec = Vec::<u8>::from_hex("03a0ff08aa49cf756b592e455dc17567eec56902d2484a7b6f385d3c9dfc6820da").unwrap();
        (txout_ref,
         PegoutRequest {
            request: txout_ref,
            previous_request: None,
            n_previous_requests: 0,
            dest_output: bitcoin::TxOut { script_pubkey: script, value: value },
            height: height,
            dest_pubkey: arbitrary_pubkey_vec,
            authorization_proof: vec![],
            required_conflicts: Default::default(),
            fee: thread_rng().gen::<u64>() % 10000,
        })
    }

    fn assert_set_equality<T: Eq + ::std::hash::Hash + Debug>(one: &HashSet<T>, two: &[T]) {
        for obj in one {
            if !two.contains(obj) { panic!("Right array does not contain {:?}", obj); }
        }
        for obj in two {
            if !one.contains(obj) { panic!("Left array does not contain {:?}", obj); }
        }
    }

    fn hashset<T: ::std::hash::Hash + Clone + Eq>(data: &[T]) -> HashSet<T> {
        data.iter().cloned().collect()
    }

    #[test]
    fn conflict_tracker() {
        let txid = random_outpoint().txid; // txid doesn't matter

        // Build conflict tracker
        let mut utxos = TestSetup::new(test_descriptor_1()).utxotable();

        // Create a bunch of inputs and pegout requests
        let inputs: Vec<_> = (0..10)
            .map(|_| random_outpoint())
            .collect();
        let requests: Vec<_> = (0..10)
            .map(|_| {
                let (outpoint, pr) = random_pending_withdraw(100, Amount::from_sat(5000));
                utxos.pegout_map.insert(outpoint, pr);
                outpoint
            })
            .collect();

        // Start test
        // 1. Add a single tx to the tracker
        let mut proposal = transaction::ConcreteProposal {
            inputs: vec![inputs[0], inputs[1], inputs[2]],
            pegouts: vec![requests[0]],
            change: vec![Amount::ZERO],
        };
        for _ in 0..3 { // Repeating same tx should be OK
            utxos.record_conflicts(
                txid, &proposal.input_set(), proposal.pegouts.iter().copied(),
            ).unwrap();
            assert_eq!(
                utxos.pegout_map[&requests[0]].required_conflicts,
                proposal.input_set(),
            );
            assert_eq!(
                utxos.pegout_map[&requests[1]].required_conflicts,
                HashSet::new()
            );
        }

        // 2. Add more pegouts. Should still be OK as long as the input set is unchanged
        proposal.pegouts.push(requests[1]);
        utxos.record_conflicts(
            txid, &proposal.input_set(), proposal.pegouts.iter().copied(),
        ).unwrap();
        assert_eq!(
            utxos.pegout_map[&requests[0]].required_conflicts,
            hashset(&inputs[0..3])
        );
        assert_eq!(
            utxos.pegout_map[&requests[1]].required_conflicts,
            hashset(&inputs[0..3])
        );
        assert_eq!(
            utxos.pegout_map[&requests[2]].required_conflicts,
            HashSet::new()
        );

        // 3. Add more inputs and another output. These should be accepted but the
        //    new inputs appear in the CT. Also drop one input that should disappear
        //    from the CT.
        proposal.inputs.remove(0);
        proposal.inputs.push(inputs[3]);
        proposal.inputs.push(inputs[4]);
        proposal.pegouts.push(requests[2]);
        utxos.record_conflicts(
            txid, &proposal.input_set(), proposal.pegouts.iter().copied(),
        ).unwrap();
        assert_eq!(
            utxos.pegout_map[&requests[0]].required_conflicts,
            hashset(&inputs[1..3])
        );
        assert_eq!(
            utxos.pegout_map[&requests[1]].required_conflicts,
            hashset(&inputs[1..3])
        );
        assert_eq!(
            utxos.pegout_map[&requests[2]].required_conflicts,
            hashset(&inputs[1..5])
        );
        assert_eq!(
            utxos.pegout_map[&requests[3]].required_conflicts,
            HashSet::new()
        );

        // 4. Try to add a non-conflicting transaction spending any of these outputs
        let utxos_checkpoint = utxos.clone();
        let mut bad_proposal = transaction::ConcreteProposal {
            inputs: vec![inputs[5], inputs[6]],
            pegouts: vec![requests[0]],
            change: vec![Amount::ZERO],
        };
        if let Err(ProposalError::AttemptedDoubleSpend(x)) =
            utxos.record_conflicts(txid, &bad_proposal.input_set(), bad_proposal.pegouts.iter().copied())
        {
            assert_eq!(x, requests[0]);
        } else {
            panic!("expected double spend");
        }
        bad_proposal.pegouts = vec![requests[1]];
        if let Err(ProposalError::AttemptedDoubleSpend(x)) =
            utxos.record_conflicts(txid, &bad_proposal.input_set(), bad_proposal.pegouts.iter().copied())
        {
            assert_eq!(x, requests[1]);
        } else {
            panic!("expected double spend");
        }
        bad_proposal.pegouts = vec![requests[0], requests[1]];
        if let Err(ProposalError::AttemptedDoubleSpend(x)) =
            utxos.record_conflicts(txid, &bad_proposal.input_set(), bad_proposal.pegouts.iter().copied())
        {
            assert!(x == requests[0] || x == requests[1]);
        } else {
            panic!("expected double spend");
        }
        // Check that if the first request (requests[5]) is OK but the second
        // request (requests[1]) is not, that the conflict tracker does not
        // update its state. See #55.
        bad_proposal.pegouts = vec![requests[5], requests[1]];
        if let Err(ProposalError::AttemptedDoubleSpend(x)) =
            utxos.record_conflicts(txid, &bad_proposal.input_set(), bad_proposal.pegouts.iter().copied())
        {
            assert_eq!(x, requests[1]);
        } else {
            panic!("expected double spend");
        }
        assert_eq!(utxos, utxos_checkpoint);

        // 5. ...but it's fine if the requests don't have conflict requirements
        bad_proposal.pegouts = vec![requests[3], requests[4]];
        utxos.record_conflicts(
            txid, &bad_proposal.input_set(), bad_proposal.pegouts.iter().copied(),
        ).unwrap();

        // 6. Add a transaction that doesn't need to conflict with anything, but happens
        //    to conflict with the output{0, 1, 2} one; also add one that conflicts with
        //    both the output{0, 1, 2} and the output{3, 4} one and this one.
        let c1_proposal = transaction::ConcreteProposal {
            inputs: vec![inputs[0], inputs[7], inputs[8]],
            pegouts: vec![requests[5]],
            change: vec![Amount::ZERO],
        };
        utxos.record_conflicts(
            txid, &c1_proposal.input_set(), c1_proposal.pegouts.iter().copied(),
        ).unwrap();

        let c_all_proposal = transaction::ConcreteProposal {
            inputs: vec![inputs[1], inputs[5], inputs[7]],
            pegouts: vec![requests[6]],
            change: vec![Amount::ZERO],
        };
        utxos.record_conflicts(
            txid, &c_all_proposal.input_set(), c_all_proposal.pegouts.iter().copied(),
        ).unwrap();

        // Now we're tracking transactions that process outputs 0 through 6. Check
        // that these are tracked correctly. Loop for a bit confirming random
        // transactions, ensuring this does not change anything.
        for _ in 0..100 {
            assert_eq!(
                utxos.pegout_map[&requests[0]].required_conflicts,
                hashset(&inputs[1..3])
            ); // (no change since step 3)
            assert_eq!(
                utxos.pegout_map[&requests[1]].required_conflicts,
                hashset(&inputs[1..3])
            ); // (no change since step 3)
            assert_eq!(
                utxos.pegout_map[&requests[2]].required_conflicts,
                hashset(&inputs[1..5])
            ); // (no change since step 3)
            assert_eq!(
                utxos.pegout_map[&requests[3]].required_conflicts,
                hashset(&inputs[5..7])
            ); // only bad_tx from step 5
            assert_eq!(
                utxos.pegout_map[&requests[4]].required_conflicts,
                hashset(&inputs[5..7])
            ); // only bad_tx from step 5
            assert_eq!(
                utxos.pegout_map[&requests[5]].required_conflicts,
                hashset(&[inputs[0], inputs[7], inputs[8]])
            ); // only c1 from step 6
            assert_eq!(
                utxos.pegout_map[&requests[6]].required_conflicts,
                hashset(&[inputs[1], inputs[5], inputs[7]])
            ); // only call from step 6

            let random_proposal = transaction::ConcreteProposal {
                inputs: (0..50).map(|_| random_outpoint()).collect(),
                pegouts: vec![],
                change: vec![Amount::ZERO],
            };
            utxos.clear_conflicts(txid, random_proposal.input_set());
        }

        // At this point we split up the conflict tracker so we can try various ways of emptying it.
        let mut utxos = vec![utxos; 5];  // vec! will call clone()

        // A1. Try confirming the tx from step 3. Should cause us to stop tracking outputs 0, 1, 2, 6,
        //     since every tx spending one of those conflicts with this.
        utxos[0].clear_conflicts(txid, proposal.inputs.clone());
        utxos[0].clear_conflicts(txid, proposal.inputs.clone()); // double-confirming should succeed
        assert_set_equality(&utxos[0].pegout_map[&requests[0]].required_conflicts, &[]); // gone
        assert_set_equality(&utxos[0].pegout_map[&requests[1]].required_conflicts, &[]); // gone
        assert_set_equality(&utxos[0].pegout_map[&requests[2]].required_conflicts, &[]); // gone
        assert_set_equality(&utxos[0].pegout_map[&requests[3]].required_conflicts, &inputs[5..7]); // no change
        assert_set_equality(&utxos[0].pegout_map[&requests[4]].required_conflicts, &inputs[5..7]); // no change
        assert_set_equality(&utxos[0].pegout_map[&requests[5]].required_conflicts, &[inputs[0], inputs[7], inputs[8]]); // no change
        assert_set_equality(&utxos[0].pegout_map[&requests[6]].required_conflicts, &[]); // gone

        // A2. Confirm the tx from step 5. It uses input 7 so should clear out the rest of the tracker.
        utxos[0].clear_conflicts(txid, bad_proposal.inputs.clone());
        assert_set_equality(&utxos[0].pegout_map[&requests[3]].required_conflicts, &[]); // gone
        assert_set_equality(&utxos[0].pegout_map[&requests[4]].required_conflicts, &[]); // gone
        assert_set_equality(&utxos[0].pegout_map[&requests[5]].required_conflicts, &[inputs[0], inputs[7], inputs[8]]); // no change

        // A3. Confirm `c1`, the only tx that should still be in the trackr.
        utxos[0].clear_conflicts(txid, c1_proposal.inputs.clone());
        assert_set_equality(&utxos[0].pegout_map[&requests[5]].required_conflicts, &[]); // gone
        assert_eq!(utxos[0].conflict_map, HashMap::new());

        // B1. With a new CT, try confirming call from step 6. This conflicts with everything
        //     in the tracker and should empty it in one go.
        utxos[1].clear_conflicts(txid, c_all_proposal.inputs.clone());
        for outpoint in &requests[0..7] {
            assert_set_equality(&utxos[1].pegout_map[outpoint].required_conflicts, &[]); // gone
        }
        // See bug #56; this tx does not have input 1, but by confirming it we
        // stop caring about every tx that *does*. So input 1 should also be
        // removed.
        assert_eq!(utxos[1].conflict_map, HashMap::new());

        // C1. Same as above but remove the outputs from call (they shouldn't affect anything)
        let c_all_toothless = transaction::ConcreteProposal {
            inputs: c_all_proposal.inputs.clone(),
            pegouts: vec![],
            change: vec![],
        };
        utxos[2].clear_conflicts(txid, c_all_toothless.input_set());
        for outpoint in &requests[0..7] {
            assert_set_equality(&utxos[2].pegout_map[outpoint].required_conflicts, &[]); // gone
        }
        assert_eq!(utxos[2].conflict_map, HashMap::new());
    }

    fn utxoset_serialization_roundtrip(utxos: &UtxoTable) {
        let mut w: Vec<u8> = vec![];

        serde_json::to_writer(&mut w, utxos)
            .expect("serializing");
        let new_utxos = serde_json::from_reader(&w[..])
            .expect("deserializing");

        assert_eq!(*utxos, new_utxos);
    }

    #[test]
    fn conflict_tracker_2() {
        let txid = random_outpoint().txid; // txid doesn't matter

        let mut utxo_template = TestSetup::new(test_descriptor_1()).utxotable();

        let inputs: Vec<_> = (0..4)
            .map(|_| random_outpoint())
            .collect();
        let requests: Vec<_> = (0..3)
            .map(|_| {
                let (outpoint, pr) = random_pending_withdraw(100, Amount::from_sat(5000));
                utxo_template.pegout_map.insert(outpoint, pr);
                outpoint
            })
            .collect();

        let proposals = vec![
            transaction::ConcreteProposal {
                inputs: vec![inputs[0], inputs[1]],
                pegouts: vec![requests[0], requests[1]],
                change: vec![Amount::from_sat(100)],
            },
            transaction::ConcreteProposal {
                inputs: vec![inputs[1], inputs[2]],
                pegouts: vec![requests[1]],
                change: vec![Amount::from_sat(100), Amount::from_sat(200)],
            },
            transaction::ConcreteProposal {
                inputs: vec![inputs[2]],
                pegouts: vec![requests[2]],
                change: vec![Amount::from_sat(100), Amount::from_sat(200), Amount::from_sat(300)],
            },
        ];

        let permutations = vec![
            vec![0, 1, 2],
            vec![0, 2, 1],
            vec![1, 0, 2],
            vec![1, 2, 0],
            vec![2, 0, 1],
            vec![2, 1, 0],
        ];
        let mut utxos = vec![utxo_template.clone(); permutations.len()];

        // test that the order of `record_conflicts` does not matter
        for (count, permutation) in permutations.iter().enumerate() {
            for i in permutation {
                utxoset_serialization_roundtrip(&mut utxos[count]);
                utxos[count].record_conflicts(
                    txid, &proposals[*i].input_set(), proposals[*i].pegouts.iter().copied(),
                ).unwrap();
                // add same tx
                utxos[count].record_conflicts(
                    txid, &proposals[*i].input_set(), proposals[*i].pegouts.iter().copied(),
                ).unwrap();
            }
            if count > 0 {
                assert_eq!(utxos[count], utxos[0]);
            }
        }

        // attempt to add double spend
        let proposal_c = transaction::ConcreteProposal {
            inputs: vec![inputs[3]],
            pegouts: vec![requests[2]],
            change: vec![],
        };
        if let Err(ProposalError::AttemptedDoubleSpend(x)) =
            utxos[0].record_conflicts(txid, &proposal_c.input_set(), proposal_c.pegouts.iter().copied())
        {
            assert_eq!(x, requests[2]);
        } else {
            panic!("expected double spend");
        }

        let mut utxo = utxos[0].clone();
        utxo.clear_conflicts(txid, proposals[0].input_set());
        utxoset_serialization_roundtrip(&mut utxo);
        if let Err(ProposalError::AttemptedDoubleSpend(x)) =
            utxo.record_conflicts(txid, &proposal_c.input_set(), proposal_c.pegouts.iter().copied())
        {
            assert_eq!(x, requests[2]);
        } else {
            panic!("expected double spend");
        }
        utxo.clear_conflicts(txid, proposals[2].inputs.clone());

        utxoset_serialization_roundtrip(&mut utxo);
        assert!(utxo.conflict_map.is_empty());

        let mut utxo = utxos[0].clone();
        utxo.clear_conflicts(txid, proposals[1].inputs.clone());
        utxoset_serialization_roundtrip(&mut utxo);
        utxo.record_conflicts(
            txid, &proposal_c.input_set(), proposal_c.pegouts.iter().copied(),
        ).unwrap();
        utxoset_serialization_roundtrip(&mut utxo);
        utxo.clear_conflicts(txid, proposal_c.inputs.clone());
        assert!(utxo.conflict_map.is_empty());

        let mut utxo = utxos[0].clone();
        utxo.clear_conflicts(txid, proposals[2].inputs.clone());
        // Because tx0 was added, tx1 and tx2 don't share an input from the PoV
        // of the conflict tracker.
        utxoset_serialization_roundtrip(&mut utxo);
        utxo.clear_conflicts(txid, proposals[0].inputs.clone());
        assert!(utxo.conflict_map.is_empty());

        // test what happens if multiple main_refs point to the same side_ref
        let mut utxo = utxo_template.clone();
        utxo.record_conflicts(
            txid, &proposals[1].input_set(), proposals[1].pegouts.iter().copied(),
        ).unwrap();
        utxoset_serialization_roundtrip(&mut utxo);
        utxo.clear_conflicts(txid, proposals[1].inputs.clone());
        assert!(utxo.conflict_map.is_empty());
    }

    #[test]
    fn finalize_pegin() {
        let tx: elements::Transaction = deserialize(&hex!("
            0200000001013fe9fcf1d5eae66a152efa45ad32baa5eed3cf11ab5e04edde65
            0313b58ed8c90000004000ffffffff0201f80bb0038f482243202f0b2dcf88d9
            b4e7f930a48a3fcdc003af76b1f9d60e63010000000005f5c88c001976a914d7
            cc0ea6d5e53af78c7802101519cc100692668e88ac01f80bb0038f482243202f
            0b2dcf88d9b4e7f930a48a3fcdc003af76b1f9d60e6301000000000000187400
            0000000000000002473044022048cf10f12a31cb0ec36ba3a6f79fad7e0dea3f
            1aa790a5aed02f8e8455c8cb1502201a2624089ce70c893dfd07a156ba91223e
            dd5680cbd93d3336285ceefcb3dc1401210205914becd15ac5d2f72ad0aa42e8
            4349c825a544d8c16e78ecc21534ef561fd4060800e1f5050000000020f80bb0
            038f482243202f0b2dcf88d9b4e7f930a48a3fcdc003af76b1f9d60e63200622
            6e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1600
            141ab7f5995cf0dfcb90cbb02b63397e5326eae6febe020000000113244fa59f
            cb407124038ff9121ed546f6dc217571cb366a50d3193f2c80298c0000000049
            483045022100d1e212715d2dcbc1c66d76f43d9f326f54ff339b565c68f046ed
            74040730433b02201d9ccbad57566100a06b4be47a4c777cbd7c99e0a08e17f7
            bf10458117426cd801feffffff0200e1f5050000000017a914774b87be1ef871
            d82a01edbb89a70bf4bb59310387a88c8b44000000001976a914b14b73956239
            21dbbce438f4fc1fc8f1a495affa88acf4010000b700000020a060086af92ac3
            4dbbc8bd89bbbe03ef7e0016930f7fdc806ff15d163b5fda5e32105949c74822
            2d3e1c5b6e0a4d47f8de45b25d63f145c4056682a7b15cc3da56a2815bffff7f
            20000000000300000003946c969d81a3b0ca473ab54c11fa665234d6ce1ad09e
            87a1dbc56eb6de4002b83fe9fcf1d5eae66a152efa45ad32baa5eed3cf11ab5e
            04edde650313b58ed8c9fccdc0d07eaf48f928fecfc07707b95769704d25f855
            529711ed6450cc9b3c95010b00000000
        ")).unwrap();
        let setup = TestSetup::new(test_descriptor_1());
        let mut utxos = setup.utxotable();

        assert_eq!(utxos.main_utxos.len(), 0);

        let asset_id = elements::AssetId::from_str("630ed6f9b176af03c0cd3f8aa430f9e7b4d988cf2d0b2f204322488f03b00bf8").unwrap();
        let mut iter = TxIterator::new(
            &tx,
            tx.txid(),
            bitcoin::BlockHash::from_str(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
            ).unwrap(),
            elements::confidential::Asset::Explicit(asset_id),
        );
        if let Some(TxObject::Pegin(data)) = iter.next() {
            utxos.finalize_pegin(data, 0, Some(setup.descriptor()), false);
        } else {
            panic!("Expected pegin");
        }
        assert_eq!(iter.next(), Some(TxObject::Fee(6260)));
        assert_eq!(iter.next(), None);

        assert_eq!(utxos.main_utxos.len(), 1);
        let main_out_ref = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_str("c9d88eb5130365deed045eab11cfd3eea5ba32ad45fa2e156ae6ead5f1fce93f").unwrap(),
            vout: 0,
        };
        assert_eq!(tx.input[0].is_pegin(), true);
        assert_eq!(tx.input[0].previous_output.txid.as_raw_hash(), main_out_ref.txid.as_raw_hash());
        assert_eq!(tx.input[0].previous_output.vout, main_out_ref.vout);

        let main_utxo = utxos.main_utxos.get(&main_out_ref).unwrap();
        assert_eq!(main_utxo.value.to_sat(), 100000000);
    }

    #[test]
    fn finalize_pegout() {
        let tx: elements::Transaction = deserialize(&hex!("
            020000000001f6d59ba2e098a2a2eaecf06b02aa0773773449caf62bd4e9f17c
            db9b0d679954000000006b483045022100c74ee0dd8f3f6c909635f7a2bb8dd2
            052e3547f94a520cdba2aa12668059dae302204306e11033f18f65560a52a860
            b098e7df0fa7d35350d16f1c5a86e2da2ae37e012102b672f428ad984563c0de
            c80b3912fcad871338545df1538fe26c390826fbb4b2000000000101f80bb003
            8f482243202f0b2dcf88d9b4e7f930a48a3fcdc003af76b1f9d60e6301000000
            0005f5c92c00a06a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a
            1fc7b2b73cf188910f1976a914bedb324be05d1a1254afeb3e7ef40fea0368bc
            1e88ac2102e25e582ac1adc69f168aa7dbf0a97341421e10b22c659927de24fd
            ac6e9f1fae4101a48fe52775701556a4a2dbf3d95c0c13845bbf87271e745b1c
            454f8ebcb5cd4792a4139f419f192ca6e389531d46fa5857f2c109dfe4003ad8
            b2ce504b488bed00000000
        ")).unwrap();
        // Same as above but uses OP_TRUE instead of OP_RETURN.
        let bad_tx_nonnull: elements::Transaction = deserialize(&hex!("
            020000000001f6d59ba2e098a2a2eaecf06b02aa0773773449caf62bd4e9f17c
            db9b0d679954000000006b483045022100c74ee0dd8f3f6c909635f7a2bb8dd2
            052e3547f94a520cdba2aa12668059dae302204306e11033f18f65560a52a860
            b098e7df0fa7d35350d16f1c5a86e2da2ae37e012102b672f428ad984563c0de
            c80b3912fcad871338545df1538fe26c390826fbb4b2000000000101f80bb003
            8f482243202f0b2dcf88d9b4e7f930a48a3fcdc003af76b1f9d60e6301000000
            0005f5c92c00a0 51 2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a
            1fc7b2b73cf188910f1976a914bedb324be05d1a1254afeb3e7ef40fea0368bc
            1e88ac2102e25e582ac1adc69f168aa7dbf0a97341421e10b22c659927de24fd
            ac6e9f1fae4101a48fe52775701556a4a2dbf3d95c0c13845bbf87271e745b1c
            454f8ebcb5cd4792a4139f419f192ca6e389531d46fa5857f2c109dfe4003ad8
            b2ce504b488bed00000000
        ")).unwrap();
        let mut utxos = TestSetup::new(test_descriptor_1()).utxotable();
        let height = 23;

        assert_eq!(utxos.reverse_map.len(), 0);
        assert_eq!(utxos.pegout_map.len(), 0);

        let asset_id = elements::AssetId::from_str("630ed6f9b176af03c0cd3f8aa430f9e7b4d988cf2d0b2f204322488f03b00bf8").unwrap();
        let mut bad_iter = TxIterator::new(
            &bad_tx_nonnull,
            bad_tx_nonnull.txid(),
            bitcoin::BlockHash::from_str(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
            ).unwrap(),
            elements::confidential::Asset::Explicit(asset_id),
        );
        assert_eq!(None, bad_iter.next());

        // Genesis hash is wrong
        let mut bad_iter = TxIterator::new(
            &tx,
            tx.txid(),
            bitcoin::BlockHash::from_str(
                "00000000000000000000000000000000000000000012afca590b1a11466e2206"
            ).unwrap(),
            elements::confidential::Asset::Explicit(asset_id),
        );
        assert_eq!(None, bad_iter.next());

        // Asset ID is wrong
        let asset_id = elements::AssetId::from_str("000000000000000000000000000000e7b4d988cf2d0b2f204322488f03b00bf8").unwrap();
        let mut bad_iter = TxIterator::new(
            &tx,
            tx.txid(),
            bitcoin::BlockHash::from_str(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
            ).unwrap(),
            elements::confidential::Asset::Explicit(asset_id),
        );
        assert_eq!(None, bad_iter.next());

        let asset_id = elements::AssetId::from_str("630ed6f9b176af03c0cd3f8aa430f9e7b4d988cf2d0b2f204322488f03b00bf8").unwrap();
        let mut iter = TxIterator::new(
            &tx,
            tx.txid(),
            bitcoin::BlockHash::from_str(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
            ).unwrap(),
            elements::confidential::Asset::Explicit(asset_id),
        );

        let (sideout, pegout) = if let Some(TxObject::Pegout(outpoint, data)) = iter.next() {
            (outpoint, data)
        } else {
            panic!("Expected pegout");
        };
        assert_eq!(None, iter.next());

        utxos.finalize_pegout_request(sideout, pegout.clone(), height, 0);

        assert_eq!(utxos.reverse_map.len(), 1);
        assert_eq!(utxos.pegout_map.len(), 1);
        let new_pending_out = PegoutRequest {
            request: sideout,
            previous_request: None,
            n_previous_requests: 0,
            dest_output: bitcoin::TxOut {
                script_pubkey: bitcoin::ScriptBuf::from_hex("76a914bedb324be05d1a1254afeb3e7ef40fea0368bc1e88ac").expect("script"),
                value: Amount::from_sat(99993900),
            },
            height: height,
            dest_pubkey: vec![
                0x02,
                0xe2, 0x5e, 0x58, 0x2a, 0xc1, 0xad, 0xc6, 0x9f,
                0x16, 0x8a, 0xa7, 0xdb, 0xf0, 0xa9, 0x73, 0x41,
                0x42, 0x1e, 0x10, 0xb2, 0x2c, 0x65, 0x99, 0x27,
                0xde, 0x24, 0xfd, 0xac, 0x6e, 0x9f, 0x1f, 0xae,
            ],
            authorization_proof: vec![
                0x01,
                0xa4, 0x8f, 0xe5, 0x27, 0x75, 0x70, 0x15, 0x56,
                0xa4, 0xa2, 0xdb, 0xf3, 0xd9, 0x5c, 0x0c, 0x13,
                0x84, 0x5b, 0xbf, 0x87, 0x27, 0x1e, 0x74, 0x5b,
                0x1c, 0x45, 0x4f, 0x8e, 0xbc, 0xb5, 0xcd, 0x47,
                0x92, 0xa4, 0x13, 0x9f, 0x41, 0x9f, 0x19, 0x2c,
                0xa6, 0xe3, 0x89, 0x53, 0x1d, 0x46, 0xfa, 0x58,
                0x57, 0xf2, 0xc1, 0x09, 0xdf, 0xe4, 0x00, 0x3a,
                0xd8, 0xb2, 0xce, 0x50, 0x4b, 0x48, 0x8b, 0xed,
            ],
            required_conflicts: Default::default(),
            fee: 0,
        };
        utxos.pegout_map.get(&sideout).unwrap();

        assert_eq!(utxos.pegout_map[&sideout], new_pending_out);
        assert_eq!(utxos.reverse_map[&new_pending_out.dest_output], vec![sideout]);
    }

    #[test]
    fn main_output_percentiles() {
        // Build utxoset
        let setup = TestSetup::new(test_descriptor_1());
        let signed_input_weight = setup.descriptor.signed_input_weight();
        let mut utxos = setup.utxotable();
        let fee_pool = fee::Pool::new(Amount::from_sat(fee::tests::FALLBACK_FEE_RATE));
        let million = 1000000;
        let (main_ref, main_out) = random_main_utxo(million, 0, setup.descriptor());
        utxos.main_utxos.insert(main_ref, main_out);
        assert_eq!(
            utxos.main_output_percentiles(
                &vec![].into_iter().collect(),
                fee_pool.economical_amount(signed_input_weight),
            ),
            Some([million,million,million,million,million])
        );
        assert_eq!(
            utxos.main_output_percentiles(
                &vec![main_ref].into_iter().collect(),
                fee_pool.economical_amount(signed_input_weight),
            ),
            None
        );
        let (main_ref, main_out) = random_main_utxo(2*million, 0, setup.descriptor());
        utxos.main_utxos.insert(main_ref, main_out);
        assert_eq!(
            utxos.main_output_percentiles(
                &vec![].into_iter().collect(),
                fee_pool.economical_amount(signed_input_weight),
            ),
            Some([million,million,million,2*million,2*million])
        );
    }

    #[test]
    fn sweep_utxo_test() {
        // Build utxoset with outputs with dummy CSV
        let setup = TestSetup::new(test_descriptor_1());
        let mut utxos = setup.utxotable();
        let mut fee_pool = fee::Pool::new(Amount::from_sat(fee::tests::FALLBACK_FEE_RATE));
        fee_pool.add(Amount::from_sat(500000));

        for i in 0..5 {
            let (main_ref, main_out) = random_main_utxo(100000, i, setup.descriptor());
            utxos.main_utxos.insert(main_ref, main_out);
        }

        let script = bitcoin::ScriptBuf::new();
        let mut proposal = transaction::Proposal::new(
            &script
        );

        let input_exclude = HashSet::new();

        // Nothing will expire before the near expiry threshold.
        let signers = setup.peers();
        let no_exp = setup.csv() - CONSTANTS.near_expiry_threshold;
        for i in 0..no_exp {
            utxos.add_critical_inputs(&mut proposal, &fee_pool, &input_exclude, Amount::ONE_SAT, i, &signers);
            assert_eq!(proposal.n_inputs(), 0);
            proposal = transaction::Proposal::new(
                &script
            );
        }

        for i in 1..5 {
            utxos.add_critical_inputs(&mut proposal, &fee_pool, &input_exclude, Amount::ONE_SAT, i+no_exp, &signers);
            assert_eq!(proposal.n_inputs(), i as usize);
            proposal = transaction::Proposal::new(
                &script
            );
        }

    }

}
