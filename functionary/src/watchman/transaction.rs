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

//! # Transactions
//! Assembles and verifies Bitcoin transactions and signatures

use std::collections::{HashMap, HashSet};
use std::{cell, cmp, fmt, io, mem, ops};

use bitcoin;
use bitcoin::secp256k1::{self, Message, Secp256k1, ecdsa::Signature};
use bitcoin::util::sighash::SighashCache;
use miniscript::{self, DescriptorTrait};

use common::constants;
use descriptor::LiquidDescriptor;
use common::hsm;
use logs::ProposalError;
use message;
use peer;
use tweak;
use watchman::blockchain::{self, fee};
use watchman::utxotable::{PegoutRequest, SpendableUtxo, Utxo};

/// Some utility methods on Bitcoin transaction
pub trait TransactionUtil {
    /// Calculate the tx fee.
    fn calculate_fee(&self, inputs: &[SpendableUtxo]) -> u64;
}

impl TransactionUtil for bitcoin::Transaction {
    fn calculate_fee(&self, inputs: &[SpendableUtxo]) -> u64 {
        let total_out = self.output.iter().map(|o| o.value).sum::<u64>();
        let total_in = self.input.iter().map(|i| inputs.iter()
            .find(|i2| i2.outpoint == i.previous_output)
            .expect("provided inputs didn't match the provided transaction")
            .value
        ).sum::<u64>();
        total_in - total_out
    }
}

/// A collection of signatures to be added to a transaction, one per input
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransactionSignatures(Vec<(Signature, bitcoin::EcdsaSighashType)>);

impl From<Vec<(Signature, bitcoin::EcdsaSighashType)>> for TransactionSignatures {
    fn from(data: Vec<(Signature, bitcoin::EcdsaSighashType)>) -> TransactionSignatures {
        TransactionSignatures(data)
    }
}

impl Default for TransactionSignatures {
    fn default() -> TransactionSignatures {
        TransactionSignatures(vec![])
    }
}

impl ops::Index<ops::RangeFull> for TransactionSignatures {
    type Output = [(Signature, bitcoin::EcdsaSighashType)];

    fn index(&self, _: ops::RangeFull) -> &[(Signature, bitcoin::EcdsaSighashType)] {
        &self.0[..]
    }
}

impl fmt::Display for TransactionSignatures {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("[")?;
        for (n, (ref sig, hashtype)) in self.0.iter().enumerate() {
            if n > 0 {
                f.write_str(", ")?;
            }
            fmt::Display::fmt(sig, f)?;
            write!(f, "{:02x}", hashtype.to_u32())?;
        }
        f.write_str("]")?;
        Ok(())
    }
}

impl message::NetEncodable for TransactionSignatures {
    fn encode<W: io::Write>(&self, w: W) -> Result<usize, message::Error> {
        message::NetEncodable::encode(&self.0, w)
    }

    fn decode<R: io::Read>(r: R) -> Result<Self, message::Error> {
        Ok(TransactionSignatures(message::NetEncodable::decode(r)?))
    }
}

/// Description of a specific signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SigResult {
    /// Valid signature
    Good,
    /// No signature
    Missing,
    /// Sighash type is not ALL
    NotSighashAll,
    /// Invalid signature
    Invalid,
    /// Non-tweakable key encountered
    NonTweakableKey,
}

impl SigResult {
    /// Set self to the most severe of the two.
    fn update(&mut self, also: SigResult) {
        *self = if *self == SigResult::Invalid || also == SigResult::Invalid {
            SigResult::Invalid
        } else  if *self == SigResult::NotSighashAll || also == SigResult::NotSighashAll {
            SigResult::NotSighashAll
        } else  if *self == SigResult::Missing || also == SigResult::Missing {
            SigResult::Missing
        } else {
            SigResult::Good
        };
    }
}

impl fmt::Display for SigResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Takes a list of signatures and completes a multisig transaction. Returns an
/// array of `SigResult`s which indicate which peers are missing which signatures
pub fn assemble_tx<C: secp256k1::Verification>(
    secp: &Secp256k1<C>,
    tx: &bitcoin::Transaction,
    cache: &mut SighashCache<&bitcoin::Transaction>,
    input: &[SpendableUtxo],
    peer_sigs: &HashMap<peer::Id, &TransactionSignatures>,
) -> Result<bitcoin::Transaction, HashMap<peer::Id, SigResult>> {
    debug_assert_eq!(tx.input.len(), input.len());

    let mut ret_tx = tx.clone();
    let mut sig_results = HashMap::new();
    let mut success = true;

    for i in 0..ret_tx.input.len() {
        let witness_script = input[i].descriptor.liquid_witness_script();
        let sighash = cache.segwit_signature_hash(
            i,
            &witness_script,
            input[i].value,
            bitcoin::EcdsaSighashType::All
        ).unwrap();
        let msg = Message::from_slice(&sighash).unwrap();

        // Build signature witness
        let res = input[i].descriptor.satisfy(
            &mut ret_tx.input[i],
            &Satisfier {
                sighash: msg,
                input_idx: i,
                secp,
                peer_sigs,
                sig_results: cell::RefCell::new(&mut sig_results),
            },
        );

        if let Err(e) = res {
            success = false;
            log!(Debug, "miniscript error: {}", e);
            continue;
        }

        // Replace witness script and scriptSig with Liquified versions
        if input[i].descriptor.is_legacy_liquid_descriptor() {
            assert!(!ret_tx.input[i].script_sig.is_empty());
            ret_tx.input[i].script_sig = bitcoin::blockdata::script::Builder::new()
                .push_slice(&witness_script.to_v0_p2wsh()[..])
                .into_script();

            let mut witness = ret_tx.input[i].witness.to_vec();
            witness.pop();
            witness.push(witness_script.into_bytes());
            ret_tx.input[i].witness = bitcoin::Witness::from_vec(witness);
        } else {
            assert!(ret_tx.input[i].script_sig.is_empty());
            assert_eq!(ret_tx.input[i].witness.last().unwrap(), &witness_script[..]);
        }

    }

    if success {
        Ok(ret_tx)
    } else {
        Err(sig_results)
    }
}

enum UndoAction<'utxo> {
    /// Add an input, with given signed input weight, to the proposal
    AddInput(&'utxo SpendableUtxo),
    /// Add a pegout, with given output weight, to the propoal
    AddPegout(elements::OutPoint),
    /// Add a change output of the given amount.
    AddChange(u64),
    /// Add a set of inputs, one of which must be present in the final tx,
    /// to the proposal
    AddConflictSet,
    /// Replace the conflict-set at the given index
    ReplaceConflictSet(usize, HashSet<&'utxo SpendableUtxo>),
}

/// Helper structure to enforce atomic updates of a proposal. It keeps track
/// of all updates and undoes them when it is dropped. A successful update
/// should be followed by a call to the `clear` method to prevent this.
struct ProposalUpdate<'a, 'utxo: 'a, 'pegout: 'a> {
    proposal: &'a mut Proposal<'utxo, 'pegout>,
    undo: Vec<UndoAction<'utxo>>,
}

impl<'a, 'utxo: 'a, 'pegout: 'a> ProposalUpdate<'a, 'utxo, 'pegout> {
    fn new(proposal: &'a mut Proposal<'utxo, 'pegout>)
        -> ProposalUpdate<'a, 'utxo, 'pegout>
    {
        ProposalUpdate {
            proposal: proposal,
            undo: vec![],
        }
    }

    fn add_input(&mut self, utxo: &'utxo SpendableUtxo) {
        if self.proposal.inputs.insert(utxo) {
            self.undo.push(UndoAction::AddInput(utxo));
        }
    }

    /// Add inputs to the proposal until it balances, failing if it runs
    /// out of available UTXOs or if the resulting transaction would exceed
    /// the maximum weight.
    ///
    /// If this method errors, the update should be discarded (by dropping it).
    fn add_inputs<I>(&mut self, fee_pool: &fee::Pool, mut utxos: I) -> Result<(), ProposalError>
        where I: Iterator<Item=&'utxo SpendableUtxo>,
    {
        let mut weight = self.proposal.check_signed_weight()?;
        let mut fee = fee_pool.calculate_fee(weight);
        fee_pool.validate_fee(weight, fee)?;
        let mut input_amount = self.proposal.input_value();
        let output_amount = self.proposal.output_value();

        while input_amount < output_amount + fee {
            if let Some(utxo) = utxos.next() {
                self.add_input(utxo);
                weight = self.proposal.check_signed_weight()?;
                fee = fee_pool.calculate_fee(weight);
                fee_pool.validate_fee(weight, fee)?;
                input_amount = self.proposal.input_value();
            } else {
                return Err(ProposalError::Unbalanced {
                    input_value: input_amount,
                    output_value: output_amount + fee,
                });
            }
        }
        Ok(())
    }

    fn add_pegout(&mut self, pegout: &'pegout PegoutRequest) {
        assert!(self.proposal.pegouts.insert(pegout.request, pegout).is_none());
        self.undo.push(UndoAction::AddPegout(pegout.request));
    }

    fn add_change(&mut self, amount: u64) {
        self.proposal.change.push(amount);
        self.undo.push(UndoAction::AddChange(amount));
    }

    fn update_conflict_sets(&mut self, new_reqs: HashSet<&'utxo SpendableUtxo>) {
        let mut satisfied_conflicts = false;
        for (n, existing_set) in self.proposal.conflict_input_sets.iter_mut().enumerate() {
            if !existing_set.is_disjoint(&new_reqs) {
                let inter = existing_set.intersection(&new_reqs).cloned().collect();
                let old_set = mem::replace(existing_set, inter);
                self.undo.push(UndoAction::ReplaceConflictSet(n, old_set));
                satisfied_conflicts = true;
                break;
            }
        }
        if !satisfied_conflicts {
            self.proposal.conflict_input_sets.push(new_reqs);
            self.undo.push(UndoAction::AddConflictSet);
        }
    }

    fn clear_undo(&mut self) {
        self.undo.clear();
    }
}

impl<'a, 'utxo: 'a, 'pegout: 'a> Drop for ProposalUpdate<'a, 'utxo, 'pegout> {
    fn drop(&mut self) {
        for item in mem::replace(&mut self.undo, vec![]) {
            match item {
                UndoAction::AddInput(utxo) => {
                    self.proposal.inputs.remove(&utxo);
                },
                UndoAction::AddPegout(request) => {
                    self.proposal.pegouts.remove(&request);
                },
                UndoAction::AddChange(amount) => {
                    let idx = self.proposal.change.iter().enumerate()
                        .rfind(|(_, c)| **c == amount).unwrap().0;
                    self.proposal.change.remove(idx);
                },
                UndoAction::AddConflictSet => {
                    self.proposal.conflict_input_sets.pop();
                },
                UndoAction::ReplaceConflictSet(idx, set) => {
                    self.proposal.conflict_input_sets[idx] = set;
                },
            }
        }
    }
}

/// An under-construction transaction proposal
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proposal<'utxo, 'pegout> {
    /// Set of inputs to spend.
    inputs: HashSet<&'utxo SpendableUtxo>,
    /// Sets of inputs needed to satisfy conflict requirements. At least
    /// one input from each set must be included in the final transaction.
    conflict_input_sets: Vec<HashSet<&'utxo SpendableUtxo>>,
    /// Set of pegout requests to process, with cached `TxOut` weight
    pegouts: HashMap<elements::OutPoint, &'pegout PegoutRequest>,
    /// Change `scriptPubKey`
    change_script_pubkey: &'pegout bitcoin::Script,
    /// Cached size of the change output.
    change_txout_size: usize,
    /// Set of change outputs to add
    change: Vec<u64>,
}

impl<'utxo, 'pegout> Proposal<'utxo, 'pegout> {
    /// Create a new empty transaction proposal with nothing except
    /// a single dust-change output
    pub fn new(change_spk: &'pegout bitcoin::Script) -> Proposal {
        Proposal {
            inputs: Default::default(),
            conflict_input_sets: Default::default(),
            pegouts: Default::default(),
            change_script_pubkey: change_spk,
            change_txout_size: Proposal::txout_size(change_spk),
            change: vec![constants::MINIMUM_DUST_CHANGE],
        }
    }

    /// Helper to determine the size in bytes of an output, given a `scriptPubKey`
    fn txout_size(spk: &bitcoin::Script) -> usize {
        let spk_len = spk.len();
        let vi_len = bitcoin::VarInt(spk_len as u64).len();
        8 + vi_len + spk_len
    }

    /// Helper to determine the set of additional inputs to include to satisfy
    /// conflict requirements. It starts with the list of `conflict_input_sets`,
    /// and attempts to take a single input from each set in the list. It does
    /// this by computing the weight of each possible choice and choosing the
    /// one with the least weight; in doing so, it also looks at the existing
    /// set of inputs in the proposal, which it considers to have weight 0.
    /// This is because it's a no-op to add an already-added input to the
    /// transaction.
    fn conflict_set(&self) -> HashSet<&'utxo SpendableUtxo> {
        let mut chosen = HashSet::new();
        for set in &self.conflict_input_sets {
            let choice = set
                .iter()
                .copied()
                .min_by_key(|utxo| {
                    if self.inputs.contains(utxo) || chosen.contains(utxo) {
                        0
                    } else {
                        utxo.signed_input_weight()
                    }
                })
                .unwrap(); // unwrap OK as all sets are nonempty

            if !self.inputs.contains(&choice) {
                chosen.insert(choice);
            }
        }
        chosen
    }

    /// The unsigned tx size in bytes for the proposal tx.
    pub fn unsigned_size(&self) -> usize {
        let conflicts = self.conflict_set();
        let n_inputs = self.inputs.len() + conflicts.len();
        let n_outputs = self.pegouts.len() + self.change.len();

        conflicts.iter().map(|u| u.unsigned_input_size()).sum::<usize>()
            + self.inputs.iter().map(|u| u.unsigned_input_size()).sum::<usize>()
            + self.pegouts.values().map(|r| r.txout_size()).sum::<usize>()
            + self.change.len() * self.change_txout_size
            + if n_inputs >= 253 { 3 } else { 1 }
            + if n_outputs >= 253 { 3 } else { 1 }
            + if n_inputs > 0 { 2 } else { 0 } // segwit flags
            + 8 // version (4), locktime (4)
    }

    /// Estimates the fully signed weight of a transaction
    fn signed_weight(&self) -> usize {
        let conflicts = self.conflict_set();
        let n_inputs = self.inputs.len() + conflicts.len();
        let n_outputs = self.pegouts.len() + self.change.len();

        conflicts.iter().map(|u| u.signed_input_weight()).sum::<usize>()
            + self.inputs.iter().map(|u| u.signed_input_weight()).sum::<usize>()
            + self.pegouts.values().map(|r| 4 * r.txout_size()).sum::<usize>()
            + self.change.len() * 4 * self.change_txout_size
            + if n_inputs >= 253 { 12 } else { 4 }
            + if n_outputs >= 253 { 12 } else { 4 }
            + if n_inputs > 0 { 2 } else { 0 } // segwit flags
            + 32 // version (16), locktime (16)
    }

    /// Checks that the signed weight (also returned) is within
    /// bounds of the maximum proposal weight.
    pub fn check_signed_weight(&self) -> Result<usize, ProposalError> {
        let weight = self.signed_weight();

        if weight > constants::MAX_PROPOSAL_TX_WEIGHT {
            Err(ProposalError::Oversize {
                got: weight,
                max: constants::MAX_PROPOSAL_TX_WEIGHT,
            })
        } else {
            Ok(weight)
        }
    }

    /// (Attempt to) add a single input to the proposal. If the
    /// input already exists this is a no-op.
    pub fn add_input(
        &mut self,
        fee_pool: &fee::Pool,
        utxo: &'utxo SpendableUtxo,
    ) -> Result<(), blockchain::Error> {
        let mut update = ProposalUpdate::new(self);
        update.add_input(utxo);
        let tx_weight = update.proposal.check_signed_weight()?;
        let fee = fee_pool.calculate_fee(tx_weight);
        fee_pool.validate_fee(tx_weight, fee)?;
        update.clear_undo();
        Ok(())
    }

    /// Add inputs to the proposal until it balances, failing if it runs
    /// out of available UTXOs or if the resulting transaction would exceed
    /// the maximum weight.
    pub fn add_inputs<I>(&mut self, fee_pool: &fee::Pool, utxos: I) -> Result<(), blockchain::Error>
        where I: Iterator<Item=&'utxo SpendableUtxo>,
    {
        let mut update = ProposalUpdate::new(self);
        update.add_inputs(fee_pool, utxos)?;
        update.clear_undo();
        Ok(())
    }

    /// Add a pegout to the transaction, as well as necessary conflict
    /// requirements and sufficient inputs to rebalance the transaction
    pub fn add_pegout<I, F, P>(
        &mut self,
        pegout: &'pegout PegoutRequest,
        fee_pool: &fee::Pool,
        input_exclude: &HashSet<bitcoin::OutPoint>,
        utxos: I,
        mut conflict_lookup: F,
        validate_pak_proof: &P,
    ) -> Result<(), blockchain::Error> where
        I: Iterator<Item=&'utxo SpendableUtxo>,
        F: FnMut(&bitcoin::OutPoint) -> &'utxo SpendableUtxo,
        P: Fn(&PegoutRequest) -> Result<(), hsm::Error>,
    {
        let mut update = ProposalUpdate::new(self);

        // 0. Check whether the parent of this pegout is included
        if let Some(previous) = pegout.previous_request {
            if !update.proposal.pegouts.contains_key(&previous) {
                return Err(ProposalError::SkippedPegout {
                    request: pegout.request,
                    previous: previous,
                }.into());
            }
        }

        // 1. Deal with conflict-tracker requirements
        if !pegout.required_conflicts.is_empty() {
            // Look up data and filter excluded inputs
            let new_requirements: HashSet<_> = pegout
                .required_conflicts
                .difference(input_exclude)
                .map(|outpoint| conflict_lookup(outpoint))
                .collect();
            if new_requirements.is_empty() {
                return Err(ProposalError::NoAvailableConflicts(pegout.request).into());
            }
            update.update_conflict_sets(new_requirements);
        }

        // 2. Add the pegout
        update.add_pegout(pegout);

        // 3. Try to rebalance
        update.add_inputs(fee_pool, utxos)?;

        // 4. Let the HSM check whether the PAK proof is valid.
        // We do this check last because it takes a long time and we might have
        // already failed by some of the earlier checks (f.e. size checks).
        validate_pak_proof(pegout)?;

        update.clear_undo();
        Ok(())
    }

    /// Add a single change output.
    fn add_change(&mut self, fee_pool: &fee::Pool, amount: u64) -> Result<(), ProposalError> {
        let mut update = ProposalUpdate::new(self);
        update.add_change(amount);
        let tx_weight = update.proposal.check_signed_weight()?;
        let fee = fee_pool.calculate_fee(tx_weight);
        fee_pool.validate_fee(tx_weight, fee)?;
        update.clear_undo();
        Ok(())
    }

    /// The amount of change that is left over, if any.
    /// Returns [None] if there is already not enough change.
    fn leftover_change(&self, fee_pool: &fee::Pool) -> Option<u64> {
        let input = self.input_value();
        let output = self.output_value();
        let weight = self.signed_weight();
        let fee = fee_pool.calculate_fee(weight);
        input.checked_sub(output + fee)
    }

    /// Helper to set the change output(s) to ensure the transaction has
    /// a sane feerate
    pub fn adjust_change<I>(
        &mut self,
        fee_pool: &fee::Pool,
        utxos: I,
        desired_n_main_outputs: usize,
        n_outputs_with_pending: usize,
    ) where I: Iterator<Item=&'utxo SpendableUtxo> {
        // Assert that we're calling this function before any other operation
        // that may have affected the change distribution. In particular, we
        // assume that the coin selection put an initial "dummy change" output
        // in place, which it used for weight/input-output balance computation
        // but otherwise ignored.
        assert_eq!(self.change, &[constants::MINIMUM_DUST_CHANGE]);
        assert!(n_outputs_with_pending >= self.inputs.len(),
                "{} < {}", n_outputs_with_pending, self.inputs.len());

        let mut extra_change = self.leftover_change(fee_pool)
            .expect("tx should balance at this point because of call to add_inputs");

        // Aside from the one default change output, we might want to add some
        // more change outputs because we want our wallet to have a certain
        // number of total UTXOs. However, if we're close enough to our target,
        // (expressed as the "radius"), we don't yet add more.
        let n_outputs = n_outputs_with_pending - self.inputs.len();
        let clamped_desired = desired_n_main_outputs.saturating_sub(constants::N_MAIN_OUTPUTS_RADIUS);

        if n_outputs < clamped_desired {
            let desired_n_change = cmp::min(
                desired_n_main_outputs - n_outputs,
                constants::MAXIMUM_CHANGE_OUTPUTS,
            );

            let n_to_add = desired_n_change - 1; // already have one change output
            // (4 weight multiplier and 2 bytes for potential nOut VarInt increase)
            let change_fee = fee_pool.calculate_fee(4 * (2 + n_to_add * self.change_txout_size));
            let val_to_add = n_to_add as u64 * constants::MINIMUM_OPPORTUNISTIC_CHANGE + change_fee;
            if extra_change < val_to_add {
                // Try adding our currently highest-valued UTXO to the
                // proposal, with the intent of splitting it up.
                if let Some(max) = utxos.max_by_key(|utxo| utxo.value) {
                    if self.add_input(fee_pool, max).is_ok() {
                        // Recompute weight and input value; this should have
                        // changed, but may not have, e.g. if the input we
                        // just added was already going to be added in order
                        // to satisfy a conflict requirement.

                        extra_change = self.leftover_change(fee_pool)
                            .expect("add_input makes sure input is economical");
                    }
                }
            }

            // Add as many change outputs as we can
            let new_change_val = constants::MINIMUM_OPPORTUNISTIC_CHANGE;
            while self.change.len() < desired_n_change && extra_change >= new_change_val {
                // Try to add a new change output and revert in case not ok.
                if self.add_change(fee_pool, new_change_val).is_err() {
                    break;
                }

                if let Some(change) = self.leftover_change(fee_pool) {
                    extra_change = change;
                } else {
                    self.change.pop();
                    break;
                }
            }
        }

        // Adjust all the change outputs to consume the remainder
        // of the change
        let change_adj = extra_change / self.change.len() as u64;
        for i in 1..self.change.len() {
            self.change[i] += change_adj;
            extra_change -= change_adj;
        }
        self.change[0] += extra_change;
        debug_assert_eq!(Some(0), self.leftover_change(fee_pool));

        // Done. Let's do some sanity checks.
        let total_in = self.input_value();
        let total_out = self.output_value();
        debug_assert!(total_out <= total_in);
        let fee = total_in - total_out;
        let target_fee = fee_pool.calculate_fee(self.signed_weight());
        debug_assert!(fee >= target_fee,
            "final fee of {} undershoots target fee of {}", fee, target_fee,
        );
    }

    /// Accessor for the number of inputs in the final transaction
    pub fn n_inputs(&self) -> usize {
        let conflicts = self.conflict_set();
        self.inputs.len() + conflicts.len()
    }

    /// Accessor for the total number pegouts in the final transaction
    pub fn n_pegouts(&self) -> usize {
        self.pegouts.len()
    }

    /// Total value of all inputs, including conflict requirements.
    /// weight, which is 160 wu less).
    pub fn input_value(&self) -> u64 {
        let conflicts = self.conflict_set();
        self.inputs.iter().map(|utxo| utxo.value).sum::<u64>()
            + conflicts.iter().map(|utxo| utxo.value).sum::<u64>()
    }

    /// Total value of all outputs, including change
    pub fn output_value(&self) -> u64 {
        self.pegouts.values().map(|req| req.dest_output.value).sum::<u64>()
            + self.change.iter().cloned().sum::<u64>()
    }

    /// Instantiates the proposal by choosing specific inputs for conflicts
    /// and putting everything in order
    pub fn to_concrete(&self) -> ConcreteProposal {
        let conflicts = self.conflict_set();

        let mut inputs = Vec::with_capacity(
            self.inputs.len() + conflicts.len(),
        );
        inputs.extend(self.inputs.iter().map(|utxo| utxo.outpoint));
        inputs.extend(conflicts.iter().map(|utxo| utxo.outpoint));

        ConcreteProposal {
            inputs: inputs,
            pegouts: self.pegouts.keys().cloned().collect(),
            change: self.change.clone(),
        }
    }
}

/// A completed transaction proposal, ready for network transmission
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConcreteProposal {
    /// List of inputs to spend
    pub inputs: Vec<bitcoin::OutPoint>,
    /// List of pegouts to process
    pub pegouts: Vec<elements::OutPoint>,
    /// List of change outputs to add
    pub change: Vec<u64>,
}

impl ConcreteProposal {
    /// Create a [HashSet] with the inputs of this proposal.
    pub fn input_set(&self) -> HashSet<bitcoin::OutPoint> {
        self.inputs.iter().copied().collect()
    }
}

/// Helper structure to indicate the fee-checking behaviour
/// of a conversion from a transaction proposal to an unsigned
/// transaction
pub enum FeeCheck<'a> {
    /// Validate that the transaction fee is sane
    Validate(&'a fee::Pool),
    /// Validate that the transaction fee is sane, and dock its
    /// fees from the fee pool (temporarily)
    Dock(&'a mut fee::Pool),
    /// Dock its fees from the fee pool (temporarily) without
    /// checking whether the fee is reasonable
    ForceDock(&'a mut fee::Pool),
    /// Finalize the transaction
    Confirm(&'a mut fee::Pool),
    /// Don't do any fee-checking. Only useful for testing.
    None,
}

impl ConcreteProposal {
    /// Helper function to estimate the signed weight of a transaction.
    /// Assumes the `scriptSig` of every input is blank.
    pub fn signed_weight(
        unsigned_tx: &bitcoin::Transaction,
        input_map: &HashMap<bitcoin::OutPoint, &SpendableUtxo>,
    ) -> usize {
        assert!(
            unsigned_tx.input.iter().all(|txin| txin.script_sig.is_empty())
        );
        // +2 for segwit flag and marker byte;
        // -4 for empty scriptSig in each input of `unsigned_tx`
        unsigned_tx.weight() as usize
            + 2
            + input_map
                .values()
                .map(|utxo| utxo.descriptor.satisfaction_weight() - 4)
                .sum::<usize>()
    }

    /// Expand a proposal to a full transaction
    pub fn to_unsigned_tx<'u, 'p, U, P>(
        &self,
        mut utxo_lookup: U,
        mut pegout_lookup: P,
        change_spk: &bitcoin::Script,
        fee_check: FeeCheck,
    ) -> Result<(bitcoin::Transaction, Vec<SpendableUtxo>), ProposalError> where
        U: FnMut(&bitcoin::OutPoint) -> Option<&'u Utxo>,
        P: FnMut(&elements::OutPoint) -> Option<&'p PegoutRequest>,
    {
        // Easy sanity checks
        if self.change.is_empty() ||
            self.change.len() > constants::MAXIMUM_CHANGE_OUTPUTS
        {
            return Err(ProposalError::BadChangeCount {
                got: self.change.len(),
                min: 1,
                max: constants::MAXIMUM_CHANGE_OUTPUTS,
            });
        }

        let mut input_map = HashMap::new();
        let mut unknown_inputs = Vec::new();
        for input in &self.inputs {
            if let Some(utxo) = (&mut utxo_lookup)(input) {
                match utxo {
                    Utxo::Unspendable(_) => {
                        return Err(ProposalError::UnspendableInput(*input));
                    }
                    Utxo::Spendable(utxo) | Utxo::OnlyReclaimable(utxo) => {
                        if input_map.insert(*input, utxo).is_some() {
                            return Err(ProposalError::DuplicateInput(*input));
                        }
                    }
                }
            } else {
                unknown_inputs.push(*input);
            }
        }
        if !unknown_inputs.is_empty() {
            return Err(ProposalError::UnknownInputs(unknown_inputs));
        }

        let mut pegout_map = HashMap::new();
        for pegout in &self.pegouts {
            if let Some(request) = (&mut pegout_lookup)(pegout) {
                if pegout_map.insert(*pegout, request).is_some() {
                    return Err(ProposalError::DuplicatePegout(*pegout));
                }
                if let Some(previous) = request.previous_request {
                    if !self.pegouts.contains(&previous) {
                        return Err(ProposalError::SkippedPegout {
                            request: *pegout,
                            previous: previous,
                        });
                    }
                }
            } else {
                return Err(ProposalError::UnknownPegout(*pegout));
            }
        }

        for amount in &self.change {
            if *amount < constants::MINIMUM_DUST_CHANGE {
                return Err(ProposalError::BadChangeAmount {
                    got: *amount,
                    min: constants::MINIMUM_DUST_CHANGE,
                });
            }
        }

        let input_value = input_map.values().map(|utxo| utxo.value).sum::<u64>();
        let output_value = pegout_map.values().map(|req| req.dest_output.value).sum::<u64>()
            + self.change.iter().cloned().sum::<u64>();
        if output_value > input_value {
            return Err(ProposalError::Unbalanced {
                input_value: input_value,
                output_value: output_value,
            });
        }

        // Build transaction without scriptSigs so we can more easily
        // estimate their weight.
        let mut outputs = Vec::with_capacity(
            self.pegouts.len() + self.change.len()
        );
        outputs.extend(self.pegouts.iter().map(|out| pegout_map[out].dest_output.clone()));
        outputs.extend(self.change.iter().map(|val| bitcoin::TxOut {
            value: *val,
            script_pubkey: change_spk.clone(),
        }));

        let mut unsigned_tx = bitcoin::Transaction {
            version: 1,
            lock_time: 0,
            input: self.inputs.iter().map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: bitcoin::Script::new(),
                sequence: 0xffffffff,
                witness: bitcoin::Witness::default(),
            }).collect(),
            output: outputs,
        };

        let signed_weight = ConcreteProposal::signed_weight(&unsigned_tx, &input_map);
        if signed_weight > constants::MAXIMUM_TX_WEIGHT {
            return Err(ProposalError::Oversize {
                got: signed_weight,
                max: constants::MAXIMUM_TX_WEIGHT,
            });
        }

        // Now add scriptSigs. Must be done before feepool updates to ensure
        // that the feepool records the correct txid (see bug #177), but
        // after weight calculation, since otherwise the `satisfaction_weight`
        // method we used for that would have double-counted the scriptSigs.
        for txin in &mut unsigned_tx.input {
            txin.script_sig = input_map[&txin.previous_output].descriptor.unsigned_script_sig();
        }

        slog!(CreatedUnsignedTx, txid: unsigned_tx.txid(),
            unsigned_weight: unsigned_tx.weight() as usize,
            estimated_signed_weight: signed_weight
        );

        let fee = input_value - output_value;
        match fee_check {
            FeeCheck::Validate(fee_pool) => {
                fee_pool.validate_fee(signed_weight, fee)?;
            },
            FeeCheck::Dock(fee_pool) => {
                fee_pool.validate_fee(signed_weight, fee)?;
                fee_pool.temporarily_dock_tx(&unsigned_tx, fee);
            },
            FeeCheck::ForceDock(fee_pool) => {
                fee_pool.temporarily_dock_tx(&unsigned_tx, fee);
            },
            FeeCheck::Confirm(fee_pool) => {
                // Dock fees in case this hasn't already happened (see #225)
                fee_pool.temporarily_dock_tx(&unsigned_tx, fee);
                fee_pool.confirm(&unsigned_tx.txid());
            },
            FeeCheck::None => {},
        }

        let inputs = self.inputs.iter().map(|outpoint| input_map[outpoint].clone()).collect();
        Ok((unsigned_tx, inputs))
    }
}

impl message::NetEncodable for ConcreteProposal {
    fn encode<W: io::Write>(&self, mut w: W) -> Result<usize, message::Error> {
        let mut len = 0;
        len += message::NetEncodable::encode(&self.inputs, &mut w)?;
        len += message::NetEncodable::encode(&self.pegouts, &mut w)?;
        len += message::NetEncodable::encode(&self.change, &mut w)?;
        Ok(len)
    }

    fn decode<R: io::Read>(mut r: R) -> Result<Self, message::Error> {
        Ok(ConcreteProposal {
            inputs: message::NetEncodable::decode(&mut r)?,
            pegouts: message::NetEncodable::decode(&mut r)?,
            change: message::NetEncodable::decode(&mut r)?,
        })
    }
}

/// Temporary structure used to call Miniscript's `satisfy` function
struct Satisfier<'a, 's, C: secp256k1::Verification> {
    sighash: secp256k1::Message,
    input_idx: usize,
    secp: &'s Secp256k1<C>,
    peer_sigs: &'a HashMap<peer::Id, &'a TransactionSignatures>,
    sig_results: cell::RefCell<&'a mut HashMap<peer::Id, SigResult>>,
}

impl<'a, 's, C> miniscript::Satisfier<tweak::Key> for Satisfier<'a, 's, C>
    where C: secp256k1::Verification,
{
    fn lookup_ecdsa_sig(&self, key: &tweak::Key) -> Option<bitcoin::EcdsaSig> {
        let (id, pk) = match *key {
            tweak::Key::Tweakable(id, pk) => (id, pk),
            tweak::Key::Tweaked { peer, tweaked_pk, .. } => (peer, tweaked_pk),
            tweak::Key::TweakedNonFunc { .. }
            | tweak::Key::NonFunctionary(..)
            | tweak::Key::Untweakable(..) => {
                slog!(CombineSigs, input_idx: self.input_idx, key: key.to_string(), id: None,
                    sig_result: &format!("{}", SigResult::NonTweakableKey), msg: "",
                );
                return None;
            }
        };

        let mut sig_results = self.sig_results.borrow_mut();
        let result = sig_results.entry(id).or_insert(SigResult::Good);

        let sigs = match self.peer_sigs.get(&id) {
            Some(sigs) => sigs,
            _ => {
                result.update(SigResult::Missing);
                slog!(CombineSigs, input_idx: self.input_idx, key: key.to_string(), id: Some(id),
                    sig_result: &format!("{}", result), msg: "",
                );
                return None;
            }
        };

        if sigs.0.len() > self.input_idx {
            let (sig, sighash) = sigs.0[self.input_idx];
            if sighash != bitcoin::EcdsaSighashType::All {
                slog!(CombineSigs, input_idx: self.input_idx, key: key.to_string(), id: Some(id),
                    sig_result: &format!("{}", SigResult::NotSighashAll),
                    msg: &format!("sighash_flag: {:?}", sighash).to_string(),
                );
                result.update(SigResult::NotSighashAll);
                None // bad sighash flag
            } else if self.secp.verify_ecdsa(&self.sighash, &sig, &pk).is_err() {
                slog!(CombineSigs, input_idx: self.input_idx, key: key.to_string(), id: Some(id),
                    sig_result: &format!("{}", SigResult::Invalid),
                    msg: &format!("invalid_sig: {}", sig).to_string(),
                );
                result.update(SigResult::Invalid);
                None // invalid sig
            } else {
                slog!(CombineSigs, input_idx: self.input_idx, key: key.to_string(), id: Some(id),
                    sig_result: &format!("{}", SigResult::Good), msg: "",
                );
                let (sig, hash_ty) = sigs.0[self.input_idx];
                let ecdsa_sig = bitcoin::EcdsaSig {
                    sig,
                    hash_ty,
                };
                Some(ecdsa_sig)
            }
        } else {
            slog!(CombineSigs, input_idx: self.input_idx, key: key.to_string(), id: Some(id),
                sig_result: &format!("{}", SigResult::Missing), msg: "",
            );
            result.update(SigResult::Missing);
            None // not enough sigs
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin;
    use bitcoin::consensus::deserialize;
    use bitcoin::util::sighash::SighashCache;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::secp256k1::{Secp256k1, ecdsa::Signature};

    use miniscript::TranslatePk;
    use tweak::{self, Tweak};
    use watchman::utxotable::SpendableUtxo;
    use super::*;

    /// Convert owned hashmap into hashmap of refs
    fn ref_sigs(sigs: &HashMap<peer::Id, TransactionSignatures>) -> HashMap<peer::Id, &TransactionSignatures> {
        sigs.iter().map(|(k, v)| (*k, v)).collect()
    }

    #[test]
    fn bip143_sig() {
        let secp = Secp256k1::new();

        let tx = deserialize::<bitcoin::Transaction>(
            &hex!("
                010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000
                ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f
                05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000
            ")[..],
        ).unwrap();

        let inputs = vec![
            SpendableUtxo::new(Default::default(), 987654321, 0, Tweak::none(), "\
                wsh(multi(\
                    6,\
                    [416e64726577]0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3,\
                    [untweaked]03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b,\
                    [untweaked]034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a,\
                    [untweaked]033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4,\
                    [untweaked]03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16,\
                    [untweaked]02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b\
                ))\
            ".parse().unwrap()),
        ];

        let witness0 = inputs[0].descriptor.liquid_witness_script();

        let my_id = peer::Id::from(&b"Andrew"[..]);
        let mut sigs = HashMap::new();

        let mut cache = SighashCache::new(&tx);
        assert_eq!(
            cache.segwit_signature_hash(0, &witness0, inputs[0].value, bitcoin::EcdsaSighashType::All).unwrap(),
            bitcoin::Sighash::from_hex(
                "7cee48b240dc974544893a10d0fb2b27b6c17379040ab54b5bce3d26e50b5c18"
            ).unwrap()
        );

        // missing sig
        let tx_res = assemble_tx(&secp, &tx, &mut cache, &inputs, &ref_sigs(&sigs));
        assert!(tx_res.is_err());

        // invalid sig (wrong sighash)
        sigs.insert(my_id, TransactionSignatures(vec![(
            Signature::from_str("\
                304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2\
                b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce\
            ").unwrap(),
            bitcoin::EcdsaSighashType::None,
        )]));
        let tx_res = assemble_tx(&secp, &tx, &mut cache, &inputs, &ref_sigs(&sigs));
        assert!(tx_res.is_err());

        // invalid sig (last bit flipped from a valid sig)
        sigs.insert(my_id, TransactionSignatures(vec![(
            Signature::from_str("\
                304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2\
                b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870cf\
            ").unwrap(),
            bitcoin::EcdsaSighashType::All,
        )]));
        let tx_res = assemble_tx(&secp, &tx, &mut cache, &inputs, &ref_sigs(&sigs));
        assert!(tx_res.is_err());

        // good sig
        sigs.insert(my_id, TransactionSignatures(vec![(
            Signature::from_str("\
                304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2\
                b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce\
            ").unwrap(),
            bitcoin::EcdsaSighashType::All,
        )]));
        let tx_res = assemble_tx(&secp, &tx, &mut cache, &inputs, &ref_sigs(&sigs));
        assert!(tx_res.is_err()); // without 5 more sigs we can't actually finish the tx

        // extra sigs shouldn't hurt anything
        sigs.insert(my_id, TransactionSignatures(vec![(
            Signature::from_str("\
                304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2\
                b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce\
            ").unwrap(),
            bitcoin::EcdsaSighashType::All,
        ), (
            Signature::from_str("\
                304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2\
                b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce\
            ").unwrap(),
            bitcoin::EcdsaSighashType::All,
        )]));
        let tx_res = assemble_tx(&secp, &tx, &mut cache, &inputs, &ref_sigs(&sigs));
        assert!(tx_res.is_err()); // without 5 more sigs we can't actually finish the tx
    }

    #[test]
    fn bip143_sig_multiple_inputs() {
        let secp = Secp256k1::new();

        let tx = deserialize::<bitcoin::Transaction>(
            &hex!("
                0200000002d79d61bc1675a9e6dc375d4c09fe657127353fedc6ef92a57d705be900143a950100000000ff
                ffffff460458a7dbce6d8ec40d19fdba6ac92edc070db6b8348161cdbe89d0c333b95d0100000000ffffff
                ff0100e1f505000000001976a9146b5a9dc33db1ad1ef6ae81042a0d77825e8f176188ac00000000
            ")[..],
        ).unwrap();

        let saberhagen_id = peer::Id::from(&b"Saberh"[..]);
        let nakamoto_id = peer::Id::from(&b"Nakamo"[..]);
        let mouton_id = peer::Id::from(&b"Mouton"[..]);
        // descriptor from the watchman integration tests but with a 2-of-3 policy instead
        // of 3-of-3.
        let descriptor: miniscript::Descriptor<tweak::Key> = FromStr::from_str(
            &format!(
                "sh(wsh\
                    (or_d\
                        (multi(2,\
                            [{}]023c9cd9c6950ffee24772be948a45dc5ef1986271e46b686cb52007bac214395a,\
                            [{}]0336ea361f136591ff60aa4d85e7e3faa9aa5758551fb9e7971fdc492288a19de7,\
                            [{}]03fa40da236bd82202a985a9104e851080b5940812685769202a3b43e4a8b13e6a),\
                        and_v(\
                            v:older(10000),\
                            multi(1,\
                                  [untweaked]023303dedc51b9d227b17c9fb4710f96b844e1ccdc2c776e1b7274bd4e246b6202,\
                                  [untweaked]03024c3b4f830854d6d26d6e34d92aff4c703bf57e85cd42abe328d928e01d4286,\
                                  [untweaked]03fe4e8c8d99b9dcbb529a87d54f606bae0149a34018325547fa0c2239e038a1c9)\
                   ))))",
                saberhagen_id, nakamoto_id, mouton_id)).unwrap();
        let inputs = vec![
            SpendableUtxo::new(Default::default(), 10000000, 0, Tweak::none(), descriptor.clone()),
            SpendableUtxo::new(Default::default(), 100000000, 0, Tweak::none(), descriptor.clone()),
        ];
        let witness0 = inputs[0].descriptor.liquid_witness_script();
        let witness1 = inputs[1].descriptor.liquid_witness_script();

        let mut cache = SighashCache::new(&tx);
        // Note that the message actually signed are the *reverse* of the byte strings below
        assert_eq!(
            cache.segwit_signature_hash(0, &witness0, inputs[0].value, bitcoin::EcdsaSighashType::All).unwrap(),
            bitcoin::Sighash::from_hex(
                "a1b5cb6a46647d5950fad46a1a394a02c045aa2814101cac0f58ec06f6fdca7d"
            ).unwrap()
        );
        assert_eq!(
            cache.segwit_signature_hash(1, &witness1, inputs[1].value, bitcoin::EcdsaSighashType::All).unwrap(),
            bitcoin::Sighash::from_hex(
                "e0dd62c5f33c80bb19820bc84102ec67117ca738910a90fc74cf6edfa6052ada"
            ).unwrap()
        );
        let mut sigs = HashMap::new();
        // These signatures were computed with the "sighacker" CLI program as
        // ./sighacker <secret key> <message>
        sigs.insert(saberhagen_id, TransactionSignatures(vec![(
            // sighacker sign 11b7e73fcc3bf4cd2e0ea4452942e438a7cb0142bb75b135822c964a7b17b066 7dcafdf606ec580fac1c101428aa45c0024a391a6ad4fa50597d64466acbb5a1
            Signature::from_str("\
                3045022100e783f89e9185c02f8a9edc95b380a4a1402894a46c52e8e1597c36d0ec1d7c6002200dffe\
                d8134262a286c462fdf65f00b5755f77982df50cc86df386bab3376f9bb\
            ").unwrap(),
            bitcoin::EcdsaSighashType::All,
        ), (
            // sighacker sign 11b7e73fcc3bf4cd2e0ea4452942e438a7cb0142bb75b135822c964a7b17b066 da2a05a6df6ecf74fc900a9138a77c1167ec0241c80b8219bb803cf3c562dde0
            Signature::from_str("\
                3045022100e473896f594d13c9007779a42788b5d384c3c3010175177c5cd4ef0960a00c3f022030662\
                2b1d9cb8d31f662abb9f0dc6132e32abd62a41d026ba7f23dc8f08dc711\
            ").unwrap(),
            bitcoin::EcdsaSighashType::All,
        )]));
        sigs.insert(nakamoto_id, TransactionSignatures(vec![(
            // sighacker sign eaab94ee982e57b7d0717509a518ed6a6f8dfc0eb4963297fc48c58322b791cb 7dcafdf606ec580fac1c101428aa45c0024a391a6ad4fa50597d64466acbb5a1
            Signature::from_str("\
                30440220511192b12830920cd2d61534a612a1fedd0d90affc0a8b0e60a36b92bb716a3602204f1e507\
                28fb506ebbc66eb8d4bfb32d50f011eb1765f6bddb84ee83df567886b\
            ").unwrap(),
            bitcoin::EcdsaSighashType::All,
        ), (
            // sighacker sign eaab94ee982e57b7d0717509a518ed6a6f8dfc0eb4963297fc48c58322b791cb da2a05a6df6ecf74fc900a9138a77c1167ec0241c80b8219bb803cf3c562dde0
            Signature::from_str("\
                3045022100bbd392e5fbe30b592f08523598862305e19051f0535107ab5bfd3f543260abcf022003707\
                f44f411d37e3a99bb7915c94742335abe250b458786489bfbadaaa5d5b5\
            ").unwrap(),
            bitcoin::EcdsaSighashType::All,
        )]));
        sigs.insert(mouton_id, TransactionSignatures(vec![(
            // sighacker sign 020936aea439583c98c82c013af023b2355e4bc25049b52d4edae0c8578fcd0b 7dcafdf606ec580fac1c101428aa45c0024a391a6ad4fa50597d64466acbb5a1
            Signature::from_str("\
                3045022100bfa740fedc2abe6cea87af3c0d48ba07f05419be5eec19363bd63e3ba25d09d902206a3bb\
                f0890a314451334b117372646463f65478908cefa4db1a116fdd48284d7\
            ").unwrap(),
            bitcoin::EcdsaSighashType::All,
        ), (
            // sighacker sign 020936aea439583c98c82c013af023b2355e4bc25049b52d4edae0c8578fcd0b da2a05a6df6ecf74fc900a9138a77c1167ec0241c80b8219bb803cf3c562dde0
            Signature::from_str("\
                304402202df113f07a8c251135956875c28484d6adac627bf8de8243e2f18ddc4301fe9802202604b63\
                09e3dfe812179f00f42c8fe259991db5d02e65cd3ee0fb17e26ff06d4\
            ").unwrap(),
            bitcoin::EcdsaSighashType::All,
        )]));

        // All signatures present
        let tx_res = assemble_tx(&secp, &tx, &mut cache, &inputs, &ref_sigs(&sigs));
        assert!(tx_res.is_ok());
        // NULLDUMMY, signature, signature, witness script
        assert_eq!(tx_res.unwrap().input[0].witness.len(), 4);

        // Nakamoto completely missing
        let mut sigs_tmp = sigs.clone();
        sigs_tmp.remove(&nakamoto_id);
        let tx_res = assemble_tx(&secp, &tx, &mut cache, &inputs, &ref_sigs(&sigs_tmp));
        assert!(tx_res.is_ok());
        assert_eq!(tx_res.unwrap().input[0].witness.len(), 4);

        // Nakamoto sent one invalid and one good signature and Mouton sent one
        // good and one invalid signature.
        let mut sigs_tmp = sigs.clone();
        let mut nakamoto_sigs = sigs_tmp.remove(&nakamoto_id).unwrap()[..].to_vec();
        let mut mouton_sigs = sigs_tmp.remove(&mouton_id).unwrap()[..].to_vec();
        {
            let saberhagen_sigs = &sigs_tmp.get(&saberhagen_id).unwrap()[..];
            nakamoto_sigs[0] = saberhagen_sigs[0];
            mouton_sigs[1] = saberhagen_sigs[1];
        }
        sigs_tmp.insert(nakamoto_id, TransactionSignatures(nakamoto_sigs));
        sigs_tmp.insert(mouton_id, TransactionSignatures(mouton_sigs));
        let tx_res = assemble_tx(&secp, &tx, &mut cache, &inputs, &ref_sigs(&sigs_tmp));
        assert!(tx_res.is_ok());
        assert_eq!(tx_res.unwrap().input[0].witness.len(), 4);

        // Everyone sends an invalid signature for the first input
        let mut sigs_tmp = sigs.clone();
        let mut nakamoto_sigs = sigs_tmp.remove(&nakamoto_id).unwrap()[..].to_vec();
        let mut saberhagen_sigs = sigs_tmp.remove(&saberhagen_id).unwrap()[..].to_vec();
        let mut mouton_sigs = sigs_tmp.remove(&mouton_id).unwrap()[..].to_vec();
        nakamoto_sigs[0] = saberhagen_sigs[0];
        saberhagen_sigs[0] = mouton_sigs[0];
        mouton_sigs[0] = nakamoto_sigs[0];
        sigs_tmp.insert(nakamoto_id, TransactionSignatures(nakamoto_sigs));
        sigs_tmp.insert(saberhagen_id, TransactionSignatures(saberhagen_sigs));
        sigs_tmp.insert(mouton_id, TransactionSignatures(mouton_sigs));
        let tx_res = assemble_tx(&secp, &tx, &mut cache, &inputs, &ref_sigs(&sigs_tmp));
        assert!(tx_res.is_err());
    }

    #[test]
    fn signed_weight() {
        // transaction spending 2-of-3 multisig
        let tx_hex = "\
            01000000000102da801d43d90ed9405249f75c757b41d5deb672a5a490d07fe6\
            e7d6c6cefb80ff010000002322002088c33cf6084215f28499897fefdbcade34\
            3767e5934b4dda6d5d563c9cb1294f44454557e044c5fd3292dc2d8051e5b389\
            37247e718720747b052ef1b421d06fd7e6b7e5000000002322002039a2fe1153\
            0b0e9a7cdbfd15f2400c687f330818ee5cd45689da8b9b182354e64f414d4c0b\
            40c9f505000000001976a9144469397e71394d7852eafde236c90bf86dac9d54\
            88ac1b3d0f000000000017a914e512eab35b75bfac91bb5650f6b10c4884051d\
            8a871b3d0f000000000017a914e512eab35b75bfac91bb5650f6b10c4884051d\
            8a871b3d0f000000000017a914e512eab35b75bfac91bb5650f6b10c4884051d\
            8a871b3d0f000000000017a914e512eab35b75bfac91bb5650f6b10c4884051d\
            8a871b3d0f000000000017a914e512eab35b75bfac91bb5650f6b10c4884051d\
            8a871b3d0f000000000017a914e512eab35b75bfac91bb5650f6b10c4884051d\
            8a871b3d0f000000000017a914e512eab35b75bfac91bb5650f6b10c4884051d\
            8a871b3d0f000000000017a914e512eab35b75bfac91bb5650f6b10c4884051d\
            8a871b3d0f000000000017a914e512eab35b75bfac91bb5650f6b10c4884051d\
            8a871b3d0f000000000017a914e512eab35b75bfac91bb5650f6b10c4884051d\
            8a870400483045022100f59d363148b817c7c438d65ce09fab1944be13af5e84\
            90fa710a25bf14dd6b410220662acc2c5635d784134966f41794e6ee6d21a60c\
            c539b915c12e7bdcec7b80b301483045022100f331a89d371358d3280e8f12af\
            02a8e3ce4708b069d7d9fdc59e1323cedd397f0220208d0cdacd0decd625b710\
            4729cb6dda79b9543c21c90b702b5f4f198b2e74b001695221026650b981fd08\
            9b724502f7169b27850f4d2d0b635bcc34c42a276fd9655c39ce21035615e027\
            3eacc3b6a4a0a9a74ef36046118b95c385942f31eeca659d3f04de9721025791\
            cb818511d6ae9a9f4e62363ac0bd72a6bfcd11a0bce5a584e9d80f774d6853ae\
            0400483045022100a4b60dacbe728e7ab23de8d18df2b71edb5893c0635da316\
            435ac9bc1145eabb02202ca14fbc3c913deb8495efca14cbc19b3fe3c9336b57\
            e757c5a07d2736dc7ea6014830450221009187b6c471397c72b112514a2468f4\
            976c55f41bd6f43a74666d1533d2b067f6022004f9024e8f339965a6ddb3581f\
            59be5e1522318537c7589de62515423d52d30101695221023c9cd9c6950ffee2\
            4772be948a45dc5ef1986271e46b686cb52007bac214395a2102756e27cb004a\
            f05a6e9faed81fd68ff69959e3c64ac8c9f6cd0e08fd0ad0e75d2103fa40da23\
            6bd82202a985a9104e851080b5940812685769202a3b43e4a8b13e6a53ae0000\
            0000\
        ";
        let tx_bytes = Vec::<u8>::from_hex(tx_hex).unwrap();
        // witness data starts at 040048 (16 lines = 512 bytes plus 4 more
        // chars = 2 bytes), ends at the locktime (4 bytes before the end)
        let witness_bytes = &tx_bytes[514..tx_bytes.len() - 4];
        let mut tx = deserialize::<bitcoin::Transaction>(&tx_bytes).unwrap();
        let direct_weight = tx.weight() as usize;

        let mut input_map = HashMap::new();
        for input in &mut tx.input {
            let witness_script = bitcoin::Script::from(input.witness.to_vec().pop().unwrap());

            let miniscript = miniscript::Miniscript::parse(&witness_script)
                .expect("valid miniscript")
                .translate_pk(
                    &mut |key: &bitcoin::PublicKey| tweak::Key::from_public_key(key.inner.clone()),
                    &mut |_h: &bitcoin::hashes::hash160::Hash| unimplemented!(),
                )
                .expect("translate keys");

            let descriptor = miniscript::Descriptor::new_sh_wsh(miniscript).unwrap();
            input_map.insert(
                input.previous_output,
                SpendableUtxo::new(input.previous_output, 10000, 0, Tweak::none(), descriptor),
            );
            input.script_sig = bitcoin::Script::new();
            input.witness = bitcoin::Witness::default();
        }

        let mut input_ref_map = HashMap::new();
        for (outpoint, utxo) in &input_map {
            input_ref_map.insert(*outpoint, utxo);
        }

        // Manually compute the weight to preserve continuity of unit
        // tests from the pre-`Transaction::get_weight` days
        let weight_nonwitness = 4 * (tx_bytes.len() - witness_bytes.len() - 2); // -2 for flag and marker
        let weight_witness = witness_bytes.len() + 2; // +2 for flag and marker
        let weight_of_signed_tx_expected = weight_nonwitness + weight_witness;

        assert_eq!(
            direct_weight,
            weight_of_signed_tx_expected
        );
        assert_eq!(
            ConcreteProposal::signed_weight(&tx, &input_ref_map),
            weight_of_signed_tx_expected
        );
    }

    #[test]
    fn test_adjust_change() {
        use std::iter;
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::{Txid, OutPoint};
        use descriptor::LiquidDescriptor;
        use elements;

        // A common watchman descriptor.
        let desc: miniscript::Descriptor<tweak::Key> =
            "sh(wsh(or_d(multi(3,[untweaked]03024c3b4f830854d6d26d6e34d92aff4c703bf57e85cd42abe\
            328d928e01d4286,[untweaked]03024c3b4f830854d6d26d6e34d92aff4c703bf57e85cd42abe328d928e\
            01d4286,[untweaked]03024c3b4f830854d6d26d6e34d92aff4c703bf57e85cd42abe328d928e01d4286)\
            ,and_v(v:older(2016),multi(1,[untweaked]023303dedc51b9d227b17c9fb4710f96b844e1ccdc2\
            c776e1b7274bd4e246b6202,[untweaked]03024c3b4f830854d6d26d6e34d92aff4c703bf57e85cd42abe\
            328d928e01d4286,[untweaked]03ff4e8c8d99b9dcbb529a87d54f606bae0149a34018325547fa0c2239e\
            038a1c9)))))".parse().unwrap();
        // Any reasonable script (just used for size).
        let any_script = desc.liquid_script_pubkey();

        let mut counter = iter::successors(Some(1u8), |n| Some(n + 1));
        macro_rules! outpoint { () => {{
            OutPoint::new(Txid::hash(&[counter.next().unwrap()]), 0)
        }};}
        macro_rules! el_outpoint { () => {{
            elements::OutPoint {
                txid: elements::Txid::hash(&[counter.next().unwrap()]),
                vout: 0,
            }
        }};}
        macro_rules! tweak { () => {{
            let h = sha256::Hash::hash(&[counter.next().unwrap()]);
            Tweak::some(&h.into_inner()[..])
        }};}
        macro_rules! utxo { ($val:expr) => {{
            SpendableUtxo::new(outpoint!(), $val, 0, tweak!(), desc.clone())
        }};}
        macro_rules! pegout { ($val:expr) => {{
            PegoutRequest {
                request: el_outpoint!(),
                previous_request: Some(el_outpoint!()),
                n_previous_requests: 1,
                dest_output: bitcoin::TxOut {
                    value: $val,
                    script_pubkey: any_script.clone(),
                },
                height: 0,
                dest_pubkey: Vec::new(),
                authorization_proof: Vec::new(),
                required_conflicts: vec![outpoint!()].into_iter().collect(),
                fee: 2_000,
            }
        }};}

        // This is our intended fee rate.
        const FEE_RATE: u64 = 1_000; // sats / vkb

        let inputs = vec![ utxo!(600_000) ];
        let utxo_conflict = utxo!(700_000);
        let pegouts = vec![ pegout!(500_000) ];

        let proposal = Proposal {
            inputs: inputs.iter().collect(),
            conflict_input_sets: vec![vec![&utxo_conflict].into_iter().collect()],
            pegouts: pegouts.iter().map(|r| (r.request, r)).collect(),
            change_script_pubkey: &any_script,
            change_txout_size: Proposal::txout_size(&any_script),
            change: vec![ constants::MINIMUM_DUST_CHANGE ],
        };
        let utxos = vec![utxo!(200_000), utxo!(300_000), utxo!(400_000), utxo!(500_000)];

        // Here 1 and 2 is the multiplier used for the desired total outputs,
        // for 1 it will not try to add extra change, but for 2 it will try
        // to add extra change.
        for i in &[1, 2] {
            let desired_n = i * constants::N_MAIN_OUTPUTS_RADIUS;

            let mut proposal = proposal.clone();
            let mut fee_pool = fee::Pool::new(FEE_RATE);
            fee_pool.add(10_000);
            proposal.adjust_change(&fee_pool, utxos.iter(), desired_n, 5);

            if *i == 1 {
                assert_eq!(proposal.change.len(), 1);
            } else {
                assert_ne!(proposal.change.len(), 1);
            }

            let fee = proposal.input_value() - proposal.output_value();
            let vsize = proposal.signed_weight() as u64 / 4;
            assert!((fee*1000)/vsize - FEE_RATE <= 2); // allowed to be off by 2
            // the off by 2 is because total fee and change fee are both rounded up
        }
    }
}
