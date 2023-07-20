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


//! Dynafed consensus tracking
//!
//! This module provides a [ConsensusTracker] that will keep track of
//! both historical consensus parameters on the chain and the active
//! consensus parameters.
//!
//! It links on-chain parameters with the known descriptors provided in the
//! config files.

use std::borrow::Cow;
use bitcoin;
use bitcoin::hashes::sha256;
use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::{self, Secp256k1};
use elements::dynafed;
use common::rollouts::ROLLOUTS;
use miniscript::Descriptor;

use common::{BlockHeight, PakList};
use descriptor::{self, TweakableDescriptor, LiquidDescriptor};
use tweak;

/// Result for looking up a descriptor in our consensus history
/// by scriptPubKey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescLookupResult<'a> {
    /// Found descriptor the given scriptPubKey is the regular script of.
    Regular(&'a descriptor::Cached),
    /// Found descriptor the given scriptPubKey is the CSV-tweaked script of.
    CsvTweaked(&'a descriptor::Cached),
    /// No descriptor found.
    NotFound,
}

impl<'a> DescLookupResult<'a> {
    /// Get the descriptor if one is found.
    pub fn get(self) -> Option<&'a descriptor::Cached> {
        match self {
            DescLookupResult::Regular(desc) => Some(desc),
            DescLookupResult::CsvTweaked(desc) => Some(desc),
            DescLookupResult::NotFound => None,
        }
    }
}

/// Result for lookup up a scriptPubkey in the consensus tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpkLookupResult<'a> {
    /// The spk is of a params with known descriptor.
    Known(&'a descriptor::Cached),
    /// The spk is of an old params we don't know the descriptor of.
    Old,
    /// The spk is the CSV tweaked version of a params with a known descriptor.
    KnownCsvTweaked(&'a descriptor::Cached),
    /// The spk is the CSV tweaked version of an old params we don't know the descriptor of.
    OldCsvTweaked,
    /// The spk is not ours.
    Unknown,
}

impl<'a> SpkLookupResult<'a> {
    /// Get the descriptor if one is found.
    pub fn descriptor(self) -> Option<&'a descriptor::Cached> {
        match self {
            SpkLookupResult::Known(desc) => Some(desc),
            SpkLookupResult::KnownCsvTweaked(desc) => Some(desc),
            SpkLookupResult::Old => None,
            SpkLookupResult::OldCsvTweaked => None,
            SpkLookupResult::Unknown => None,
        }
    }

    /// Return whether the spk was ours or not.
    pub fn is_ours(&self) -> bool {
        match self {
            SpkLookupResult::Known(..) => true,
            SpkLookupResult::KnownCsvTweaked(..) => true,
            SpkLookupResult::Old => true,
            SpkLookupResult::OldCsvTweaked => true,
            SpkLookupResult::Unknown => false,
        }
    }
}

/// Consensus parameters cached by the [ConsensusTracker].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedParams {
    /// The root of the params.
    pub root: sha256::Midstate,

    /// `scriptPubKey` used for pegins.
    pub fedpeg_program: bitcoin::Script,
    /// For v0 fedpeg programs, the witness script of the fedpeg program.
    pub fedpeg_script: Vec<u8>,
    /// The PAK list.
    pub pak_list: PakList,

    /// The descriptor for these params if it's known.
    pub descriptor: Option<descriptor::Cached>,
    /// The height at which this params were allowed to active.
    /// Keep this to make sure we never activate older params.
    pub start_height: Option<BlockHeight>,
    /// The CSV-tweaked variant of the change script.
    /// Only for the legacy descriptor.
    pub csv_tweaked_program: Option<bitcoin::Script>,

    /// The mainchain commitment from the block where these parameters were activated
    /// Value will be 0 for the legacy params.
    pub first_mainchain_commitment_height: BlockHeight
}

impl TrackedParams {
    fn new(
        params: dynafed::Params,
        known: Option<(BlockHeight, descriptor::Cached)>,
        first_mainchain_commitment_height: BlockHeight,
    ) -> TrackedParams {
        assert!(params.is_full());
        let root = params.calculate_root();
        if let dynafed::Params::Full { fedpeg_program, fedpegscript, extension_space, .. } = params {
            TrackedParams {
                root: root,
                fedpeg_program: fedpeg_program,
                fedpeg_script: fedpegscript,
                pak_list: PakList::from_extension_space(&extension_space)
                    .expect("unparsable PAK list activated on the network"),
                start_height: known.as_ref().map(|(h, _)| *h),
                csv_tweaked_program: known.as_ref().and_then(|(_, d)| d.csv_tweaked_spk.clone()),
                descriptor: known.map(|(_, d)| d),
                first_mainchain_commitment_height: first_mainchain_commitment_height
            }

        } else {
            unreachable!()
        }
    }

    /// Whether this is a params for which we know the CPE.
    pub fn is_known(&self) -> bool {
        self.descriptor.is_some()
    }

    /// Check if the given output script and claim script could be a pegin for
    /// these parameters.
    /// Returns the tweaked descriptor on match.
    fn matches_pegin<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        output_script: &bitcoin::Script,
        claim_script: &[u8],
    ) -> Option<Descriptor<tweak::Key>> {
        let tweaked_desc = self.descriptor.as_ref()?.tweak(secp, &claim_script[..]);
        if *output_script == tweaked_desc.liquid_script_pubkey() {
            Some(tweaked_desc)
        } else {
            None
        }
    }

    /// Whether the given scriptPubkey matches the fedpeg_program.
    pub fn matches(&self, spk: &bitcoin::Script) -> bool {
        // this should always keep matching the legacy csv tweaked program
        // because it's used for chain sync
        *spk == self.fedpeg_program
            || self.csv_tweaked_program.as_ref().map(|s| s == spk).unwrap_or(false)
    }

    /// Same as [matches], but returns the descriptor, regular or tweaked, that was matched.
    pub fn matches_descriptor(&self, spk: &bitcoin::Script) -> Option<&Descriptor<tweak::Key>> {
        self.descriptor.as_ref().and_then(|d| d.matches(spk))
    }
}

/// In charge of tracking the consensus parameters in the sidechain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusTracker {
    /// The length of dynafed epochs.
    epoch_length: BlockHeight,
    /// The history of active params.
    /// At all times these are ordered by block height.
    history: Vec<(BlockHeight, TrackedParams)>,
    /// The known descriptors and the block height at which they are allowed to activate.
    /// This vector is ordered by the height.
    known_descriptors: Vec<(BlockHeight, descriptor::Cached)>,
    /// The most recent mainchain commitment that has been registered
    latest_mainchain_commitment_height: Option<BlockHeight>,
}

impl ConsensusTracker {
    /// Create a new tracker with the given known descriptors and the heights
    /// at which they are allowed to activate.
    pub fn new(epoch_length: BlockHeight) -> ConsensusTracker {
        ConsensusTracker {
            epoch_length: epoch_length,
            history: Vec::new(),
            known_descriptors: Vec::new(),
            latest_mainchain_commitment_height: None,
        }
    }

    /// Set the epoch length in case this ConsensusTracker was deserialized from a state file
    /// that didn't have one.
    pub fn set_epoch_length(&mut self, epoch_length: BlockHeight) {
        // remove this method once all nodes have a consensus tracker
        let _ = common::rollouts::CONSENSUS_TRACKER;
        self.epoch_length = epoch_length;
    }

    /// Find an activated descriptor which matches the provided script_pubkey (regular or tweaked).
    pub fn matches_activated_descriptor(&self, spk: &bitcoin::Script) -> Option<&Descriptor<tweak::Key>> {
        let legacy_descriptor = self.legacy_descriptor();
        if let Some(desc) = legacy_descriptor.matches(spk) {
            return Some(desc);
        }

        for (_, params) in self.history.iter() {
            if let Some(descriptor) = params.matches_descriptor(spk) {
                return Some(descriptor)
            }
        }

        None
    }

    /// Whether the given scriptPubkey matches the currently active fedpeg_program.
    pub fn matches_active_spk(&self, spk: &bitcoin::Script) -> bool {
        if let Some((_, active_params)) = &self.history.last() {
            active_params.matches(spk)
        } else {
            false
        }
    }

    /// Update the set of known descriptors by adding the ones we don't yet
    /// have and updating the heights of the ones we already had.
    pub fn update_known_descriptors(
        &mut self,
        new_descriptors: impl IntoIterator<Item = (BlockHeight, descriptor::Cached)>,
    ) {
        self.known_descriptors = new_descriptors.into_iter().collect();
        self.known_descriptors.sort_by_key(|(h, _)| *h);
    }

    /// Get the dynafed epoch length.
    pub fn epoch_length(&self) -> BlockHeight {
        self.epoch_length
    }

    /// The currently active parameters.
    pub fn active_params(&self) -> Option<&TrackedParams> {
        self.history.last().map(|(_, p)| p)
    }

    /// Get the legacy descriptor which is the one in the config starting at height 0.
    pub fn legacy_descriptor(&self) -> &descriptor::Cached {
        self.known_descriptors.iter()
            .find(|(s, _)| *s == 0)
            .map(|(_, d)| d)
            .expect("no legacy (pre-dynafed) descriptor was provided in the config")
    }

    /// This function returns the same as [legacy_descriptor] but is named specially
    /// to be used in all places where the previously hardcoded descriptor is used.
    /// These places will all need refactoring as soon as the descriptor is no longer
    /// permanent.
    /// Thus, this method and all its usages must be refactored (carefully) in order
    /// to support dynamic parameters.
    pub fn initial_permanent_descriptor(&self) -> &descriptor::Cached {
        let desc = self.legacy_descriptor();

        // As long as this method is used anywhere, all descriptors occuring everywhere
        // should be exactly the same.
        let config = self.known_descriptors.iter().map(|(_, d)| d);
        let history = self.history.iter()
            .map(|(_, p)| p.descriptor.as_ref().expect("no unknown params allowed"));
        if !config.chain(history).all(|d| d == desc) {
            log!(Warn, "not all wm descriptors identical!");
            for (h, d) in &self.known_descriptors {
                log!(Debug, "known_descriptor: {}: {}", h, **d);
            }
            for (h, p) in &self.history {
                log!(Debug, "history: {}: {}", h, **p.descriptor.as_ref().unwrap());
            }
        }

        desc
    }

    /// Check whether a wm df transition has already happened.
    pub fn wm_transition_made(&self) -> bool {
        let mut iter = self.history.iter();
        let first = match iter.next() {
            Some((_, p)) => &p.fedpeg_program,
            None => return false,
        };

        iter.any(|(_, p)| p.fedpeg_program != *first)
    }

    /// The currently active descriptor.
    pub fn active_descriptor(&self) -> &descriptor::Cached {
        if let Some(params) = self.active_params() {
            params.descriptor.as_ref().expect("active params should be known")
        } else {
            self.legacy_descriptor()
        }
    }

    /// The active change scriptPubKey.
    pub fn active_change_spk(&self) -> &bitcoin::Script {
        let desc = self.active_descriptor();
        if ROLLOUTS.hsm_csv_tweak != common::rollouts::HsmCsvTweak::Legacy {
            &desc.spk
        } else {
            desc.csv_tweaked_spk.as_ref().unwrap_or(&desc.spk)
        }
    }

    /// The params active at the given height.
    pub fn params_at(&self, sidechain_height: BlockHeight) -> Option<&TrackedParams> {
        // From the back, look for the first one with a start height
        // lower than our target height.
        self.history.iter().rev().find(|(h, _)| *h <= sidechain_height).map(|(_, p)| p)
    }

    /// The watchman descriptor active at the given sidechain height.
    pub fn descriptor_at(&self, sidechain_height: BlockHeight) -> &descriptor::Cached {
        if let Some(params) = self.params_at(sidechain_height) {
            params.descriptor.as_ref()
                .expect("no descriptor known for params at requested height")
        } else {
            self.legacy_descriptor()
        }
    }

    /// The watchman descriptor active at the given mainchain height.
    /// Mainchain commitments are used to map heights between the mainchain and the sidechain.
    pub fn descriptor_at_mainchain_height(
        &self,
        mainchain_height: BlockHeight
    ) -> &descriptor::Cached {
        if let Some(latest_height) = self.latest_mainchain_commitment_height {
            assert!(mainchain_height < latest_height, "unable to determine descriptor at a given \
                mainchain height before we commit to a height past it");

            // Find the latest parameter which had been activated by this mainchain height
            let mut sidechain_height = 0;
            for (activation_height, params) in self.history.iter().rev() {
                if params.first_mainchain_commitment_height <= mainchain_height {
                    print!("Activation height: {}, commit: {}. mainchain_height: {}\n",
                        activation_height,
                        params.first_mainchain_commitment_height,
                        mainchain_height);
                    sidechain_height = *activation_height;
                    break;
                }
            }

            self.descriptor_at(sidechain_height)
        } else {
            // pre-dynafed
            self.legacy_descriptor()
        }
    }

    /// The change scriptPubKey active at the given sidechain height.
    pub fn change_spk_at(&self, sidechain_height: BlockHeight) -> &bitcoin::Script {
        let desc = self.descriptor_at(sidechain_height);

        if ROLLOUTS.hsm_csv_tweak != common::rollouts::HsmCsvTweak::Legacy {
            &desc.spk
        } else {
            desc.csv_tweaked_spk.as_ref().unwrap_or(&desc.spk)
        }
    }

    /// Has the given scriptPubKey (fedpeg_program) been activated by the given mainchain_height.
    /// Note: this scriptPubKey does *not* have to still be active.
    ///
    /// The mainchain time is mapped to the sidechain time using the mainchain commitments in
    /// each sidechain block's coinbase.
    ///
    /// This method returns [None] when
    /// `mainchain_height >= self.latest_mainchain_commitment_height and we have not found a match.
    ///
    /// This is done to ensure that we all watchmen come to the same conclusion on each output,
    /// *regardless* of when they start syncing. This is important, because there are some
    /// situations where we cannot be certain of whether a given scriptPubKey belongs to the
    /// federation until we see more blocks.
    ///
    /// More specifically, until we have seen `mainchain_commitment_x + 1`, we cannot be certain
    /// of the parameters that were active at `mainchain_commitment_x`, and thus we cannot provide
    /// a [false] answer with certainty.
    ///
    /// To understand why, consider the following example:
    ///
    ///    Two sets of dynafed parameters: p1 and p2
    ///
    ///    time_x: sidechain [p1, commit: 99] <- [p1, commit: 100]
    ///    time_y: sidechain [p1, commit: 99] <- [p1, commit: 100] <- [p2, commit: 100]
    ///
    /// A watchman syncing at time_x will conclude that a different set of parameters
    /// were active at mainchain block 100 than a watchman that is syncing at time_y.
    ///
    /// This is a bad outcome because the two watchmen will not agree on which outputs belong to
    /// the federation, and so their proposals might not match.
    ///
    /// Thus, it is essential that all watchmen come to the same conclusion on each output,
    /// *regardless* of when they start syncing.
    ///
    /// Once we identify an output as matching one of the already activated fedpeg_programs, it is
    /// impossible for this output to no longer match in the future. This is because, even if we
    /// transition away from a fedpeg_program, it will still have been active at some point.
    /// A completed dynafed transition cannot be reversed and erased from history.
    ///
    /// Thus, we don't have to check that
    /// `mainchain_height < self.latest_mainchain_commitment_height` before returning [true].
    /// If the result is [true] at some point, it will always be [true] at any future time.
    ///
    /// However, if we identify no match, the situation described in the example above is still
    /// possible. It only stops being possible when
    /// `mainchain_height < self.latest_mainchain_commitment_height`. Since, at that point,
    /// we will have received all sidechain blocks that commited to `mainchain_height`
    /// and we can be certain of all the parameters that had been activated by that time.
    ///
    /// Thus, we need to wait for the condition
    /// `mainchain_height < self.latest_mainchain_commitment_height` to be true before providing
    /// a [false] response.
    ///
    /// A [None] response indicates that we cannot yet be certain of the correct answer.
    pub fn is_activated_spk_at(
        &self,
        spk: &bitcoin::Script,
        mainchain_height: BlockHeight
    ) -> Option<bool> {
        if self.legacy_descriptor().matches(spk).is_some() {
            // Always consider the legacy descriptor to be a valid spk.
            return Some(true);
        }

        // Check all parameters which had been activated by this mainchain height
        for (_, params) in self.history.iter().rev() {
            if params.first_mainchain_commitment_height > mainchain_height {
                continue;
            }

            if params.matches(spk) {
                return Some(true);
            }
        }

        if let Some(latest_height) = self.latest_mainchain_commitment_height {
            if mainchain_height < latest_height {
                return Some(false);
            }
            return None;
        } else {
            // pre-dynafed
            return Some(false);
        }
    }

    /// Lookup a descriptor by scriptPubKey.
    pub fn lookup_descriptor(&self, spk: &bitcoin::Script) -> DescLookupResult {
        for (_, desc) in &self.known_descriptors {
            if *spk == desc.spk {
                return DescLookupResult::Regular(desc);
            }
            if desc.csv_tweaked_spk.as_ref().map(|s| s == spk).unwrap_or(false) {
                return DescLookupResult::CsvTweaked(desc);
            }
        }
        DescLookupResult::NotFound
    }

    /// Lookup the scriptPubkey in the history of parameters.
    pub fn lookup_spk(&self, spk: &bitcoin::Script) -> SpkLookupResult {
        // reverse to match most relevant
        for (_, params) in self.history.iter().rev() {
            if *spk == params.fedpeg_program {
                if let Some(ref desc) = params.descriptor {
                    return SpkLookupResult::Known(desc);
                } else {
                    return SpkLookupResult::Old;
                }
            } else if Some(spk) == params.csv_tweaked_program.as_ref() {
                if let Some(ref desc) = params.descriptor {
                    return SpkLookupResult::KnownCsvTweaked(desc);
                } else {
                    return SpkLookupResult::OldCsvTweaked;
                }
            }
        }

        // If the spk was not found in the dynafed parameter history then check the legacy
        // descriptor
        if *spk == self.legacy_descriptor().spk {
            return SpkLookupResult::Known(self.legacy_descriptor());
        } else if Some(spk) == self.legacy_descriptor().csv_tweaked_spk.as_ref() {
            return SpkLookupResult::KnownCsvTweaked(self.legacy_descriptor());
        }

        SpkLookupResult::Unknown
    }

    /// Given a pegin tx, find the federation descriptor corresponding to the output.
    ///
    /// This method makes the assumption that the consensus tracker and the pegin finding
    /// logic traverse the sidechain in parallel. This means that the fedpegscript
    /// used in the pegin will be from one of the two most recent registered epochs.
    pub fn find_pegin_descriptor<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        output_script: &bitcoin::Script,
        claim_script: &[u8],
        sidechain_height: BlockHeight,
    ) -> Option<Descriptor<tweak::Key>> {
        let mut params = self.history.iter().rev();

        let last = params.next()?;
        if let Some(desc) = last.1.matches_pegin(secp, output_script, claim_script) {
            return Some(desc);
        }

        // If the last params are already active for more than an epoch, exit.
        if last.0 <= sidechain_height.saturating_sub(self.epoch_length) {
            return None;
        }

        let previous = params.next()?;
        // prevent trying twice on same descriptor
        if previous.1.descriptor == last.1.descriptor {
            return None;
        }

        previous.1.matches_pegin(secp, output_script, claim_script)
    }

    /// Given a pegin tx, find the federation descriptor corresponding to the output.
    ///
    /// Unlike `find_pegin_descriptor` this method will scan all the descriptors, not
    /// just the last two.
    pub fn find_historial_pegin_descriptor<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        output_script: &bitcoin::Script,
        claim_script: &[u8],
    )-> Option<Descriptor<tweak::Key>> {
        for (_, params) in self.history.iter().rev() {
            if let Some(desc) = params.matches_pegin(secp, output_script, claim_script) {
                return Some(desc);
            }
        }
        return None
    }

    /// Add new (full) params that activated in the given blockheight.
    ///
    /// Sets the params' first mainchain commitment to [self.latest_mainchain_commitment].
    /// Make sure that field is up to date before calling this method.
    fn add_params(
        &mut self,
        sidechain_height: BlockHeight,
        params: dynafed::Params,
    ) {
        assert!(params.is_full());
        assert!(self.history.is_empty() || sidechain_height > self.history.last().unwrap().0);
        let root = params.calculate_root();

        // Check if we know the params' descriptor. If we do, then we can perform a sanity check.
        let fedpeg_program = params.fedpeg_program().unwrap();
        let known = self.known_descriptors.iter()
            .filter(|(_, desc)| desc.spk == *fedpeg_program)
            .last();
        if let Some((latest_start, ref desc)) = known {
            // Make sure that we didn't go back to this params from others.
            if let Some(active) = self.active_params() {
                if let Some(active_start) = active.start_height {
                    if active_start > *latest_start {
                        panic!(
                            "deprecated params activated (root: {}, start: {}, current start: {})",
                            root, latest_start, active_start,
                        );
                    }
                }
            }

            let net = bitcoin::Network::Bitcoin;
            slog!(ChangeAddress, address: bitcoin::Address::from_script(&desc.spk, net).unwrap());
            if let Some(ref tweaked) = desc.csv_tweaked_spk {
                slog!(CsvTweakedChangeAddress,
                    address: bitcoin::Address::from_script(tweaked, net).unwrap(),
                );
            }
        }

        // If the last params were known, we want the newer ones also to be.
        // With the exception of the initial one.
        if let Some((_, prev)) = self.history.last() {
            if self.history.len() > 1 && prev.is_known() && known.is_none() {
                log!(Warn, "unknown parameters {} found after a set of params that were known {}",
                    prev.root, root,
                );
            }
        }

        let first_commit = self.latest_mainchain_commitment_height
            .expect("adding dynafed parameters before any mainchain commitments are known");
        let tracked = TrackedParams::new(params, known.cloned(), first_commit);
        slog!(WatchmanConsensusChanged,
            params_root: root,
            fedpeg_program: Cow::Borrowed(&tracked.fedpeg_program),
            fedpeg_script: tracked.fedpeg_script.to_hex(),
            pak_list: Cow::Borrowed(&tracked.pak_list),
        );

        self.history.push((sidechain_height, tracked));
    }

    /// Call this whenever a new epoch is synced with the params.
    /// The tracker will figure out if this is an update and store the new params.
    pub fn register_epoch(&mut self, height: BlockHeight, params: &dynafed::Params) {
        assert!(params.is_full());

        let active = self.active_params();
        if active.is_none() || params.calculate_root() != active.unwrap().root {
            self.add_params(height, params.clone());
        }
    }

    /// Update the latest mainchain commitment.
    /// [mainchain_commitment] must never decrease.
    fn register_mainchain_commitment(&mut self, mainchain_commitment_height: BlockHeight) {
        if let Some(latest_mainchain_commitment_height) = self.latest_mainchain_commitment_height {
            if mainchain_commitment_height < latest_mainchain_commitment_height {
                log!(Error, "a mainchain commitment which moved backwards was found: {:?} -> {}, this should not happen",
                    latest_mainchain_commitment_height, mainchain_commitment_height
                );
                return;
            }
        }

        self.latest_mainchain_commitment_height = Some(mainchain_commitment_height);
    }

    /// Call this whenever a new sidechain block is synced.
    ///
    /// [params] should only be provided if the block contained full params.
    /// The tracker will figure out if this is an update and store the new params.
    ///
    /// [mainchain_commitment] should be [None] for pre-dynafed blocks.
    pub fn register_sidechain_block(
        &mut self,
        sidechain_height: BlockHeight,
        mainchain_commitment_height: Option<BlockHeight>,
        params: Option<&dynafed::Params>
    ) {
        log!(Info, "Registering sidechain block with consensus tracker, \
            sidechain height: {}, mainchain commitment height: {:?}, params CPE root: {:?}.",
            sidechain_height, mainchain_commitment_height, params.map(|p| p.calculate_root()));

        // Register new mainchain commitment before adding the new params, because
        // the params' first_mainchain_commitment will be set to [self.last_mainchain_commitment]
        if let Some(mainchain_commitment_height) = mainchain_commitment_height {
            self.register_mainchain_commitment(mainchain_commitment_height)
        }

        if let Some(params) = params {
            assert!(params.is_full());

            let active = self.active_params();
            if active.is_none() || params.calculate_root() != active.unwrap().root {
                self.add_params(sidechain_height, params.clone());
            }
        }
    }

    /// Returns the last mainchain commitment that was succesfully registered with the tracker
    pub fn latest_mainchain_commitment_height(&self) -> Option<BlockHeight> {
        self.latest_mainchain_commitment_height
    }
}

impl Default for ConsensusTracker {
    fn default() -> ConsensusTracker {
        // this default impl can be removed when all nodes have a consensus tracker
        let _ = common::rollouts::CONSENSUS_TRACKER;
        ConsensusTracker {
            epoch_length: 0,
            history: Vec::new(),
            known_descriptors: Vec::new(),
            latest_mainchain_commitment_height: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use bitcoin::hashes::sha256;
    use bitcoin::secp256k1;

    use descriptor::{self, TweakableDescriptor};
    use watchman;

    pub fn test_params_0() -> dynafed::Params {
        dynafed::Params::Full {
            signblockscript: Default::default(),
            signblock_witness_limit: Default::default(),
            fedpeg_program: watchman::blockchain::tests::test_descriptor_1().liquid_script_pubkey(),
            fedpegscript: Default::default(),
            extension_space: Default::default(),
        }
    }

    pub fn test_params_1() -> dynafed::Params {
        dynafed::Params::Full {
            signblockscript: Default::default(),
            signblock_witness_limit: Default::default(),
            fedpeg_program: watchman::blockchain::tests::test_descriptor_2().liquid_script_pubkey(),
            fedpegscript: Default::default(),
            extension_space: Default::default(),
        }
    }

    pub fn test_params_2() -> dynafed::Params {
        dynafed::Params::Full {
            signblockscript: Default::default(),
            signblock_witness_limit: Default::default(),
            fedpeg_program: watchman::blockchain::tests::test_descriptor_3().liquid_script_pubkey(),
            fedpegscript: Default::default(),
            extension_space: Default::default(),
        }
    }

    #[test]
    fn test_match_pegin() {
        let desc = watchman::blockchain::tests::test_descriptor_1();
        let cached = descriptor::Cached::from(desc.clone());
        let claim_script = secp256k1::rand::random::<[u8; 20]>();
        let secp = secp256k1::Secp256k1::new();

        let tweaked = desc.tweak(&secp, &claim_script[..]);
        let tweaked_spk = tweaked.liquid_script_pubkey();

        let params = TrackedParams {
            root: sha256::Midstate::default(),
            fedpeg_program: desc.liquid_script_pubkey(),
            fedpeg_script: desc.liquid_witness_script().to_bytes(),
            pak_list: PakList::default(),
            descriptor: Some(cached.clone()),
            start_height: Some(10),
            csv_tweaked_program: cached.csv_tweaked_spk.clone(),
            first_mainchain_commitment_height: 0,
        };

        assert_eq!(
            params.matches_pegin(&secp, &tweaked_spk, &claim_script),
            Some(tweaked),
        );
    }

    #[test]
    /// Registers multiple dynafed parameters at different mainchain times, and confirms
    /// that change is identified correctly when given a mainchain height.
    fn test_is_activated_spk_at() {
        let desc_0 = watchman::blockchain::tests::test_descriptor_1();
        let desc_1 = watchman::blockchain::tests::test_descriptor_2();
        let desc_2 = watchman::blockchain::tests::test_descriptor_3();

        let params_0 = test_params_0();
        let params_1 = test_params_1();
        let params_2 = test_params_2();

        let change_spk_0 = params_0.fedpeg_program().unwrap();
        let change_spk_1 = params_1.fedpeg_program().unwrap();
        let change_spk_2 = params_2.fedpeg_program().unwrap();

        let mut consensus = ConsensusTracker::new(1);
        consensus.update_known_descriptors(vec![
            (0, descriptor::Cached::from(desc_0)), // legacy descriptor
            (5, descriptor::Cached::from(desc_1)),
            (10, descriptor::Cached::from(desc_2))
        ]);
        assert!(consensus.latest_mainchain_commitment_height.is_none());

        consensus.register_sidechain_block(1, None, None);
        consensus.register_sidechain_block(2, None, None);

        // Record the first dynafed transition (params are equal to the legacy descriptor)
        consensus.register_sidechain_block(3, Some(8), Some(&params_0));
        consensus.register_sidechain_block(4, Some(9), None);
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 9);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 8).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 8).unwrap(), false);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 8).unwrap(), false);

        // Second dynafed transition
        consensus.register_sidechain_block(5, Some(10), Some(&params_1));
        consensus.register_sidechain_block(6, Some(12), None);
        consensus.register_sidechain_block(7, Some(12), None);
        consensus.register_sidechain_block(8, Some(12), None);
        consensus.register_sidechain_block(9, Some(13), None);
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 13);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 9).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 9).unwrap(), false);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 9).unwrap(), false);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 10).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 10).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 10).unwrap(), false);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 11).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 11).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 11).unwrap(), false);

        assert!(consensus.is_activated_spk_at(&change_spk_2, 13).is_none(),
            "is_activated_spk_at should return None if result is false \
            & mainchain_height >= latest_mainchain_commitment_height");
        assert!(consensus.is_activated_spk_at(&change_spk_2, 14).is_none(),
            "is_activated_spk_at should return None if result is false \
            & mainchain_height >= latest_mainchain_commitment_height");
        assert!(consensus.is_activated_spk_at(&change_spk_2, 30).is_none(),
            "is_activated_spk_at should return None if result is false \
            & mainchain_height >= latest_mainchain_commitment_height");
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 12).unwrap(), false);

        // Third dynafed transition
        consensus.register_sidechain_block(10, Some(14), Some(&params_2));
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 14);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 13).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 13).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 13).unwrap(), false);

        // Even though the following heights (14, 20) >= latest_mainchain_commitment_height, we should return true, not None.
        // A true result can never become false in the future.
        // Refer to the doc of is_activated_spk_at for more details.
        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 14).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 14).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 14).unwrap(), true);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 20).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 20).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 20).unwrap(), true);
    }

    #[test]
    /// Test that known parameters are not considered change until they are explicitly registered
    /// in a sidechain block
    fn test_unregistered_params() {
        let desc_0 = watchman::blockchain::tests::test_descriptor_1();
        let desc_1 = watchman::blockchain::tests::test_descriptor_2();

        let params_0 = test_params_0();
        let params_1 = test_params_1();

        let change_spk_0 = params_0.fedpeg_program().unwrap();
        let change_spk_1 = params_1.fedpeg_program().unwrap();

        let mut consensus = ConsensusTracker::new(1);
        consensus.update_known_descriptors(vec![
            (0, descriptor::Cached::from(desc_0)), // legacy descriptor
            (5, descriptor::Cached::from(desc_1)),
        ]);
        assert!(consensus.latest_mainchain_commitment_height.is_none());

        consensus.register_sidechain_block(1, Some(8), Some(&params_0));
        consensus.register_sidechain_block(2, Some(9), None);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 8).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 8).unwrap(), false);

        consensus.register_sidechain_block(3, Some(9), None);
        consensus.register_sidechain_block(4, Some(11), None);
        consensus.register_sidechain_block(5, Some(12), None);
        consensus.register_sidechain_block(6, Some(14), None);

        // change_spk_1 should not become change until we explicitly register its parameters
        // (even if we reach its earliest activation block height)
        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 12).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 12).unwrap(), false);

        assert!(consensus.is_activated_spk_at(&change_spk_1, 15).is_none(), "is_activated_spk_at should return \
            None if result is false & mainchain_height >= latest_mainchain_commitment_height");

        consensus.register_sidechain_block(7, Some(15), Some(&params_1));
        consensus.register_sidechain_block(8, Some(16), None);

        // change_spk_1 should be considered change now
        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 15).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 15).unwrap(), true);

        // change_spk_1 should only be considered change after its actual activation height (15)
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 12).unwrap(), false);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 13).unwrap(), false);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 14).unwrap(), false);
    }

    #[test]
    /// Test correct handling of registered parameters whose descriptor is unknown.
    ///
    /// This situation would occur when syncing old history (transactions from a federation whose
    /// CPE is no longer present in the network config).
    fn test_unknown_descriptors() {
        let desc_0 = watchman::blockchain::tests::test_descriptor_1();
        let desc_2 = watchman::blockchain::tests::test_descriptor_3();

        let params_0 = test_params_0();
        let params_1 = test_params_1();
        let params_2 = test_params_2();

        let change_spk_0 = params_0.fedpeg_program().unwrap();
        let change_spk_1 = params_1.fedpeg_program().unwrap();
        let change_spk_2 = params_2.fedpeg_program().unwrap();

        let mut consensus = ConsensusTracker::new(1);

        // Leave desc_1 as unknown
        consensus.update_known_descriptors(vec![
            (0, descriptor::Cached::from(desc_0)), // legacy descriptor
            (10, descriptor::Cached::from(desc_2)),
        ]);
        assert!(consensus.latest_mainchain_commitment_height.is_none());

        consensus.register_sidechain_block(1, Some(8), Some(&params_0));
        consensus.register_sidechain_block(2, Some(8), None);
        consensus.register_sidechain_block(3, Some(9), None);
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 9);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 8).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 8).unwrap(), false);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 8).unwrap(), false);

        consensus.register_sidechain_block(3, Some(9), None);
        consensus.register_sidechain_block(4, Some(12), None);
        consensus.register_sidechain_block(5, Some(12), None);
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 12);

        // Register the params whose descriptor is unknown
        consensus.register_sidechain_block(6, Some(13), Some(&params_1));
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 13);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 12).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 12).unwrap(), false);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 12).unwrap(), false);

        // change_spk_1 should be considered change at mainchain block 13 despite its descriptor
        // being unknown, since its parameters have already activated on the sidechain by that point.
        //
        // NB the descriptor is used to determine information about peers, but it should not be needed
        // to determine if a utxo is change.
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 13).unwrap(), true);

        consensus.register_sidechain_block(8, Some(14), None);
        consensus.register_sidechain_block(9, Some(15), None);
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 15);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 14).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 14).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 14).unwrap(), false);

        // Register the final params (whose descriptor is known by the ConsensusTracker)
        consensus.register_sidechain_block(10, Some(15), Some(&params_2));
        consensus.register_sidechain_block(11, Some(15), None);
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 15);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 14).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 14).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 14).unwrap(), false);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 15).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 15).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 15).unwrap(), true);

        consensus.register_sidechain_block(12, Some(35), None);
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 35);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 30).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 30).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_2, 30).unwrap(), true);
    }

    /// Test that old parameters are not allowed to activate.
    #[test]
    #[should_panic]
    fn test_old_param_registration() {
        let desc_0 = watchman::blockchain::tests::test_descriptor_1();
        let desc_1 = watchman::blockchain::tests::test_descriptor_2();

        let params_0 = test_params_0();
        let params_1 = test_params_1();

        let change_spk_0 = params_0.fedpeg_program().unwrap();
        let change_spk_1 = params_1.fedpeg_program().unwrap();

        let mut consensus = ConsensusTracker::new(1);

        consensus.update_known_descriptors(vec![
            (0, descriptor::Cached::from(desc_0)), // legacy descriptor
            (3, descriptor::Cached::from(desc_1)),
        ]);
        assert!(consensus.latest_mainchain_commitment_height.is_none());

        consensus.register_sidechain_block(1, Some(8), Some(&params_0));
        consensus.register_sidechain_block(2, Some(9), None);

        assert_eq!(consensus.is_activated_spk_at(&change_spk_0, 8).unwrap(), true);
        assert_eq!(consensus.is_activated_spk_at(&change_spk_1, 8).unwrap(), false);

        consensus.register_sidechain_block(3, Some(9), Some(&params_1));

        // Try to activate old params (for an old sidechain block). This should panic.
        consensus.register_sidechain_block(2, Some(9), Some(&params_0));
    }

    #[test]
    fn test_descriptor_at_mainchain_height() {
        let desc_0 = watchman::blockchain::tests::test_descriptor_1();
        let desc_1 = watchman::blockchain::tests::test_descriptor_2();
        let desc_2 = watchman::blockchain::tests::test_descriptor_3();

        let params_0 = test_params_0();
        let params_1 = test_params_1();
        let params_2 = test_params_2();

        let change_spk_0 = params_0.fedpeg_program().unwrap();
        let change_spk_1 = params_1.fedpeg_program().unwrap();
        let change_spk_2 = params_2.fedpeg_program().unwrap();

        let mut consensus = ConsensusTracker::new(1);
        consensus.update_known_descriptors(vec![
            (0, descriptor::Cached::from(desc_0)), // legacy descriptor
            (5, descriptor::Cached::from(desc_1)),
            (10, descriptor::Cached::from(desc_2))
        ]);
        assert!(consensus.latest_mainchain_commitment_height.is_none());

        consensus.register_sidechain_block(1, None, None);
        consensus.register_sidechain_block(2, None, None);

        // Record the first dynafed transition (params are equal to the legacy descriptor)
        consensus.register_sidechain_block(3, Some(8), Some(&params_0));
        consensus.register_sidechain_block(4, Some(9), None);
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 9);

        assert_eq!(consensus.descriptor_at_mainchain_height(8).spk, *change_spk_0);

        let result = std::panic::catch_unwind(|| consensus.descriptor_at_mainchain_height(9));
        assert!(result.is_err(),"we should not be able to determine a descriptor at a given \
            mainchain height before we commit to a height past it");

        // Second dynafed transition
        consensus.register_sidechain_block(5, Some(10), Some(&params_1));
        consensus.register_sidechain_block(6, Some(12), None);
        consensus.register_sidechain_block(7, Some(12), None);
        consensus.register_sidechain_block(8, Some(12), None);
        consensus.register_sidechain_block(9, Some(13), None);
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 13);

        assert_eq!(consensus.descriptor_at_mainchain_height(8).spk, *change_spk_0);
        assert_eq!(consensus.descriptor_at_mainchain_height(10).spk, *change_spk_1);

        let result = std::panic::catch_unwind(|| consensus.descriptor_at_mainchain_height(13));
        assert!(result.is_err(), "we should not be able to determine a descriptor at a given \
            mainchain height before we commit to a height past it");

        // Third dynafed transition
        consensus.register_sidechain_block(10, Some(14), Some(&params_2));
        consensus.register_sidechain_block(11, Some(15), None);
        consensus.register_sidechain_block(12, Some(16), None);
        assert_eq!(consensus.latest_mainchain_commitment_height.unwrap(), 16);

        assert_eq!(consensus.descriptor_at_mainchain_height(8).spk, *change_spk_0);
        assert_eq!(consensus.descriptor_at_mainchain_height(10).spk, *change_spk_1);
        assert_eq!(consensus.descriptor_at_mainchain_height(13).spk, *change_spk_1);
        assert_eq!(consensus.descriptor_at_mainchain_height(14).spk, *change_spk_2);
        assert_eq!(consensus.descriptor_at_mainchain_height(15).spk, *change_spk_2);

        let result = std::panic::catch_unwind(|| consensus.descriptor_at_mainchain_height(16));
        assert!(result.is_err(), "we should not be able to determine a descriptor at a given \
            mainchain height before we commit to a height past it");
    }
}
