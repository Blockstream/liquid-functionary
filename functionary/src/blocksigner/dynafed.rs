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

//! # Dynamic Federations
//!
//! Support for triggering dynamic federation transitions
//!

use std::fmt;
use std::{io, ops::Index};
use std::collections::HashSet;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use common::{util::ToElementsScript, BlockHeight};
use elements::{self, BlockExtData};
use miniscript::{TranslatePk, DescriptorTrait, Descriptor};

use blocksigner::config::Configuration;
use descriptor::LiquidDescriptor;
use message;
use tweak;
use peer;

use crate::descriptor::TweakableDescriptor;

/// The bitmask for the BIP9 deployment of dynafed.
/// This value is the same for liquidv1 and elementsregtest.
pub const DYNAFED_BIP9_VERSIONBIT_MASK: u32 = 1 << 25;

/// Status of the CPE lifecycle
/// New -> Proposed -> Activated -> Old
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParamsStatus {
    /// New CPE that is yet to be proposed.
    New,
    /// CPE that has been proposed but is not yet active.
    Proposed,
    /// CPE that has been activated and is currently active.
    Activated,
    /// Old CPE that is no longer active.
    Old,
}

impl Default for ParamsStatus {
    fn default() -> Self {
        Self::New
    }
}

impl fmt::Display for ParamsStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// Consensus parameters, with auxiliary data used to determine
/// when to signal
#[derive(Debug, Clone)]
pub struct Params {
    /// The parameters' root
    pub root: sha256::Midstate,
    /// Height at which to start signalling
    pub start_height: BlockHeight,
    /// The named blocksigning descriptor, as found in the config file
    pub signblock_descriptor_named: Descriptor<String>,
    /// Key-populated blocksigning descriptor
    pub signblock_descriptor: Descriptor<tweak::Key>,
    /// The watchman descriptor
    pub watchman_descriptor: Descriptor<PublicKey>,
    /// List of peers which have indicated support for these parameters
    pub signalled: HashSet<peer::Id>,
    /// The actual parameters
    pub params: elements::dynafed::Params,
    /// Lifeycle status of these params
    pub status: ParamsStatus,
}

impl Params {
    /// Get the set of block signing keys of these parameters.
    pub fn block_signing_keys(&self) -> HashSet<PublicKey> {
        let mut ret = HashSet::new();
        self.signblock_descriptor.translate_pk::<_, _, ()>(
            |tweaked| {
                if let tweak::Key::Tweakable(_id, ref pk) = tweaked {
                    if !ret.insert(pk.clone()) {
                        panic!("signblock descriptor has a duplicate key {}: {}",
                            pk, self.signblock_descriptor_named,
                        );
                    }
                    Ok(pk.clone())
                } else {
                    unreachable!("config already parsed this descriptor")
                }
            },
            |_pkh| unreachable!("config already parsed this descriptor"),
        ).unwrap();
        ret
    }

    /// Returns the signblock and watchman descriptors, with the signblock descriptor key
    /// translated from [tweak::Key] to [PublicKey].
    pub fn normalized_descriptors(&self) -> (Descriptor<PublicKey>, Descriptor<PublicKey>) {
        (self.signblock_descriptor.to_descriptor_publickey(), self.watchman_descriptor.clone())
    }

    /// Returns true if these `Params` are still new.
    pub fn never_proposed(&self) -> bool {
        matches!(self.status, ParamsStatus::New)
    }

    /// Returns true if these `Params` have never been activated.
    pub fn never_activated(&self) -> bool {
        matches!(self.status, ParamsStatus::New | ParamsStatus::Proposed)
    }

    /// Returns true if these `Params` are currently proposed.
    pub fn is_proposed(&self) -> bool {
        matches!(self.status, ParamsStatus::Proposed)
    }

    /// Sets this `Params` status to Proposed.
    /// Returns `ParamsStatus::Proposed` as a convenience for callers.
    pub fn set_proposed(&mut self) -> ParamsStatus {
        self.status = ParamsStatus::Proposed;
        ParamsStatus::Proposed
    }

    /// Returns true if these `Params` are currently activated.
    pub fn is_activated(&self) -> bool {
        matches!(self.status, ParamsStatus::Activated)
    }

    /// Sets this `Params` status to Activated.
    /// Returns `ParamsStatus::Activated` as a convenience for callers.
    pub fn set_activated(&mut self) -> ParamsStatus {
        self.status = ParamsStatus::Activated;
        ParamsStatus::Activated
    }

    /// Returns true if these `Params` are old.
    pub fn is_old(&self) -> bool {
        matches!(self.status, ParamsStatus::Old)
    }

    /// Sets this `Params` status to Old.
    /// Returns `ParamsStatus::Old` as a convenience for callers.
    pub fn set_old(&mut self) -> ParamsStatus {
        self.status = ParamsStatus::Old;
        ParamsStatus::Old
    }
}

/// The set of CPEs the functionary knows about with minimum start heights and
/// peer votes tracked to ensure that we only propose things at the right time
/// and with sufficient support to avoid consensus failures.
// Their uniqueness and order based on the start height is ensured in the constructor.
// Roots don't duplicate.
pub struct CpeSet(Vec<Params>);

impl CpeSet {
    /// Constructs a new `CpeSet` from the set of CPEs specified in the
    /// node's configuration
    pub fn from_config(config: &Configuration) -> Result<CpeSet, String> {
        let mut set = Vec::<Params>::with_capacity(config.consensus.cpe.len());

        for cpe in &config.consensus.cpe {
            // Check that start height is unique.
            if set.iter().any(|e| e.start_height == cpe.start as BlockHeight) {
                return Err(format!("duplicate CPE with start height {}", cpe.start));
            }

            let bs_desc = config.convert_descriptor(&cpe.blocksigner_descriptor);
            let wm_desc = &cpe.watchman_descriptor;

            let signblockscript = bs_desc.script_pubkey().to_elements_script();
            let max_weight = bs_desc.max_satisfaction_weight().expect("descriptor to be satisfiable");
            let signblock_witness_limit = cpe.override_signblock_witness_limit.unwrap_or(max_weight) as u32;
            let fedpeg_program = wm_desc.liquid_script_pubkey();

            let params = elements::dynafed::Params::Full {
                signblockscript,
                signblock_witness_limit,
                fedpeg_program,
                fedpegscript: wm_desc.liquid_witness_script().into_bytes(),
                extension_space: cpe.watchman_pak_list.to_extension_space(),
            };
            let root = params.calculate_root();
            if let Some(dup) = set.iter().find(|e| e.root == root) {
                return Err(format!(
                    "duplicate CPE with root {} (start={} & start={})", root, cpe.start, dup.start_height,
                ));
            }
            if cpe.root_hash.is_some() && cpe.root_hash.unwrap() != root {
                return Err(format!("start: {}, root in config file ({}) does not match calculated root ({})",
                    cpe.start, cpe.root_hash.unwrap(), root));
            }
            set.push(Params {
                root: root,
                start_height: cpe.start as BlockHeight,
                signblock_descriptor_named: cpe.blocksigner_descriptor.clone(),
                signblock_descriptor: bs_desc,
                watchman_descriptor: wm_desc.clone(),
                signalled: HashSet::with_capacity(config.consensus.peers.len()),
                params: params,
                status: ParamsStatus::New,
            });

            let wm_desc = &cpe.watchman_descriptor;
            let (addr_main, addr_test, addr_main_tweaked, addr_test_tweaked) = if wm_desc.is_legacy_liquid_descriptor() {
                let tweaked_spk = wm_desc.csv_tweaked_descriptor().liquid_script_pubkey();
                let send_tweaked = wm_desc.liquid_script_pubkey() != tweaked_spk;
                (
                    bitcoin::Address::from_script(&wm_desc.liquid_script_pubkey(), bitcoin::Network::Bitcoin).unwrap(),
                    bitcoin::Address::from_script(&wm_desc.liquid_script_pubkey(), bitcoin::Network::Regtest).unwrap(),
                    if send_tweaked {Some(bitcoin::Address::from_script(&tweaked_spk, bitcoin::Network::Bitcoin).unwrap().to_string())} else {None},
                    if send_tweaked {Some(bitcoin::Address::from_script(&tweaked_spk, bitcoin::Network::Regtest).unwrap().to_string())} else {None},
                )
            } else {
                (
                    wm_desc.address(bitcoin::Network::Bitcoin).unwrap(),
                    wm_desc.address(bitcoin::Network::Regtest).unwrap(),
                    None,
                    None,
                )
            };

            slog!(ConsensusParameterParsed, height: cpe.start as u64, root: root,
                  signblock_descriptor: &cpe.blocksigner_descriptor.to_string(),
                  watchman_descriptor: &wm_desc.to_string(),
                  watchman_change_address_mainnet: &addr_main.to_string(),
                  watchman_change_address_regtest: &addr_test.to_string(),
                  watchman_change_address_mainnet_tweaked: addr_main_tweaked,
                  watchman_change_address_regtest_tweaked: addr_test_tweaked,
                  watchman_pak_list: cpe.watchman_pak_list.iter().cloned().map(From::from).collect(),
            );
        }

        // Sort the CPEs by start height.
        set.sort_by(|e1, e2| e1.start_height.cmp(&e2.start_height));

        assert_eq!(0, set.get(0).expect("empty CPE list!").start_height,
            "first CPE does not have start height 0",
        );

        let mut ret = CpeSet(set);
        // Initialize the signalling tally.
        ret.reset_signalling();
        Ok(ret)
    }

    /// Get the pre-dynafed parameters.
    pub fn pre_dynafed_params(&self) -> Option<&Params> {
        self.0.iter().find(|e| e.start_height == 0)
    }

    /// Whether we have all we need to activate dynafed.
    pub fn dynafed_ready(&self, n_peers: usize) -> bool {
        !self.0.is_empty() && self.0[0].signalled.len() * 5 >= n_peers * 4
    }

    /// Accessor for a vector of parameters with a start height lower or equal
    /// to the given height.
    pub fn params_at(&self, height: BlockHeight) -> Vec<elements::dynafed::Params> {
        self.0.iter().filter(|p| p.start_height <= height).map(|p| p.params.clone()).collect()
    }

    /// Reset all vote counts to 1 in preparation for a new round
    pub fn reset_signalling(&mut self) {
        self.0.iter_mut().for_each(|e| e.signalled.clear());
    }

    /// Record support for all known params before or for the given height.
    pub fn record_self_support(&mut self, id: peer::Id, height: BlockHeight) {
        self.0.iter_mut().filter(|p| p.start_height <= height).for_each(|p| {
            p.signalled.insert(id);
        })
    }

    /// Record that a peer has voted for (i.e. included in its `Status` message)
    /// support for a given proposal. Returns true if the vote was recorded;
    /// false if the referenced parameter set was unknown to us
    pub fn record_param_support(&mut self, root: sha256::Midstate, peer: peer::Id) -> bool {
        for cpe in self.0.iter_mut() {
            if cpe.root == root {
                cpe.signalled.insert(peer);
                return true;
            }
        }
        false
    }

    /// Accessor for the parameters by their root.
    pub fn get_params(&self, root: sha256::Midstate) -> Option<&Params> {
        self.0.iter().find(|e| e.root == root)
    }

    /// Dump tally of parameters
    pub fn audit_params(&self, n_peers: usize) {
        self.0.iter().for_each(|e| slog!(ConsensusParameterTally, signalled: e.signalled.clone(),
            height: e.start_height, root: e.root,
            signblock_descriptor: format!("{}", e.signblock_descriptor_named).as_str(),
            peer_count: n_peers,
        ));
    }

    /// Determine the parameters which should be proposed in the
    /// next block. If the returned parameters are active, it is the
    /// caller's responsibility to notice this and not bother proposing.
    pub fn target_params(&self,
        current_root: sha256::Midstate,
        target_height: BlockHeight,
        n_peers: usize,
    ) -> Option<&Params> {
        // Never go backwards.
        let eligible = self.0.iter().skip_while(|e| e.root != current_root).collect::<Vec<_>>();

        // Then filter the ones that have enough signalling from peers.
        let accepted = eligible.into_iter().filter(|e| e.signalled.len() * 5 >= n_peers * 4);

        // Then take the newest one with a start height below or on target.
        accepted.rev().find(|e| e.start_height <= target_height)
    }

    /// Get the legacy consensus parameters (if they exist)
    pub fn legacy_params(&self) -> Option<&Params> {
        self.0.iter().find(|e| e.start_height == 0)
    }

    /// Get the Elements consensus parameters for the given root.
    pub fn consensus_by_root(&self, root: sha256::Midstate) -> Option<&elements::dynafed::Params> {
        self.0.iter().find(|e| e.root == root).map(|e| &e.params)
    }


    /// Iterates through the CPE set updating each entry's status.
    /// Returns a hashmap of updated entries only, and their new status.
    pub fn update_params_status(&mut self, header: &elements::BlockHeader) {
        if let BlockExtData::Dynafed {
            current,
            proposed,
            ..
        } = &header.ext
        {
            let current_root = current.calculate_root();
            let proposed_root = proposed.calculate_root();
            self.update_params_status_by_roots(header.height, current_root, proposed_root);
        }
    }

    fn update_params_status_by_roots(
        &mut self,
        height: u32,
        current_root: sha256::Midstate,
        proposed_root: sha256::Midstate,
    ) {
        let mut iter = self.0.iter_mut().peekable();
        let mut previous: Option<&mut Params> = None;

        while let Some(this) = iter.next() {
            if let Some(next) = iter.peek_mut() {
                // there is a cpe after this one
                // check if it's proposed in this block
                if next.root == proposed_root && !next.is_proposed() {
                    let proposed = next.set_proposed();
                    slog!(ParamsUpdated, root: next.root, status: proposed.to_string(), height: height.into())
                }
            }

            if this.root == current_root {
                // this cpe is active
                if !this.is_activated() {
                    let activated = this.set_activated();
                    slog!(ParamsUpdated, root: this.root, status: activated.to_string(), height: height.into())
                }

                // the previous cpe is old
                if let Some(previous) = previous {
                    if !previous.is_old() {
                        let old = previous.set_old();
                        slog!(ParamsUpdated, root: previous.root, status: old.to_string(), height: height.into())
                    }
                }
            }
            previous = Some(this);
        }
    }
}

impl Index<usize> for CpeSet {
    type Output = Params;

    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

// Wrap elements consensus encoding to allow dynafed params
// to be transferred over the network protocol
impl message::NetEncodable for elements::dynafed::Params {
    fn encode<W: io::Write>(&self, w: W) -> Result<usize, message::Error> {
        elements::encode::Encodable::consensus_encode(self, w)
            .map_err(message::Error::BadParseElements)
    }

    fn decode<R: io::Read>(r: R) -> Result<Self, message::Error> {
        elements::encode::Decodable::consensus_decode(r)
            .map_err(message::Error::BadParseElements)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::sha256;

    #[test]
    fn test_target_params() {
        let peer1 = peer::Id::from(&[1, 0, 0, 0, 0, 0][..]);
        let peer2 = peer::Id::from(&[2, 0, 0, 0, 0, 0][..]);
        let peer3 = peer::Id::from(&[3, 0, 0, 0, 0, 0][..]);

        // generate 5 different params with empty signalled
        let params = (1u8..6).map(|i| Params {
            root: sha256::Midstate::from_inner([i; 32]),
            start_height: 10 * i as u64,
            signalled: Default::default(),
            // rest is dummy because unused in this test
            signblock_descriptor_named: "sh(1)".parse().unwrap(),
            signblock_descriptor: "sh(1)".parse().unwrap(),
            watchman_descriptor: "sh(1)".parse().unwrap(),
            params: elements::dynafed::Params::Null,
            status: ParamsStatus::New,
        }).collect::<Vec<_>>();

        let mut set = CpeSet(params.clone());
        set.record_self_support(peer1, 100);
        assert!(set.target_params(params[0].root, 21, 4).is_none());
        assert_eq!(set.target_params(params[0].root, 21, 1).unwrap().root, params[1].root);

        set.record_param_support(params[0].root, peer2);
        set.record_param_support(params[0].root, peer3);
        set.record_param_support(params[1].root, peer2);
        set.record_param_support(params[1].root, peer3);
        set.record_param_support(params[2].root, peer2);
        // 2 doesn't have enough votes
        assert_eq!(set.target_params(params[0].root, 100, 3).unwrap().root, params[1].root);

        set.record_param_support(params[2].root, peer3);
        assert_eq!(set.target_params(params[0].root, 100, 3).unwrap().root, params[2].root);
        // 1 and 2 are later
        assert_eq!(set.target_params(params[0].root, 11, 3).unwrap().root, params[0].root);
        // 2 is later
        assert_eq!(set.target_params(params[0].root, 21, 3).unwrap().root, params[1].root);
    }

    #[test]
    fn it_update_params_status() {
        let params = (1..=4).map(|i| Params {
            root: sha256::Midstate::from_inner([i; 32]),
            start_height: 10 * i as u64,
            signalled: Default::default(),
            signblock_descriptor_named: "sh(1)".parse().unwrap(),
            signblock_descriptor: "sh(1)".parse().unwrap(),
            watchman_descriptor: "sh(1)".parse().unwrap(),
            params: elements::dynafed::Params::Null,
            status: ParamsStatus::New,
        }).collect::<Vec<_>>();

        let mut set = CpeSet(params);
        for cpe in set.0.iter() {
            assert!(cpe.never_proposed());
            assert!(cpe.never_activated());
        }

        // current 0, proposed none
        let current_root = set[0].root;
        let proposed_root = sha256::Midstate::default();
        set.update_params_status_by_roots(1, current_root, proposed_root);
        assert!(set[0].is_activated());
        assert!(set[1].never_proposed());
        assert!(set[2].never_proposed());
        assert!(set[3].never_proposed());

        // current 0, proposed 1
        let current_root = set[0].root;
        let proposed_root = set[1].root;
        set.update_params_status_by_roots(2, current_root, proposed_root);
        assert!(set[0].is_activated());
        assert!(set[1].is_proposed());
        assert!(set[2].never_proposed());
        assert!(set[3].never_proposed());

        // current 1, proposed none
        let current_root = set[1].root;
        let proposed_root = sha256::Midstate::default();
        set.update_params_status_by_roots(3, current_root, proposed_root);
        assert!(set[0].is_old());
        assert!(set[1].is_activated());
        assert!(set[2].never_proposed());
        assert!(set[3].never_proposed());

        // current 1, proposed 2
        let current_root = set[1].root;
        let proposed_root = set[2].root;
        set.update_params_status_by_roots(4, current_root, proposed_root);
        assert!(set[0].is_old());
        assert!(set[1].is_activated());
        assert!(set[2].is_proposed());
        assert!(set[3].never_proposed());


        // current 2, proposed none
        let current_root = set[2].root;
        let proposed_root = sha256::Midstate::default();
        set.update_params_status_by_roots(5, current_root, proposed_root);
        assert!(set[0].is_old());
        assert!(set[1].is_old());
        assert!(set[2].is_activated());
        assert!(set[3].never_proposed());

        // current 2, proposed 3
        let current_root = set[2].root;
        let proposed_root = set[3].root;
        set.update_params_status_by_roots(6, current_root, proposed_root);
        assert!(set[0].is_old());
        assert!(set[1].is_old());
        assert!(set[2].is_activated());
        assert!(set[3].is_proposed());

        // current 3, proposed none
        let current_root = set[3].root;
        let proposed_root = sha256::Midstate::default();
        set.update_params_status_by_roots(7, current_root, proposed_root);
        assert!(set[0].is_old());
        assert!(set[1].is_old());
        assert!(set[2].is_old());
        assert!(set[3].is_activated());
    }
}
