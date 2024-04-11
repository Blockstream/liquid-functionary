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
//!
//! Configuration file for the blocksigner
//!

use bitcoin::secp256k1::{PublicKey, SecretKey};
use elements::hashes::sha256;
use miniscript::Descriptor;
use std::time::Duration;
use common::constants::Constants;

use config;
use common::PakList;
use peer;
use tweak;
use common::rollouts::Rollouts;
use common::deserialize_duration_ms;

/// Local configuration (RPC connections, etc)
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct Local {
    /// Verbosity level of the logging system
    pub log_level: logs::Severity,
    /// Period (in ms) to monitor for throttling
    pub log_period_ms: Option<u64>,
    /// Limit on emission of a given log per log_period_ms
    pub log_max_instance_per_period: Option<u32>,
    /// The addresses and ports to listen on
    pub listen_addresses: Vec<String>,
    /// Path to a UNIX socket used to communicate with the HSM, if one exists,
    /// or the literal `false`
    #[serde(deserialize_with = "config::deserialize_hsm_socket")]
    pub hsm_socket: Option<String>,
    /// http://url:port of the sidechaind RPC
    pub sidechaind_rpc_url: String,
    /// RPC username for sidechaind
    pub sidechaind_rpc_user: String,
    /// RPC password for sidechaind
    pub sidechaind_rpc_pass: String,

    //NB make this non-optional as soon as this is generally deployed
    /// http://url:port of the bitcoind RPC
    pub bitcoind_rpc_url: Option<String>,
    /// RPC username for bitcoind
    pub bitcoind_rpc_user: Option<String>,
    /// RPC password for bitcoind
    pub bitcoind_rpc_pass: Option<String>,

    /// Signal dynafed activation, default is true.
    pub signal_dynafed_activation: Option<bool>,

    /// Any feature rollouts to be overridden via the config
    pub feature_rollouts: Option<Rollouts>,
    /// Any constants to be overridden via the config
    pub constants: Option<Constants>,
}

/// Node configuration (name, keys, etc)
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct Node {
    /// Name of this node (must index into peer list)
    pub name: String,
    /// Blocksigning secret key, if one is available..
    /// (If not, the code will fall back to trying to use an HSM.)
    #[serde(deserialize_with = "config::deserialize_secret_key_opt")]
    pub signing_secret_key: Option<SecretKey>,
    /// Network authentication secret key (in base58)
    #[serde(deserialize_with = "config::deserialize_secret_key")]
    pub communication_secret_key: SecretKey,
    /// How many peers must precommit to a block before we'll sign it
    pub precommit_threshold: usize,
}

/// Consensus parameter entry
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct BlocksignerConsensusParams {
    /// The minimum starting blockheight at which the parameters should
    /// become active
    pub start: usize,
    /// Blocksigning network descriptor
    pub blocksigner_descriptor: Descriptor<String>,
    /// If given, it overwrites the signblock_witness_limit field.
    pub override_signblock_witness_limit: Option<usize>,
    /// Watchman network descriptor
    pub watchman_descriptor: Descriptor<PublicKey>,
    /// PAK entries
    #[serde(default, with = "serde_paklist_config")]
    pub watchman_pak_list: PakList,
    /// Optional root hash validation
    pub root_hash: Option<sha256::Midstate>,
}

pub mod serde_paklist_config {
    //! Different serde serialization for PAK lists in config files:
    //! As a list of online/offline pairs.
    #![allow(missing_docs)]

    use common::PakList;
    use bitcoin::secp256k1::PublicKey;

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<PakList, D::Error> {
        let list: Vec<(PublicKey, PublicKey)> = serde::Deserialize::deserialize(d)?;
        Ok(PakList::from_pairs(list))
    }

    #[allow(unused)] // might be useful later
    pub fn serialize<S: serde::Serializer>(pak: &PakList, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&pak.pairs().collect::<Vec<_>>(), s)
    }
}

/// Consensus configuration (other peers, etc)
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct Consensus {
    /// List of description of all peers
    #[serde(alias="peer")]
    pub peers: Vec<peer::Peer>,
    /// Duration of stage 1 (in ms)
    #[serde(alias="stage1_ms")]
    #[serde(deserialize_with = "deserialize_duration_ms")]
    pub stage1: Duration,
    /// Duration of stage 2 (in ms)
    #[serde(alias="stage2_ms")]
    #[serde(deserialize_with = "deserialize_duration_ms")]
    pub stage2: Duration,
    /// Duration of stage 3 (in ms)
    #[serde(alias="stage3_ms")]
    #[serde(deserialize_with = "deserialize_duration_ms")]
    pub stage3: Duration,
    /// Vector of dynamic-federation transitions
    #[serde(default)]
    pub cpe: Vec<BlocksignerConsensusParams>,
}

/// Global blocksigner settings structure
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct Configuration {
    /// Local settings
    pub local: Local,
    /// Node settings
    pub node: Node,
    /// Consensus settings
    pub consensus: Consensus,
}

impl Configuration {
    /// Total length of all rounds
    pub fn heartbeat(&self) -> Duration {
        self.consensus.stage1 + self.consensus.stage2 + self.consensus.stage3
    }

    /// Look up the peer ID of the current node
    pub fn my_id(&self) -> peer::Id {
        let mut ret = None;
        for peer in &self.consensus.peers {
            if peer.name == self.node.name {
                if ret.is_none() {
                    ret = Some(peer::Id::from(peer.sign_pk));
                } else {
                    panic!("Saw {} twice in the peer list", self.node.name);
                }
            }
        }
        ret.expect("Did not find own name in the peer list.")
    }

    /// Convert a stringly-typed descriptor into one where the pubkeys
    /// are populated, using the peer-key mapping given by this configuration
    pub fn convert_descriptor(
        &self,
        descriptor: &miniscript::Descriptor<String>,
    ) -> miniscript::Descriptor<tweak::Key> {
        config::translate_descriptor(
            descriptor,
            |key| self
                .consensus
                .peers
                .iter()
                .find(|peer| peer.name == *key)
                .map(|peer| (peer::Id::from(peer.sign_pk), peer.sign_pk)),
        )
    }
}
