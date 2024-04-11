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
//! Configuration file for the watchman
//!

use bitcoin::secp256k1::SecretKey;
use std::time::Duration;
use bitcoin::Amount;

use config;
use config::deserialize_hex_bitcoin_tx;
use config::serialize_bitcoin_tx_hex;
use common::BlockHeight;
use common::constants::Constants;
use peer;
use tweak;
use common::rollouts::Rollouts;
use common::deserialize_duration_ms;

/// Local configuration (RPC connections, etc)
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct Local {
    /// Verbosity level of the logging syste
    pub log_level: logs::Severity,
    /// Period (in ms) to monitor for throttling
    pub log_period_ms: Option<u64>,
    /// Limit on emission of a given log per log_period_ms
    pub log_max_instance_per_period: Option<u32>,
    /// The addresses and ports to listen on
    pub listen_addresses: Vec<String>,
    /// Path to a UNIX socket used to communicate with the HSM, if one exists
    #[serde(deserialize_with = "config::deserialize_hsm_socket")]
    pub hsm_socket: Option<String>,
    /// http://url:port of the sidechaind RPC
    pub sidechaind_rpc_url: String,
    /// RPC username for sidechaind
    pub sidechaind_rpc_user: String,
    /// RPC password for sidechaind
    pub sidechaind_rpc_pass: String,

    /// http://url:port of the bitcoind RPC
    pub bitcoind_rpc_url: String,
    /// RPC username for bitcoind
    pub bitcoind_rpc_user: String,
    /// RPC password for bitcoind
    pub bitcoind_rpc_pass: String,

    /// Any feature rollouts to be overridden via the config
    pub feature_rollouts: Option<Rollouts>,
    /// Any constants to be overridden via the config
    pub constants: Option<Constants>,

    /// A list of explicitly defined Federation UTXOs that this watchman should sweep if it can
    /// ASAP
    pub explicit_sweep_utxos: Option<Vec<bitcoin::OutPoint>>,
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

    /// Number of Bitcoin blocks to skip when doing initial sync
    pub main_skip_height: BlockHeight,
    /// Number of wallet UTXOs to target when choosing coins
    pub n_main_outputs: usize,
    /// How many peers must precommit to a transaction before we'll sign it
    pub precommit_threshold: usize,
}

/// Consensus parameter entry
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct WatchmanConsensusParams {
    /// The minimum starting blockheight at which the parameters should
    /// become active
    pub start: usize,
    /// Watchman federation descriptor
    pub wm_descriptor: miniscript::Descriptor<String>,
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

    /// Feerate to use when Bitcoind cannot provide one
    pub fallback_fee_rate: Amount,
    /// Whether to validate PAK proofs when processing pegouts
    pub validate_pegout_authorization_proof: bool,
    /// We get the mainchain confirmation threshold from the sidechain node.
    /// However older sidechain nodes (<= 0.14.x) don't provide the required
    /// field in the sidechaininfo. In that case this fallback is used.
    #[serde(alias = "n_mainchain_confirms")]
    pub fallback_mainchain_confirmations: Option<BlockHeight>,
    /// The epoch length to use if a functionary is started on a predynafed network
    pub predynafed_epoch_length: Option<BlockHeight>,
    /// Vector of dynamic-federation consensus parameters.
    #[serde(default)]
    pub cpes: Vec<WatchmanConsensusParams>,
    /// A list of failed pegins to try sweep
    pub failed_pegins: Option<Vec<FailedPeginData>>,
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
    /// Check the sanity of the config.
    /// Panics if any of the descriptors cannot be translated
    pub fn sanity_check(&self) -> Result<(), String> {
        // Make sure we ourselves are part of the peer list.
        match self.consensus.peers.iter().filter(|p| p.name == self.node.name).count() {
            0 => return Err("we don't appear in the peer list".into()),
            1 => {},
            _ => return Err("we appear multiple times in the peer list".into()),
        }

        // Sanity check all the descriptors
        config::wm_desc_sanity_check(
            self.consensus.cpes.iter().map(|cpe| {
                self.typed_watchman_descriptor(&cpe.wm_descriptor)
            })
        )
    }

    /// Total length of all rounds
    pub fn heartbeat(&self) -> Duration {
        self.consensus.stage1 + self.consensus.stage2 + self.consensus.stage3
    }

    /// Look up the peer ID of the current node
    pub fn my_id(&self) -> peer::Id {
        let me = self.consensus.peers.iter().find(|p| p.name == self.node.name).unwrap();
        peer::Id::from(me.sign_pk)
    }

    /// Translate the stringified keys into strongly typed keys usable by the library
    pub fn typed_watchman_descriptor(
        &self,
        watchman_descriptor: &miniscript::Descriptor<String>
    ) -> miniscript::Descriptor<tweak::Key> {
        config::translate_descriptor(
            &watchman_descriptor,
            |key| self
                .consensus
                .peers
                .iter()
                .find(|peer| peer.name == *key)
                .map(|peer| (peer::Id::from(peer.sign_pk), peer.sign_pk),
        ))
    }
}

/// The data required to try recover a failed peg-in transaction
#[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
pub struct FailedPeginData {
    /// The full mainchain peg-in lock transaction
    #[serde(deserialize_with = "deserialize_hex_bitcoin_tx", serialize_with = "serialize_bitcoin_tx_hex")]
    pub mainchain_tx: bitcoin::Transaction,
    /// pegin lock output index
    pub vout: u32,
    /// Blockhash of the mainchain block containing lock transaction
    pub mainchain_blockhash: bitcoin::BlockHash,
    /// The peg-in claim script
    pub claim_script: bitcoin::ScriptBuf,
}
