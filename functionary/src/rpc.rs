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

//! # RPC
//! Support for interacting with bitcoind and sidechaind RPC interfaces
//!

use std::collections::HashSet;
use std::time::{Duration, Instant};
use std::cmp;

use bitcoin;
use bitcoin::consensus::{deserialize, Decodable};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::{sha256, sha256d};
use bitcoin::secp256k1::PublicKey;
use serde_json;
use serde::Serialize;
use serde_json::value::RawValue;

use common::BlockHeight;
use common::PakList;
use utils::InChain;

/// RPC error code from Core.
pub const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;

const RPC_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Get information on a Bitcoin tx.
///
/// This is mapped with the getrawtransaction response.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BitcoinTxInfo {
    /// The full transaction in hex
    pub hex: String,
    /// The txid in hex
    pub txid: bitcoin::Txid,
    /// The hash of the block this transaction appeared in, if any
    #[serde(default)]
    pub blockhash: Option<bitcoin::BlockHash>,
}

/// Get information on an Elements tx.
///
/// This is mapped with the getrawtransaction response.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ElementsTxInfo {
    /// The full transaction in hex
    pub hex: String,
    /// The txid in hex
    pub txid: elements::Txid,
    /// The hash of the block this transaction appeared in, if any
    #[serde(default)]
    pub blockhash: Option<elements::BlockHash>,
}

/// Response to `estimatesmartfee`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct EstimateSmartFeeResponse {
    /// The feerate.
    #[serde(default, with = "bitcoin::util::amount::serde::as_btc::opt")]
    pub feerate: Option<bitcoin::Amount>,
    /// Errors encountered during processing
    #[serde(default)]
    pub errors: Vec<String>,
    /// The number of blocks which this feerate is targeting
    pub blocks: BlockHeight,
}

/// Type representing the serialization of PAK lists over RPC.
#[derive(Deserialize)]
struct RpcPakList {
    online: Vec<PublicKey>,
    offline: Vec<PublicKey>,
}

impl Into<PakList> for RpcPakList {
    fn into(self) -> PakList {
        PakList::from_pairs(self.offline.into_iter().zip(self.online.into_iter()).collect())
    }
}

/// Information about the sidechain.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct SidechainInfo {
    /// Genesis blockhash on the mainchain
    #[serde(rename = "parent_blockhash")]
    pub parent_genesis: bitcoin::BlockHash,
    /// Asset ID of the pegged asset
    pub pegged_asset: elements::AssetId,
    /// Federated peg script
    pub fedpegscript: bitcoin::Script,
    /// The depth for a pegin transaction to be considered final.
    /// Older versions (<= 0.14.x) of Elements don't provide this field.
    pub pegin_confirmation_depth: Option<BlockHeight>,
}

/// Return for [blockchain_info] method.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockchainInfo {
    /// Current height.
    pub current_height: BlockHeight,
    /// Hash of the currently best block.
    pub best_blockhash: elements::BlockHash,
    /// The currently active signblockscript.
    pub signblock_script: elements::Script,
    /// CPE info from getblockchaininfo
    pub consensus_params: elements::dynafed::Params,
    /// How many blocks we are into the current epoch
    pub epoch_age: BlockHeight,
    /// How many blocks in an epoch
    pub epoch_length: BlockHeight,
    /// Size in bytes of the block and undo files
    pub size_on_disk: u64,
}

/// Return for [gettxout] method.
#[derive(Clone,Debug, Deserialize, Serialize)]
pub struct GetTxOutResponse {
    ///The hash of the block at the tip of the chain
    bestblock: bitcoin::BlockHash,
    /// Number of mainchain confirmations
    pub confirmations: u32,
    /// Value of output
    value: f64
}

/// Return for [getmempoolentry] method.
#[derive(Clone,Debug, Deserialize, Serialize)]
pub struct GetMempoolEntryResponse {
    /// block height when transaction entered pool
    pub height: BlockHeight,
    /// virtual transaction size as defined in BIP 141
    pub vsize: u64,
    /// transaction weight as defined in BIP 141
    pub weight: u64,
}

/// Trait representing something we can do general JSONRPC queries on; abstracts
/// over `jsonrpc::client::Client` so it can be mocked out during testing.
pub trait Rpc {
    /// Convenience method to do a JSONRPC query and deserialize the result
    fn jsonrpc_query<T: serde::de::DeserializeOwned>(
        &self,
        query: &str,
        args: &[jsonrpc::serde_json::Value],
    ) -> Result<T, jsonrpc::Error>;

    /// If there is any other error returns the Error, otherwise returns false.
    fn is_warming_up(&self, endpoint_name: &str) -> Result<bool, jsonrpc::Error>;

    /// Check the version of the daemon we're communicating with
    fn version(&self) -> Result<usize, jsonrpc::Error> {
        #[derive(Deserialize)]
        struct Response {
            version: usize
        }

        let res = self.jsonrpc_query::<Response>("getnetworkinfo", &[])?;
        Ok(res.version)
    }

    /// Get the number of blocks in the best chain.
    fn block_count(&self) -> Result<BlockHeight, jsonrpc::Error> {
        self.jsonrpc_query("getblockcount", &[])
    }

    /// Check whether a given block is in the chain. Also checks that it is
    /// at the expected number of confirmations.
    fn block_is_in_chain(
        &self,
        block_hash: sha256d::Hash,
        expected_depth: BlockHeight,
    ) -> InChain {
        #[derive(Deserialize)]
        pub struct Response {
            pub confirmations: isize,
        }
        match self.jsonrpc_query::<Response>("getblockheader", &[block_hash.to_string().into()]) {
            Ok(resp) => {
                if resp.confirmations == -1 {
                    InChain::ForkedOff
                } else if resp.confirmations == expected_depth as isize {
                    InChain::Yes
                } else {
                    InChain::WrongDepth(resp.confirmations as BlockHeight)
                }
            }
            Err(e @ jsonrpc::Error::Transport(_)) => InChain::RpcError(e),
            Err(_) => InChain::NotFound,
        }
    }
}

/// Bitcoin Core-specific RPC methods.
pub trait BitcoinRpc: Rpc {
    /// Convenience method to do a JSONRPC query for a hex-encoded consensus-encoded object
    fn jsonrpc_query_hex<T: Decodable>(
        &self,
        query: &'static str,
        args: &[jsonrpc::serde_json::Value],
    ) -> Result<T, jsonrpc::Error> {
        let hex = self.jsonrpc_query::<String>(query, args)?;
        match Vec::<u8>::from_hex(&hex[..]) {
            Ok(data) => {
                match deserialize::<T>(&data) {
                    Ok(result) => Ok(result),
                    // this error should never ever happen; perhaps we should panic since this
                    // indicates a faulty/untrustworthy JSONRPC, but since we're able to keep
                    // going, we might as well. in some cases (e.g. mempool getrawtransaction)
                    // it ultimately doesn't matter whether or not our rpc calls work.
                    Err(e) => Err(jsonrpc::Error::Json(
                        serde::de::Error::custom(format!("[bug] bad consensus-encoded data from jsonrpc: {}", e))
                    )),
                }
            }
            // ditto for this one
            Err(e) => Err(jsonrpc::Error::Json(
                serde::de::Error::custom(format!("[bug] bad hex from jsonrpc: {}", e))
            )),
        }
    }

    /// Get a raw transaction.
    fn raw_tx(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction, jsonrpc::Error> {
        self.jsonrpc_query_hex("getrawtransaction", &[txid.to_string().into()])
    }

    /// Get a raw block.
    fn raw_block(&self, hash: bitcoin::BlockHash) -> Result<bitcoin::Block, jsonrpc::Error> {
        self.jsonrpc_query_hex("getblock", &[hash.to_string().into(), false.into()])
    }

    /// Get the raw block header.
    fn raw_header(&self, hash: bitcoin::BlockHash) -> Result<bitcoin::BlockHeader, jsonrpc::Error> {
        self.jsonrpc_query_hex("getblockheader", &[hash.to_string().into(), false.into()])
    }

    /// Send a tx to the network.
    fn send_tx(&self, tx: &bitcoin::Transaction) -> Result<bitcoin::Txid, jsonrpc::Error> {
        self.jsonrpc_query(
            "sendrawtransaction",
            &[bitcoin::consensus::encode::serialize_hex(tx).into()],
        )
    }

    /// Check a supposedly signed transaction for errors.
    fn check_signed_tx(&self, tx: &bitcoin::Transaction) -> Result<Option<String>, jsonrpc::Error> {
        let version = self.version()?;
        let cmd = if version >= 17_00_00 {
            "signrawtransactionwithkey"
        } else {
            "signrawtransaction"
        };

        #[derive(Deserialize, Serialize)]
        pub struct Response {
            pub complete: bool,
            #[serde(default)]
            pub errors: serde_json::Value,
        }
        let res = self.jsonrpc_query::<Response>(cmd,
            &[bitcoin::consensus::encode::serialize_hex(tx).into(), Vec::<String>::new().into()])?;
        if res.complete {
            Ok(None)
        } else {
            Ok(Some(res.errors.to_string()))
        }
    }

    /// get the Merkle proof for a transaction with given txid
    fn txout_proof(&self, txid: bitcoin::Txid, blockhash: bitcoin::BlockHash) -> Result<String, jsonrpc::Error> {
        let txid_args: Vec<jsonrpc::serde_json::Value> = vec![txid.to_string().into()];
        self.jsonrpc_query(
            "gettxoutproof",
            &[
                txid_args.into(),
                blockhash.to_string().into(),
            ],
        )
    }

    /// get details about an unspent output
    fn txout(&self, txid: bitcoin::Txid, vout: u32, include_mempool: bool) -> Result<GetTxOutResponse, jsonrpc::Error> {
        self.jsonrpc_query(
            "gettxout",
            &[
                txid.to_string().into(),
                vout.into(),
                include_mempool.into(),
            ],
        )
    }

    /// Get a smart fee estimate.
    fn estimate_smart_fee(&self, confirm_target: BlockHeight) -> Result<EstimateSmartFeeResponse, jsonrpc::Error> {
        self.jsonrpc_query("estimatesmartfee", &[confirm_target.into()])
    }

    /// Get all txids in the mempool.
    fn raw_mempool(&self) -> Result<HashSet<bitcoin::Txid>, jsonrpc::Error> {
        self.jsonrpc_query::<HashSet<bitcoin::Txid>>("getrawmempool", &[])
    }

    /// Check the mempool for a specific transaction
    fn mempool_entry(&self, txid: &bitcoin::Txid) -> Result<GetMempoolEntryResponse, jsonrpc::Error> {
        self.jsonrpc_query(
            "getmempoolentry",
            &[
                txid.to_string().into(),
            ],
        )
    }

    /// Get information on a tx.
    fn tx_info(&self, txid: bitcoin::Txid) -> Result<BitcoinTxInfo, jsonrpc::Error> {
        self.jsonrpc_query("getrawtransaction", &[txid.to_string().into(), 1.into()])
    }

    /// The last block hash in the chain.
    fn tip(&self) -> Result<bitcoin::BlockHash, jsonrpc::Error> {
        self.jsonrpc_query("getbestblockhash", &[])
    }

    /// Get the block hash at the given height.
    fn block_at(&self, height: BlockHeight) -> Result<bitcoin::BlockHash, jsonrpc::Error> {
        self.jsonrpc_query("getblockhash", &[height.into()])
    }

    /// Asks a jsonrpc client for the block at depth `n` in its chain
    fn block_at_depth(
        &self,
        n: BlockHeight,
    ) -> Result<(BlockHeight, bitcoin::BlockHash), jsonrpc::Error> {
        assert!(n > 0);
        let height = match self.block_count()? {
            // If we have only the genesis, return this as the block at depth n,
            // regardless of n
            0 => 0,
            // otherwise treat n as a 1-indexed depth (as "depth 1" is intuitively
            // the tip itself and "depth 0" is meaningless). Subtract (n - 1) from
            // the tip.
            h => cmp::max(h, n - 1) - (n - 1),
        };
        let hash = self.jsonrpc_query("getblockhash", &[height.into()])?;
        Ok((height, hash))
    }

    /// Look up a specified blockhash and return its height, if it exists in the chain
    fn block_height(
        &self,
        block_hash: bitcoin::BlockHash,
    ) -> Result<Option<BlockHeight>, jsonrpc::Error> {
        #[derive(Deserialize)]
        struct Response {
            pub height: BlockHeight,
        }
        match self.jsonrpc_query::<Response>("getblockheader", &[block_hash.to_string().into()]) {
            Ok(resp) => Ok(Some(resp.height)),
            Err(e @ jsonrpc::Error::Transport(_)) => Err(e),
            Err(_) => Ok(None),
        }
    }
}

/// Elements Core-specific RPC methods.
pub trait ElementsRpc: Rpc {
    /// Convenience method to do a JSONRPC query for a hex-encoded consensus-encoded object
    fn jsonrpc_query_hex<T: elements::encode::Decodable>(
        &self,
        query: &'static str,
        args: &[jsonrpc::serde_json::Value],
    ) -> Result<T, jsonrpc::Error> {
        let hex = self.jsonrpc_query::<String>(query, args)?;
        match Vec::<u8>::from_hex(&hex[..]) {
            Ok(data) => {
                match elements::encode::deserialize::<T>(&data) {
                    Ok(result) => Ok(result),
                    // this error should never ever happen; perhaps we should panic since this
                    // indicates a faulty/untrustworthy JSONRPC, but since we're able to keep
                    // going, we might as well. in some cases (e.g. mempool getrawtransaction)
                    // it ultimately doesn't matter whether or not our rpc calls work.
                    Err(e) => Err(jsonrpc::Error::Json(
                        serde::de::Error::custom(format!("[bug] bad consensus-encoded data from jsonrpc: {}", e))
                    )),
                }
            }
            // ditto for this one
            Err(e) => Err(jsonrpc::Error::Json(
                serde::de::Error::custom(format!("[bug] bad hex from jsonrpc: {}", e))
            )),
        }
    }

    /// Get info about the sidechain.
    fn sidechain_info(&self) -> Result<SidechainInfo, jsonrpc::Error> {
        self.jsonrpc_query("getsidechaininfo", &[])
    }

    /// Get a raw transaction.
    fn raw_tx(&self, txid: elements::Txid) -> Result<elements::Transaction, jsonrpc::Error> {
        self.jsonrpc_query_hex("getrawtransaction", &[txid.to_string().into()])
    }

    /// Get a raw block.
    fn raw_block(&self, hash: elements::BlockHash) -> Result<elements::Block, jsonrpc::Error> {
        self.jsonrpc_query_hex("getblock", &[hash.to_string().into(), false.into()])
    }

    /// Get a raw block header.
    fn raw_header(
        &self,
        hash: elements::BlockHash,
    ) -> Result<elements::BlockHeader, jsonrpc::Error> {
        self.jsonrpc_query_hex("getblockheader", &[hash.to_string().into(), false.into()])
    }

    /// Get a raw block header at the given height.
    fn raw_header_at(&self, height: BlockHeight) -> Result<elements::BlockHeader, jsonrpc::Error> {
        self.raw_header(self.block_at(height)?)
    }

    /// Get some information of the blockchain.
    fn blockchain_info(&self) -> Result<BlockchainInfo, jsonrpc::Error> {
        #[derive(Deserialize)]
        pub struct Response {
            pub blocks: BlockHeight,
            pub bestblockhash: elements::BlockHash,
            pub current_params_root: sha256::Midstate,
            pub current_signblock_hex: elements::Script,
            pub max_block_witness: u32,
            pub current_fedpeg_program: bitcoin::Script,
            pub current_fedpeg_script: bitcoin::Script,
            pub extension_space: Vec<String>,
            pub epoch_age: BlockHeight,
            pub epoch_length: BlockHeight,
            pub size_on_disk: u64,
        }

        let res = self.jsonrpc_query::<Response>("getblockchaininfo", &[])?;
        let params = elements::dynafed::Params::Full {
            signblockscript: res.current_signblock_hex.clone(),
            signblock_witness_limit: res.max_block_witness,
            fedpeg_program: res.current_fedpeg_program,
            fedpegscript: res.current_fedpeg_script.into_bytes(),
            extension_space: res.extension_space.into_iter()
                .map(|h| FromHex::from_hex(&h).expect("invalid hex")).collect(),
        };
        assert_eq!(params.calculate_root(), res.current_params_root, "our root calculation is broken?!");

        Ok(BlockchainInfo {
            current_height: res.blocks,
            best_blockhash: res.bestblockhash,
            signblock_script: res.current_signblock_hex,
            consensus_params: params,
            epoch_age: res.epoch_age,
            epoch_length: res.epoch_length,
            size_on_disk: res.size_on_disk,
        })
    }

    /// Get a new generated block.
    fn new_block(&self) -> Result<elements::Block, jsonrpc::Error> {
        self.jsonrpc_query_hex("getnewblockhex", &[])
    }

    /// Get a new generated block.
    fn new_block_with_commitments(&self, commitments: &[Vec<u8>]) -> Result<elements::Block, jsonrpc::Error> {
        let hex_commitments: Vec<String> = commitments.into_iter().map(|c| c.to_hex()).collect();

        let args = Vec::from([0.into(), serde_json::Value::Null, serde_json::Value::from(hex_commitments)]);

        self.jsonrpc_query_hex("getnewblockhex", &args)
    }

    /// Test a proposed new block.
    fn test_proposed_block(&self, block: &elements::Block) -> Result<(), jsonrpc::Error> {
        let acceptnonstd = true;
        let _ = self.jsonrpc_query::<jsonrpc::serde_json::Value>(
            "testproposedblock",
            &[elements::encode::serialize_hex(block).into(), acceptnonstd.into()]
        )?;

        Ok(())
    }

    /// Submit a block for broadcasting.
    /// Returns None on success, Some(errors) on errors.
    fn submit_block(&self, block: &elements::Block) -> Result<Option<String>, jsonrpc::Error> {
        let res = self.jsonrpc_query::<jsonrpc::serde_json::Value>(
            "submitblock",
            &[elements::encode::serialize_hex(block).into()],
        )?;
        Ok(match res {
            jsonrpc::serde_json::Value::Null => None,
            jsonrpc::serde_json::Value::String(s) => Some(s),
            j => {
                let res = j.to_string();
                slog!(UnexpectedRpcResponse, daemon: "elements", command: "submitblock",
                    response: &res
                );
                Some(res)
            }
        })
    }

    /// Favor this block over other blocks with the same work.
    /// Returns None on success, Some(errors) on errors.
    fn precious_block(&self, hash: elements::BlockHash) -> Result<Option<String>, jsonrpc::Error> {
        let res = self.jsonrpc_query::<jsonrpc::serde_json::Value>(
            "preciousblock",
            &[hash.to_string().into()],
        )?;
        Ok(match res {
            jsonrpc::serde_json::Value::Null => None,
            jsonrpc::serde_json::Value::String(s) => Some(s),
            j => {
                let res = j.to_string();
                slog!(UnexpectedRpcResponse, daemon: "elements", command: "preciousblock",
                    response: &res
                );
                Some(res)
            }
        })
    }

    /// Send a tx to the network.
    fn send_tx(&self, tx: &elements::Transaction) -> Result<elements::Txid, jsonrpc::Error> {
        self.jsonrpc_query("sendrawtransaction", &[elements::encode::serialize_hex(tx).into()])
    }

    /// Get the active PAK list.
    fn pak_list(&self) -> Result<PakList, jsonrpc::Error> {
        #[derive(Deserialize)]
        struct Response {
            block_paklist: RpcPakList,
        }
        let res = self.jsonrpc_query::<Response>("getpakinfo", &[])?;
        Ok(res.block_paklist.into())
    }

    /// Get all txids in the mempool.
    fn raw_mempool(&self) -> Result<HashSet<elements::Txid>, jsonrpc::Error> {
        self.jsonrpc_query::<HashSet<elements::Txid>>("getrawmempool", &[])
    }

    /// Get information on a tx.
    fn tx_info(&self, txid: elements::Txid) -> Result<BitcoinTxInfo, jsonrpc::Error> {
        self.jsonrpc_query("getrawtransaction", &[txid.to_string().into(), 1.into()])
    }

    /// The last block hash in the chain.
    fn tip(&self) -> Result<elements::BlockHash, jsonrpc::Error> {
        self.jsonrpc_query("getbestblockhash", &[])
    }

    /// Get the block hash at the given height.
    fn block_at(&self, height: BlockHeight) -> Result<elements::BlockHash, jsonrpc::Error> {
        self.jsonrpc_query("getblockhash", &[height.into()])
    }

    /// Asks a jsonrpc client for the block at depth `n` in its chain.
    /// `n` must be greater than 0, and a depth of 1 is the chain tip.
    fn block_at_depth(
        &self,
        n: BlockHeight,
    ) -> Result<(BlockHeight, elements::BlockHash), jsonrpc::Error> {
        assert!(n > 0);
        let height = match self.block_count()? {
            // If we have only the genesis, return this as the block at depth n,
            // regardless of n
            0 => 0,
            // otherwise treat n as a 1-indexed depth (as "depth 1" is intuitively
            // the tip itself and "depth 0" is meaningless). Subtract (n - 1) from
            // the tip.
            h => cmp::max(h, n - 1) - (n - 1),
        };
        let hash = self.jsonrpc_query("getblockhash", &[height.into()])?;
        Ok((height, hash))
    }

    /// Look up a specified blockhash and return its height, if it exists in the chain
    fn block_height(
        &self,
        block_hash: elements::BlockHash,
    ) -> Result<Option<BlockHeight>, jsonrpc::Error> {
        #[derive(Deserialize)]
        struct Response {
            pub height: BlockHeight,
        }
        match self.jsonrpc_query::<Response>("getblockheader", &[block_hash.to_string().into()]) {
            Ok(resp) => Ok(Some(resp.height)),
            Err(e @ jsonrpc::Error::Transport(_)) => Err(e),
            Err(_) => Ok(None),
        }
    }

    /// Get the block's confirmation status: tuple of its confirmed height and the number of
    /// confirmations.
    /// This is different from just [block_height] because orphans also have a height, but are not
    /// confirmed.
    fn block_confirm_status(&self, block: elements::BlockHash) -> Result<Option<(BlockHeight, i64)>, jsonrpc::Error> {
        #[derive(Deserialize)]
        struct Response {
            pub height: BlockHeight,
            pub confirmations: i64,
        }
        match self.jsonrpc_query::<Response>("getblockheader", &[block.to_string().into()]) {
            Ok(resp) => Ok(Some((resp.height, resp.confirmations))),
            Err(e @ jsonrpc::Error::Transport(_)) => Err(e),
            Err(_) => Ok(None)
        }
    }

    /// Return the height of the current tip
    fn tip_height(&self) -> Result<BlockHeight, jsonrpc::Error> {
        let tip = self.tip().unwrap();
        Ok(self.block_height(tip)?.expect(format!("Block {} should exist", tip).as_str()))
    }
}

/// If there is any other error returns the Error, otherwise returns false.
fn is_warming_up(client: &jsonrpc::client::Client, endpoint_name: &str) -> Result<bool, jsonrpc::Error> {
    const RPC_IN_WARMUP: i32 = -28;
    let request = client.build_request("getblockchaininfo", &[]);
    match client.send_request(request) {
        Ok(response) => {
            match response.error {
                Some(e) => {
                    if e.code == RPC_IN_WARMUP {
                        slog!(WarmingUp, daemon: endpoint_name);
                        return Ok(true);
                    } else {
                        let e = jsonrpc::Error::Rpc(e);
                        slog!(Error, daemon: endpoint_name, action: "warmup check".to_owned(),
                            error: &e
                        );
                        return Err(e);
                    }
                }
                None => {
                    slog!(WarmedUp, daemon: endpoint_name);
                    return Ok(false);
                }
            }
        }
        Err(e) => {
            slog!(Error, daemon: endpoint_name, action: "warmup check".to_owned(), error: &e
            );
            return Err(e);
        }
    };
}

/// A Bitcoin Core client.
pub struct Bitcoin {
    /// The underlying jsonrpc client.
    client: jsonrpc::client::Client,
    /// Params to make this type cloneable (url, user, pass);
    params: (String, Option<String>, Option<String>),
}

impl Bitcoin {
    /// Create a new Bitcoin Core client.
    pub fn new(url: String, user: Option<String>, pass: Option<String>) -> Bitcoin {
        let mut client_builder = jsonrpc::simple_http::Builder::new()
            .timeout(RPC_TIMEOUT)
            .url(url.as_str())
            .expect("simple_http builder");
        if let Some(u) = user.clone() {
            client_builder = client_builder.auth(u, pass.clone());
        }
        let client = client_builder.build();
        Bitcoin {
            params: (url.clone(), user.clone(), pass.clone()),
            client: jsonrpc::Client::with_transport(client),
        }
    }
}

impl Rpc for Bitcoin {
    /// Convenience method to do a JSONRPC query and deserialize the result
    fn jsonrpc_query<T: serde::de::DeserializeOwned>(
        &self,
        query: &str,
        args: &[jsonrpc::serde_json::Value],
    ) -> Result<T, jsonrpc::Error> {
        let args_raw: Vec<Box<RawValue>> = args.iter().map(|a| jsonrpc::arg(a)).collect();
        slog!(RpcRequest, daemon: "bitcoin", method: query, arguments: &args_raw.iter().map(|a| a.get()).collect::<Vec<_>>());
        let request = self.client.build_request(query, &args_raw);
        let start_time = Instant::now();
        let result = self.client.send_request(request);
        let response = result?;
        let duration_ns = start_time.elapsed().as_nanos();
        if let Some(ref error) = response.error {
            slog!(RpcResponse, daemon: "bitcoin", method: query, result: format!("error: {:?}", error).as_str(), duration_ns);
        } else if let Some(ref result) = response.result {
            let size = result.get().len();
            slog!(RpcResponse, daemon: "bitcoin", method: query, duration_ns,
                result: format!("{} bytes", size).as_str(),
            );
            slog!(RpcResultTrace, daemon: "bitcoin", result: &result.to_string());
        } else {
            slog!(RpcResponse, daemon: "bitcoin", method: query, result: "null", duration_ns);
        }
        response.result::<T>()
    }

    fn is_warming_up(&self, endpoint_name: &str) -> Result<bool, jsonrpc::Error> {
        is_warming_up(&self.client, endpoint_name)
    }
}
impl BitcoinRpc for Bitcoin {}

impl Clone for Bitcoin {
    fn clone(&self) -> Bitcoin {
        let (url, user, pass) = self.params.clone();
        Bitcoin {
            params: self.params.clone(),
            client: jsonrpc::client::Client::simple_http(url.as_str(), user, pass)
                .expect("Problem creating Bitcoin client"),
        }
    }
}

/// An Elements Core client.
pub struct Elements {
    /// The underlying jsonrpc client.
    pub client: jsonrpc::client::Client,
    /// Params to make this type cloneable (url, user, pass);
    params: (String, Option<String>, Option<String>),
}

impl Elements {
    /// Create a new Elements Core client.
    pub fn new(url: String, user: Option<String>, pass: Option<String>) -> Elements {
        let mut client_builder = jsonrpc::simple_http::Builder::new()
            .timeout(RPC_TIMEOUT)
            .url(url.as_str())
            .expect("simple_http builder");
        if let Some(u) = user.clone() {
            client_builder = client_builder.auth(u, pass.clone());
        }
        let client = client_builder.build();
        Elements {
            params: (url.clone(), user.clone(), pass.clone()),
            client: jsonrpc::client::Client::with_transport(client),
        }
    }
}

impl Rpc for Elements {
    /// Convenience method to do a JSONRPC query and deserialize the result
    fn jsonrpc_query<T: serde::de::DeserializeOwned>(
        &self,
        query: &str,
        args: &[jsonrpc::serde_json::Value],
    ) -> Result<T, jsonrpc::Error> {
        let args_raw: Vec<Box<RawValue>> = args.iter().map(|a| jsonrpc::arg(a)).collect();
        slog!(RpcRequest, daemon: "elements", method: query, arguments: &args_raw.iter().map(|a| a.get()).collect::<Vec<_>>());
        let request = self.client.build_request(query, &args_raw);
        let start_time = Instant::now();
        let response = self.client.send_request(request)?;
        let duration_ns = start_time.elapsed().as_nanos();
        if let Some(ref error) = response.error {
            slog!(RpcResponse, daemon: "elements", method: query, result: format!("error: {:?}", error).as_str(), duration_ns);
        } else if let Some(ref result) = response.result {
            let size = result.get().len();
            slog!(RpcResponse, daemon: "elements", method: query, duration_ns,
                result: format!("{ } bytes", size).as_str(),
            );
            slog!(RpcResultTrace, daemon: "elements", result: &result.to_string());
        } else {
            slog!(RpcResponse, daemon: "elements", method: query, result: "null", duration_ns);
        }
        response.result::<T>()
    }

    fn is_warming_up(&self, endpoint_name: &str) -> Result<bool, jsonrpc::Error> {
        is_warming_up(&self.client, endpoint_name)
    }
}
impl ElementsRpc for Elements {}

impl Clone for Elements {
    fn clone(&self) -> Elements {
        let (url, user, pass) = self.params.clone();
        Elements {
            params: self.params.clone(),
            client: jsonrpc::client::Client::simple_http(url.as_str(), user, pass)
                .expect("Problem creating Elements client"),
        }
    }
}

#[cfg(test)]
mod tests {
    use jsonrpc::serde_json;

    use super::*;

    #[test]
    fn hash_decode() {
        let hash_str = "\"84e3fba7a2e319acd03098f80ad4b44f8efbcd7e6a70cced228b2d706c2012c6\"";
        let _: bitcoin::hashes::sha256d::Hash = serde_json::from_str(&hash_str).expect("decoding json");
        let _: bitcoin::BlockHash = serde_json::from_str(&hash_str).expect("decoding json");
        let _: bitcoin::Txid = serde_json::from_str(&hash_str).expect("decoding json");
    }

    #[test]
    fn estimatesmartfee_decode() {
        let estimatesmartfee = "{
          \"feerate\": 0.00044301,
          \"blocks\": 2
        }";
        let decode: EstimateSmartFeeResponse = serde_json::from_str(&estimatesmartfee).expect("decoding json");
        assert_eq!(decode.feerate.unwrap().as_sat(), 44301);
        assert!(decode.errors.is_empty());
        assert_eq!(decode.blocks, 2);

        let estimatesmartfee = "{
          \"errors\": [\"Insufficient data or no feerate found\"],
          \"blocks\": 26
        }";
        let decode: EstimateSmartFeeResponse = serde_json::from_str(&estimatesmartfee).expect("decoding json");
        assert_eq!(decode.errors[0], "Insufficient data or no feerate found");
        assert!(decode.feerate.is_none());
        assert_eq!(decode.blocks, 26);
    }
}
