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

//! # Tx index logs
//!

use std::collections::HashSet;

/// The confirmation height of a tx.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TxHeight {
    /// Tx is confirmed at the given block height.
    Block(u64),
    /// Tx is in the mempool.
    Mempool,
}

impl ::serde::Serialize for TxHeight {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match *self {
            TxHeight::Block(ref h) => ::serde::Serialize::serialize(h, s),
            TxHeight::Mempool => s.serialize_str("mempool"),
        }
    }
}

/// Record a newly indexed transaction.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RecordTx {
    /// The txid of the tx.
    pub txid: bitcoin::Txid,
    /// The block height the transaction is confirmed in, or mempool.
    pub block_height: TxHeight,
    /// The block hash the transaction is confirmed in, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<bitcoin::BlockHash>,
    /// The pegouts this transaction handles.
    pub handles_pegouts: HashSet<elements::OutPoint>,
    /// The watchman inputs spent by the tx.
    pub spends_inputs: HashSet<bitcoin::OutPoint>,
    /// The change this tx adds to our utxo pool.
    pub change_outputs: Vec<u64>,
    /// Total value of fee donations.
    pub total_fee_donation: u64,
}

/// Record that an indexed transaction changed.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RecordTxChange {
    /// The txid of the tx.
    pub txid: bitcoin::Txid,
    /// The confirmation height of the tx before.
    pub old_height: TxHeight,
    /// The confirmation height of the tx now.
    pub new_height: TxHeight,
}

/// A transaction has been confirmed by enough blocks to be considered final.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FinalizeTx {
    /// The txid of the tx.
    pub txid: bitcoin::Txid,
    /// The block height the transaction is confirmed in.
    pub block_height: u64,
    /// The watchman inputs spent by the tx.
    pub spends_inputs: HashSet<bitcoin::OutPoint>,
    /// The pegouts this transaction handles.
    pub handles_pegouts: HashSet<elements::OutPoint>,
    /// Total value of fee donations.
    pub total_fee_donation: u64,
    /// This transaction was reported as detected before.
    /// If false, it was finalized right away, probably during a catchup sync.
    pub seen_before: bool,
}

/// The index was asked to drop a certain tx from tracking.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DropTx {
    /// The txid.
    pub txid: bitcoin::Txid,
    /// The block at which we first saw the tx.
    pub first_seen: u64,
    /// The number of blocks the tx has been unconfirmed for.
    pub age: u64,
}

/// We have to undo a block because the active chain changed.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct UndoBlock<'a> {
    /// The block height.
    pub height: u64,
    /// The block hash.
    pub hash: bitcoin::BlockHash,
    /// The block hash of the block that comes in this block's place.
    pub replacement_hash: bitcoin::BlockHash,
    /// The relevant transactions that were in the block.
    pub relevant_txs: &'a [bitcoin::Txid],
}

/// There was a deep reorganization of the Bitcoin chain and now
/// maybe our funds are at risk. Shut down immediately and require
/// human intervention to assess the damage.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DeepBitcoinReorg {
    /// Height that we consider "confirmed" and should never reorg
    pub height: u64,
    /// Blockhash we expected at that height
    pub original: bitcoin::BlockHash,
    /// The blockhash that we now see at that height
    pub reorged: bitcoin::BlockHash,
}
