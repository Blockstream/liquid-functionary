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

//! # Transaction Index
//!
//! An index that keeps track of all in-flight transactions the watchman is
//! interested in. In-flight means that the transaction is in the mempool or
//! confirmed in the blockchain, but not yet finalized (because it does not have
//! enough confirmations).

use std::collections::{HashSet, HashMap, BTreeMap, VecDeque};
use std::{cmp, fmt, error, mem};

use bitcoin;
use jsonrpc;

use common::BlockHeight;
use logs::{functionary as log, get_round_stage};
use logs::ProposalError;
use utils::{self, BlockRef};
use rpc::BitcoinRpc;

/// A TxIndex error.
#[derive(Debug)]
pub enum Error {
    /// A bitcoind RPC error.
    BitcoinRpc(jsonrpc::Error),
    /// Blockchain not synced to minimum height, cannot update txindex.
    BlockchainNotSynced {
        /// Minimum height after which we expect all
        /// relevant blockchain activity to occur.
        skip_height: BlockHeight,
        /// Current height according to bitcoind.
        actual_height: BlockHeight,
    },
}

impl From<jsonrpc::Error> for Error {
    fn from(e: jsonrpc::Error) -> Error {
        Error::BitcoinRpc(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::BitcoinRpc(ref x) => write!(f, "bitcoind rpc: {}", x),
            Error::BlockchainNotSynced {
                skip_height,
                actual_height,
            } => write!(
                f,
                "blockchain not synced: actual height {} is below min {}",
                actual_height, skip_height
            ),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::BitcoinRpc(ref x) => Some(x),
            _ => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::BitcoinRpc(_) => "bitcoind rpc",
            Error::BlockchainNotSynced { .. } => "blockchain not synced",
        }
    }
}

/// A closure call for the [TxIndex::update_from_rpc] method.
/// This exists because the Rust borrowck doesn't allow us to create two
/// closures.
#[derive(PartialEq, Eq, Debug)]
#[allow(missing_docs)]
pub enum UpdateClosureCall<'a> {
    TxMeta(&'a bitcoin::Transaction, BlockHeight),
    FinalizedTx(bitcoin::Txid, Tx),
}

/// A closure result for the [TxIndex::update_from_rpc] method.
/// This exists because the Rust borrowck doesn't allow us to create two
/// closures.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum UpdateClosureResult {
    TxMeta(Result<Option<Vec<OutputMeta>>, ProposalError>),
    FinalizedTx,
}

/// The confirmation status of an indexed transaction.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
pub enum TxStatus {
    /// The tx was mined in the given block.
    ConfirmedIn(BlockRef),
    /// The tx has been in the mempool since we observed the given block height.
    MempoolSince(BlockHeight),
}

impl TxStatus {
    /// Check whether the tx is in the mempool or confirmed.
    pub fn is_mempool(&self) -> bool {
        match self {
            TxStatus::ConfirmedIn(_) => false,
            TxStatus::MempoolSince(_) => true,
        }
    }

    /// Get the hash of the [BlockRef] if it's a [BlockRef::Block].
    pub fn hash(&self) -> Option<bitcoin::BlockHash> {
        match self {
            TxStatus::ConfirmedIn(ref block) => Some(block.hash),
            TxStatus::MempoolSince(_) => None,
        }
    }

    /// Get the height of the [BlockRef] if it's a [BlockRef::Block].
    pub fn height(&self) -> Option<BlockHeight> {
        match self {
            TxStatus::ConfirmedIn(ref block) => Some(block.height),
            TxStatus::MempoolSince(_) => None,
        }
    }

    /// Convert to the type used in the logging crate.
    pub fn for_log(&self) -> log::txindex::TxHeight {
        match self {
            TxStatus::ConfirmedIn(ref block) => log::txindex::TxHeight::Block(block.height),
            TxStatus::MempoolSince(_) => log::txindex::TxHeight::Mempool,
        }
    }
}

/// Relevant info about a block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BlockInfo {
    /// The block ref.
    blockref: BlockRef,
    /// List if interesting txs in the block.
    relevant_txs: Vec<bitcoin::Txid>,
    /// The latest mainchain commitment on the sidechain when we first scanned this block's txs.
    #[serde(default)]
    initial_scan_commitment_height: BlockHeight,
}

impl BlockInfo {
    /// The height of the block.
    fn height(&self) -> BlockHeight {
        self.blockref.height
    }
}

/// Metadata about a pegout on a tx made by the watchman.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub enum OutputMeta {
    /// Pegout delivery output.
    Pegout(elements::OutPoint),
    /// Change output.
    Change,
    /// Fee donation output.
    Donation,
    /// Output unrelated to watchman activity.
    Irrelevant,
}

impl<'de> serde::Deserialize<'de> for OutputMeta {
    fn deserialize<D: serde::de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use utils::serialize::ElementsOutpointSerdeWrapper;

        #[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
        enum OutputMetaStub {
            Pegout(ElementsOutpointSerdeWrapper),
            Change,
            Donation,
            Irrelevant,
        }

        let ret = OutputMetaStub::deserialize(d)?;
        Ok(match ret {
            OutputMetaStub::Pegout(p) => OutputMeta::Pegout(p.into()),
            OutputMetaStub::Change => OutputMeta::Change,
            OutputMetaStub::Donation => OutputMeta::Donation,
            OutputMetaStub::Irrelevant => OutputMeta::Irrelevant,
        })
    }
}

/// A transaction indexed by the txindex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tx {
    /// The full transaction.
    pub tx: bitcoin::Transaction,
    /// The ref of the block this tx is confirmed in, "mempool" otherwise.
    pub status: TxStatus,
    /// The metadata we keep for each output.
    output_meta: Vec<OutputMeta>,
}

impl Tx {
    /// Whether this tx was made by the federation or only has
    /// incoming fee donations.
    pub fn is_federation_tx(&self) -> bool {
        // We know that federation txs can only have [Pegout] and [Change],
        // while non-federation txs can only have [Donation] and [Irrelevant].
        match self.output_meta[0] {
            OutputMeta::Pegout(_) | OutputMeta::Change => true,
            OutputMeta::Donation | OutputMeta::Irrelevant => false,
        }
    }

    /// Get an iterator over the federation inputs this tx spends.
    // NB We don't provide an iterator over raw inputs to avoid footguns
    // because we are always interested in federation inputs.
    pub fn iter_federation_inputs(&self) -> impl Iterator<Item = bitcoin::OutPoint> + Clone + '_ {
        // So basically we want to either return an empty iterator for
        // non-federation txs and an iterator over all inputs for federation
        // txs. Since Rust makes that a bit hard, we do a bit of an ugly hack
        // and just filter away all inputs when it's not a federation tx.
        let federation_tx = self.is_federation_tx();
        self.tx.input.iter().take_while(move |_| federation_tx).map(|i| i.previous_output)
    }

    /// Get an iterator over the outputs of this tx and their metadata.
    pub fn iter_outputs(&self) -> impl Iterator<Item = (bitcoin::OutPoint, &bitcoin::TxOut, OutputMeta)> + Clone + '_ {
        let txid = self.tx.txid();
        // Basically just zip both iterators together and enumerate.
        self.tx.output.iter().enumerate().zip(self.output_meta.iter().copied())
            .map(move |((n, txout), meta)| (bitcoin::OutPoint::new(txid, n as u32), txout, meta))
    }

    /// Get an iterator over all pegout delivery outputs in this tx and the
    /// pegout request they are delivering.
    pub fn iter_pegouts(&self) -> impl Iterator<Item = elements::OutPoint> + Clone + '_ {
        self.iter_outputs().filter_map(|(_, _, meta)| {
            if let OutputMeta::Pegout(outpoint) = meta {
                Some(outpoint)
            } else {
                None
            }
        })
    }

    /// Get an iterator over all change outputs in this tx.
    pub fn iter_change(&self) -> impl Iterator<Item = &bitcoin::TxOut> + Clone + '_ {
        self.iter_outputs().filter_map(|(_, output, meta)| {
            if meta == OutputMeta::Change {
                Some(output)
            } else {
                None
            }
        })
    }

    /// Get an iterator over all fee donations in this tx.
    pub fn iter_donations(&self) -> impl Iterator<Item = &bitcoin::TxOut> + Clone + '_ {
        self.iter_outputs().filter_map(|(_, output, meta)| {
            if meta == OutputMeta::Donation {
                Some(output)
            } else {
                None
            }
        })
    }
}

///
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIndex {
    /// Map of confirmed transactions by their txid.
    #[serde(with = "utils::serialize::hashmap")]
    txindex: HashMap<bitcoin::Txid, Tx>,

    /// Map of block refs to relevant info about the block. This is necessary to
    /// deal with blockchain reorganizations. Therefore stores the [depth] - 1
    /// latest blocks of the active chain. It's ordered by height to allow easy
    /// pruning.
    #[serde(default, rename = "block_index")]
    blocks: VecDeque<BlockInfo>,
    /// For compatibility purposes.
    #[serde(default, rename = "blocks",
        with = "utils::serialize::btreemap", skip_serializing_if = "BTreeMap::is_empty")]
    old_blocks: BTreeMap<BlockHeight, BlockInfo>,
    /// A block with [depth] - 1 blocks on top in the active chain is considered
    /// finalized and doesn't need to be tracked by [blocks] (anymore).
    depth: BlockHeight,
    /// The height at which we expect activity to occur and where we will start
    /// syncing.
    skip_height: BlockHeight,
    /// The height of the latest commitment made in the sidechain.
    /// Blocks more recent than this should be rescanned.
    #[serde(default)]
    commitment_height: BlockHeight,
    /// The height below which blocks are considered finalized.
    finalized_height: BlockHeight,

    /// An in-memory cache of mempool transaction seen and in which round they were
    /// last seen
    #[serde(default, skip_serializing)]
    mempool_seen: HashMap<bitcoin::Txid, u64>,
}

impl TxIndex {
    /// Create a new transaction index.
    pub fn new(skip_height: BlockHeight, depth: BlockHeight) -> TxIndex {
        assert!(depth > 1);
        TxIndex {
            skip_height: skip_height,
            commitment_height: skip_height,
            finalized_height: skip_height,
            depth: depth,
            txindex: HashMap::new(),
            blocks: VecDeque::with_capacity(depth as usize),
            old_blocks: BTreeMap::new(),
            mempool_seen: HashMap::new(),
        }
    }

    /// Potentially convert from an old schema if needed.
    pub fn ensure_schema(&mut self) {
        // Clear mempool_seen in case it still exists.
        if !self.mempool_seen.is_empty() {
            self.mempool_seen.clear();
        }

        // Convert the blocks index schema.
        if !self.old_blocks.is_empty() {
            assert!(self.blocks.is_empty(), "both blocks and old blocks specified");

            for (height, block) in mem::replace(&mut self.old_blocks, BTreeMap::new()).into_iter() {
                if let Some(last) = self.blocks.back() {
                    assert_eq!(height, last.height() + 1, "blocks are not correctly ordered");
                }
                self.blocks.push_back(block);
            }
        }
    }

    /// Get the chain tip height of the main chain.
    pub fn max_height(&self) -> BlockHeight {
        self.blocks.back().map(|b| b.height()).unwrap_or(0)
    }

    /// The height at which we expect activity to occur and where we will start
    /// syncing.
    pub fn skip_height(&self) -> BlockHeight {
        self.skip_height
    }

    /// Get the block height at which block are considered final.
    pub fn finalized_height(&self) -> BlockHeight {
        self.finalized_height
    }

    /// Get an entry in the index.
    pub fn get(&self, txid: bitcoin::Txid) -> Option<&Tx> {
        self.txindex.get(&txid)
    }

    /// Get an iterator over all in-flight transactions.
    pub fn in_flight_txs(&self) -> impl Iterator<Item = (&bitcoin::Txid, &Tx)> {
        self.txindex.iter()
    }

    /// Return the total number of in-flight txs tracked by the tx index.
    pub fn n_in_flight_txs(&self) -> usize {
        self.txindex.len()
    }

    /// Checks if we have the given tx in our index and updates the status if we have.
    /// Returns true if we had the tx.
    fn check_tx_update_status(&mut self, txid: bitcoin::Txid, status: TxStatus) -> bool {
        if let Some(tx) = self.txindex.get_mut(&txid) {
            if tx.status == status {
                return true;
            }

            slog!(RecordTxChange, txid: txid, old_height: tx.status.for_log(),
                new_height: status.for_log()
            );

            // Update the status, preserving the oldest mempool height.
            if let (TxStatus::MempoolSince(h1), TxStatus::MempoolSince(h2)) = (tx.status, status) {
                tx.status = TxStatus::MempoolSince(cmp::min(h1, h2));
            } else {
                tx.status = status;
            }

            true
        } else {
            false
        }
    }

    /// Records all the relevant transactions in the block and returns a list of their TXIDs.
    /// The transaction is added to `new_txs` if this is the first time we've seen it.
    fn record_relevant_transactions<C>(
        &mut self,
        block_ref: BlockRef,
        block: bitcoin::Block,
        new_txs: &mut HashSet<bitcoin::Txid>,
        closure: &mut C,
        rescanning_block: bool,
    ) -> Vec<bitcoin::Txid>
        where C: for <'a> FnMut(UpdateClosureCall<'a>) -> UpdateClosureResult,
    {
        let mut relevant_txids = Vec::new();
        let status = TxStatus::ConfirmedIn(block_ref);
        for tx in block.txdata {
            let txid = tx.txid();

            if !rescanning_block {
                // Check if we already previously indexed the tx.
                if self.check_tx_update_status(txid, status) {
                    relevant_txids.push(txid);
                    continue;
                }
            }

            // When we're past the commitment height, we might encounter
            // unexpected inputs or outputs because we haven't seen their
            // sidechain counterpart yet. So then we just allow failure
            // and we'll revisit the tx later on a next iteration.
            let allow_failure = block_ref.height > self.commitment_height;

            // To find which sidechain params were active for this block, we have to find
            // the sidechain block which committed to height + self.depth - 1.
            // See https://gl.blockstream.io/liquid/functionary/-/issues/1063.
            let meta = match closure(UpdateClosureCall::TxMeta(&tx, block_ref.height + self.depth - 1)) {
                UpdateClosureResult::TxMeta(Ok(meta)) => meta,
                UpdateClosureResult::TxMeta(Err(e)) => {
                    if !allow_failure {
                        if let ProposalError::UnknownInputs(unknown_inputs) = e {
                            slog_fatal!(DetectedUnknownInputs, txid: tx.txid(), unknown_inputs);
                        } else {
                            panic!("fatal sync error: {}", e);
                        }
                    } else {
                        log!(Debug, "new tx {} detected with an allowed failure: {}", tx.txid(), e);
                    }
                    None
                },
                _ => unreachable!(),
            };
            if let Some(meta) = meta {
                self.record_transaction(tx, status, meta, !rescanning_block);
                relevant_txids.push(txid);
                new_txs.insert(txid);
            }
        }
        relevant_txids
    }

    /// Records a new transaction into the index.
    fn record_transaction(
        &mut self,
        tx: bitcoin::Transaction,
        status: TxStatus,
        meta: Vec<OutputMeta>,
        log_on_dup: bool,
    ) {
        let txid = tx.txid();
        let entry = Tx {
            tx: tx,
            status: status,
            output_meta: meta,
        };

        slog!(RecordTx, txid: txid, block_height: status.for_log(),
            block_hash: status.hash(),
            spends_inputs: entry.iter_federation_inputs().collect(),
            handles_pegouts: entry.iter_pegouts().collect(),
            change_outputs: entry.iter_change().map(|o| o.value).collect(),
            total_fee_donation: entry.iter_donations().map(|o| o.value).sum(),
        );

        if let Some(e) = self.txindex.insert(txid, entry) {
            if log_on_dup {
                log!(Error, "recorded tx was already in the index: {:?}", e);
            }
        }
    }

    /// Update the state of the index using the bitcoin rpc.
    ///
    /// If the target is more than 5000 blocks ahead of the previous
    /// commitment height, this method will return after syncing 5000 blocks
    /// so that the intermediate state can be synced to disk and so that sync
    /// progress can be made on the sidechain.
    ///
    /// It returns a boolean that indicates whether the sync was complete.
    /// That is, if returned [false], this method should be invoked again after
    /// re-syncing the sidechain.
    /// It also returns a set of newly detected relevant transactions that are not yet finalized
    /// (by txid); these can be used for conflict tracking.
    ///
    /// Additionally, the closure will be called using the
    /// [UpdateClosureCall::FinalizedTx] variant for every tx that was
    /// finalized.
    pub fn update_from_rpc<C>(&mut self,
        bitcoind: &impl BitcoinRpc,
        commitment_height: BlockHeight,
        mut closure: C,
    ) -> Result<(bool, HashSet<bitcoin::Txid>), Error>
        where C: for <'a> FnMut(UpdateClosureCall<'a>) -> UpdateClosureResult,
    {
        // If we just upgraded to the first version that has this field,
        // we set it to our latest height or to the current commitment height.
        // NB this can be removed as soon as all funcs are updated to have this field
        if self.commitment_height == 0 {
            self.commitment_height = cmp::min(self.max_height(), commitment_height);
        }

        let tip = bitcoind.block_count()?;
        if tip < self.skip_height {
            return Err(Error::BlockchainNotSynced {
                skip_height: self.skip_height,
                actual_height: tip,
            });
        }
        log!(Trace, "current mainchain tip {}", tip);

        // Don't sync more than 5000 blocks in one go so upstream can save to disk.
        let sync_to = match self.blocks.is_empty() {
            false => cmp::min(tip, self.max_height() + 5000),
            true => cmp::min(tip, self.skip_height + 5000 - 1),
        };
        log!(Debug, "Syncing tx index until {}; local tip is {}, last commitment was {}, new {}",
            sync_to, self.max_height(), self.commitment_height, commitment_height,
        );

        // First, we fetch block headers starting from the tip to build a hash
        // chain of all the blocks we need to sync.
        let mut blocks_to_sync = Vec::with_capacity(5000);
        let mut cursor = BlockRef::new(sync_to, bitcoind.block_at(sync_to)?);
        loop {
            // See if we're in territory of block heights we already synced.
            // Because then we're either done or we discovered a reorg
            // and need to undo it.
            if let Some(known_tip) = self.blocks.back().map(|b| b.blockref) {
                if cursor.height < known_tip.height {
                    panic!("inconsistent txindex state! cursor={}, tip={}",
                        cursor.height, known_tip.height,
                    );
                }
                if cursor.height == known_tip.height {
                    if cursor.hash != known_tip.hash {
                        // Reorg detected, undo the block.
                        let block = self.blocks.pop_back().unwrap();
                        for txid in &block.relevant_txs {
                            let tx = self.txindex.get_mut(txid).expect("corrupt index");
                            if tx.is_federation_tx() {
                                // We can keep the indexed tx, so that we don't have to redo work.
                                tx.status = TxStatus::MempoolSince(tip);
                            } else {
                                // If it's not, we need to redo the work to reconsider the
                                // outputs. This is because someone might have donated to
                                // change addresses from different historical federations
                                // so peers syncing at different times might otherwise have
                                // differing views on the relevance of these txs.
                                self.txindex.remove(txid);
                            }
                        }
                        slog!(UndoBlock, height: cursor.height, hash: known_tip.hash,
                            replacement_hash: cursor.hash, relevant_txs: &block.relevant_txs
                        );

                        if self.blocks.is_empty() {
                            // We undid the entire chain we had stored.
                            slog_fatal!(DeepBitcoinReorg, height: cursor.height,
                                original: known_tip.hash, reorged: cursor.hash,
                            );
                        }
                    } else {
                        break; // We reached our own tip, so we're done!
                    }
                }
            }

            // Ensure we don't accidentally go all the way back to block 0 in prod.
            assert!(self.max_height() == 0 || cursor.height > self.max_height(),
                "failed {} > {}", cursor.height, self.max_height(),
            );
            blocks_to_sync.push(cursor);

            // Stop once we reach the skip height.
            if cursor.height <= self.skip_height() {
                break;
            }

            let header = bitcoind.raw_header(cursor.hash)?;
            cursor = BlockRef::new(cursor.height - 1, header.prev_blockhash);
        }

        // Undo the blocks that we synced past the last commitment because we
        // need to scan them again.
        assert!(commitment_height >= self.commitment_height, "commitment height reversed");
        let last_commitment_height = self.commitment_height;
        self.commitment_height = commitment_height;
        // We do minus one here to make sure the block of the actual
        // commitment is also revisited.
        while self.max_height() > last_commitment_height.saturating_sub(1) {
            let last = self.blocks.pop_back().unwrap();
            log!(Trace, "undoing block {} because it's above the commitment", last.blockref);
            assert!( // that we're attaching correctly
                blocks_to_sync.last().map(|r| r.height == last.blockref.height + 1).unwrap_or(true),
                "attaching a block that doesn't match: last ref {:?}, attaching: {:?}",
                blocks_to_sync.last(), last.blockref,
            );
            blocks_to_sync.push(last.blockref);

            for txid in &last.relevant_txs {
                let tx = self.txindex.get_mut(txid).expect("corrupt index");
                if tx.is_federation_tx() {
                    // We can keep the indexed tx, so that we don't have to redo work.
                    tx.status = TxStatus::MempoolSince(tip);
                } else {
                    // If it's not, we need to redo the work to reconsider the
                    // outputs. This is because someone might have donated to
                    // change addresses from different historical federations
                    // so peers syncing at different times might otherwise have
                    // differing views on the relevance of these txs.
                    self.txindex.remove(txid);
                }
            }
        }

        // With a depth of N, we keep N-1 blocks. So if depth is 4 and the tip is 9,
        // we keep only 7, 8, 9. I.e. blocks after `tip - (depth - 1)`.
        self.finalized_height = commitment_height.saturating_sub(self.depth.saturating_sub(1));

        // Then sync all blocks in the hash chain we just built and finalize
        // blocks when they get old enough.
        let mut new_txs = HashSet::new();
        for block_ref in blocks_to_sync.into_iter().rev() {
            let block = bitcoind.raw_block(block_ref.hash)?;
            if let Some(last) = self.blocks.back() {
                assert_eq!(block.header.prev_blockhash, last.blockref.hash,
                    "we should be syncing the block following our last block..",
                );
            }

            // Now record the new tx data in the block.
            let relevant_txids = self.record_relevant_transactions(
                block_ref,
                block,
                &mut new_txs,
                &mut closure,
                false,
            );
            let block_info = BlockInfo {
                blockref: block_ref,
                relevant_txs: relevant_txids,
                initial_scan_commitment_height: self.commitment_height,
            };
            self.blocks.push_back(block_info);

            // Now finalize the oldest block in case it's old enough.
            //
            // We set the threshold so that we make sure we keep at least
            // one block in initial sync.
            let threshold = cmp::min(self.finalized_height, sync_to - 1);
            if self.blocks.front().unwrap().height() <= threshold {
                let mut block_info = self.blocks.pop_front().unwrap();

                // If we initially parsed this block before we had a commitment to
                // block.height + (self.depth - 1) on the sidechain, then it is possible that we
                // missed valid donations / change (if the block at block.height was re-orged).
                // For more details on this race condition, see
                // https://gl.blockstream.io/liquid/functionary/-/issues/1063.
                //
                // This will only occur if we are following the chain in real-time. If we are
                // syncing older history, we will have had a commitment to block.height + (self.depth - 1)
                // on the sidechain when we first scanned the block, and this won't have occurred.
                //
                // When this occurs, we should rescan the transaction again when finalizing the block,
                // since by then we will have had a commitment to block.height + (self.depth - 1)
                // on the sidechain, and thus we can be certain that it won't be re-orged.
                //
                // Rescanning every single block would double the overall chain sync time. However,
                // we only need to do a rescan when we are near the tip. So, we don't need care a
                // much about efficiency here, since the watchman rounds are long enough to do
                // multiple block scans with no issues.
                //
                // More precisely, we must rescan when the initial scan occured before we had
                // a commitment on the sidechain to mainchain block block.height + (self.depth - 1).
                //
                // Note: we only finalize a block when we reach commitment
                //       block.height + (self.depth - 1), so we can be certain that the rescan will
                //       identify all relevant transactions in the block.
                //
                if block_info.initial_scan_commitment_height < block_info.blockref.height + self.depth - 1 {
                    let block = bitcoind.raw_block(block_info.blockref.hash)?;
                    block_info.relevant_txs = self.record_relevant_transactions(
                        block_info.blockref,
                        block,
                        &mut HashSet::new(), // don't add missed txs to `new_txs` since we only missed change or donations
                        &mut closure,
                        true
                    );
                }

                for txid in block_info.relevant_txs {
                    // In case we just detected the tx in this update cycle, remove it from the
                    // newly detected txs.  We will log this as well.
                    let seen_before = !new_txs.remove(&txid);

                    let tx = self.txindex.remove(&txid).expect("corrupt txindex");
                    let inputs = tx.iter_federation_inputs().collect();
                    let pegouts = tx.iter_pegouts().collect();
                    slog!(FinalizeTx, txid: txid, block_height: tx.status.height().unwrap(),
                        spends_inputs: inputs,
                        handles_pegouts: pegouts,
                        total_fee_donation: tx.iter_donations().map(|o| o.value).sum(),
                        seen_before: seen_before
                    );

                    // Call the finalize_tx closure.
                    match closure(UpdateClosureCall::FinalizedTx(txid, tx)) {
                        UpdateClosureResult::FinalizedTx => {},
                        _ => unreachable!(),
                    }
                }
            }
        }

        // Check if we reached the actual tip before we sync mempool.
        // We might be caching up or a new block might have arrived since we started.
        let mempool = bitcoind.raw_mempool()?;
        if self.max_height() != bitcoind.block_count()? {
            log!(Debug, "synced to height {}, bitcoin already is at {}",
                self.max_height(), bitcoind.block_count()?,
            );
            return Ok((false, new_txs));
        }

        // We're really at the tip, so we can also sync the mempool.
        let status = TxStatus::MempoolSince(tip);
        let current_round = get_round_stage().round;
        let mut cache_hits = 0;
        for txid in mempool.iter() {
            // Check if we already previously indexed the tx.
            if self.check_tx_update_status(*txid, status) {
                continue;
            }

            if self.mempool_seen.insert(txid.clone(), current_round).is_some() {
                cache_hits += 1;
                continue;
            }

            // We do `if let Ok()` because we don't care about the error case here; if we
            // can't get a transaction from a txid we just got from the mempool, probably
            // it was confirmed or something. In any case we only use the mempool as advice,
            // it's fine if we miss stuff.
            if let Ok(tx) = bitcoind.raw_tx(*txid) {
                let meta = match closure(UpdateClosureCall::TxMeta(&tx, self.max_height())) {
                    UpdateClosureResult::TxMeta(Ok(meta)) => meta,
                    UpdateClosureResult::TxMeta(Err(e)) => {
                        if let ProposalError::UnknownInputs(..) = e {
                            log!(Debug, "new tx {} detected with an allowed failure: {}", txid, e);
                        } else {
                            panic!("fatal sync error: {}", e);
                        }
                        None
                    },
                    _ => unreachable!(),
                };
                if let Some(meta) = meta {
                    self.record_transaction(tx, status, meta, true);
                    new_txs.insert(*txid);
                }
            }
        }

        let pre_prune_cache_size = self.mempool_seen.len() as u64;
        // Clear out txid's we haven't seen for more than 2 rounds
        self.mempool_seen.retain(|_, round_last_seen| round_last_seen >= &mut current_round.saturating_sub(2));
        let post_prune_cache_size = self.mempool_seen.len() as u64;

        slog!(MempoolCacheStatus, number_of_hits: cache_hits, cache_size: post_prune_cache_size, number_pruned: pre_prune_cache_size.saturating_sub(post_prune_cache_size));

        // Now we can remove all indexed transactions that are
        // no longer in the actual mempool.
        // If we do this before going over confirmed transactions, we might
        // remove a tx from the index and then falsely "rediscover" it.
        self.txindex.retain(|txid, tx| {
            let retain = !tx.status.is_mempool() || mempool.contains(txid);
            if !retain {
                log!(Debug, "dropping tx {} because it was dropped from mempool: {:?}", txid, tx);
            }
            retain
        });

        Ok((true, new_txs))
    }

    /// Insert dummy blocks for testing.
    /// This is used to influence the max_height and finalized_height methods.
    #[cfg(test)]
    pub fn insert_dummy_blocks_until(&mut self, height: BlockHeight) {
        while self.blocks.back().map(|b| b.height()).unwrap_or(0) < height {
            let new_ref = if let Some(last) = self.blocks.back() {
                BlockRef::new(last.height() + 1, Default::default())
            } else {
                BlockRef::new(1, Default::default())
            };
            self.blocks.push_back(BlockInfo {
                blockref: new_ref,
                relevant_txs: vec![],
                initial_scan_commitment_height: 0,
            });
        }
        self.finalized_height = std::cmp::max(self.finalized_height, height.saturating_sub(self.depth - 1));
    }
}

#[cfg(test)]
pub mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use bitcoin::{self, Transaction};
    use bitcoin::consensus::encode::{deserialize, serialize_hex};

    use super::*;

    use utils::BlockRef;

    struct RpcDummy(
        /* chain */ Vec<bitcoin::Block>,
        /* mempool (max 255) */ Vec<bitcoin::Transaction>,
    );
    impl_dummy_rpc!(
        RpcDummy,
        dummy,
        "getbestblockhash" => {
            dummy.0.last().unwrap().block_hash()
        },
        "getblockhash", height => {
            let h: usize = height; // this is needed to set the type
            assert!(h < dummy.0.len());
            dummy.0[h].block_hash()
        },
        "getblockcount" => {
            dummy.0.len() as BlockHeight - 1
        },
        "getblockheader", target => {
            serialize_hex(&dummy.0.iter().find(|b| b.block_hash() == target)
                .expect(&format!("getblockheader for {}", target)).header)
        },
        "getblock", target => {
            serialize_hex(dummy.0.iter().find(|b| b.block_hash() == target).unwrap())
        },
        "getrawmempool" => {
            dummy.1.iter().map(|tx| tx.txid()).collect::<Vec<bitcoin::Txid>>()
        },
        "getrawtransaction", txid => {
            serialize_hex(dummy.1.iter().find(|tx| tx.txid() == txid).unwrap())
        }
    );

    /// An empty TxMeta object.
    fn empty_relevant() -> Vec<OutputMeta> {
        vec![OutputMeta::Irrelevant; 50]
    }

    /// Constructor used in tests in other modules.
    pub fn new_tx(tx: Transaction, status: TxStatus, meta: Vec<OutputMeta>) -> Tx {
        Tx {
            tx: tx,
            status: status,
            output_meta: meta,
        }
    }

    // The following blocks represent the blockchain transitions
    //
    // g -> 1 -> 2
    // g -> 1 -> 2_ALT -> 3_ALT -> 4_ALT -> 5_ALT
    // g -> 1 -> 2_ALT -> 3     -> 4     -> 5     -> 6
    // g -> 1 -> 2_ALT -> 3_ALT -> 4_ALT -> 5_ALT -> 6_ALT
    //
    // That is, blocks are added in order, but the txindex sees a 1-block,
    // 3-block and 4-block reorg. It is set to be able to handle only
    // 3-block reorgs.
    //

    pub const BLOCK0: [u8; 81] = hex!("
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000002a00000000
    ");

    pub const BLOCK1: [u8; 285] = hex!(
        "
010000004ed9ae8e4384f85eb9504b39950134b723823f431e8584ce276ff651d8f7d8cd3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000
    "
    );

    pub const BLOCK2: [u8; 262] = hex!(
        "
0000002060a925134dd72afad69eadbfa5466049fabd8ecc45b1239ed3a20185d1dc9c4a9f7d5b656a9c2c2062510bf620b424c81ef79add1b2d2e64ea693c11ad7cb78171bdd45bffff7f200600000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff0200f2052a0100000023210235d07faf522b00c430a2fbee70af3b786653b51e9963b61209c4d5dd1cf16a78ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000
    "
    );

    pub const BLOCK2_ALT: [u8; 262] = hex!(
        "
0000002060a925134dd72afad69eadbfa5466049fabd8ecc45b1239ed3a20185d1dc9c4a24b8b1c68e0ca15bad2d001e7028646165d14783518ad7ab7ba805dd7c4cec0e4de4d45bffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff0200f2052a0100000023210200e976e8f8dbdd9277d596aa62f9201c007135b1b9076905821230b2b8f37749ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000
    "
    );

    pub const BLOCK3_ALT: [u8; 262] = hex!(
        "
0000002001422d871eb91ea112d3c53ebd806314ac900400bbbcbf1e52a465ff96748c425d9d08b6823d33a50591d800444ee10108aa4e9b2b80606486052dac0c865d65dee4d45bffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03520101ffffffff0200f2052a010000002321029abbf40879ba37020f8303095303b6fefaf66ba2c0e2c2bc56677bac58874bafac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000
    "
    );

    pub const BLOCK4_ALT: [u8; 262] = hex!(
        "
000000206bd80eff30024107235bf24e0a515417770f5cd7068b7ec51f3f6599a67ac0d52e2a9a7b74a5f629d9e4adb3d477e7dbc160baa0176d10471fd5a88d4960e49a8fe5d45bffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03530101ffffffff0200f2052a010000002321021700a01326844f1512de941a08bf88bc913e49310ab89b99f6d0c0fce51ed679ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000
    "
    );

    pub const BLOCK5_ALT: [u8; 262] = hex!(
        "
00000020f92a0ebde83c3d8add9ec1b26006d1951d392268972923897c95bb2f5b0af74815f76329660d400214fe2e67f92507cfe89e93d5103c2b873b83df252240307e74ebd55bffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03540101ffffffff0200f2052a01000000232103d9c0d3e3298b7718dc764de7c480a0b1f1c8bc775c370bd747d05e5b4427209dac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000
    "
    );

    // builds on `BLOCK1_ALT`
    pub const BLOCK3: [u8; 262] = hex!(
        "
0000002001422d871eb91ea112d3c53ebd806314ac900400bbbcbf1e52a465ff96748c42ba75732af9befe5c0c371782ab20056c25b9112a17d878e69c07e5538bd4db8ffeecd55bffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03520101ffffffff0200f2052a01000000232103a6ae7e291698f0766634659ffd6268e9bf36fb381de72027b021fe7dedf701daac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000
    "
    );

    pub const BLOCK4: [u8; 262] = hex!(
        "
00000020f10a43e8fe28145405a0328decdba32c1a5f3cd5967ee236cadf48d2edf96e89bdec700e5a4635a88b35215556a383ec9ba894a736b3f31c28dd1d9593030c3dfeecd55bffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03530101ffffffff0200f2052a01000000232103a6ae7e291698f0766634659ffd6268e9bf36fb381de72027b021fe7dedf701daac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000
    "
    );

    pub const BLOCK5: [u8; 262] = hex!(
        "
0000002057a71c62571051b3816c3ce0abbc94be4b6c822493f82a5046d3950e6517e7fb0225668c9ab466247fe2a4314ba73b817ed1a645f073fb16e84abc3890d01edaffecd55bffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03540101ffffffff0200f2052a01000000232103a6ae7e291698f0766634659ffd6268e9bf36fb381de72027b021fe7dedf701daac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000
    "
    );

    pub const BLOCK6: [u8; 262] = hex!(
        "
0000002014e23d5b18d4b34e8e88cc7ea9ee302b1c406b4e2c0d5477ee3cbaeb790b628d0225668c9ab466247fe2a4314ba73b817ed1a645f073fb16e84abc3890d01edaffecd55bffff7f20000000000102000000000101ddb4653938679c79a7780a07a1c4e5c393b237677459c3a467db52d64ff771e70000000003540101ffffffff0200f2052a01000000232103a6ae7e291698f0766634659ffd6268e9bf36fb381de72027b021fe7dedf701daac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000
    "
    );

    pub const BLOCK7: [u8; 262] = hex!(
        "
0000002078d8ac378186fac5266c0bac7b589ad094fff408aeae5a3ec3d932de449b3f5f0225668c9ab466247fe2a4314ba73b817ed1a645f073fb16e84abc3890d01edaffecd55bffff7f2000000000010200000000010171a588af41b2fc4fb7beae0c2756c7c81d1ba625da7f00fc358f246ffa4c6a010000000003540101ffffffff0200f2052a01000000232103a6ae7e291698f0766634659ffd6268e9bf36fb381de72027b021fe7dedf701daac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000
    "
    );

    fn typehint<T>(v: T) -> T {
        v
    } // trick by mbrubeck

    #[derive(Copy, Clone, Debug)]
    struct BlockData {
        name: &'static str,
        blockref: BlockRef,
        coinbase_txid: bitcoin::Txid,
    }

    macro_rules! def_block_vars {
        ($block:ident, $blockdata:ident <- $var:expr, $height:expr) => {
            let $block: bitcoin::Block = deserialize(&$var).unwrap();
            println!("Block '{}': {}", stringify!($block), $block.block_hash());
            let $blockdata = BlockData {
                name: stringify!($block),
                blockref: BlockRef::new($height, $block.block_hash()),
                coinbase_txid: $block.txdata[0].txid(),
            };
        };
    }

    macro_rules! check_blockchain {
        ($txidx:expr, $active_blocks:expr, $unknown_blocks:expr) => {
            let known_len = typehint::<&[BlockData]>($active_blocks).len();
            let known_txs = typehint::<&[BlockData]>($active_blocks).iter().filter(
                |d| d.coinbase_txid != Default::default()
            ).count();

            assert_eq!($txidx.depth, 4); // fixed
            assert_eq!($txidx.txindex.len(), known_txs, "txindex len");
            assert_eq!($txidx.blocks.len(), known_len, "blocks len");

            for data in typehint::<&[BlockData]>($active_blocks) {
                assert!(
                    $txidx.blocks.iter().find(|b| b.height() == data.blockref.height).is_some(),
                    "active blocks {:?}", data
                );
                if data.coinbase_txid != Default::default() {
                    assert!(
                        $txidx.txindex.get(&data.coinbase_txid).is_some(),
                        "active txindex {:?}", data
                    );
                }
            }

            for data in typehint::<&[BlockData]>($unknown_blocks) {
                let ref_at_height = $txidx.blocks.iter().find(|b| b.height() == data.blockref.height).map(|b| b.blockref);
                assert!(
                    ref_at_height != Some(data.blockref),
                    "unknown blocks {:?}", data
                );
                assert!(
                    $txidx.txindex.get(&data.coinbase_txid).is_none(),
                    "unknown txindex {:?}", data
                );
            }
        };
    }

    /// Creates a closure to be used in the `update_from_rpc` call to txindex.
    /// The closure will always return the same relevant tx metadata, the one
    /// given as an argument.
    /// The counters that are also returned will count the number of times each
    /// of the two calls have been made.
    fn create_counting_closure(
        txmeta_ret: Option<Vec<OutputMeta>>,
    ) -> (
        impl for <'a> FnMut(UpdateClosureCall<'a>) -> UpdateClosureResult,
        Rc<Cell<(usize, usize)>>,
    ) {
        let counters = Rc::new(Cell::new((0usize, 0usize)));

        let counters_clone = counters.clone();
        let closure = move |c: super::UpdateClosureCall| {
            let mut counts = counters_clone.get();
            let ret = match c {
                super::UpdateClosureCall::TxMeta(_, _) => {
                    counts.0 += 1;
                    super::UpdateClosureResult::TxMeta(Ok(txmeta_ret.clone()))
                }
                super::UpdateClosureCall::FinalizedTx(..) => {
                    counts.1 += 1;
                    super::UpdateClosureResult::FinalizedTx
                }
            };
            counters_clone.set(counts);
            ret
        };

        (closure, counters)
    }

    #[test]
    fn test_past_commitment_blocks() {
        //! Test that checks that blocks past the commitment height are
        //! correctly re-checked once the commitment height passes them.

        let block0: bitcoin::Block = deserialize(&BLOCK0).unwrap();
        println!("Block 'block0': {}", block0.block_hash());

        def_block_vars!(block1, _block1_data <- BLOCK1, 1);
        def_block_vars!(block2, _block2_data <- BLOCK2_ALT, 2);
        def_block_vars!(block3, _block3_data <- BLOCK3, 3);
        def_block_vars!(block4, _block4_data <- BLOCK4, 4);
        def_block_vars!(block5, _block5_data <- BLOCK5, 5);
        def_block_vars!(block6, _block6_data <- BLOCK6, 6);
        def_block_vars!(block7, _block7_data <- BLOCK7, 7);

        let (mut closure, counters) = create_counting_closure(None);
        let mut txidx = TxIndex::new(0, 4); // depth of 4 means 3 "unconfirmed" blocks

        let rpc = RpcDummy(vec![
            block0.clone(), block1.clone(), block2.clone(),
            block3.clone(), block4.clone(), block5.clone(),
            block6.clone(),
        ], vec![]);

        txidx.update_from_rpc(&rpc, 2, &mut closure).unwrap();
        assert_eq!(6, txidx.blocks.len());
        assert_eq!(6, txidx.blocks.back().unwrap().blockref.height);
        assert!(txidx.blocks.iter().all(|b| b.relevant_txs.is_empty()));
        assert_eq!((6, 0), counters.get()); // no finalized blocks yet (but all 6 blocks are scanned)

        // From now on, blocks are relevant.
        let (mut closure, counters) = create_counting_closure(Some(empty_relevant()));

        // So with commitment 3, it will resync block 1 & 2, and keep block 3-6
        txidx.update_from_rpc(&rpc, 3, &mut closure).unwrap();
        assert_eq!(6, txidx.blocks.len());
        // First 2 blocks, the ones from the previous commitment, shouldn't be changed.
        assert!(txidx.blocks.iter().take(1).all(|b| b.relevant_txs.is_empty()));
        // Revisited from tip to commitment - 1, so all 2 through 6 are revisited.
        assert!(txidx.blocks.iter().skip(1).all(|b| !b.relevant_txs.is_empty()));
        assert_eq!((5, 0), counters.get());
        assert_eq!(txidx.blocks[0].blockref.hash, block1.block_hash());
        assert_eq!(txidx.blocks[1].blockref.hash, block2.block_hash());
        assert_eq!(txidx.blocks[2].blockref.hash, block3.block_hash());
        assert_eq!(txidx.blocks[3].blockref.hash, block4.block_hash());
        assert_eq!(txidx.blocks[4].blockref.hash, block5.block_hash());

        txidx.update_from_rpc(&rpc, 4, &mut closure).unwrap();
        assert_eq!(5, txidx.blocks.len());
        assert!(txidx.blocks.iter().all(|b| !b.relevant_txs.is_empty()));
        // All "relevant" txs in this test are donations, so they are re-checked.
        assert_eq!((10, 1), counters.get()); // block 1 will be re-scanned when finalized
        assert_eq!(txidx.blocks[0].blockref.hash, block2.block_hash());
        assert_eq!(txidx.blocks[1].blockref.hash, block3.block_hash());
        assert_eq!(txidx.blocks[2].blockref.hash, block4.block_hash());
        assert_eq!(txidx.blocks[3].blockref.hash, block5.block_hash());
        assert_eq!(txidx.blocks[4].blockref.hash, block6.block_hash());

        // Here block 3 will be finalized and that was the first block with some relevant txs
        txidx.update_from_rpc(&rpc, 5, &mut closure).unwrap();
        assert_eq!(4, txidx.blocks.len());
        assert!(txidx.blocks.iter().all(|b| !b.relevant_txs.is_empty()));
        // All "relevant" txs in this test are donations, so they are re-checked.
        assert_eq!((14, 2), counters.get()); // block2 will be re-scanned when finalized
        assert_eq!(txidx.blocks[0].blockref.hash, block3.block_hash());
        assert_eq!(txidx.blocks[1].blockref.hash, block4.block_hash());
        assert_eq!(txidx.blocks[2].blockref.hash, block5.block_hash());
        assert_eq!(txidx.blocks[3].blockref.hash, block6.block_hash());
    }

    #[test]
    fn reorg_handling() {
        let (mut closure, counters) = create_counting_closure(Some(empty_relevant()));
        let mut txidx = TxIndex::new(0, 4); // depth of 4 means 3 "unconfirmed" blocks

        let block0: bitcoin::Block = deserialize(&BLOCK0).unwrap(); // genesis block (g)
        let block0_data = BlockData {
            name: "block0",
            blockref: BlockRef::new(0, block0.block_hash()),
            coinbase_txid: Default::default(),
        };
        // "name" is currently unused so put this line in to avoid a compile error
        block0_data.name.to_string();

        def_block_vars!(block1, block1_data <- BLOCK1, 1);
        def_block_vars!(block2, block2_data <- BLOCK2, 2);
        def_block_vars!(block3, block3_data <- BLOCK3, 3);
        def_block_vars!(block4, block4_data <- BLOCK4, 4);
        def_block_vars!(block5, block5_data <- BLOCK5, 5);

        def_block_vars!(block2_alt, block2_alt_data <- BLOCK2_ALT, 2);
        def_block_vars!(block3_alt, block3_alt_data <- BLOCK3_ALT, 3);
        def_block_vars!(block4_alt, block4_alt_data <- BLOCK4_ALT, 4);
        def_block_vars!(block5_alt, block5_alt_data <- BLOCK5_ALT, 5);

        let mut rpc = RpcDummy(vec![block0, block1], vec![]);
        //
        check_blockchain!(
            txidx,
            &[],
            &[
                block1_data,
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block2_alt_data,
                block3_alt_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );

        // g -> 1
        let target = rpc.0.len() as BlockHeight - 1;
        counters.set((0, 0));
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("update with 1 block");
        check_blockchain!(
            txidx,
            &[block1_data],
            &[
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block2_alt_data,
                block3_alt_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );
        assert_eq!((1, 0), counters.get());

        // g -> 1
        let target = rpc.0.len() as BlockHeight - 1;
        counters.set((0, 0));
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("update with 1 block, noop");
        check_blockchain!(
            txidx,
            &[block1_data],
            &[
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block2_alt_data,
                block3_alt_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );
        assert_eq!((1, 0), counters.get());

        // g -> 1 -> 2
        rpc.0.push(block2);
        let target = rpc.0.len() as BlockHeight - 1;
        counters.set((0, 0));
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("update with second block");
        check_blockchain!(
            txidx,
            &[block1_data, block2_data],
            &[
                block3_data,
                block4_data,
                block5_data,
                block2_alt_data,
                block3_alt_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );
        assert_eq!((2, 0), counters.get());

        // g -> 1 -> 2_ALT (1-block reorg)
        rpc.0.pop();
        rpc.0.push(block2_alt);
        let target = rpc.0.len() as BlockHeight - 1;
        counters.set((0, 0));
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("1-block reorg");
        check_blockchain!(
            txidx,
            &[block1_data, block2_alt_data],
            &[
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block3_alt_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );
        assert_eq!((1, 0), counters.get());

        // Add a block -- we are now at height 4; index should prune after this
        rpc.0.push(block3_alt);
        let target = rpc.0.len() as BlockHeight - 1;
        counters.set((0, 0));
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("third block");
        check_blockchain!(
            txidx,
            &[block1_data, block2_alt_data, block3_alt_data],
            &[
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );
        assert_eq!((2, 0), counters.get());

        // Add a block -- genesis should be dropped now, no net change in counts
        rpc.0.push(block4_alt);
        let target = rpc.0.len() as BlockHeight - 1;
        counters.set((0, 0));
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("fourth block");
        check_blockchain!(
            txidx,
            &[block2_alt_data, block3_alt_data, block4_alt_data],
            &[
                block1_data,
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block5_alt_data,
            ]
        );
        assert_eq!((3, 1), counters.get()); // block1 is rescanned when finalized

        // Add a block -- both sides of the 1-block fork should be dropped, so net reduction in counts
        rpc.0.push(deserialize(&BLOCK5_ALT).unwrap());
        let target = rpc.0.len() as BlockHeight - 1;
        counters.set((0, 0));
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("fifth block");
        check_blockchain!(
            txidx,
            &[block3_alt_data, block4_alt_data, block5_alt_data],
            &[
                block1_data,
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block2_alt_data,
            ]
        );
        assert_eq!((3, 1), counters.get()); // block2_alt is rescanned when finalized
    }

    #[test]
    #[should_panic(expected = "F-T901")]
    fn deep_reorg_panic() {
        let (mut closure, counters) = create_counting_closure(Some(empty_relevant()));
        let mut txidx = TxIndex::new(0, 3);

        let rpc1 = RpcDummy(
            vec![
                deserialize::<bitcoin::Block>(&BLOCK1).unwrap(),
                deserialize::<bitcoin::Block>(&BLOCK2_ALT).unwrap(),
                deserialize::<bitcoin::Block>(&BLOCK3_ALT).unwrap(),
                deserialize::<bitcoin::Block>(&BLOCK4_ALT).unwrap(),
                deserialize::<bitcoin::Block>(&BLOCK5_ALT).unwrap(),
            ],
            vec![],
        );
        let rpc2 = RpcDummy(
            vec![
                deserialize::<bitcoin::Block>(&BLOCK1).unwrap(),
                deserialize::<bitcoin::Block>(&BLOCK2_ALT).unwrap(),
                deserialize::<bitcoin::Block>(&BLOCK3).unwrap(),
                deserialize::<bitcoin::Block>(&BLOCK4).unwrap(),
                deserialize::<bitcoin::Block>(&BLOCK5).unwrap(),
            ],
            vec![],
        );

        let target = rpc1.0.len() as BlockHeight - 1;
        txidx.update_from_rpc(&rpc1, target, &mut closure).expect("initial 5-block chain");
        assert_eq!((5, 3), counters.get()); // block1 & block2 are NOT re-scanned when finalized, because we had enough commitments during the initial scan
        let target = rpc2.0.len() as BlockHeight - 1;
        let _ = txidx.update_from_rpc(&rpc2, target, &mut closure); // this call panics
    }

    #[test]
    fn test_size_bound() {
        // Test that checks that the memory size (estimated by the serialized size) doesn't keep
        // growing when adding blocks (past the max depth to keep).

        let (mut closure, counters) = create_counting_closure(Some(vec![
            OutputMeta::Pegout(Default::default()),
            OutputMeta::Change,
            OutputMeta::Donation,
        ]));

        // Make sure all txids are unique by rolling the version field.
        let mut tx_counter = 0;
        let witness = vec![vec![1; 10]; 2];
        let mut gen_tx_with_size = || bitcoin::Transaction {
            version: {
                tx_counter += 1;
                tx_counter
            },
            lock_time: 0,
            input: vec![bitcoin::TxIn {
                previous_output: Default::default(),
                script_sig: vec![1; 10].into(),
                sequence: 0,
                witness: bitcoin::Witness::from_vec(witness.clone()),
            }],
            output: vec![bitcoin::TxOut {
                value: 0,
                script_pubkey: vec![1; 10].into(),
            }],
        };
        let gen_block_with_size = |prev, txs| bitcoin::Block {
            header: bitcoin::BlockHeader {
                version: 0,
                prev_blockhash: prev,
                merkle_root: Default::default(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txdata: txs,
        };

        let mut rpc = RpcDummy(vec![gen_block_with_size(Default::default(), vec![])], vec![]);
        let mut last_block_hash = rpc.0.last().unwrap().block_hash();
        let depth = 20;
        let mut index = TxIndex::new(0, depth);
        let mut max_size = None;
        for i in 0..(2 * depth) {
            // Add a new block that continues the chain.
            let block_txs = (0..3).map(|_| gen_tx_with_size()).collect();
            let next_block = gen_block_with_size(last_block_hash, block_txs);
            last_block_hash = next_block.block_hash();
            rpc.0.push(next_block);
            rpc.1 = (0..5).map(|_| gen_tx_with_size()).collect();

            let target = rpc.0.len() as BlockHeight - 1;
            let (done, new) = index.update_from_rpc(&rpc, target, &mut closure).unwrap();
            assert!(done);
            assert_eq!(new.len(), 3 + 5);
            if i < depth - 1 {
                assert_eq!((i + 1) * 8, counters.get().0 as u64);
                assert_eq!(counters.get().1, 0);
            } else {
                let finalized_blocks = i - (depth - 1) + 1;
                let expected_rescanned_txs = 3 * finalized_blocks;
                assert_eq!((i + 1) * 8 + expected_rescanned_txs, counters.get().0 as u64);
                assert_eq!(counters.get().1, 3 * (i + 2 - depth) as usize);
            }

            // Check sizes.
            let size = jsonrpc::serde_json::to_string(&index).unwrap().len();
            if i == depth {
                // It grows a bit more because block and tx indexes change in number of digits.
                max_size = Some(size + 90);
            }
            if let Some(max) = max_size {
                assert!(size < max, "{} < {} diff={}", size, max, size - max + 1);
            }
        }
    }

    #[test]
    fn test_fork_past_commitment () {
        // Simulate BLOCK2_ALT having a sidechain transaction which is not recognized until
        // it is finalized. This tests our handling of the issue described in
        // https://gl.blockstream.io/liquid/functionary/-/issues/1063.
        //
        // Hardcode all transactions to have 3 relevant UTXOs, except for the transaction in BLOCK2_ALT,
        // which should only have 1 relevant UTXO until we see it again.
        // At that point 2 more will be identified (3 total).
        let block2_alt_txid = "0eec4c7cdd05a87babd78a518347d165616428701e002dad5ba10c8ec6b1b824";
        let (mut closure, counters) = {
            let counters = Rc::new(Cell::new((0, 0))); // tuple: (new_txs, finalized_txs)
            let seen_txids = Rc::new(RefCell::new(HashSet::<String>::new()));

            let counters_clone = counters.clone();
            let seen_clone = seen_txids.clone();

            let closure = move |c: super::UpdateClosureCall| {
                let mut counts = counters_clone.get();
                let mut seen = seen_clone.borrow_mut();
                let ret = match c {
                    super::UpdateClosureCall::TxMeta(tx, _commitment_height) => {
                        let txid = format!("{:?}", tx.txid());
                        if txid == block2_alt_txid {
                            if !seen.contains(&txid) {
                                seen.insert(txid);
                                counts.0 += 1;
                                super::UpdateClosureResult::TxMeta(Ok(Some([
                                    OutputMeta::Pegout(Default::default()),
                                ].into())))
                            } else {
                                counts.0 += 2;
                                super::UpdateClosureResult::TxMeta(Ok(Some([
                                    OutputMeta::Change,
                                    OutputMeta::Donation,
                                ].into())))
                            }
                        } else {
                            if !seen.contains(&txid) {
                                seen.insert(txid);
                                counts.0 += 3;
                                super::UpdateClosureResult::TxMeta(Ok(Some([
                                    OutputMeta::Pegout(Default::default()),
                                    OutputMeta::Change,
                                    OutputMeta::Donation,
                                ].into())))
                            } else {
                                super::UpdateClosureResult::TxMeta(Ok(Some(empty_relevant())))
                            }
                        }
                    },
                    super::UpdateClosureCall::FinalizedTx(..) => {
                        counts.1 += 1;
                        super::UpdateClosureResult::FinalizedTx
                    }
                };
                counters_clone.set(counts);
                ret
            };

            (closure, counters)
        };

        let mut txidx = TxIndex::new(0, 4); // depth of 4 means 3 "unconfirmed" blocks

        let block0: bitcoin::Block = deserialize(&BLOCK0).unwrap(); // genesis block (g)
        let block0_data = BlockData {
            name: "block0",
            blockref: BlockRef::new(0, block0.block_hash()),
            coinbase_txid: Default::default(),
        };
        // "name" is currently unused so put this line in to avoid a compile error
        block0_data.name.to_string();

        def_block_vars!(block1, block1_data <- BLOCK1, 1);
        def_block_vars!(block2, block2_data <- BLOCK2, 2);
        def_block_vars!(block3, block3_data <- BLOCK3, 3);
        def_block_vars!(block4, block4_data <- BLOCK4, 4);
        def_block_vars!(block5, block5_data <- BLOCK5, 5);

        def_block_vars!(block2_alt, block2_alt_data <- BLOCK2_ALT, 2);
        def_block_vars!(block3_alt, block3_alt_data <- BLOCK3_ALT, 3);
        def_block_vars!(block4_alt, block4_alt_data <- BLOCK4_ALT, 4);
        def_block_vars!(block5_alt, block5_alt_data <- BLOCK5_ALT, 5);

        let mut rpc = RpcDummy(vec![block0, block1], vec![]);

        check_blockchain!(
            txidx,
            &[],
            &[
                block1_data,
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block2_alt_data,
                block3_alt_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );

        // g -> 1
        let target = rpc.0.len() as BlockHeight - 1;
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("update with 1 block");
        check_blockchain!(
            txidx,
            &[block1_data],
            &[
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block2_alt_data,
                block3_alt_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );
        assert_eq!((3, 0), counters.get()); // block 1 has 3 spendable UTXOs

        // g -> 1
        let target = rpc.0.len() as BlockHeight - 1;
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("update with 1 block, noop");
        check_blockchain!(
            txidx,
            &[block1_data],
            &[
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block2_alt_data,
                block3_alt_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );
        assert_eq!((3, 0), counters.get());

        // g -> 1 -> 2
        rpc.0.push(block2);
        let target = rpc.0.len() as BlockHeight - 1;
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("update with second block");
        check_blockchain!(
            txidx,
            &[block1_data, block2_data],
            &[
                block3_data,
                block4_data,
                block5_data,
                block2_alt_data,
                block3_alt_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );
        assert_eq!((6, 0), counters.get()); // both blocks have 3 spendable UTXOs

        // g -> 1 -> 2_ALT (1-block reorg)
        rpc.0.pop();
        rpc.0.push(block2_alt);
        let target = rpc.0.len() as BlockHeight - 1;
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("1-block reorg");
        check_blockchain!(
            txidx,
            &[block1_data, block2_alt_data],
            &[
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block3_alt_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );
        assert_eq!((7, 0), counters.get()); // block1 has 3 spendable UTXOs, block2_alt should only have 1 until we reach commitment 5

        // Add a block -- we are now at height 4; index should prune after this
        rpc.0.push(block3_alt);
        let target = rpc.0.len() as BlockHeight - 1;
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("third block");
        check_blockchain!(
            txidx,
            &[block1_data, block2_alt_data, block3_alt_data],
            &[
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block4_alt_data,
                block5_alt_data,
            ]
        );
        assert_eq!((10, 0), counters.get()); // block3_alt has 3 spendable UTXOs

        // Add a block -- genesis should be dropped now
        rpc.0.push(block4_alt);
        let target = rpc.0.len() as BlockHeight - 1;
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("fourth block");
        check_blockchain!(
            txidx,
            &[block2_alt_data, block3_alt_data, block4_alt_data],
            &[
                block1_data,
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block5_alt_data,
            ]
        );
        // block4_alt has 3 spendable UTXOs, finalize block1 (all 3 UTXOs will be rescanned)
        assert_eq!((13, 1), counters.get());

        // Add a block -- both sides of the 1-block fork should be dropped
        rpc.0.push(deserialize(&BLOCK5_ALT).unwrap());
        let target = rpc.0.len() as BlockHeight - 1;
        txidx.update_from_rpc(&rpc, target, &mut closure).expect("fifth block");
        check_blockchain!(
            txidx,
            &[block3_alt_data, block4_alt_data, block5_alt_data],
            &[
                block1_data,
                block2_data,
                block3_data,
                block4_data,
                block5_data,
                block2_alt_data,
            ]
        );
        // block5_alt has 3 spendable UTXOs.
        // Finalizing block2_alt should cause 2 new spendable UTXOs to be found
        // expected total new UTXOs = 13 + 3 + 2 = 18
        assert_eq!((18, 2), counters.get());
    }
}
