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


//! # Fee Pool
//! Computes and validates fee amounts for transactions; also tracks how many
//! funds are available for spending on fees.
//!

use std::{cmp, error, fmt, io};
use std::collections::{HashMap, HashSet};
use bitcoin;
use bitcoin::OutPoint;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use common::constants;
use message;
use logs::ProposalError;
use utils;
use rpc::BitcoinRpc;

/// Fee pool error
#[derive(Debug)]
pub enum Error {
    /// We did not receive a fee estimate but instead a vector of errors.
    NoFeeEstimate(Vec<String>),
    /// JSONRPC communication
    Rpc(jsonrpc::Error),
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Rpc(ref x) => Some(x),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NoFeeEstimate(ref errors) => write!(f, "bitcoind is not able to provide a fee estimate: {}", errors.join(". ")),
            Error::Rpc(ref x) => write!(f, "rpc: {}", x),
        }
    }
}

#[doc(hidden)]
impl From<jsonrpc::Error> for Error {
    fn from(e: jsonrpc::Error) -> Error {
        Error::Rpc(e)
    }
}

/// ConflictingTransactions is a data structure that keeps track of
/// transaction and conflicts between them for the purpose of fee accounting.
/// This does not interact with utxotable::ConflictTracker.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ConflictingTransactions {
    #[serde(with = "utils::serialize::hashmap")]
    inputs_map: HashMap<bitcoin::Txid, HashSet<bitcoin::OutPoint>>
}

impl ConflictingTransactions {
    /// Create new ConflictingTransactions
    pub fn new() -> ConflictingTransactions {
        ConflictingTransactions {
            inputs_map: HashMap::new(),
        }
    }

    /// Add a transaction
    pub fn add(&mut self, txid: &bitcoin::Txid, txinputs: HashSet<bitcoin::OutPoint>) {
        self.inputs_map.insert(*txid, txinputs);
    }

    /// Confirm a transaction which removes the transaction and all
    /// conflicting transactions. Returns the txids of all removed
    /// transactions except the original one.
    pub fn confirm(&mut self, txid: &bitcoin::Txid) -> Vec<bitcoin::Txid> {
        let inputs = match self.inputs_map.remove(txid) {
            Some(inputs) => inputs,
            None => return Vec::new(),
        };

        self.find_conflicts(inputs)
    }

    /// Find conflicts with other txs, drop conflicting txs
    pub fn find_conflicts(&mut self, inputs: HashSet<OutPoint>) -> Vec<bitcoin::Txid> {
        let mut conflicts = Vec::new();
        self.inputs_map.retain(|txid, other_inputs| {
            let conflicting = !inputs.is_disjoint(other_inputs);
            if conflicting {
                conflicts.push(*txid);
            }
            !conflicting // retain when not conflicting
        });

        conflicts
    }

    /// True if ConflictingTransactions is empty
    pub fn is_empty(&self) -> bool{
        self.inputs_map.is_empty()
    }
}

/// Main fee pool structure
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Pool {
    /// Hard ceiling on transaction fee, in sat
    maximum_fee: u64,
    /// Current estimate for the appropriate fee/kb rate
    fee_rate: u64,
    /// Fee/kb rate if estimation is not possible
    fallback_fee_rate: u64,
    /// Total amount of money we have to spend on fees, in sat. This may go negative
    /// in certain circumstances (say, if the signer has temporarily docked a lot of
    /// fees, then an unconfirmed transaction appears which docks even more). This
    /// probably indicates a network issue, but in general it is not preventable, so
    /// we maintain `available_funds` as a signed value.
    available_funds: i64,
    /// Map from txids to the fees that are temporarily docked for them
    fee_map: HashMap<bitcoin::Txid, u64>,
    /// Manages conflicting transactions for temporarily_dock'ing and
    /// undock'ing
    conflicting_transactions: ConflictingTransactions,
}

impl Pool {
    /// Creates a new fee pool
    pub fn new(fallback_fee_rate: u64) -> Pool {
        Pool {
            maximum_fee: 10_000_000,  // 0.1btc
            fee_rate: fallback_fee_rate,
            fallback_fee_rate: fallback_fee_rate,
            available_funds: 0,
            fee_map: HashMap::new(),
            conflicting_transactions: ConflictingTransactions::new(),
        }
    }

    /// Updates feerate from RPC
    pub fn update_rate_rpc(&mut self, bitcoind: &impl BitcoinRpc) -> Result<(), Error> {
        let estimate = bitcoind.estimate_smart_fee(constants::TX_CONFIRM_TARGET)?;
        let fee_per_kb = match estimate.feerate {
            Some(feerate) => feerate.as_sat(),
            None => {
                // When the response does not contain a feerate then return errors if there are some
                return Err(Error::NoFeeEstimate(estimate.errors))
            }
        };
        let block_estimate = estimate.blocks;

        slog!(NewFeeEstimate, fee_rate: fee_per_kb, blocks: block_estimate);

        if block_estimate > 25 {
            Err(Error::NoFeeEstimate(vec!["Estimate is for too many blocks in the future".to_owned()]))
        } else {
            self.fee_rate = fee_per_kb as u64;
            Ok(())
        }
    }

    /// Given the weight of some data, return the amount of fees required
    /// to pay for it.
    fn calculate_fee_uncapped(&self, tx_weight: usize) -> u64 {
        // (feerate * weight + 3999) / 4000
        // (the +3999 to make sure we round up)
        return self.fee_rate.saturating_mul(tx_weight as u64).saturating_add(3999) / 4000;
    }

    /// Given the (estimated) size of a signed transaction in bytes, return the
    /// amount of fees that should be attached to it. If the amount would be
    /// greater than the available funds in the pool, return an error
    pub fn calculate_fee(&self, tx_weight: usize) -> u64 {
        let base = self.calculate_fee_uncapped(tx_weight);
        cmp::min(base, self.maximum_fee)
    }

    /// Decide whether a fee amount for a given transaction is acceptable (within
    /// our min and max and within some threshold of what we'd compute) and if
    /// we have enough funds available.
    pub fn validate_fee(&self, tx_weight: usize, fee: u64) -> Result<(), ProposalError> {
        const ACCEPTABLE_FEE_FACTOR: u64 = 5;
        // Divide by 4000 because the feerate is given in terms of 1Kvsize
        let base = self.calculate_fee_uncapped(tx_weight);

        if fee as i64 > self.available_funds {
            return Err(ProposalError::InsufficientFees {
                available: self.available_funds,
                needed: fee,
            });
        }
        if fee > self.maximum_fee {
            return Err(ProposalError::FeeTooHigh {
                maximum: self.maximum_fee,
                got: fee,
            });
        }
        if fee > base * ACCEPTABLE_FEE_FACTOR {
            return Err(ProposalError::FeeTooHigh {
                maximum: base * ACCEPTABLE_FEE_FACTOR,
                got: fee,
            });
        }
        if fee < base / ACCEPTABLE_FEE_FACTOR {
            return Err(ProposalError::FeeTooLow {
                minimum: base / ACCEPTABLE_FEE_FACTOR,
                got: fee,
            });
        }
        Ok(())
    }

    /// Accessor for available funds
    pub fn available_funds(&self) -> i64 {
        self.available_funds
    }

    /// Dock the available funds.
    fn force_dock(&mut self, amount: u64) {
        self.available_funds -= amount as i64;
    }

    /// Dock fees for a transaction. Wrapper for `temporarily_dock`.
    pub fn temporarily_dock_tx(&mut self, tx: &bitcoin::Transaction, amount: u64) {
        let mut txinputs = HashSet::new();
        for input in &tx.input {
            txinputs.insert(input.previous_output);
        }
        self.temporarily_dock(tx.txid(), txinputs, amount);
    }

    /// Dock fees and record the txid of the transaction. Also record
    /// conflicts with already temporarily_dock'ed transactions such that the
    /// fee of all conflicting transactions can be undocked when one confirms.
    fn temporarily_dock(&mut self, txid: bitcoin::Txid, txinputs: HashSet<bitcoin::OutPoint>, amount: u64) {
        if self.fee_map.contains_key(&txid) {
            return
        }
        self.force_dock(amount);
        self.fee_map.insert(txid, amount);
        slog!(DockFees, docked: amount, available: self.available_funds, txid: txid);
        self.conflicting_transactions.add(&txid, txinputs);
    }

    /// Return all fees corresponding to some transaction to the fee pool.
    /// This includes returning the fees of transactions that have been
    /// temporarily_dock'ed and are in conflict with the undocked transaction.
    pub fn confirm(&mut self, txid: &bitcoin::Txid) {
        for txid in &self.conflicting_transactions.confirm(txid) {
            if let Some(amount) = self.fee_map.remove(txid) {
                self.available_funds += amount as i64;
                slog!(ReclaimFees, txid: *txid, added: amount, available: self.available_funds);
            }
        }
        slog!(Confirm, txid: *txid);
        self.fee_map.remove(txid);
    }

    /// Return all fees associated with transaction that conflict with the provided transaction
    pub fn reclaim_conflicting_fees(&mut self, tx: &bitcoin::Transaction) {
        let mut txinputs = HashSet::new();
        for input in &tx.input {
            txinputs.insert(input.previous_output);
        }

        for txid in &self.conflicting_transactions.find_conflicts(txinputs) {
            if let Some(amount) = self.fee_map.remove(txid) {
                self.available_funds += amount as i64;
                slog!(ReclaimFees, txid: *txid, added: amount, available: self.available_funds);
            }
        }
    }

    /// Accessor for the total value temporarily docked
    pub fn temporarily_docked(&self) -> u64 {
        self.fee_map.values().fold(0, |x, y| x + y)
    }

    /// Add funds to the available funds pool
    pub fn add(&mut self, amount: u64) {
        self.available_funds += amount as i64;
        slog!(AddFees, added: amount, available: self.available_funds);
    }

    /// Set funds to the available funds pool
    pub fn set(&mut self, amount: i64) {
        self.available_funds = amount;
    }

    /// Verifies the fee pool has been cleared out during tests
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        assert_eq!(self.fee_map, HashMap::new());  // verbosely log if not empty
        self.fee_map.is_empty()
    }

    /// The economical amount is defined as the amount that is larger than the fee required to
    /// spend it.
    pub fn economical_amount(&self, signed_input_weight: usize) -> u64 {
        self.calculate_fee_uncapped(signed_input_weight)
    }

    /// Returns a summary of the fee pool
    pub fn summary(&self) -> PoolSummary {
        PoolSummary {
            fee_rate: self.fee_rate,
            available_funds: self.available_funds,
            temporarily_docked: self.temporarily_docked(),
        }
    }

    /// Log the fee pool status.
    pub fn log_status(&self) {
        slog!(FeePoolStatus,
            fee_rate: self.fee_rate,
            available_funds: self.available_funds,
            temporarily_docked: self.temporarily_docked(),
            maximum_fee: self.maximum_fee,
            fallback_fee_rate: self.fallback_fee_rate,
        );
    }
}

/// Fee pool summary. Useful for sending info about the fee pool in a
/// network message.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PoolSummary {
    /// Current estimate for the appropriate fee/kb rate
    pub fee_rate: u64,
    /// Total amount of money we have to spend on fees, in sat.
    pub available_funds: i64,
    /// Temporarily docked fees, in sat
    pub temporarily_docked: u64,
}

impl message::NetEncodable for PoolSummary {
    fn encode<W: io::Write>(&self, mut w: W) -> Result<usize, message::Error> {
        w.write_u64::<LittleEndian>(self.fee_rate)?;
        w.write_i64::<LittleEndian>(self.available_funds)?;
        w.write_u64::<LittleEndian>(self.temporarily_docked)?;
        Ok(8 * 3)
    }

    fn decode<R: io::Read>(mut r: R) -> Result<Self, message::Error> {
        Ok(PoolSummary {
            fee_rate: r.read_u64::<LittleEndian>()?,
            available_funds: r.read_i64::<LittleEndian>()?,
            temporarily_docked: r.read_u64::<LittleEndian>()?,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use common::BlockHeight;

    use bitcoin;
    use bitcoin::hashes::Hash;

    pub const FALLBACK_FEE_RATE: u64 = 20000;

    #[derive(Serialize)]
    #[serde(untagged)]
    enum ESFResponse {
        Success {
            blocks: BlockHeight,
            feerate: f64,
        },
        Fail {
            blocks: BlockHeight,
            errors: Vec<&'static str>,
        },
    }

    struct RpcDummy {
        fee_rate_sat: Option<u64>,
        blocks: BlockHeight,
    }
    impl_dummy_rpc!(
        RpcDummy,
        dummy,
        "estimatesmartfee" => match dummy.fee_rate_sat {
            Some(x) => ESFResponse::Success {
                blocks: dummy.blocks,
                feerate: x as f64 / 1_0000_0000.0,
            },
            None => ESFResponse::Fail {
                blocks: dummy.blocks,
                errors: vec!["Insufficient data or no feerate found"],
            },
        }
    );

    #[test]
    fn test_fee_pool() {
        let txids = vec![
            bitcoin::Txid::hash(b""),
            bitcoin::Txid::hash(b"abc"),
            bitcoin::Txid::hash(b"123"),
            bitcoin::Txid::hash(b"321"),
            bitcoin::Txid::hash(b"cba"),
        ];
        // Actual test
        let mut pool = Pool::new(FALLBACK_FEE_RATE);

        let conflict_outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::hash(b"lol"),
            vout: 0,
        };

        assert_eq!(pool.fee_rate, FALLBACK_FEE_RATE);
        assert!(pool.update_rate_rpc(&RpcDummy { fee_rate_sat: Some(0), blocks: 26 }).is_err());
        assert_eq!(pool.fee_rate, FALLBACK_FEE_RATE);
        pool.update_rate_rpc(&RpcDummy { fee_rate_sat: Some(0), blocks: 25 }).expect("set feerate to 0");
        match pool.update_rate_rpc(&RpcDummy { fee_rate_sat: None, blocks: 25 }) {
            Err(Error::NoFeeEstimate(v)) => {
                assert_eq!(v, vec!["Insufficient data or no feerate found".to_owned()]);
            }
            Err(x) => panic!("Expected `NoFeeEstimate` error, got {}", x),
            Ok(_) => panic!("Expected `NoFeeEstimate` error, got Ok"),
        }
        assert_eq!(pool.fee_rate, 0);
        assert!(pool.update_rate_rpc(&RpcDummy {
            fee_rate_sat: Some(FALLBACK_FEE_RATE),
            blocks: 0,
        }).is_ok());
        assert_eq!(pool.fee_rate, FALLBACK_FEE_RATE);

        let fee1kb = FALLBACK_FEE_RATE;
        // empty pool
        assert_eq!(pool.available_funds(), 0);
        assert_eq!(pool.calculate_fee_uncapped(4000), fee1kb);
        assert!(pool.validate_fee(4000, pool.calculate_fee(4000)).is_err());
        assert!(pool.validate_fee(100, pool.calculate_fee(100)).is_err());
        assert_eq!(pool.available_funds(), 0);
        pool.confirm(&txids[0]);
        pool.confirm(&txids[0]);
        pool.confirm(&txids[1]);
        pool.confirm(&txids[2]);
        assert_eq!(pool.available_funds(), 0);

        // add enough to pay for one tx
        pool.add(fee1kb * 2);
        assert_eq!(pool.available_funds(), 2 * fee1kb as i64);
        assert_eq!(pool.calculate_fee_uncapped(4000), fee1kb);
        assert_eq!(pool.calculate_fee(4000), fee1kb);
        assert_eq!(pool.calculate_fee(1), fee1kb / 4000);
        assert_eq!(pool.available_funds(), 2 * fee1kb as i64);
        // dock it
        pool.force_dock(fee1kb);
        assert_eq!(pool.available_funds(), fee1kb as i64);
        pool.temporarily_dock(txids[0], Default::default(), fee1kb);
        assert_eq!(pool.available_funds(), 0);

        // temporarily dock some stuff
        pool.add(fee1kb * 3);
        pool.temporarily_dock(txids[1], Default::default(), fee1kb);
        pool.temporarily_dock(txids[2], vec![conflict_outpoint].into_iter().collect(), fee1kb);
        pool.temporarily_dock(txids[4], vec![conflict_outpoint].into_iter().collect(), fee1kb);
        assert_eq!(pool.available_funds(), 0);

        // Undock the above "temporarily docked" values. (Don't undock txids[2],
        // we'll need that below)
        pool.confirm(&txids[0]);
        assert_eq!(pool.available_funds(), 0);
        pool.confirm(&txids[0]);
        assert_eq!(pool.available_funds(), 0);
        pool.confirm(&txids[1]);
        assert_eq!(pool.available_funds(), 0);
        pool.confirm(&txids[3]);
        assert_eq!(pool.available_funds(), 0);

        // Try force-docking to go below zero
        pool.force_dock(fee1kb * 8);
        assert_eq!(pool.available_funds(), -8 * fee1kb as i64);
        pool.force_dock(fee1kb * 3);
        assert_eq!(pool.available_funds(), -11 * fee1kb as i64);

        // Ensure both adding and undocking work with negative `available_funds`
        pool.confirm(&txids[2]);
        assert_eq!(pool.available_funds(), -10 * fee1kb as i64);
        pool.add(fee1kb * 8);
        assert_eq!(pool.available_funds(), -2 * fee1kb as i64);
        pool.add(fee1kb * 5);
        assert_eq!(pool.available_funds(), 3 * fee1kb as i64);
        pool.force_dock(fee1kb);
        assert_eq!(pool.available_funds(), 2 * fee1kb as i64);
        pool.temporarily_dock(txids[0], Default::default(), fee1kb);
        assert_eq!(pool.available_funds(), fee1kb as i64);

        // Try temporarily docking to go below zero
        pool.temporarily_dock(txids[3], Default::default(), 2 * fee1kb);
        assert_eq!(pool.available_funds(), -1 * fee1kb as i64);
        pool.temporarily_dock(txids[1], vec![conflict_outpoint].into_iter().collect(), 2 * fee1kb);
        assert_eq!(pool.available_funds(), -3 * fee1kb as i64);
        pool.temporarily_dock(txids[2], vec![conflict_outpoint].into_iter().collect(), fee1kb);
        assert_eq!(pool.available_funds(), -4 * fee1kb as i64);
        pool.confirm(&txids[2]); // recover fees from txids[1]
        assert_eq!(pool.available_funds(), -2 * fee1kb as i64);
        pool.confirm(&txids[3]); // no-op, confirmed tx without conflicts
        assert_eq!(pool.available_funds(), -2 * fee1kb as i64);
        pool.confirm(&txids[1]); // no-op, was no longer tracking this tx
        assert_eq!(pool.available_funds(), -2 * fee1kb as i64);
    }

    #[test]
    fn dock_same_tx_twice() {
        let txid = bitcoin::Txid::hash(b"");

        let mut pool = Pool::new(FALLBACK_FEE_RATE);
        // empty pool
        pool.add(1000);
        assert_eq!(pool.available_funds(), 1000);
        pool.temporarily_dock(txid, Default::default(), 500);
        assert_eq!(pool.available_funds(), 500);
        pool.temporarily_dock(txid, Default::default(), 500);
        assert_eq!(pool.available_funds(), 500);
        pool.confirm(&txid);
        assert_eq!(pool.available_funds(), 500);
    }

    #[test]
    fn test_temporarily_docking_fees() {
        let txids = vec![
            bitcoin::Txid::hash(b""),
            bitcoin::Txid::hash(b"abc"),
            bitcoin::Txid::hash(b"123"),
        ];
        let inputs = vec![
            bitcoin::OutPoint { txid: bitcoin::Txid::hash(b"tx0"), vout: 0 },
            bitcoin::OutPoint { txid: bitcoin::Txid::hash(b"tx0"), vout: 1 },
            bitcoin::OutPoint { txid: bitcoin::Txid::hash(b"tx1"), vout: 0 },
            bitcoin::OutPoint { txid: bitcoin::Txid::hash(b"tx1"), vout: 1 },
        ];

        // Actual test
        let mut pool = Pool::new(FALLBACK_FEE_RATE);
        // empty pool
        assert_eq!(pool.available_funds(), 0);

        // add something to fee pool
        let initial = 1000;
        pool.add(1000);

        // input0     input1      input2    input4
        // [      tx0      ]
        //            [      tx1       ]
        //                       [       tx2      ]
        let tx0fee = 1i64;
        let tx1fee = 10i64;
        let tx2fee = 100i64;
        pool.temporarily_dock(txids[0], vec![inputs[0], inputs[1]].into_iter().collect(), tx0fee as u64);
        assert_eq!(pool.available_funds(), initial - tx0fee);
        pool.temporarily_dock(txids[1], vec![inputs[1], inputs[2]].into_iter().collect(), tx1fee as u64);
        assert_eq!(pool.available_funds(), initial - tx0fee - tx1fee);
        pool.temporarily_dock(txids[2], vec![inputs[2], inputs[3]].into_iter().collect(), tx2fee as u64);
        assert_eq!(pool.available_funds(), initial - tx0fee - tx1fee - tx2fee);

        let pool_original = pool.clone();
        pool.confirm(&txids[1]);
        assert_eq!(pool.available_funds(), initial - tx1fee);
        assert!(pool.conflicting_transactions.is_empty());
        assert_eq!(pool.fee_map, HashMap::new());

        let mut pool = pool_original.clone();
        pool.confirm(&txids[0]);
        assert_eq!(pool.available_funds(), initial - tx0fee - tx2fee);
        // txids[1] is not tracked anymore
        pool.confirm(&txids[1]);
        assert_eq!(pool.available_funds(), initial - tx0fee - tx2fee);
        pool.confirm(&txids[2]);
        assert_eq!(pool.available_funds(), initial - tx0fee - tx2fee);
        assert!(pool.conflicting_transactions.is_empty());
        assert_eq!(pool.fee_map, HashMap::new());

        let mut pool = pool_original.clone();
        pool.confirm(&txids[1]);
        // Both txids[0] and txids[2] were removed and their fees recovered
        assert_eq!(pool.available_funds(), initial - tx1fee);
        assert!(pool.conflicting_transactions.is_empty());
        assert_eq!(pool.fee_map, HashMap::new());
        // Nothing tracked anymore, these should be no-ops
        pool.confirm(&txids[0]);
        pool.confirm(&txids[1]);
        pool.confirm(&txids[2]);
        assert_eq!(pool.available_funds(), initial - tx1fee);
        assert!(pool.conflicting_transactions.is_empty());
        assert_eq!(pool.fee_map, HashMap::new());
    }
}

