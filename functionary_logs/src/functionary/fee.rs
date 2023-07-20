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

//! # Watchman fee pool losg
//!

/// Status of the feepool.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FeePoolStatus {
    /// Current estimate for the appropriate fee/kb rate
    pub fee_rate: u64,
    /// Total amount of money we have to spend on fees, in sat.
    pub available_funds: i64,
    /// Temporarily docked fees, in sat
    pub temporarily_docked: u64,
    /// Hard ceiling on transaction fee, in sat
    pub maximum_fee: u64,
    /// Fee/kb rate if estimation is not possible
    pub fallback_fee_rate: u64,
}

/// Obtained new fee estimate from bitcoind
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct NewFeeEstimate {
    /// Feerate, in satoshi per vkb
    pub fee_rate: u64,
    /// Number of blocks we expect a confirmation to take
    /// at this feerate
    pub blocks: u64,
}

/// Failed to get a fee estimate from bitcoind
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct FeeEstimateFailed {
    /// Stringified error
    pub error: String,
}

/// Docked fees from pool
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DockFees {
    /// Transaction for which we're docking the fees
    pub txid: bitcoin::Txid,
    /// Amount docked from the pool
    pub docked: u64,
    /// New amount of available fees
    pub available: i64,
}

/// Reclaim fees from a transaction which we no longer believe
/// will confirm
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ReclaimFees {
    /// Transaction which we decided will not confirm
    pub txid: bitcoin::Txid,
    /// Amount added to the pool
    pub added: u64,
    /// New amount of available fees
    pub available: i64,
}

/// Confirm a transaction (we will never reclaim its fees)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Confirm {
    /// Transaction which was confirmed
    pub txid: bitcoin::Txid,
}

/// Added fees to the pool
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AddFees {
    /// Amount added to the pool
    pub added: u64,
    /// New amount of available fees
    pub available: i64,
}

