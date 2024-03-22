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


//! # Accounting related logs
//!

use bitcoin::hashes::sha256d;

/// Status of the watchman accounts
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AccountingStatus {
    /// The total amount of pegged-in coins
    pub pegged_in: u64,
    /// Total amount of non-user funds
    pub non_user_funds: u64,
    /// How many outputs we now control
    pub n_controlled_outputs: usize,
    /// Total amount of BTC we now control.
    pub controlled_total: u64,
    /// New number of requested pegouts
    pub n_requested_pegouts: usize,
    /// Total amount in all requested pegouts
    pub requested_total: u64,
    /// Discrepancy (non-user funds + pegged-in funds - controlled funds)
    pub discrepancy: i64,
}

/// Attempt to claim/record pegin twice (fatal)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DoublePegin {
    /// The outpoint that was claimed twice
    pub outpoint: bitcoin::OutPoint,
}

/// Use of donated funds to correct discrepancy between controlled
/// funds and pegged-in coins
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DiscrepancyCorrection {
    /// Mainchain outpoint where funds were donated,
    pub outpoint: bitcoin::OutPoint,
    /// Amount of the correction
    pub correction: u64,
    /// New discrepancy
    pub discrepancy: i64,
}

/// A transaction caused the discrepancy between federation-controlled funds
/// and pegged-in funds to change. This should never happen and likely
/// indicates a serious bug in the federation software or the consensus
/// layer. Requires immediate human intervention. Once fixed, a discrepancy
/// can be corrected by sending funds to the watchman untweaked/change
/// address.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DiscrepancyChanged {
    /// The transaction responsible for the discrepancy change. Might be on
    /// either blockchain. We are using the underlying hash here so this can
    /// be used by both Bitcoin and Elements Txids.
    pub txid: sha256d::Hash,
    /// Original discrepancy value
    pub old_discrepancy: i64,
    /// New discrepancy
    pub discrepancy: i64,
    /// The Bitcoin Txid if applicable
    pub bitcoin_txid: Option<bitcoin::Txid>,
    /// The Elements Txid if applicable
    pub elements_txid: Option<elements::Txid>,
}

/// Transaction spent a UTXO we don't recognize (fatal)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct SpendUnknownUtxo {
    /// TXID of the offending transaction
    pub txid: bitcoin::Txid,
    /// Outpoint we don't recognize that was spent
    pub outpoint: bitcoin::OutPoint,
}

/// Transaction created a UTXO we don't recognize (fatal)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct FinalizeUnknownOutput {
    /// Outpoint that was created that we didn't recognize
    pub outpoint: bitcoin::OutPoint,
}

/// Burned coins in excess of total pegged in coins (fatal)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ExcessBurn {
    /// Pegout request
    pub outpoint: elements::OutPoint,
    /// Amount attempted to peg out
    pub amount: u64,
    /// Amount actually on the sidechain
    pub available: u64,
}

/// Requested pegout in excess of total pegged in coins (fatal)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ExcessPegout {
    /// Pegout request
    pub outpoint: elements::OutPoint,
    /// Amount attempted to peg out
    pub amount: u64,
    /// Amount actually on the sidechain
    pub available: u64,
}

/// Attempt to claim/record pegin (debug)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Pegin {
    /// The claimed mainchain outpint
    pub outpoint: bitcoin::OutPoint,
    /// The TXID on the sidechain which makes the claim
    pub txid: elements::Txid,
    /// Amount of the pegin
    pub amount: u64,
    /// The new total amount of pegged-in coins
    pub pegged_in: u64,
    /// How many outputs we now control
    pub n_controlled_outputs: usize,
}

/// Request a pegout (debug)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Pegout<'a> {
    /// Sidechain outpoint requesting the pegout
    pub outpoint: elements::OutPoint,
    /// Mainchain output destination
    pub destination: &'a bitcoin::TxOut,
    /// New total pegged-in amount
    pub pegged_in: u64,
    /// New number of requested pegouts
    pub n_requested_pegouts: usize,
    /// Total amount in all requested pegouts
    pub requested_total: u64,
}

/// Burn coins on the sidechain (debug)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Burn {
    /// outpoint that was burned
    pub outpoint: elements::OutPoint,
    /// amount
    pub amount: u64,
    /// New total pegged-in amount
    pub pegged_in: u64,
    /// New non-user funds amount
    pub non_user_funds: u64,
}

/// Send coins directly to the federation on the mainchain (Debug)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Donation {
    /// outpoint of the donation
    pub outpoint: bitcoin::OutPoint,
    /// amount
    pub amount: u64,
    /// New non-user funds amount
    pub non_user_funds: u64,
    /// How many outputs we now control
    pub n_controlled_outputs: usize,
}

/// Finalize the spending of a UTXO
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct FinalizeSpend {
    /// Outpoint being spent
    pub outpoint: bitcoin::OutPoint,
    /// TXID of the spending transaction
    pub txid: bitcoin::Txid,
    /// Amount of the spent output
    pub amount: u64,
    /// How many outputs we now control
    pub n_controlled_outputs: usize,
}

/// Finalize the creation of a pegout
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct FinalizePegout<'a> {
    /// Mainchain outpoint of the pegout
    pub outpoint: bitcoin::OutPoint,
    /// Mainchain output destination
    pub destination: &'a bitcoin::TxOut,
    /// New number of requested pegouts
    pub n_requested_pegouts: usize,
    /// Total amount in all requested pegouts
    pub requested_total: u64,
}

/// Send coins directly to the federation on the mainchain (Debug)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Change {
    /// outpoint of the donation
    pub outpoint: bitcoin::OutPoint,
    /// amount
    pub amount: u64,
    /// How many outputs we now control
    pub n_controlled_outputs: usize,
}


/// Update for the fees in a finalized transaction
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct FinalizeFee {
    /// Mainchain txid
    pub txid: bitcoin::Txid,
    /// Fee amount of the transaction
    pub fee: u64,
    /// New non-user funds amount
    pub non_user_funds: u64,
}

