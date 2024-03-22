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


//! # Accounting
//!
//! Measures various quantities (e.g. total money pegged into the system,
//! total money controlled by the watchmen) and cross-checks them to ensure
//! everything is consistent.
//!

use std::collections::HashMap;
use std::cmp;

use bitcoin::{Amount, SignedAmount};
use utils;

/// Structure containing all accounting information
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Account {
    /// Total amount of coins in the sidechain (pegins minus pegouts, as
    /// determined by the sidechain).
    pegged_in: Amount,
    /// Total amount of watchman-controlled coins which do not correspond
    /// to pegged-in user funds
    non_user_funds: Amount,
    /// Map of every UTXO under control
    #[serde(with = "utils::serialize::hashmap")]
    controlled_funds: HashMap<bitcoin::OutPoint, Amount>,
    /// Map of pegouts which have been requested on the sidechain but not
    /// yet finalized on the mainchain. Maps from mainchain outputs to the
    /// number of pegouts requested to that output.
    #[serde(with = "utils::serialize::hashmap")]
    requested_pegout: HashMap<bitcoin::TxOut, usize>,
}

impl Account {
    /// Create a new empty accounting record
    pub fn new() -> Account {
        Account {
            pegged_in: Amount::ZERO,
            non_user_funds: Amount::ZERO,
            controlled_funds: HashMap::new(),
            requested_pegout: HashMap::new(),
        }
    }

    /// Accessor for the total number of controlled utxos
    pub fn n_controlled_outputs(&self) -> usize {
        self.controlled_funds.len()
    }

    /// Accessor for the total number of requested pegouts
    pub fn n_requested_pegouts(&self) -> usize {
        self.requested_pegout
            .values()
            .cloned()
            .sum::<usize>()
    }

    /// Accessor for the total amount of all requested pegouts
    pub fn requested_pegout_total(&self) -> Amount {
        self.requested_pegout
            .iter()
            .map(|(output, qty)| output.value * *qty as u64)
            .sum::<Amount>()
    }

    /// Accessor for the total amount of pegged-in (user) funds
    pub fn pegged_in(&self) -> Amount {
        self.pegged_in
    }

    /// Accessor for the total amount of non-user funds
    pub fn non_user_funds(&self) -> Amount {
        self.non_user_funds
    }

    /// Record a pegin of a specified amount
    pub fn pegin(&mut self, outpoint: bitcoin::OutPoint, side_txid: elements::Txid, amount: Amount) {
        if let Some(old_amount) = self.controlled_funds.insert(outpoint, amount) {
            assert_eq!(old_amount, amount);
            slog_fatal!(DoublePegin, outpoint: outpoint);
        }
        self.pegged_in += amount;
        slog!(Pegin, outpoint: outpoint, txid: side_txid, amount: amount.to_sat(),
            pegged_in: self.pegged_in.to_sat(), n_controlled_outputs: self.controlled_funds.len()
        );
    }

    /// Record a pegout (the request on the sidechain, not a mainchain transaction)
    pub fn pegout(&mut self, outpoint: elements::OutPoint, output: bitcoin::TxOut) {
        if self.pegged_in < output.value {
            slog_fatal!(ExcessPegout, outpoint: outpoint, amount: output.value.to_sat(),
                available: self.pegged_in.to_sat(),
            );
        }
        self.pegged_in -= output.value;
        slog!(Pegout, outpoint: outpoint, destination: &output, pegged_in: self.pegged_in.to_sat(),
            n_requested_pegouts: 1 + self.n_requested_pegouts(),
            requested_total: (output.value + self.requested_pegout_total()).to_sat()
        );
        *self.requested_pegout.entry(output).or_insert(0) += 1;
    }

    /// Record a "fee donation" in which somebody creates a transaction
    /// on the mainchain directly transferring coins to watchman control.
    /// If there is a discrepancy, such donations are first used to correct
    /// the discrepancy before being applied to the fee pool. Returns the
    /// final amount added to the fee pool.
    pub fn fee_donation(&mut self, outpoint: bitcoin::OutPoint, amount: Amount) -> Amount {
        if let Some(old_amount) = self.controlled_funds.insert(outpoint, amount) {
            assert_eq!(old_amount, amount);
            panic!("Tried to record donation {} ({}) twice", outpoint, amount);
        }

        let discrepancy = self.discrepancy();
        let correction;
        if discrepancy.is_negative() {
            correction = cmp::min(amount, discrepancy.abs().to_unsigned().expect("absolute can't be negative"));
        } else {
            correction = Amount::ZERO;
        }

        self.non_user_funds += amount - correction;

        slog!(Donation, outpoint: outpoint, amount: amount.to_sat(), non_user_funds: self.non_user_funds.to_sat(),
                n_controlled_outputs: self.controlled_funds.len()
        );
        if correction != Amount::ZERO {
            slog!(DiscrepancyCorrection, outpoint: outpoint, correction: correction.to_sat(),
                discrepancy: (discrepancy + correction.to_signed().expect("signed amount")).to_sat()
            );
        }

        amount - correction
    }

    /// Record a "fee burn" where a user simply burns coins on the sidechain,
    /// de-facto transferring them to watchman control
    pub fn fee_burn(&mut self, outpoint: elements::OutPoint, amount: Amount) {
        if self.pegged_in < amount {
            slog_fatal!(ExcessBurn, outpoint: outpoint, amount: amount.to_sat(), available: self.pegged_in.to_sat());
        }

        self.non_user_funds += amount;
        self.pegged_in -= amount;
        slog!(Burn, outpoint: outpoint, amount: amount.to_sat(), pegged_in: self.pegged_in.to_sat(),
            non_user_funds: self.non_user_funds.to_sat()
        );
    }

    /// Finalize a pegout transaction on the main chain
    pub fn finalize_federation_tx(
        &mut self,
        tx: &bitcoin::Transaction,
        change_spk: Option<&bitcoin::ScriptBuf>,
    ) {
        let txid = tx.txid();
        let mut input_amount = Amount::ZERO;
        let mut output_amount = Amount::ZERO;

        // Record spend of all inputs
        for input in &tx.input {
            if let Some(amount) = self.controlled_funds.remove(&input.previous_output) {
                input_amount += amount;
                slog!(FinalizeSpend, outpoint: input.previous_output, txid: txid, amount: amount.to_sat(),
                    n_controlled_outputs: self.controlled_funds.len()
                );
            } else {
                slog_fatal!(SpendUnknownUtxo, txid: txid, outpoint: input.previous_output);
            }
        }
        // Record all outputs as peg-outs or change
        for (n, output) in tx.output.iter().enumerate() {
            output_amount += output.value;
            let outpoint = bitcoin::OutPoint {
                txid,
                vout: n as u32,
            };

            if Some(&output.script_pubkey) == change_spk {
                self.controlled_funds.insert(outpoint, output.value);
                slog!(Change, outpoint: outpoint, amount: output.value.to_sat(),
                    n_controlled_outputs: self.controlled_funds.len()
                );
            } else if let Some((old_output, mut qty)) = self.requested_pegout.remove_entry(output) {
                qty -= 1;
                if qty > 0 {
                    self.requested_pegout.insert(old_output, qty);
                }
                slog!(FinalizePegout, outpoint: outpoint, destination: output,
                    n_requested_pegouts: self.n_requested_pegouts(),
                    requested_total: self.requested_pegout_total().to_sat()
                );
            } else {
                slog_fatal!(FinalizeUnknownOutput, outpoint: outpoint);
            }
        }
        // Record difference as fee
        assert!(input_amount >= output_amount);
        let fee = input_amount - output_amount;
        self.non_user_funds -= fee;
        slog!(FinalizeFee, txid: txid, fee: fee.to_sat(), non_user_funds: self.non_user_funds.to_sat());
    }

    /// Report the discrepancy between pegged-in funds and controlled funds
    /// This value should always be zero. A negative value indicates that we
    /// are missing money (more pegged in than we control) and a positive
    /// value indicates that we control money we haven't accounted for.
    pub fn discrepancy(&self) -> SignedAmount {
        let controlled = self.controlled_funds.values().cloned().sum::<Amount>();
        let pegged_in = self.non_user_funds + self.pegged_in + self
            .requested_pegout
            .iter()
            .map(|(output, qty)| output.value * *qty as u64)
            .sum::<Amount>();

        controlled
            .to_signed()
            .expect("signed amount")
            .checked_sub(pegged_in.to_signed().expect("signed amount"))
            .expect("signed overflow")
    }

    /// Log all accounting data
    pub fn log_status(&self) {
        slog!(AccountingStatus,
            pegged_in: self.pegged_in.to_sat(),
            non_user_funds: self.non_user_funds.to_sat(),
            n_controlled_outputs: self.controlled_funds.len(),
            controlled_total: self.controlled_funds.values().copied().sum::<Amount>().to_sat(),
            n_requested_pegouts: self.n_requested_pegouts(),
            requested_total: self.requested_pegout_total().to_sat(),
            discrepancy: self.discrepancy().to_sat()
        );
    }
}

