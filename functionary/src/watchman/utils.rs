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

//! # Utils
//! Utility helpers for use in the watchman functionary code

use bitcoin::TxOut;
use common::BlockHeight;
use rpc::BitcoinRpc;
use std::collections::HashSet;
use watchman::blockchain::Error;
use watchman::config::Configuration;

/// Find the height of a mainchain block based on blockhash and turn the bitcoind error into a functionary
/// error
pub fn mainchain_block_height(
    blockhash: bitcoin::BlockHash,
    bitcoind: &impl BitcoinRpc,
) -> Result<BlockHeight, Error> {
    match bitcoind.block_height(blockhash) {
        Ok(Some(n)) => Ok(n),
        Ok(None) => Err(Error::BlockNotFound(blockhash)),
        Err(e) => Err(Error::Rpc(e)),
    }
}

/// Validate the list of failed_pegin's in the Watchman configs
pub fn validate_failed_pegin_config_entries(config: &Configuration) -> Result<(), String> {
    // Check that there are no duplicate entries in the failed_pegins list
    if let Some(failed_pegins) = config.consensus.failed_pegins.as_ref() {
        let mut dupe_set = HashSet::new();
        for failed_pegin in failed_pegins.iter() {
            if !dupe_set.insert(failed_pegin) {
                return Err(format!("Duplicate `failed_pegin` entry found"));
            }

            let outpoint =
                bitcoin::OutPoint::new(failed_pegin.mainchain_tx.txid(), failed_pegin.vout);
            let output: &TxOut =
                match failed_pegin.mainchain_tx.output.get(failed_pegin.vout as usize) {
                    Some(o) => o,
                    None => {
                        return Err(format!(
                            "Failed pegin output index in Failed Pegin ({}:{}) does not exist",
                            failed_pegin.mainchain_tx.txid(),
                            failed_pegin.vout
                        ));
                    }
                };
            slog!(LoadedFailedPegin, outpoint, value: output.value);
        }
    }

    Ok(())
}
