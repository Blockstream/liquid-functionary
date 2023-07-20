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

//! # Pegout Tracking logs
//!

use std::borrow::Cow;

use bitcoin;
use elements;

/// Record a pegout request
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RecordRequest<'a> {
    /// The outpoint of the request on the sidechain
    pub request: elements::OutPoint,
    /// The output which the request is to
    pub output: Cow<'a, bitcoin::TxOut>,
    /// Total number of pegout requests to this output
    pub n_remaining: usize,
}

/// A "pegout request" with the wrong genesis hash but correct asset
/// ID was found on the blockchain. This is not technically a pegout
/// request, so the watchmen won't respect it, but it does burn the
/// user's coins. Normally the watchmen take such burned coins for
/// their fee pool, but because this looks like a mistake, instead
/// we log it and ignore the coins. Requires human intervention but
/// there may be nothing that can be done.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RequestBadGenesis<'a> {
    /// The outpoint of the request on the sidechain
    pub request: elements::OutPoint,
    /// The scriptPubKey which the request is to
    pub dest_script_pubkey: &'a bitcoin::Script,
    /// The amount attempting to be pegged out
    pub value: u64,
    /// Genesis block that the request points at (should be the Bitcoin
    /// genesis hash, but is not)
    pub genesis: bitcoin::BlockHash,
}

/// Finalized the processing of a pegout on the mainchain; forget
/// about the corresponding request
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ForgetRequest<'a> {
    /// The mainchain transaction that processes the pegout
    pub txid: bitcoin::Txid,
    /// The pegout request that is being finalized
    pub request: elements::OutPoint,
    /// The output which processes it
    pub output: Cow<'a, bitcoin::TxOut>,
    /// Remaining number of pegout requests to this output
    pub n_remaining: usize,
}

