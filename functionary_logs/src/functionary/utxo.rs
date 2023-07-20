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

//! # UTXO Tracking logs
//!

use bitcoin;
use serde;
use std::collections::HashSet;
use std::fmt;

use common::PeerId;

fn serialize_hex_opt<S: serde::Serializer>(
    data: &Option<&[u8]>,
    s: S,
) -> Result<S::Ok, S::Error> {
    struct Hexed<'a>(&'a [u8]);
    impl<'a> fmt::Display for Hexed<'a> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            for ch in self.0 {
                write!(f, "{:02x}", *ch)?;
            }
            Ok(())
        }
    }

    match *data {
        Some(data) => s.collect_str(&Hexed(data)),
        None => s.serialize_none(),
    }
}

/// Record a utxo we now control
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RecordUtxo<'a> {
    /// The outpoint of the controlled UTXO
    pub utxo: bitcoin::OutPoint,
    /// The amount it's worth, in satoshi
    pub value: u64,
    /// Height in the main blockchain that it exists at
    pub height: u64,
    /// If this output comes from a pegin, the claim script of the pegin
    #[serde(serialize_with = "serialize_hex_opt", skip_serializing_if = "Option::is_none")]
    pub claim_script: Option<&'a [u8]>,
}

/// Finalized the processing of a pegout on the mainchain; forget
/// about the corresponding request
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ForgetUtxo {
    /// The UTXO being spent
    pub utxo: bitcoin::OutPoint,
    /// The transaction that spends the UTXO
    pub txid: bitcoin::Txid,
}

/// Finalized the reclamation of a UTXO
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct FinalizedReclamation {
    /// The UTXO being reclaimed
    pub outpoint: bitcoin::OutPoint,
    /// The transaction that reclaims the UTXO
    pub txid: bitcoin::Txid,
}

/// Delete a UTXO which can no longer be spent, from our UTXO table.
///
/// This is necessary if someone sends a donation to an old fedpeg_program,
/// or if all UTXOs were not moved to the new federation following a dynafed transition
/// before the old federation went offline.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct DeleteUnspendableUtxo<'a> {
    /// The utxo that we are purging from the utxo table
    pub utxo: bitcoin::OutPoint,
    /// All of the utxo's known signers (None if we don't know its descriptor)
    pub signers: Option<HashSet<PeerId>>,
    /// All the current network peers (online or offline)
    pub peers: &'a HashSet<PeerId>
}

/// Ran into a utxo in the wallet that doesn't have a descriptor attached.
/// This should never happen after the initial sync procedure is finished.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WalletUtxoWithoutDescriptor {
    /// The UTXO's output.
    pub utxo: bitcoin::OutPoint,
    /// The value of the output.
    pub value: u64,
}
