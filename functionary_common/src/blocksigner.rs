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


use elements;
use bitcoin::secp256k1::ecdsa::Signature;

/// Whether a peer has a signature or not
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SignState {
    /// Peer did not send a status message
    Missing,
    /// Peer was NAK'd or otherwise errored and was not included in signing
    Errored,
    /// Peer did not send a precommitment
    NoPrecommit,
    /// Peer sent a precommitment but not a signature
    NoSignature,
    /// Peer sent a precommitment, but not a signature, and on the wrong block
    WrongPrecommitment(elements::BlockHash),
    /// Peer sent a signature on the wrong block
    WrongSignature {
        /// The blockhash that the peer signed (not the one we expected)
        hash: elements::BlockHash,
        /// The actual signature
        sig: Signature
    },
    /// Peer sent a valid signature on the correct block
    Success(Signature),
    /// Peer is me, and sent a valid signature on the correct block
    SelfSuccess(Signature),
}
