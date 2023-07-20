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

//! # RPC logs
//!

use jsonrpc;

/// an RPC request
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RpcRequest<'a> {
    /// The daemon we're connecting to
    pub daemon: &'a str,
    /// the method
    pub method: &'a str,
    /// the arguments
    pub arguments: &'a [String],
}

/// an RPC response
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RpcResponse<'a> {
    /// The daemon we're connecting to
    pub daemon: &'a str,
    /// the method
    pub method: &'a str,
    /// the result synopsis
    pub result: &'a str,
    /// RPC duration in nanonseconds
    pub duration_ns: u128,
}

/// Verbose result portion of an RPC response
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RpcResultTrace<'a> {
    /// The daemon we're connecting to
    pub daemon: &'a str,
    /// the result
    pub result: &'a str,
}

/// A daemon returned an RPC response that we didn't expect.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct UnexpectedRpcResponse<'a> {
    /// The daemon we're connecting to
    pub daemon: &'a str,
    /// The JSON-RPC command.
    pub command: &'a str,
    /// The response in question.
    pub response: &'a str,
}

/// Daemon is warming up and cannot respond to RPC
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WarmingUp<'a> {
    /// The daemon we're connecting to
    pub daemon: &'a str,
}

/// Daemon is done warming up and can respond to RPC
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WarmedUp<'a> {
    /// The daemon we're connecting to
    pub daemon: &'a str,
}

/// RPC communication failure
#[derive(Clone, Serialize)]
pub struct Error<'a, 'b> { /// The daemon we were connecting to
    pub daemon: &'a str,
    /// What we were trying to do when we encountered the error
    pub action: String,
    /// The error we received
    #[serde(serialize_with = "::serialize_display")]
    pub error: &'b jsonrpc::Error,
}

