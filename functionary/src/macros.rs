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


//! # Macros
//! Utility macros needed in the rest of the code.

#[cfg(test)]
macro_rules! impl_dummy_rpc {
    ($ty:ty, $altself:ident, $($call:pat $(,$arg:ident)* => $result:expr),*) => {

        impl ::rpc::Rpc for $ty {
            fn jsonrpc_query<T: ::serde::de::DeserializeOwned>(
                &self,
                query: &str,
                _args: &[::jsonrpc::serde_json::Value],
            ) -> Result<T, ::jsonrpc::Error> {
                let $altself = self;
                let json = match query {
                    $(
                    $call => {
                        $(let $arg = ::jsonrpc::serde_json::from_value(_args[0].clone()).expect("parsing argument"); )*
                        ::jsonrpc::serde_json::to_value($result).unwrap()
                    }
                    )*
                    _ => panic!("called mocked RPC `{}` which has no mock implementation", query),
                };

                Ok(::serde::Deserialize::deserialize(json)?)
            }

            fn is_warming_up(&self, _: &str) -> Result<bool, ::jsonrpc::Error> {
                unimplemented!()
            }
        }

        impl ::rpc::BitcoinRpc for $ty {}
    }
}
