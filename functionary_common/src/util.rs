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

/// A trait to convert an object into a Bitcoin Script.
pub trait ToBitcoinScript {
    /// Converts the object into a Bitcoin Script.
    fn to_bitcoin_script(&self) -> bitcoin::Script;
}

impl ToBitcoinScript for elements::Script {
    /// Allocates a new Bitcoin Script from an Elements Script.
    fn to_bitcoin_script(&self) -> bitcoin::Script {
        self.to_bytes().into()
    }
}
/// A trait to convert an object into an Elements Script.
pub trait ToElementsScript {
    /// Converts the object into an Elements Script.
    fn to_elements_script(&self) -> elements::Script;
}

impl ToElementsScript for bitcoin::Script {
    /// Allocates a new Elements Script from a Bitcoin Script.
    fn to_elements_script(&self) -> elements::Script {
        self.to_bytes().into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::{secp256k1::Secp256k1, PrivateKey};

    #[test]
    fn it_transmutes_scripts() {
        let sk =
            PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        let secp = Secp256k1::new();
        let pk = sk.public_key(&secp);

        let b = bitcoin::Script::new_p2pk(&pk);
        let e = elements::Script::new_p2pk(&pk);

        assert_eq!(e, b.clone().to_elements_script());
        assert_eq!(b, e.to_bitcoin_script());
    }
}
