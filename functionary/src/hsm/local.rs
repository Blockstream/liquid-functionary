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


//! # Local Security Module
//!
//! Implementation of a SecurityModule which takes a key from a configuration file
//!

use std::{fs, time};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::os::unix::net::UnixStream;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use elements::encode::serialize_hex;

use blocksigner;
use common::PakList;
use common::hsm::{self, Address, Command, Error, WatchmanSignStatus};
use common::constants::EPOCH_LENGTH_TESTING;
use hsm::{SecurityModule, WatchmanState};
use config::InitHSM;
use descriptor::LiquidDescriptor;
use utils;
use watchman::transaction::TransactionSignatures;
use watchman::utxotable::SpendableUtxo;

/// A simulated HSM for blocksigner that calls out to a jsonrpc client instead of signing
pub struct LocalBlocksigner {
    /// libsecp context
    secp: Secp256k1<secp256k1::SignOnly>,
    /// Handle to sidechaind
    secret_key: SecretKey,
    /// Record of the last blockheight we signed. (In general all HSM stuff needs to
    /// be in a RefCell, since the Hsm object lives in either the `Blocksigner` or
    /// `Watchman` objects, which are already immutably borrowed most of the time.)
    last_block_height: RefCell<u32>
}

impl LocalBlocksigner {
    /// Constructs a new "software security module"
    pub fn new(secret_key: SecretKey) -> LocalBlocksigner {
        LocalBlocksigner {
            secp: Secp256k1::signing_only(),
            secret_key: secret_key,
            last_block_height: RefCell::new(0)
        }
    }
}

/// Internal state of the watchman HSM stub.
#[derive(Debug, Serialize, Deserialize)]
struct LocalWatchmanState {
    n_whitelisted_addresses: usize,
    #[serde(default, with = "blocksigner::config::serde_paklist_config")]
    last_pak_list: PakList,
    /// The last header sent to the HSM.
    last_header: Option<elements::BlockHeader>,
}

/// A simulated HSM for watchman that calls out to a jsonrpc client instead of signing
pub struct LocalWatchman {
    /// libsecp context
    secp: Secp256k1<secp256k1::SignOnly>,
    /// Handle to sidechaind
    secret_key: SecretKey,
    state_file_path: PathBuf,
    state: RefCell<LocalWatchmanState>,
}

impl LocalWatchman {
    fn try_load_state(path: &Path) -> Option<LocalWatchmanState> {
        let state: Option<LocalWatchmanState> = if path.exists() {
            let file = fs::File::open(path).expect("failed to open local hsm state file");
            Some(serde_json::from_reader(file).expect("corrupt local HSM state file"))
        } else {
            None
        };

        if state.is_none() {
            log!(Debug, "try_load_state: {}: none found", path.display());
        } else {
            log!(Debug, "try_load_state: {}: white-listed addrs: {}, pak list size: {}", path.display(), state.as_ref().unwrap().n_whitelisted_addresses, state.as_ref().unwrap().last_pak_list.len(),);
        }

        state
    }

    fn save_state(&self) {
        let state = self.state.borrow();
        utils::export_to_file(
            &self.state_file_path.as_path().to_str().unwrap(),
            |fh| Ok(serde_json::to_writer(fh, &*state).unwrap()),
        );
        log!(Debug, "save_state: {}: white-listed addrs: {}, pak list size: {}", self.state_file_path.display(), state.n_whitelisted_addresses, state.last_pak_list.len(),);
    }

    /// Constructs a new "software security module"
    pub fn new(datadir: impl AsRef<Path>, secret_key: SecretKey) -> LocalWatchman {
        let state_file_path = {
            let mut path = datadir.as_ref().to_path_buf();
            path.push("local_watchman_hsm_state.json");
            path
        };
        let state = LocalWatchman::try_load_state(&state_file_path).unwrap_or_else(|| {
            LocalWatchmanState {
                n_whitelisted_addresses: 0,
                last_pak_list: PakList::default(),
                last_header: None,
            }
        });
        LocalWatchman {
            secp: Secp256k1::signing_only(),
            secret_key: secret_key,
            state_file_path: state_file_path,
            state: RefCell::new(state),
        }
    }

    /// Computes transaction signatures for segwit transactions
    fn real_sign_segwit_transaction(
        &self,
        tx: &bitcoin::Transaction,
        inputs: &[SpendableUtxo]
    ) -> Result<TransactionSignatures, Error> {
        assert_eq!(tx.input.len(), inputs.len());

        let mut ret = Vec::with_capacity(tx.input.len());

        let mut cache = SighashCache::new(tx);

        let txid = tx.txid();
        for (i, (main_out, _txin)) in inputs.iter().zip(tx.input.iter()).enumerate() {
            let sighash = cache.p2wsh_signature_hash(
                i,
                &main_out.descriptor.liquid_witness_script(),
                main_out.value,
                bitcoin::EcdsaSighashType::All,
            ).unwrap();
            log!(Debug, "SIGHASH for {} input #{}: {}", txid, i, sighash);

            let key = main_out.tweak.tweak_secret(&self.secret_key);
            let msg = secp256k1::Message::from_digest_slice(&sighash[..]).unwrap();
            let sig = self.secp.sign_ecdsa(&msg, &key);

            ret.push((sig, bitcoin::EcdsaSighashType::All));
        }

        Ok(TransactionSignatures::from(ret))
    }
}

impl SecurityModule for LocalBlocksigner {
    fn validate_block(&self, header: &elements::BlockHeader) -> Result<(), Error> {
        log!(Debug, "validate_block called: sidechain height: {}", header.height);
        let return_value = if header.height < *self.last_block_height.borrow() {
            log!(Error, "security module: block height is {} but our minimum height is {}",
                 header.height, *self.last_block_height.borrow());
            Err(Error::ReceivedNack(hsm::Command::NackBadData))
        } else {
            Ok(())
        };
        log!(Debug, "validate_block returns: {:?}", return_value);
        return_value
    }

    fn sign_block(&self, header: &elements::BlockHeader) -> Result<secp256k1::ecdsa::Signature, Error> {
        log!(Debug, "sign_block called: sidechain height: {}", header.height);
        if header.height < *self.last_block_height.borrow() {
            let return_value = Err(Error::ReceivedNack(hsm::Command::NackBadData));
            log!(Debug, "sign_block returns: {:?}", return_value);
            return return_value
        }
        // Extract the blockheader
        let header_hex = serialize_hex(header);
        log!(Debug, "signing {}", header_hex);
        let msghash = header.block_hash();
        let msghash = secp256k1::Message::from_digest_slice(&msghash[..]).unwrap();
        // Sign and build a script (unwrap() OK as our context is definitely capable)
        let sig = self.secp.sign_ecdsa(&msghash, &self.secret_key);

        // We cannot fail :)
        log!(Trace, "block height set to {}", header.height);
        *self.last_block_height.borrow_mut() = header.height;
        log!(Debug, "sign_block returns");
        Ok(sig)
    }

    // Stub in watchman functions
    fn public_key(&self) -> Result<PublicKey, Error> { unimplemented!() }
    fn set_witness_script(&self, _: &bitcoin::ScriptBuf) -> Result<(), Error> { unimplemented!() }
    fn authorized_addresses_clear(&self) -> Result<(), Error> { unimplemented!() }
    fn authorized_addresses_add(&self, _: &[u8], _: &[u8]) -> Result<(), Error> { unimplemented!() }
    fn authorization_master_keys_replace(&self, _: &PakList) -> Result<(), Error> { unimplemented!() }
    fn sign_segwit_transaction(&self,
                               _: &bitcoin::Transaction,
                               _: &[SpendableUtxo])
                               -> Result<TransactionSignatures, Error> {
        unimplemented!()
    }
    fn send_header(&self, _: &elements::BlockHeader) -> Result<(), Error> { unimplemented!() }
    fn get_watchman_state(&self) -> Result<WatchmanState, Error> { unimplemented!() }

    fn initialize_hsm(&self, _: InitHSM, _: u64) -> Result<Vec<u8>, Error> { unimplemented!() }
    fn initialize_hsm_from(&self, _: InitHSM, _: u64, _: Address) -> Result<Vec<u8>, Error> { unimplemented!() }
    fn update_tool_send(&self, _: &[u8]) -> Result<UnixStream, Error> { unimplemented!() }
    fn update_tool_recv(&self, _sock: &mut UnixStream) -> Result<(Command, Vec<u8>), Error> { unimplemented!() }
    fn get_signing_key(&self, _return_address: Address) -> Result<Vec<u8>, Error> { unimplemented!() }
    fn get_rtc(&self, _return_address: Address) -> Result<u64, Error> { unimplemented!() }
}

impl SecurityModule for LocalWatchman {
    fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_secret_key(&self.secp, &self.secret_key))
    }

    fn set_witness_script(&self, script: &bitcoin::ScriptBuf) -> Result<(), Error> {
        log!(Debug, "set_witness_script called: script len: {}", script.len());
        Err(Error::ReceivedNack(Command::NackNotAllowed))
    }

    fn authorized_addresses_clear(&self) -> Result<(), Error> {
        log!(Debug, "authorized_addresses_clear called");
        self.state.borrow_mut().n_whitelisted_addresses = 0;
        self.save_state();
        Ok(())
    }

    fn authorized_addresses_add(&self, _pk: &[u8], proof: &[u8]) -> Result<(), Error> {
        log!(Debug, "authorized_addresses_add called");
        if self.state.borrow().n_whitelisted_addresses >= 500 {
            return Err(Error::AuthorizedKeyCacheFull);
        }

        // Don't do PAK check if no PAK list has ever been sent.
        let n_keys = self.state.borrow().last_pak_list.len();
        if n_keys > 0 {
            // We do very minimal proof sanity check only based on the length.
            // if rust-secp256k1-zkp merges whitelist support, we could check the proof
            // Proof size is 33 + 32 * n_keys bytes.
            let proof_size = 33 + 32 * n_keys;
            if proof.len() != proof_size {
                log!(Debug,
                    "authorized_addresses_add failed: PAK keys: {} (proof.len {} vs. proof_size {})",
                    n_keys, proof.len(), proof_size,
                );
                return Err(Error::ReceivedNack(hsm::Command::NackBadData));
            }
        }

        self.state.borrow_mut().n_whitelisted_addresses += 1;
        self.save_state();
        Ok(())
    }

    fn authorization_master_keys_replace(&self, pak: &PakList) -> Result<(), Error> {
        log!(Debug,
            "authorization_master_keys_replace called: key list: {} keys", pak.len(),
        );
        Err(Error::ReceivedNack(Command::NackNotAllowed))
    }

    fn sign_segwit_transaction(&self,
                               tx: &bitcoin::Transaction,
                               inputs: &[SpendableUtxo])
                               -> Result<TransactionSignatures, Error> {
        log!(Debug, "sign_segwit_transaction called: length: {}", tx.input.len());
        self.real_sign_segwit_transaction(tx, inputs)
    }

    // stub in blocksigner functions
    fn validate_block(&self, _: &elements::BlockHeader) -> Result<(), Error> { unimplemented!() }
    fn sign_block(&self, _: &elements::BlockHeader) -> Result<secp256k1::ecdsa::Signature, Error> { unimplemented!() }

    fn send_header(&self, header: &elements::BlockHeader) -> Result<(), Error> {
        log!(Debug, "send_header called: height: {}", header.height);
        let mut state = self.state.borrow_mut();
        let last = &mut state.last_header;
        if let Some(ref mut last) = last {
            if header.height == last.height && header.prev_blockhash == last.prev_blockhash {
                // Overwriting tip
                log!(Warn, "chain made a one-block fork at height {}", header.height);
                *last = header.clone();
                Ok(())
            } else if header.height == last.height + 1 && header.prev_blockhash == last.block_hash() {
                // Adding on top of last
                *last = header.clone();
                Ok(())
            } else {
                Err(Error::ReceivedNack(Command::NackInvalid))
            }
        } else {
            *last = Some(header.clone());
            Ok(())
        }
    }

    fn get_watchman_state(&self) -> Result<WatchmanState, Error> {
        if let Some(last) = &self.state.borrow().last_header {
            let epoch_length = EPOCH_LENGTH_TESTING;
            let epoch_age = last.height % epoch_length;
            let need_nb_blocks = epoch_length;
            log!(Trace, "get_watchman_state: last={}; epoch_length={}; epoch_age={}; need_nb_blocks={}",
                last.height, epoch_length, epoch_age, need_nb_blocks,
            );

            // We do the naive thing here of just acting like we saw
            // block 0 and all blocks after.
            let status = if last.height >= need_nb_blocks {
                WatchmanSignStatus::CanSign
            } else {
                log!(Trace, "get_watchman_state: need more blocks, \
                    current height is {}, need to be at least {}",
                    last.height, need_nb_blocks,
                );
                WatchmanSignStatus::NeedMoreHistory
            };
            Ok(WatchmanState {
                sign_status: status,
                last_header: Some(last.block_hash()),
            })
        } else {
            Ok(WatchmanState {
                sign_status: WatchmanSignStatus::NeedMoreHistory,
                last_header: None,
            })
        }
    }

    fn initialize_hsm(&self, _: InitHSM, _: u64) -> Result<Vec<u8>, Error> { unimplemented!() }
    fn initialize_hsm_from(&self, _: InitHSM, _: u64, _: Address) -> Result<Vec<u8>, Error> { unimplemented!() }
    fn update_tool_send(&self, _: &[u8]) -> Result<UnixStream, Error> { unimplemented!() }
    fn update_tool_recv(&self, _sock: &mut UnixStream) -> Result<(Command, Vec<u8>), Error> { unimplemented!() }

    fn get_signing_key(&self, _return_address: Address) -> Result<Vec<u8>, Error> {
        unimplemented!()
    }

    fn get_rtc(&self, _return_address: Address) -> Result<u64, Error> {
        let now = time::SystemTime::now().duration_since(time::UNIX_EPOCH).expect("system time");
        let timestamp_millis: u64 = now.as_secs() * 1000 + (now.subsec_nanos() as u64) / 1000000;
        Ok(timestamp_millis)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use tweak::Tweak;

    use bitcoin::consensus::encode::deserialize;
    use bitcoin::secp256k1::ecdsa::Signature;

    #[test]
    fn p2sh_p2wsh_sign() {
        // test vector from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#P2SHP2WSH
        let secp = Secp256k1::signing_only();
        let state_file_path = tempfile::NamedTempFile::new().unwrap().into_temp_path().to_path_buf();
        let state = LocalWatchman::try_load_state(&state_file_path).unwrap_or_else(|| {
            LocalWatchmanState {
                n_whitelisted_addresses: 0,
                last_pak_list: PakList::default(),
                last_header: Default::default(),
            }
        });
        let mut hsm = LocalWatchman {
            secp: secp,
            secret_key: SecretKey::from_slice(
                &hex!("730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6"),
            ).unwrap(),
            state_file_path: state_file_path,
            state: RefCell::new(state),
        };

        let tx_in = deserialize::<bitcoin::Transaction>(
            &hex!("
                010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ff
                ffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f0500
                0000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000
            ")[..],
        ).unwrap();
        let inputs = vec![
            SpendableUtxo::new(Default::default(), bitcoin::Amount::from_sat(987654321), 0, Tweak::none(), "\
                sh(wsh(multi(\
                    6,\
                    [untweaked]0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3,\
                    [untweaked]03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b,\
                    [untweaked]034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a,\
                    [untweaked]033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4,\
                    [untweaked]03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16,\
                    [untweaked]02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b\
                )))\
            ".parse().unwrap()),
        ];

        let sigs = hsm.real_sign_segwit_transaction(&tx_in, &inputs).unwrap();
        assert_eq!(
            sigs,
            TransactionSignatures::from(vec![(
                Signature::from_str(
                    "304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2\
                     b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce"
                ).unwrap(),
                bitcoin::EcdsaSighashType::All,
            )])
        );

        // P2SH-P2WPKH test vector
        let tx_in = deserialize::<bitcoin::Transaction>(
            &hex!("
                0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000fe
                ffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f00
                0000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000
            "),
        ).unwrap();
        let inputs = vec![
            SpendableUtxo::new(Default::default(), bitcoin::Amount::from_sat(10_0000_0000), 0, Tweak::none(), "\
                sh(wpkh([untweaked]03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873))\
            ".parse().unwrap())
        ];
        hsm.secret_key = SecretKey::from_slice(
            &hex!("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf"),
        ).unwrap();

        let sigs = hsm.real_sign_segwit_transaction(&tx_in, &inputs).unwrap();
        assert_eq!(
            sigs,
            TransactionSignatures::from(vec![(
                Signature::from_str(
                    "3045022100af4577dc8fd9c3ae5c80b3099e70cc7d3985b641f71734fa3c8c3b764f3b9f\
                     51022009382a29d7c018528b891c332c4b963b34163175236e33394cfe48732cacbffc"
                ).unwrap(),
                bitcoin::EcdsaSighashType::All,
            )])
        );
    }
}
