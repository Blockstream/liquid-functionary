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


//! # Messages
//! Datastructures, de/serialization code for Liquid HSM messages and
//! related data structures
//!


/// HSM Update module
pub mod hsm_update {
    use common::hsm::{Address, Command, Header, Message};
    use common::hsm::MESSAGE_VERSION;

    /// hsm update message structure
    pub struct HSMUpdateMessage {
        msg_header: Header,
        body: Vec<u8>
    }

    impl HSMUpdateMessage {
        /// Create and initialize an hsm update message
        pub fn new(data: &[u8]) -> HSMUpdateMessage {
            let header: Header =
                Header::for_data(
                    MESSAGE_VERSION,
                    Address::Update,
                    Address::Update,
                    Command::HSMUpdate,
                    data
                );

            HSMUpdateMessage {
                msg_header: header,
                body: data.to_vec()
            }
        }
    }


    impl Message for HSMUpdateMessage {
        fn header(&self) -> &Header { &self.msg_header }
        fn payload(&self) -> &[u8] { &self.body }
    }

}


/// Blocksigner messages
pub mod blocksigner {
    use elements::encode::serialize;
    use elements;
    use common::hsm::{Address, Command, Header, Message};
    use common::hsm::MESSAGE_VERSION;

    /// Representation of a `SignBlock` HSM message
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct SignBlock {
        msg_header: Header,
        blk_header: Vec<u8>
    }

    impl SignBlock {
        /// Constructs a SignBlock message from a block header.
        pub fn new(header: &elements::BlockHeader) -> SignBlock {
            match header.ext {
                elements::BlockExtData::Proof { ref solution, .. } => {
                    debug_assert_eq!(solution.len(), 0);
                },
                elements::BlockExtData::Dynafed { ref signblock_witness, .. } => {
                    debug_assert_eq!(signblock_witness.len(), 0);
                },
            }
            let mut ser = serialize(header);
            ser.pop(); // pop off the 0 byte to be compatible with HSM v1.2.x
            SignBlock {
                msg_header: Header::for_data(
                    MESSAGE_VERSION,
                    Address::BlockSigner,
                    Address::BlockSigner,
                    Command::BlocksignerSignBlock,
                    &ser[..]),
                blk_header: ser,
            }
        }
    }

    impl Message for SignBlock {
        fn header(&self) -> &Header { &self.msg_header }
        fn payload(&self) -> &[u8] { &self.blk_header }
    }


    /// Representation of a `ValidateBlock` HSM message
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct ValidateBlock {
        msg_header: Header,
        blk_header: Vec<u8>
    }

    impl ValidateBlock {
        /// Constructs a SignBlock message from a block header.
        pub fn new(header: &elements::BlockHeader) -> ValidateBlock {
            let ser = serialize(header);
            ValidateBlock {
                msg_header: Header::for_data(MESSAGE_VERSION,
                                             Address::BlockSigner,
                                             Address::BlockSigner,
                                             Command::BlocksignerValidateBlock,
                                             &ser[..]),
                blk_header: ser,
            }
        }
    }

    impl Message for ValidateBlock {
        fn header(&self) -> &Header { &self.msg_header }
        fn payload(&self) -> &[u8] { &self.blk_header }
    }
}

/// HSM initialization message
pub mod init {
    use config::InitHSM;
    use common::hsm::{Address, Command, Header, Message};
    use common::hsm::MESSAGE_VERSION;

    /// Representation of a `HSMInit` HSM message
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct HSMInit {
        msg_header: Header,
        payload: Vec<u8>
    }

    impl HSMInit {
        /// Constructs a `HSMInit` message from a user privkey and a timestamp
        pub fn new(config: InitHSM, timestamp_millis: u64) -> HSMInit {
            let mut payload = Vec::with_capacity(1 + 32 + 8);
            let timestamp_bytes: [u8; 8] = unsafe { ::std::mem::transmute(timestamp_millis.to_le()) };

            let mut flags: u8 = 0;
            if config.force_reinit_flag {
                flags |= 0x01;
            }
            if config.blocksign_restore_key.is_some() {
                flags |= 0x02;
                if config.plaintext_key_flag {
                    flags |= 0x08;
                }
            }
            if !config.encrypted_restore_blob.is_empty() {
                flags |= 0x02 | 0x04; // Both restore and secure flags set
            }
            log!(Debug, "HSMInit: flags: 0x{:02X}", flags);
            payload.push(flags);

            if config.blocksign_restore_key.is_some() {
                // Restore mode passes in the two random keys prev generated
                payload.extend(&config.blocksign_restore_key.unwrap()[..]);
                payload.extend(&config.watchman_restore_key.unwrap()[..]);
            }

            // "Secure" restore mode passes in the ECIES-encrypted blob
            // With necessary meta-data for decryption by the HSM
            payload.extend(&config.encrypted_restore_blob[..]);

            // Normal init mode only needs user key
            payload.extend(&config.user_key.unwrap()[..]);

            payload.extend(&timestamp_bytes);

            HSMInit {
                msg_header: Header::for_data(
                    MESSAGE_VERSION,
                    Address::ParallelPort,
                    Address::BlockSigner,
                    Command::HSMInit,
                    &payload[..]),
                payload: payload
            }
        }
    }

    impl Message for HSMInit {
        fn header(&self) -> &Header { &self.msg_header }
        fn payload(&self) -> &[u8] { &self.payload }
    }
}

/// Module for general hsm query messages
pub mod hsm_query {
    use common::hsm::{Address, Command, Header, Message};
    use common::hsm::MESSAGE_VERSION;

    /// Representation of a `HSMInit` HSM message
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct GetSigningKey {
        msg_header: Header
    }

    impl GetSigningKey {
        /// Returns a new GetSigningKey message taking a parallel_port return address as parameter.
        pub fn new(return_address: Address) -> GetSigningKey {
            GetSigningKey {
                msg_header: Header::for_data(
                    MESSAGE_VERSION,
                    Address::ParallelPort,
                    return_address,
                    Command::HSMGetSigningKey,
                    &[])
            }
        }
    }

    impl Message for GetSigningKey {
        fn header(&self) -> &Header {
            &self.msg_header
        }

        fn payload(&self) -> &[u8] {
            &[]
        }
    }
}

/// Watchman-related messages
pub mod watchman {
    use std::io::Write;

    use bitcoin;
    use bitcoin::hashes::{Hash, sha256d};
    use bitcoin::consensus::encode::{Encodable, serialize};
    use byteorder::{LittleEndian, WriteBytesExt};

    use common::hsm::{Address, Command, Header, Message};
    use common::hsm::MESSAGE_VERSION;
    use common::PakList;
    use descriptor::LiquidDescriptor;
    use watchman::utxotable::SpendableUtxo;

    macro_rules! define_empty_message {
        ($name:ident, $cmd:ident) => {
            #[allow(missing_docs)]  // these are all POD types
            #[derive(Clone, PartialEq, Eq, Debug)]
            pub struct $name(Header);

            impl $name {
                #[allow(missing_docs)]
                pub fn new() -> $name {
                    $name(Header::for_data(MESSAGE_VERSION, Address::Watchman, Address::Watchman, Command::$cmd, &[]))
                }
            }

            impl Message for $name {
                fn header(&self) -> &Header { &self.0 }
                fn payload(&self) -> &[u8] { &[] }
            }
        }
    }

    define_empty_message!(GetPublicKey, WatchmanGetPublicKey);
    define_empty_message!(AuthorizedListReset, WatchmanAuthorizedListReset);
    define_empty_message!(GetWatchmanState, WatchmanState);

    /// A `AuthorizationMasterKeysReplace` message which is ferried from the sidechain
    /// daemon to the Hsm with no other processing.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct AuthorizationMasterKeysReplace {
        header: Header,
        payload: Vec<u8>
    }

    impl AuthorizationMasterKeysReplace {
        /// Creates a new `AuthorizationMasterKeysReplace` message from a RPC-provided list of master keys
        pub fn new(master_keys: &PakList) -> AuthorizationMasterKeysReplace {
            let mut payload = Vec::with_capacity(33 * 2 * master_keys.len());

            // Unlike in all other places, the HSM expects this message to be
            // serialized online key first.
            for entry in master_keys.iter() {
                payload.write_all(&entry.online.serialize()).unwrap();
                payload.write_all(&entry.offline.serialize()).unwrap();
            }

            AuthorizationMasterKeysReplace {
                header: Header::for_data(MESSAGE_VERSION,
                                         Address::Watchman,
                                         Address::Watchman,
                                         Command::WatchmanAuthorizationMasterKeysReplace,
                                         &payload[..]),
                payload: payload
            }
        }
    }

    impl Message for AuthorizationMasterKeysReplace {
        fn header(&self) -> &Header { &self.header }
        fn payload(&self) -> &[u8] { &self.payload[..] }
    }

    /// A `AuthorizationVerify` message which sends a pubkey and signature from the
    /// daemon to the Hsm with no other processing. Note we do not even validate
    /// that either is well-formed.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct AuthorizationVerify {
        header: Header,
        payload: Vec<u8>
    }

    impl AuthorizationVerify {
        /// Creates a new `AuthorizationVerify` message from the data on a pegout output pubkey and proof
        pub fn new(pk: &[u8], proof: &[u8]) -> AuthorizationVerify {
            let mut payload = Vec::with_capacity(pk.len() + proof.len());
            payload.extend(pk);
            payload.extend(proof);
            AuthorizationVerify {
                header: Header::for_data(MESSAGE_VERSION,
                                         Address::Watchman,
                                         Address::Watchman,
                                         Command::WatchmanAuthorizationVerify,
                                         &payload),
                payload: payload
            }
        }
    }

    impl Message for AuthorizationVerify {
        fn header(&self) -> &Header { &self.header }
        fn payload(&self) -> &[u8] { &self.payload[..] }
    }


    /// A `SetWitnessScript` message which is simply a script serialized as bytes,
    /// with no length marker (this is implied by the HSM message header).
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct SetWitnessScript<'a> {
        header: Header,
        script: &'a bitcoin::Script
    }

    impl<'a> SetWitnessScript<'a> {
        /// Creates a `SetWitnessScript` holding a reference to a script; expected to "wrap" the script and therefore not outlive it.
        pub fn new(script: &'a bitcoin::Script) -> SetWitnessScript {
            SetWitnessScript {
                header: Header::for_data(MESSAGE_VERSION,
                                         Address::Watchman,
                                         Address::Watchman,
                                         Command::WatchmanSetWitnessScript,
                                         &script[..]),
                script: script
            }
        }
    }

    impl<'a> Message for SetWitnessScript<'a> {
        fn header(&self) -> &Header { &self.header }
        fn payload(&self) -> &[u8] { &self.script[..] }
    }

    /// A `SignSegwitTx` message containing all the data that the HSM needs to
    /// produce BIP143 signatures
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct SignSegwitTx {
        header: Header,
        payload: Vec<u8>,
    }

    impl SignSegwitTx {
        /// Creates a new `SignSegwitTx` message
        pub fn new(tx: &bitcoin::Transaction, inputs: &[SpendableUtxo]) -> SignSegwitTx {
            let mut payload = vec![];
            let hash_prevouts = {
                let mut enc = sha256d::Hash::engine();
                for txin in &tx.input {
                    txin.previous_output.consensus_encode(&mut enc).unwrap();
                }
                sha256d::Hash::from_engine(enc)
            };

            let hash_sequence = {
                let mut enc = sha256d::Hash::engine();
                for txin in &tx.input {
                    txin.sequence.consensus_encode(&mut enc).unwrap();
                }
                sha256d::Hash::from_engine(enc)
            };

            payload.write_u32::<LittleEndian>(tx.input.len() as u32).unwrap();
            for inp in inputs {
                payload.extend(&inp.tweak[..]);
            }
            payload.write_i32::<LittleEndian>(tx.version).unwrap();
            payload.extend(&hash_prevouts[..]);
            payload.extend(&hash_sequence[..]);
            payload.write_u32::<LittleEndian>(tx.output.len() as u32).unwrap();
            for out in &tx.output {
                payload.extend(&serialize(out));
            }
            payload.write_u32::<LittleEndian>(tx.lock_time).unwrap();
            for (locked_mainout, tx_in) in inputs.iter().zip(tx.input.iter()) {
                payload.extend(&tx_in.previous_output.txid[..]);
                payload.write_u32::<LittleEndian>(tx_in.previous_output.vout).unwrap();
                payload.extend(&serialize(
                    &locked_mainout.descriptor.liquid_witness_script()
                ));
                payload.write_u64::<LittleEndian>(locked_mainout.value).unwrap();
            }
            SignSegwitTx {
                header: Header::for_data(
                    MESSAGE_VERSION,
                    Address::Watchman,
                    Address::Watchman,
                    Command::WatchmanSignSegwitTx,
                    &payload[..]),
                payload,
            }
        }
    }

    impl Message for SignSegwitTx {
        fn header(&self) -> &Header { &self.header }
        fn payload(&self) -> &[u8] { &self.payload[..] }
    }

    /// A `SendHeader` message which is an elements block header.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct SendHeader {
        header: Header,
        payload: Vec<u8>, // serialized blockheader
    }

    impl SendHeader {
        /// Creates a new `SendHeader` message.
        pub fn new(block_header: &elements::BlockHeader) -> SendHeader {
            let payload = elements::encode::serialize(block_header);
            SendHeader {
                header: Header::for_data(
                    MESSAGE_VERSION,
                    Address::Watchman,
                    Address::Watchman,
                    Command::WatchmanHeader,
                    &payload[..],
                ),
                payload: payload,
            }
        }
    }

    impl Message for SendHeader {
        fn header(&self) -> &Header { &self.header }
        fn payload(&self) -> &[u8] { &self.payload }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::rand::{RngCore, thread_rng};
    use common::hsm::{Address, Command, Header, HEADER_LEN, MESSAGE_VERSION};

    macro_rules! check_enum {
        ($e:ident, $($var:ident),*) => ({
            // Empty match to trigger exhaustiveness checking
            match $e::from_byte(0).unwrap() {
                $($e::$var => {}),*
            }
            // Actual serialize/deserialize test
            $(assert_eq!($e::from_byte($e::$var as u8).unwrap(), $e::$var);)*
        })
    }

    #[test]
    fn enum_round_trip() {
        check_enum!(Command, BlocksignerSignBlock, BlocksignerBlockSig, BlocksignerValidateBlock,
                             WatchmanGetUnilateralWithdrawPubkey, WatchmanUnilateralWithdrawPubkey, WatchmanGetUnilateralWithdrawLocktime, WatchmanUnilateralWithdrawLocktime,
                             WatchmanGetPublicKey, WatchmanPublicKey,
                             WatchmanForeChangeScript, WatchmanSetWitnessScript,
                             HSMInit, HSMInitReply, HSMGetRtcTime, HSMRtcTimeReply, HSMGetSigningKey, HSMGetSigningKeyResponse,
                             HSMAddEntropy, HSMAddEntropyFailure, HSMGetVersion, HSMGetVersionReply,
                             HSMHeartbeat, HSMHeartbeatReply, HSMGetRestoreKey, HSMGetRestoreKeyReply,
                             WatchmanSignSegwitTx, WatchmanSegwitTxSignatures,
                             WatchmanHeader, WatchmanState, WatchmanStateReply,
                             WatchmanAuthorizedListReset, WatchmanAuthorizationVerify, WatchmanAuthorizationMasterKeysReplace,
                             TamperDetectEnable, TamperDetectResponse, TamperDetectChallenge,
                             HSMUpdate, HSMUpdateACK, HSMUpdateNACK,
                             Ack, NackRetry, NackBadData, NackInternal, NackTooMany, NackRateLimit,
                             HsmOnFire, NackUnsupported, NackDeliveryFailed, NackNotAllowed,
                             NackInvalid);
        check_enum!(Address, BlockSigner, Watchman, ParallelPort, Query, Update);
    }

    #[test]
    fn header_round_trip() {
        for n in 0..1000 {
            let mut data = vec![0; n];
            (&mut thread_rng()).fill_bytes(&mut data[..]);

            let header = Header::for_data(MESSAGE_VERSION,
                                          Address::BlockSigner,
                                          Address::BlockSigner,
                                          Command::BlocksignerSignBlock,
                                          &data);
            assert_eq!(header.address, Address::BlockSigner);
            assert_eq!(header.command, Command::BlocksignerSignBlock);
            assert_eq!(header.length, n as u32);

            let ser = header.serialize();
            assert_eq!(ser.len(), HEADER_LEN);
            let dec = Header::parse(&ser).unwrap();
            assert_eq!(dec, header);
        }
    }
}

