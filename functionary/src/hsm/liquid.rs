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


//! # Real HSM
//!
//! Implementation of the SecurityModule trait corresponding to the HSM used by
//! Liquid. Communicates via UNIX socket (which is then routed over a serial
//! port by other software).
//!

use std::convert::TryInto;
use std::io::{self, Read, Write};
use std::time::Duration;
use std::os::unix::net::UnixStream;

use bitcoin;
use bitcoin::hashes::Hash;
use bitcoin::consensus::encode::deserialize;
use bitcoin::secp256k1::{self, PublicKey};
use elements;

use common::PakList;
use common::hsm::{Address, Header, HEADER_LEN, Message, Command};
use config::InitHSM;
use hsm::{Error, SecurityModule, WatchmanState};
use hsm::message;
use network::read_and_consume_magic;
use watchman::transaction::TransactionSignatures;
use watchman::utxotable::SpendableUtxo;

/// Magic bytes for messages sent to the HSM
pub const MAGIC_BYTES: &'static [u8; 4] = b"LPT1";

/// Maximum message size for a HSM message
pub const MAX_MESSAGE_SIZE: usize = 256 * 1024;

/// DEFAULT_HSM_READ_TIMEOUT is nominally how long it should take to send a
/// request to the HSM, have the HSM process it it, and get a response back.
/// The actual time allowed can be up to 2 times this duration (between the
/// the timeout waiting for the "magic" to appear and the subsequent socket
/// timeout on the rest of the message).
const DEFAULT_HSM_READ_TIMEOUT: Duration = Duration::from_millis(30000);

/// An actual HSM
pub struct LiquidHsm {
    socket_path: String
}

impl LiquidHsm {
    /// Constructs a new real HSM
    pub fn new(socket_path: String) -> LiquidHsm {
        LiquidHsm {
            socket_path: socket_path
        }
    }

    /// Executes some function on the HSM socket, returning an error if
    /// it cannot be connected to.
    fn with_opened_socket<F, R>(&self, f: F)
                                -> Result<R, Error>
                                where F: FnOnce(UnixStream) -> Result<R, Error> {
        let sock = match UnixStream::connect(&self.socket_path) {
            Ok(stream) => stream,
            Err(e) => {
                log!(Warn, "Could not connect to socket {:?}",self.socket_path);
                return Err(Error::Io(e));
            }
        };
        sock.set_write_timeout(Some(Duration::from_millis(10000)))?;
        sock.set_read_timeout(Some(DEFAULT_HSM_READ_TIMEOUT))?;
        f(sock)
    }
}

impl SecurityModule for LiquidHsm {
    fn validate_block(&self, header: &elements::BlockHeader) -> Result<(), Error> {
        log!(Debug, "validate_block called: sidechain height: {}", header.height);
        let return_value = self.with_opened_socket(|mut sock| {
            // Send block header
            let message = message::blocksigner::ValidateBlock::new(header);
            send_message(&mut sock, &message)?;
            // Read response
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::Ack => Ok(()),
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        });
        log!(Debug, "validate_block returns: {:?}", return_value);
        return_value
    }

    fn sign_block(&self, header: &elements::BlockHeader) -> Result<secp256k1::ecdsa::Signature, Error> {
        log!(Debug, "sign_block called: sidechain height: {}", header.height);
        let return_value = self.with_opened_socket(|mut sock| {
            // Send block header
            let message = message::blocksigner::SignBlock::new(header);
            send_message(&mut sock, &message)?;
            // Read response
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::BlocksignerBlockSig => {
                    secp256k1::ecdsa::Signature::from_der(&msg[..]).map_err(Error::Secp)
                }
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        });
        log!(Debug, "sign_block returns error: {:?}", return_value.as_ref().err());
        return_value
    }

    fn public_key(&self) -> Result<PublicKey, Error> {
        log!(Debug, "public_key called");
        let return_value = self.with_opened_socket(|mut sock| {
            // Send request
            let message = message::watchman::GetPublicKey::new();
            send_message(&mut sock, &message)?;
            // Read response
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::WatchmanPublicKey => {
                    Ok(PublicKey::from_slice(&msg)?)
                }
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        });
        log!(Debug, "public_key returns error: {:?}", return_value.as_ref().err());
        return_value
    }

    fn set_witness_script(&self, script: &bitcoin::Script) -> Result<(), Error> {
        log!(Debug, "set_witness_script called: script len: {}", script.len());
        let return_value = self.with_opened_socket(|mut sock| {
            // Send request
            let message = message::watchman::SetWitnessScript::new(script);
            send_message(&mut sock, &message)?;
            // Read response
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::Ack => Ok(()),
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        });
        log!(Debug, "set_witness_script returns: {:?}", return_value);
        return_value
    }

    fn authorized_addresses_clear(&self) -> Result<(), Error> {
        log!(Debug, "authorized_addresses_clear called");
        let return_value = self.with_opened_socket(|mut sock| {
            // Send request
            let message = message::watchman::AuthorizedListReset::new();
            send_message(&mut sock, &message)?;
            // Read response
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::Ack => Ok(()),
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        });
        log!(Debug, "authorized_addresses_clear returns: {:?}", return_value);
        return_value
    }

    fn authorized_addresses_add(&self, pk: &[u8], proof: &[u8]) -> Result<(), Error> {
        log!(Debug, "authorized_addresses_add called");
        let return_value = self.with_opened_socket(|mut sock| {
            // PAK authorizations should take well under a second. However, in case of
            // error the HSM may spend a full second waiting for lost data to appear on
            // the serial line (see TIMEOUT_US in src/common/message.c of the HSM source
            // tree). So we'll timeout after 5s, at which point we know that the HSM
            // is ready for us to retry.
            sock.set_read_timeout(Some(Duration::from_millis(5000)))?;

            // Send request
            let message = message::watchman::AuthorizationVerify::new(pk, proof);
            send_message(&mut sock, &message)?;
            // Read response
            let (header, msg) = match read_message(&mut sock, None) {
                Ok((h, m)) => (h, m),
                Err(e) => {
                    log!(Warn, "failed to send PAK proof: {}. Retrying.", e);
                    send_message(&mut sock, &message)?;
                    read_message(&mut sock, None)?
                }
            };
            match header.command {
                Command::Ack => Ok(()),
                Command::NackTooMany => Err(Error::AuthorizedKeyCacheFull),
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        });
        log!(Debug, "authorized_addresses_add returns: {:?}", return_value);
        return_value
    }

    fn authorization_master_keys_replace(&self, pak: &PakList) -> Result<(), Error> {
        log!(Debug,
            "authorization_master_keys_replace called: key list: {} keys", pak.len(),
        );
        let return_value = self.with_opened_socket(|mut sock| {
            // Send request
            let message = message::watchman::AuthorizationMasterKeysReplace::new(pak);
            send_message(&mut sock, &message)?;
            // Read response
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::Ack => Ok(()),
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        });
        log!(Debug, "authorization_master_keys_replace returns: {:?}", return_value);
        return_value
    }

    fn sign_segwit_transaction(
        &self,
        tx: &bitcoin::Transaction,
        inputs: &[SpendableUtxo],
    ) -> Result<TransactionSignatures, Error> {
        log!(Debug, "sign_segwit_transaction called: length: {}", tx.input.len());
        let return_value = self.with_opened_socket(|mut sock| {
            assert_eq!(tx.input.len(), inputs.len());
            // (max message size + 25% for response) / bps + HSM processing time
            // 240K * 1.25 / (3K/sec) + 20 sec = 120sec
            let round_trip_time = Duration::from_millis(120000);

            // Send request
            let message = message::watchman::SignSegwitTx::new(tx, inputs);
            send_message(&mut sock, &message)?;
            sock.set_read_timeout(Some(round_trip_time))?;
            // Read response
            let (header, msg) = read_message(&mut sock, Some(round_trip_time))?;
            match header.command {
                Command::WatchmanSegwitTxSignatures => {
                    let raw: Vec<Vec<u8>> = deserialize(&msg[..])?;
                    let mut ret = Vec::with_capacity(raw.len());
                    for sig in &raw {
                        ret.push((
                            secp256k1::ecdsa::Signature::from_der(sig)?,
                            bitcoin::EcdsaSighashType::All,
                        ));
                    }
                    Ok(TransactionSignatures::from(ret))
                }
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        });
        log!(Debug, "sign_segwit_transaction returns error: {:?}", return_value.as_ref().err());
        return_value

    }

    fn send_header(&self, header: &elements::BlockHeader) -> Result<(), Error> {
        log!(Debug, "send_header called: height: {}", header.height);
        let return_value = self.with_opened_socket(|mut sock| {
            // Send request
            let message = message::watchman::SendHeader::new(header);
            send_message(&mut sock, &message)?;
            // Read response
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::Ack => Ok(()),
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        });
        if let Err(ref e) = return_value {
            log!(Debug, "send_header returns error: {:?}", e);
        }
        return_value
    }

    fn get_watchman_state(&self) -> Result<WatchmanState, Error> {
        log!(Debug, "get_watchman_state called");
        let return_value = self.with_opened_socket(|mut sock| {
            // Send request
            let message = message::watchman::GetWatchmanState::new();
            send_message(&mut sock, &message)?;
            // Read response
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::WatchmanStateReply => {
                    if msg.len() != 33 {
                        log!(Error, "HSM sent HSM_WATCHMAN_STATE_REPLY msg of length {}", msg.len());
                        return Err(Error::Decoding(
                            "HSM_WATCHMAN_STATE_REPLY payload length was not 33 bytes"
                        ));
                    }

                    let header = elements::BlockHash::from_slice(&msg[1..33]).expect("size = 32");
                    Ok(WatchmanState {
                        sign_status: msg[0].try_into()
                            .map_err(|_| Error::Decoding("invalid WatchmanSignStatus byte"))?,
                        last_header: if header != Default::default() {
                            Some(header)
                        } else{
                            None
                        },
                    })
                }
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        });
        if let Err(ref e) = return_value {
            log!(Debug, "get_watchman_state returns error: {:?}", e);
        }
        return_value
    }

    fn initialize_hsm(&self, config: InitHSM, timestamp_millis: u64) -> Result<Vec<u8>, Error> {
        log!(Debug, "initialize_hsm called: force_reinit_flag: {}", config.force_reinit_flag);
        let return_value = self.initialize_hsm_from(config, timestamp_millis, Address::BlockSigner)?;
        log!(Debug, "initialize_hsm returns: {:?}", return_value);
        Ok(return_value)
    }

    fn initialize_hsm_from(&self, config: InitHSM, timestamp_millis: u64, return_address: Address) -> Result<Vec<u8>, Error> {
        log!(Debug, "initialize_hsm_from called: force_reinit_flag: {}, ret_addr: {:?}", config.force_reinit_flag, return_address);
        let return_value = self.with_opened_socket(|mut sock| {
            let message = message::init::HSMInit::new(config, timestamp_millis).return_address(return_address);
            send_message(&mut sock, &message)?;
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::HSMInitReply =>  Ok(msg.to_owned()),
                Command::TamperDetectChallenge => Err(Error::tamper_detect(&msg)),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        })?;
        log!(Debug, "initialize_hsm_from returns: {:?}", return_value);
        Ok(return_value)
    }

    fn get_signing_key(&self, return_address: Address) -> Result<Vec<u8>, Error> {
        log!(Debug, "get_signing_key called");
        let return_value = self.with_opened_socket(|mut sock| {
            let message = message::hsm_query::GetSigningKey::new(return_address);
            send_message(&mut sock, &message)?;
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::HSMGetSigningKeyResponse =>  Ok(msg.to_owned()),
                cmd => Err(Error::ReceivedNack(cmd))
            }
        })?;
        log!(Debug, "get_signing_key returns: {:?}", return_value);
        Ok(return_value)
    }

    fn update_tool_send(&self, data_packet: &[u8]) -> Result<UnixStream, Error> {
        log!(Debug, "update_tool_send called");
        let fnc = |mut sock| -> Result<UnixStream, Error> {
            let message = message::hsm_update::HSMUpdateMessage::new(data_packet);
            let result = send_message(&mut sock, &message);
            match result {
                Ok(_t) => Ok(sock),
                Err(e) => Err(Error::Io(e))
            }
        };
        self.with_opened_socket(fnc)
    }

    fn update_tool_recv(&self, sock: &mut UnixStream) -> Result<(Command, Vec<u8>), Error> {
        log!(Debug, "update_tool_recv called");
        let socket_copy = sock.try_clone()?;
        let (header, msg) = read_message(socket_copy, None)?;
        let return_value = match header.command {
            Command::HSMUpdateACK => Ok((Command::HSMUpdateACK, msg.to_owned())),
            Command::HSMUpdateNACK => Ok((Command::HSMUpdateNACK, msg.to_owned())),
            _ => Err(Error::Unknown)
        }?;
        log!(Debug, "update_tool_recv reply: {:?}", return_value);
        Ok(return_value)
    }

    fn get_rtc(&self, return_address: Address) -> Result<u64, Error> {
        log!(Debug, "get_rtc called");
        let timestamp_millis = self.with_opened_socket(|mut sock| {
            let message = message::hsm_query::GetRtc::new(return_address);
            send_message(&mut sock, &message)?;
            let (header, msg) = read_message(&mut sock, None)?;
            match header.command {
                Command::HSMRtcTimeReply => {
                    let encoded_time: [u8; 8] = msg[..].try_into()
                        .map_err(|_| Error::Decoding("invalid rtc payload"))?;
                    Ok(u64::from_le_bytes(encoded_time))
                }
                cmd => Err(Error::ReceivedNack(cmd))
            }
        })?;
        log!(Debug, "get_rtc returns: {:?}", timestamp_millis);
        Ok(timestamp_millis)
    }
}

// Helper functions for serial I/O

/// Actually send a message to the HSM
fn send_message(mut w: impl Write, msg: &impl Message) -> io::Result<()> {
    let mut bytes_written = MAGIC_BYTES.len();
    w.write_all(MAGIC_BYTES)?;
    let header_buf = msg.header().serialize();
    bytes_written += header_buf.len();
    w.write_all(&header_buf[..])?;
    bytes_written += msg.payload().len();
    w.write_all(msg.payload())?;
    slog!(MessageSent, message_type: msg.header().command.text(), bytes: bytes_written);
    Ok(())
}

/// Read a message from the HSM
fn read_message(mut r: impl Read, timeout: Option<Duration>) -> Result<(Header, Vec<u8>), Error> {
    let mut header_buf = [0u8; HEADER_LEN];
    let mut bytes_read: usize = MAGIC_BYTES.len();
    read_and_consume_magic(&mut r, MAGIC_BYTES, timeout.unwrap_or(DEFAULT_HSM_READ_TIMEOUT))?;
    bytes_read += header_buf.len();
    r.read_exact(&mut header_buf)?;
    let header = Header::parse(&header_buf)?;
    let msg_length = header.length as usize;

    if msg_length > MAX_MESSAGE_SIZE {
        return Err(Error::BadLength(msg_length));
    }

    let mut ret = vec![0; msg_length];
    bytes_read += msg_length;
    r.read_exact(&mut ret)?;
    slog!(MessageReceived, message_type: header.command.text(), bytes: bytes_read);
    Ok((header, ret))
}
