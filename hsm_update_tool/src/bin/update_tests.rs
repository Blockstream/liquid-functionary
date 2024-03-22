//{{ Liquid }}
//Copyright (C) {{ 2019 }}  {{ Blockstream }}

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

//! # HSM update tool
//!
//! Sends a file (e.g. rpm package) to a connected hsm via parallel_port for processing (e.g. installation).
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

extern crate bitcoin;
extern crate byteorder;
extern crate functionary;
extern crate functionary_common;
extern crate hsm_update_tool;

use hsm_update_tool::message_error::MessageError;
use hsm_update_tool::packet::*;
use hsm_update_tool::transfer_context::TransferContext;

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash};
use functionary_common::hsm::{self, Address::Update, Command::{HSMUpdateNACK, HSMUpdateACK}};
#[macro_use] extern crate functionary_logs;
use functionary::hsm::LiquidHsm;
use std::io::Write;
use std::{env, io};

fn test_send(
    context: &mut TransferContext,
    packet: &mut dyn UpdatePacketIntf,
    ) -> (u32, Result<Vec<u8>, MessageError>) {

    packet.set_id(context.get_id());
    let mut data: Vec<u8> = Vec::with_capacity(MAX_PACKET_SIZE);
    let _encode_size = match packet.marshal(&mut data) {
        Ok(t) => t,
        Err(e) => {
            return (packet.get_id(), Err(MessageError::from(e)));
        }
    };

    match context.security_module().update_tool_send(data.as_slice()) {
        Err(e) => {
            log!(Error, "Error sending packet: {}", e);
            return (packet.get_id(), Err(MessageError::from(e)));
        }
        Ok(mut sock) => {
            let result = context.security_module().update_tool_recv(&mut sock);
            log!(Debug, "Received reply to send");
            match result {
                Ok((command, reply_buf)) => {
                    log!(Debug, "Reply received is OK");

                    // Packet type sanity check
                    if (command != HSMUpdateACK) && (command != HSMUpdateNACK) {
                        // Got an odd packet - wait some more
                        log!(Error, "Got a unexpected packet - dropping");
                        return (0, Err(MessageError::BadValue));
                    }

                    let mut reply_slice = &reply_buf[..];
                    let header = match CommonUpdatePacketHeader::unmarshal(&mut reply_slice) {
                        Ok(t) => t,
                        Err(e) => {
                            log!(Error, "Could not deserialize response: {}", e);
                            return (packet.get_id(), Err(MessageError::from(e)));
                        }
                    };

                    let mut body : Vec<u8> = vec![0];
                    if !reply_slice.is_empty() {
                        body = reply_slice.to_vec();
                    }

                    if header.packet_type != PacketType::Reply {
                        log!(Error, "Got a weird reply from HSM - dropping");
                        return (header.sequenced_id, Err(MessageError::BadValue));
                    }

                    if command == HSMUpdateNACK {
                        // Got a NACK, fail fast and let caller figure out what to do.
                        log!(Warn, "The reply was a NACK!");
                        return (header.sequenced_id, Err(MessageError::ReceivedNACK));
                    }
                    // Got an ack return success
                    log!(Debug, "The replay was an ACK");
                    return (header.sequenced_id, Ok(body));
                }
                Err(hsm_error) => match hsm_error {
                    hsm::Error::Io(io_error) => {
                        if io_error.kind() == io::ErrorKind::TimedOut {
                            log!(Warn, "packet send timed out: {} - retrying", io_error);
                            return (packet.get_id(), Err(MessageError::Timeout));
                        } else {
                            log!(Error, "packet send failed: {} - retrying", io_error);
                            return (packet.get_id(), Err(MessageError::IOError(io_error)));
                        }
                    }
                    _ => {
                        log!(Error, "packet send failed: {} - retrying", hsm_error);
                        return (packet.get_id(), Err(MessageError::HSMError(hsm_error)));
                    }
                },
            }
        }
    }
}

fn send_sync_packet(context: &mut TransferContext, test_sequence_number: u32) -> bool {
    let mut packet: SyncSequenceIdOpPacket = SyncSequenceIdOpPacket::new();
    context._set_id(test_sequence_number);
    let (sequence_number, op_result) = test_send(context, &mut packet);
    match op_result {
        Ok(_) => {
            log!(Info, "Sequence ID's sync'ed with HSM");
            if sequence_number != context.get_id() {
                log!(Error, "sequence numbers do not match after sync");
                println!("FAILED");
                return false;
            }
        }
        Err(e) => {
            log!(Error, "Sync of sequence ID's failed: {}", e);
            println!("FAILED");
            return false;
        }
    }
    context.inc_id();
    return true;
}

fn send_begin_file_packet(
    context: &mut TransferContext,
    test_filename: &str,
    file_length: u32,
    file_hash: &sha256::Hash,
) -> bool {
    let mut filename: FileNameType = FileNameType {
        data: [0; max_filename_length()],
    };
    filename.data[..test_filename.as_bytes().len()].clone_from_slice(test_filename.as_bytes());

    let mut packet = BeginFileTransferOpPacket::new(&filename, file_length, &file_hash);
    let (sequence_number, op_result) = test_send(context, &mut packet);
    match op_result {
        Ok(_) => {
            log!(Info, "BeginFileTransferOp succeeded");
            if sequence_number != context.get_id() {
                log!(Error, "sequence numbers do not match after sync");
                return false;
            }
        }
        Err(e) => {
            log!(Error, "BeginFileTranferOp failed: {}", e);
            return false;
        }
    }
    context.inc_id();
    return true;
}

fn send_get_firmware_query_packet(
    context: &mut TransferContext,
    firmware_version: &mut Vec<u8>
) -> bool {
    let mut packet = GetFirmwareVersionOpPacket::new();
    let (sequence_number, op_result) = test_send(context, &mut packet);

    match op_result {
        Ok(body) => {
            log!(Info, "GetFirmwareVersionOp succeeded");
            if sequence_number != context.get_id() {
                log!(Error, "sequence numbers do not match after sync");
                return false;
            }
            *firmware_version = body;
        }
        Err(e) => {
            log!(Error, "GetFirmwareVersionOp failed: {}", e);
            return false;
        }
    }
    context.inc_id();
    return true;
}

fn send_auth_packet(
    context: &mut TransferContext,
    message: &str,
    sig: &[u8],
) -> bool {

    let mut bitcoin_message_serialized = Vec::new();
    message.to_string().consensus_encode(&mut bitcoin_message_serialized).unwrap();
    let secp_sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig[1..]).unwrap();
    let mut signatures = Vec::new();
    signatures.push(Some(secp_sig));
    signatures.push(None);
    let mut packet = AuthorizeUpgradePacket::new(&bitcoin_message_serialized[..], &signatures);
    let (sequence_number, op_result) = test_send(context, &mut packet);
    match op_result {
        Ok(_) => {
            log!(Info, "AuthorizeUpgradePacket succeeded");
            if sequence_number != context.get_id() {
                log!(Error, "sequence numbers do not match after sync");
                return false;
            }
        }
        Err(e) => {
            log!(Error, "AuthorizeUpgradePacket failed: {}", e);
            return false;
        }
    }
    context.inc_id();
    return true;
}

fn send_end_file_packet(context: &mut TransferContext, file_hash: &sha256::Hash) -> bool {
    let mut packet = EndFileTransferOpPacket::new(&file_hash);
    let (sequence_number, op_result) = test_send(context, &mut packet);
    match op_result {
        Ok(_) => {
            log!(Info, "EndFileTransferOp succeeded");

            if sequence_number != context.get_id() {
                log!(Error, "sequence numbers do not match after sync");
                return false;
            }
        }
        Err(e) => {
            log!(Error, "EndFileTranferOp failed: {}", e);
            return false;
        }
    }

    context.inc_id();
    return true;
}

fn send_file_chunk_packet(context: &mut TransferContext, data: &[u8]) -> bool {
    let mut packet = match FileChunkPacket::new(data) {
        Ok(t) => t,
        Err(_e) => {
            return false;
        }
    };

    let (sequence_number, op_result) = test_send(context, &mut packet);
    match op_result {
        Ok(_) => {
            log!(Info, "File Chunk Send reply received");
            if sequence_number != context.get_id() {
                log!(Error, "sequence numbers do not match after sync");
                return false;
            }
        }
        Err(e) => {
            log!(Error, "File Chunk send failed: {}", e);
            return false;
        }
    }

    context.inc_id();
    return true;
}

fn end_file_xfer_test(
    context: &mut TransferContext,
    test_filename: &str,
    file_length: u32,
    file_hash: &sha256::Hash,
    data: &Vec<u8>,
    sig: &Vec<u8>,
    expected_result: (bool, bool, bool),
) -> bool {
    let auth_message = "00000001".to_owned() + &file_hash.to_string();
    // future: add tests for invalid auth and assert expectations
    let _sig_result = send_auth_packet(context, &auth_message, sig.as_slice());

    let mut result = send_begin_file_packet(context, test_filename, file_length, file_hash);
    if !result {
        return result == expected_result.0;
    }

    result = send_file_chunk_packet(context, data.as_slice());
    if !result {
        return result == expected_result.1;
    }

    result = send_end_file_packet(context, file_hash);
    return result == expected_result.2;
}

fn make_hash(data: &Vec<u8>) -> sha256::Hash {
    let mut hash_engine = sha256::Hash::engine();
    let _write_result = hash_engine.write(data.as_slice());

    sha256::Hash::from_engine(hash_engine)
}

fn filename_test(context: &mut TransferContext, testfilename: &str) -> bool {
    let file_hash = make_hash(&vec![42]);

    return send_begin_file_packet(context, testfilename, 0, &file_hash);
}

fn get_firmware_version_test(context: &mut TransferContext, firmware_version: &mut Vec<u8>) -> bool {
    send_get_firmware_query_packet(context, firmware_version)
}

fn test(context: &mut TransferContext) -> bool {
    //Sequence Test
    // Send Sequence sync until ACK or timeout - all communication with the HSM
    // needs to sync sequence_numbers first.
    print!("Sequence sync test 1 .... ");
    let result = send_sync_packet(context, 42);
    if !result || context.get_id() != 43 {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    print!("Sequence sync test 2 .... ");
    let result = send_sync_packet(context, 23);
    if !result || context.get_id() != 24 {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    print!("Sequence sync test 3 .... ");
    let result = send_sync_packet(context, u32::max_value());
    if !result || context.get_id() != 1 {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // File Header Tests
    // Good filename
    print! {"File header test - good name 1 .... "}
    let result = filename_test(context, "Good_filename-test-azAZ09.tgz");
    if !result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // Good filename 2
    print! {"File header test - good name 2 .... "}
    let result = filename_test(context, "a");
    if !result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // Good filename 2
    print! {"File header test - good name 3 .... "}
    let result = filename_test(context, "123456789012345678901234567890123456789012");
    if !result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // Bad filename - negative test should NACK
    print! {"File header test - bad name 1 .... "}
    let result = filename_test(context, "bad/filename-test.tgz");
    if result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // Bad filename 2 - negative test should NACK
    print! {"File header test - bad name 2 .... "}
    let result = filename_test(context, "bad-filename*.tgz");
    if result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // Bad filename 3 - negative test should NACK
    print! {"File header test - bad name 3 .... "}
    let result = filename_test(context, "bad filename.tgz");
    if result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // Bad filename 3 - negative test should NACK
    print! {"File header test - bad name 4 .... "}
    let result = filename_test(context, ".bad-filename.tgz");
    if result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // File length too long
    print! {"File header test - bad file length .... "}
    let file_hash = make_hash(&vec![42]);
    let result = send_begin_file_packet(context, "good.bin", (50000000+1) as u32, &file_hash);
    if result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // End File xfer test - Should succeed
    print! {"End File xfer test - expect success .... "}
    let data: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    let sig: Vec<u8> = vec![32, 23, 134, 111, 127, 1, 140, 63, 105, 234, 142, 25, 213, 47, 182, 197, 27, 162, 206, 235, 171, 130, 40, 23, 74, 128, 176, 215, 248, 202, 147, 26, 179, 4, 2, 58, 143, 6, 16, 235, 12, 179, 97, 94, 241, 93, 117, 44, 18, 93, 134, 101, 225, 187, 59, 135, 53, 226, 225, 39, 200, 208, 12, 11, 59];
    let file_hash = make_hash(&data);
    let result = end_file_xfer_test(
        context,
        "good.bin",
        data.len() as u32,
        &file_hash,
        &data,
        &sig,
        (true, true, true),
    );
    if !result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // End File xfer test - Bad filelength 1
    print! {"End File xfer test - bad file length 1 .... "}
    let data: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    let file_hash = make_hash(&data);
    let result = end_file_xfer_test(
        context,
        "good.bin",
        (data.len() as u32) + 1,
        &file_hash,
        &data,
        &sig,
        (true, true, false),
    );
    if !result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // End File xfer test - Bad filelength 2
    print! {"End File xfer test - bad file length 2 .... "}
    let data: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    let file_hash = make_hash(&data);
    let result = end_file_xfer_test(
        context,
        "good.bin",
        (data.len() as u32) - 1,
        &file_hash,
        &data,
        &sig,
        (true, false, false),
    );
    if !result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // End File xfer test - Bad checksum
    print! {"End File xfer test - bad checksum .... "}
    let file_hash = make_hash(&vec![42]);
    let data: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    let result = end_file_xfer_test(
        context,
        "good.bin",
        data.len() as u32,
        &file_hash,
        &data,
        &sig,
        (true, true, false),
    );
    if !result {
        println!("FAILED");
        return false;
    }
    println!("PASSED");


    // GetFirmwareVersion test
    print! {"Get Firmware Version test .... "}
    let mut firmware_version = vec![8];
    let result = get_firmware_version_test(context, &mut firmware_version);
    if !result {
        println!("FAILED");
        return false;
    }
    let value = match std::str::from_utf8(firmware_version.as_slice()) {
        Ok(value) => value,
        Err(_) => {
           println!("FAILED");
           return false;
        }
    };
    if !"00000000".eq(value) {
        println!("FAILED");
        return false;
    }
    println!("PASSED");

    // Done
    true
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <parallel_port_socket_path>", args[0]);
        return Err("Usage".into());
    }

    // Open socket to parallel_port/hsm
    let socket_path = format!("{}/{}", args[1].clone(), Update as u8);
    let security_module = Box::new(LiquidHsm::new(socket_path));
    let mut context = TransferContext::new(security_module);

    let result = test(&mut context);
    if result {
        println! {"All Tests PASSED"};
        return Ok(());
    } else {
        println!("Test FAILED");
        return Err("Test FAILED".into());
    }
}
