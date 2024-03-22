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
extern crate base64;

extern crate getargs;

use std::fs::File;
use std::io::{Read, Write, BufRead, BufReader};
use std::{convert::TryFrom, env, io};
use std::str::FromStr;

use getargs::{Error, Opt, Options};

use bitcoin::hashes::{Hash, sha256d, sha256, HashEngine};
use functionary_common::hsm;
use functionary_common::hsm::Address::Update;
use functionary_common::hsm::Command::{HSMUpdateNACK, HSMUpdateACK};
use bitcoin::secp256k1::{self, Secp256k1};
use functionary::hsm::LiquidHsm;
use bitcoin::consensus::Encodable;
use bitcoin::VarInt;
#[macro_use] extern crate functionary_logs;

mod message_error;
mod packet;
mod transfer_context;

use message_error::MessageError;
use packet::*;
use transfer_context::*;
use GUIOperations::Unspecified;
use std::path::Path;

const MAX_SEND_TRYS: u32 = 8;

fn sleep(delta_millis: u64) {
    use std::{thread, time};
    let millis = time::Duration::from_millis(delta_millis);
    thread::sleep(millis);
}

fn usage(exe_name: &String) {
    println! ("Usage: {} -s <socket_path> {{-v | -u <update_file_path> -f <signature_file> [-r <remote_filename>] }}", exe_name);
    println!();
    println!("   -s <socket_path> : ");
    println!("               Path to parallel_port's socket directory.");
    println!();
    println!("   -u/--update <update_file_path> : ");
    println!("               <update_file_path> is the path to the file containing update to be installed.");
    println!();
    println!("   -f/--sigfile <signature_file> : ");
    println!("               <signature_file> is the path to the File containing compact ECDSA signatures for ");
    println!("               multisig threshold verification.");
    println!();
    println!("   -r/--remote <remote_filename> : ");
    println!("               [optional] The filename to use for the update on the HSM.");
    println!();
    println!("   -v/--version : ");
    println!("               retrieve the current firmware version from the HSM print it as BE hex encoded bytes");
    println!();
    println!("Examples:");
    println!("   To perform an update:");
    println!("   {} -u ./update_42.tgz -f ./sigs_for_update_42.asc -s /run/parallel_port ", exe_name);
    println!();
    println!("   To query current firmware version:");
    println!("   {} -v -s /run/parallel_port ", exe_name);
    println!();
    println!("Note 1: -v & (-u, -r, -f) are mutually exclusive.");
    println!();
    println!("Note 2: The <update_file_path> must point to a gzip'ed tar file '.tgz' containing at the very least");
    println!("        an executable shell-script file called 'install.sh' that will be run by the HSM update service.");
    println!();
    println!("Note 3: If the <remote_filename> parameter is not present, the file portion of the <update_file_path> will be used.");
    println!("        The <remote_filename> is only allowed to contain alpha-numeric character, '.', '_', & '-'.");
    println!("        and the filename can not begin with a '.'.");

}

#[derive(Debug, PartialEq)]
enum GUIOperations {
    Unspecified = 0,
    Help,
    Update,
    GetVersion,
}

impl Default for GUIOperations {
    fn default() -> Self {
        Unspecified
    }
}

#[derive(Default, Debug)]
struct UpdateArgs {
    file_path: String,
    remote_file_path: String,
    sig_file_path: String,
    socket_path: String,
    operation: GUIOperations,
}

fn filename_from_path(path: &Path) -> String {
    let filename = match path.file_name() {
        Some(f) => {
            match f.to_str() {
                Some(filename) => filename.to_string(),
                None => "".into(),
            }
        },
        None => "".into(),
    };
    filename
}

fn parse_args<'a>(options: &'a Options<'a, String>, update_args: &'a mut UpdateArgs) -> Result<&'a UpdateArgs, getargs::Error<'a>> {
    while let Some(opt) = options.next() {
        match opt? {
            Opt::Short('u') | Opt::Long("update") => {
                if update_args.operation != GUIOperations::Unspecified {
                    return Err(Error::InvalidArg {desc: "-u cannot be used with -v".to_string(), value: ""});
                }
                update_args.operation = GUIOperations::Update;
                update_args.file_path = options.value_str()?.to_string();
                //default remote filename
                if update_args.remote_file_path == "" {
                    update_args.remote_file_path = filename_from_path(Path::new(&update_args.file_path));
                }
            },
            Opt::Short('f') | Opt::Long("sigfile") => {
                update_args.sig_file_path = options.value_str()?.to_string();
            },
            Opt::Short('r') | Opt::Long("remote") => update_args.remote_file_path = options.value_str()?.to_string(),
            Opt::Short('s') | Opt::Long("socket") => update_args.socket_path = options.value_str()?.to_string(),
            Opt::Short('v') | Opt::Long("version") => {
                if update_args.operation != GUIOperations::Unspecified {
                    return Err(Error::InvalidArg {desc: "-u cannot be used with -v".to_string(), value: ""});
                }
                update_args.operation = GUIOperations::GetVersion;
            }
            Opt::Short('h') | Opt::Long("help") => {
                update_args.operation = GUIOperations::Help;
                return Ok(update_args);
            },
            opt=> return Err(Error::UnknownOpt(opt)),
        }
    }
    Ok(update_args)
}

/** main sending protocol logic */
fn send(
    context: &mut TransferContext,
    packet: &mut dyn UpdatePacketIntf,
    retry_on_nack: bool,
) -> Result<Vec<u8>, MessageError> {

    let sequenced_packet_id = context.get_id();
    let mut trys: u32 = 1;
    packet.set_id(sequenced_packet_id);
    let mut data: Vec<u8> = Vec::with_capacity(MAX_PACKET_SIZE);
    let _encode_size = packet.marshal(&mut data)?;
    let mut status = MessageError::Timeout;
    let mut reply_payload :Vec<u8> = vec![0];

    while trys <= MAX_SEND_TRYS {
        status = MessageError::Timeout;
        log!(Debug, "Sending packet to HSM update service: Packet ({}, {})", packet.get_packet_type(), packet.get_id());
        match context.security_module().update_tool_send(data.as_slice()) {
            Err(e) => {
                log!(Error, "Error sending packet: {}", e);
                sleep(500);
            }
            Ok(mut sock) => {
                loop {
                    let result = context.security_module().update_tool_recv(&mut sock);
                    log!(Debug, "Received reply to send");
                    match result {
                        Ok((command, reply_buf)) => {
                            log!(Debug, "Reply received is OK");

                            // Packet type sanity check
                            if (command != HSMUpdateACK) && (command != HSMUpdateNACK) {
                                // Got an odd packet - wait some more
                                log!(Error, "Got a unexpected packet - dropping");
                                continue;
                            }

                            let mut reply_slice = &reply_buf[..];
                            let reply_header = match CommonUpdatePacketHeader::unmarshal(&mut reply_slice)
                            {
                                Ok(t) => t,
                                Err(e) => {
                                    log!(Error, "Could not deserialize response: {}", e);
                                    continue;
                                }
                            };
                            // Right now replies have no body just a header. If/when we have replies with a body we'll
                            // we'll have to unmarshal them as well.
                            if !reply_slice.is_empty() {
                                reply_payload = reply_slice.to_vec();
                            }

                            if reply_header.packet_type != PacketType::Reply {
                                log!(Error, "Got a weird reply from HSM - dropping");
                                continue;
                            }


                            // Check sequenced_id
                            if reply_header.sequenced_id != packet.get_id() {
                                // Drop any response we're not expecting
                                log!(Warn, "Got an unexpected response id: expected {}, got {} - dropping",
                                     reply_header.sequenced_id, packet.get_id());
                                continue;
                            }
                            log!(Debug, "Got a valid reply for packet: {}", packet.get_id());


                            if command == HSMUpdateNACK {
                                // Got a NACK, fail fast and let caller figure out what to do.
                                log!(Warn, "The reply was a NACK!");
                                if retry_on_nack {
                                    break;
                                } else {
                                    return Err(MessageError::ReceivedNACK);
                                }
                            }
                            // Got an ack return success
                            log!(Debug, "The reply was an ACK");
                            context.inc_id();
                            return Ok(reply_payload);
                        }
                        Err(hsm_error) => match hsm_error {
                            hsm::Error::Io(io_error) => {
                                if io_error.kind() == io::ErrorKind::TimedOut {
                                    log!(Warn, "packet recv timed out: {} - retrying", io_error);
                                    status = MessageError::Timeout;
                                    break;
                                } else {
                                    log!(Error, "packet recv failed: {} - retrying", io_error);
                                    sleep(500);
                                    break;
                                }
                            }
                            _ => {
                                log!(Error, "packet recv failed: {} - retrying", hsm_error);
                                status = MessageError::HSMError(hsm_error);
                                sleep(500);
                                break;
                            }
                        },
                    }
                }
            }
        }
        trys += 1;
        log!(Debug, "On to send try #{}", trys);
    }
    log!(Error, "packet send failed, aborting");
    Err(status)
}

fn initiate_update_service_connection(options: &UpdateArgs) -> Result<TransferContext, Box<dyn std::error::Error>>{
    // Open socket to parallel_port/hsm
    let socket_path = format!("{}/{}", options.socket_path, Update as u8);
    let security_module = Box::new(LiquidHsm::new(socket_path));
    let mut context = TransferContext::new(security_module);

    // Send Sequence sync until ACK or timeout - all commuication with the HSM
    // needs to sync sequence_numbers first.
    let mut header: SyncSequenceIdOpPacket = SyncSequenceIdOpPacket::new();
    let op_result = send(&mut context, &mut header, true);
    match op_result {
        Ok(_) => {
            log!(Info, "Sequence ID's sync'ed with HSM");
        }
        Err(e) => {
            log!(Error, "Sync of sequence ID's failed: {}", e);
            return Err(format!("First packet send failed - aborted: {}", e).into());
        }
    }

    Ok(context)
}

fn update_operation(options: &UpdateArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Open file
    // At some point in the future it may make sense to read a file in chunks
    let mut file = match File::open(&options.file_path) {
        Ok(t) => t,
        Err(e) => {
            println!("Error opening file {}: {}", options.file_path, e.to_string());
            return Err("Exiting on error".into());
        }
    };
    let mut file_bytes = Vec::new();
    let length = file.read_to_end(&mut file_bytes)?;
    assert_eq!(length, file_bytes.len());

    // Create header packet
    if options.remote_file_path.as_bytes().len() > max_filename_length() {
        return Err("Destination filename too long".into());
    }
    let mut remote_filename: FileNameType = FileNameType {
        data: [0; max_filename_length()],
    };
    remote_filename.data[..options.remote_file_path.as_bytes().len()].clone_from_slice(options.remote_file_path.as_bytes());

    let file_length: u32 = u32::try_from(file_bytes.len())?;
    let mut engine = sha256::Hash::engine();
    engine.write_all(file_bytes.as_slice()).unwrap();
    let file_hash = sha256::Hash::from_engine(engine);

    // Now that sequence sync has been sent, send the signature message
    // to pre-authorize the upgrade payload
    // First, read off signature file
    let signature_file = match File::open(&options.sig_file_path) {
        Ok(t) => t,
        Err(e) => {
            println!("Error opening file {}: {}", options.sig_file_path, e.to_string());
            return Err("Exiting on error".into());
        }
    };

    let signature_reader = BufReader::new(signature_file);

    let secp = Secp256k1::verification_only();
    let mut bitcoin_message = "".to_owned();
    let mut bitcoin_message_serialized = Vec::new();
    let bitcoin_prefix = "\x18Bitcoin Signed Message:\n".to_owned();
    let mut signatures = Vec::new();

    for (index, line) in signature_reader.lines().enumerate() {
        let line = line.unwrap();
        // First line is the message being signed.
        if index == 0 {
            bitcoin_message = line.clone();
            bitcoin_message.consensus_encode(&mut bitcoin_message_serialized).unwrap();
        } else {
            let mut msg_engine = sha256d::Hash::engine();
            msg_engine.input(&bitcoin_prefix.as_bytes());
            // String.consensus_encode instead?
            VarInt(bitcoin_message.as_bytes().len() as u64).consensus_encode(&mut msg_engine).unwrap();
            msg_engine.input(bitcoin_message.as_bytes());

            let msg_hash_raw = sha256d::Hash::from_engine(msg_engine);
            let secp_message = secp256k1::Message::from_digest_slice(&msg_hash_raw[..]).unwrap();

            // Rest of lines follow "<pubkey> <signature>" format
            let pub_sig_pair : Vec<&str>  = line.split(" ").collect();
            if pub_sig_pair.len() == 1 {
                // No signature attached, stick no pubkey here
                signatures.push(None);
            } else {
                let pubkey = secp256k1::PublicKey::from_str(pub_sig_pair[0]).unwrap();
                let sig_bytes = base64::decode(pub_sig_pair[1]).unwrap();
                let secp_sig = secp256k1::ecdsa::Signature::from_compact(&sig_bytes[1..]).unwrap();
                // Verify the signed message
                if !secp.verify_ecdsa(&secp_message, &secp_sig, &pubkey).is_ok() {
                    println!("Upgrade signature verification failed: {}", line);
                    return Err("Exiting on error".into());
                }
                signatures.push(Some(secp_sig));
            }

        }
    }

    // Initialize the connection to the update service
    let mut context = initiate_update_service_connection(options)?;

    // Send authorize header until ACK or timeout
    let mut auth: AuthorizeUpgradePacket =  AuthorizeUpgradePacket::new(&bitcoin_message_serialized[..], &signatures);
    let op_result = send(&mut context, &mut auth, false );
    match op_result {
        Ok(_) => {
            log!(Info, "Upgrade auth ACK'ed");
        },
        Err(e) => {
            log!(Error, "Upgrade auth failed: {}", e);
            return Err("Upgrade auth send failed - aborted".into());
        }
    }

    // Send/resend header until ACK or timeout
    let mut header: BeginFileTransferOpPacket =
        BeginFileTransferOpPacket::new(&remote_filename, file_length, &file_hash);
    let op_result = send(&mut context, &mut header, false);
    match op_result {
        Ok(_) => {
            log!(Info, "File Header ACK'ed");
        }
        Err(e) => {
            log!(Error, "File Header send failed: {}", e);
            return Err("File Header send failed - aborted".into());
        }
    }

    // Loop to send parsed file packets
    const MAX_CHUNK_SIZE: usize = 4096;
    let chunk_start_id = context.get_id();
    let number_of_chunks = 1 + u32::try_from((file_bytes.len() - 1) / MAX_CHUNK_SIZE)?;
    for file_chunk in file_bytes.chunks(MAX_CHUNK_SIZE) {
        let mut file_chunk_packet = FileChunkPacket::new(file_chunk)?;
        // Right now tell send to retry on NACK unless it's the last packet
        let result = send(&mut context, &mut file_chunk_packet, true);
        let chunk_number = context.get_id() - chunk_start_id;
        match result {
            Ok(_) => {
                print!("\rSent {}/{} file chunks", chunk_number, number_of_chunks);
                let _i_dont_care_about_this_result = io::stdout().flush();
            }
            Err(e) => {
                log!(Error, "File chunk {} send failed: {}", chunk_number, e);
                println!();
                println!("Update failed, error on chunk {}: {}", chunk_number, e);
                return Err("File chunk send failed - aborted".into());
            }
        }
    }
    println!();

    let mut end_xfer_message = EndFileTransferOpPacket::new(&file_hash);
    let op_result = send(&mut context, &mut end_xfer_message, false);
    match op_result {
        Ok(_) => {
            log!(Info, "File successfully transfered");
            println!("File successfully transfered");
        }
        Err(e) => {
            log!(Info, "File checksum or save failed: {}", e);
            println!("File checksum or save failed");
            return Err("File transfer failed - aborting".into());
        }
    }

    log!(Info, "All file chunks sent!");

    //Send install trigger?
    let mut install_message =
        BeginInstallOpPacket::new(&remote_filename, &file_hash);
    let op_result = send(&mut context, &mut install_message, false);
    match op_result {
        Ok(_) => {
            log!(Info, "Install successfully initiated");
            println!("Install successfully initiated");
        }
        Err(_e) => {
            log!(Info, "Install initiation failed");
            println!("Install initiation failed");
            return Err("Install Failed!".into());
        }
    }

    Ok(())
}

fn get_version_operation(options: &UpdateArgs) -> Result<(), Box<dyn std::error::Error>>{
    let mut context = initiate_update_service_connection(options)?;
    let mut packet = GetFirmwareVersionOpPacket::new();
    let op_result = send(&mut context, &mut packet, true );
    match op_result {
        Ok(payload) => {
            log!(Info, "Get Firmware Version ACK'ed");
            // The version is transmitted as 8 bytes (hex encoded 4 byte unsigned int) in Big-Endian order.
            let value = match std::str::from_utf8(payload.as_slice()) {
                Ok(value) => value,
                Err(_) => {
                    println!("FAILED, Could not unpack firmware version response.");
                    return Err("Could not unpack firmware version response".into());
                }
            };
            println!("{}",value);
        },
        Err(e) => {
            log!(Error, "Get Firmware Version operation Failed: {}", e);
            return Err("Get Firmare Version operation Failed.".into());
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line options
    let mut a = env::args();
    let tool_name_path = a.next().unwrap_or("hsm_update_tool".into());
    let tool_name = filename_from_path(Path::new(&tool_name_path));

    let args: Vec<_> = a.collect();
    let mut update_args = UpdateArgs::default();
    let getarg_options = Options::new(&args);
    let options = match parse_args(&getarg_options, &mut update_args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("usage error: {}", e);
            usage(&tool_name);
            return Err("Usage".into());
        }
    };

    //Option compatibility check
    if options.operation == GUIOperations::Update {
        assert_ne!(options.remote_file_path,"");
        if options.sig_file_path == "" {
            eprintln!("Usage error: a signature file must be specified for updates (-f)");
            usage(&tool_name);
            return Err("Usage".into());
        }
    }
    if options.operation != GUIOperations::Update {
        if options.sig_file_path != "" {
            eprintln!("Usage error: A signature file is not required for a non-update operation.");
            usage(&tool_name);
            return Err("Usage".into());
        }
        if options.remote_file_path != "" {
            eprintln!("Usage error: A remote filename is not required for a non-update operation.");
            usage(&tool_name);
            return Err("Usage".into());
        }
    }


    match options.operation {
        GUIOperations::Update => {
            return update_operation(&options);
        },
        GUIOperations::GetVersion => {
            return get_version_operation(&options);
        },
        GUIOperations::Help => {
            usage(&tool_name);
            return Ok(());
        },
        GUIOperations::Unspecified => {
            eprintln!("Usage Error: Operation unspecified.");
            usage(&tool_name);
            return Err("Usage".into());
        }

    }

}
