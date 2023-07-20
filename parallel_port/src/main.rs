//{{ Liquid }}
//Copyright (C) {{ 2022 }}  {{ Blockstream }}

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

mod config;
mod error;
mod frame_reader;
mod constants;
mod message;
mod serial_manager;
mod serial_port_listener;
mod socket_connection_listener;
mod socket_connections;
mod socket_listener;
mod socket_manager;

#[macro_use]
extern crate functionary_logs;
use crate::config::{ParallelPortConfig, CHANNEL_BUFFER_SIZE};
use crate::message::{MessageSource, ParallelPortMessage};
use crate::serial_manager::SerialPortManager;
use crate::socket_manager::SocketManager;
use anyhow::bail;
use bitcoin::hashes::hex::ToHex;
use clap::{App, Arg};
use functionary_common::hsm::{Address, Command, MESSAGE_VERSION};
use functionary_logs::Severity::Debug;
use constants::FUNCTIONARY_VERSION;
use std::ops::Div;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::{io, thread};

const EXIT_FAILURE: i32 = 1;

fn main_inner() -> anyhow::Result<()> {
    let matches = App::new("HSM Parallel Port Multiplexer Daemon")
        .version("0.1.0")
        .arg(
            Arg::with_name("serial_port")
                .index(1)
                .help("Path to serial port connecting host to HSM")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sockets_dir")
                .help("Directory path where Unix sockets will be created")
                .index(2)
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let (serial_port_path, sockets_dir) =
        match (matches.value_of("serial_port"), matches.value_of("sockets_dir")) {
            (Some(serial_port), Some(sockets_dir)) => (serial_port, sockets_dir),
            (_, _) => bail!("Could not parse command line arguments"),
        };

    functionary_logs::initialize(Debug, None, None, "parallel_port", Box::new(io::stderr()));

    log!(Info, "Functionary Software Version  : {}", FUNCTIONARY_VERSION);
    log!(Info, "Using: {} {}", serial_port_path, sockets_dir);

    let config = ParallelPortConfig::default();
    if config.increment_sequence_numbers {
        log!(Info, "HSM sequence numbers enabled");
    }

    // Setup
    let (message_bus_tx, message_bus_rx) = mpsc::sync_channel(CHANNEL_BUFFER_SIZE);
    let mut socket_manager =
        SocketManager::initialize(sockets_dir, message_bus_tx.clone(), &config)?;
    let mut serial_port_manager =
        SerialPortManager::new(serial_port_path, &config, message_bus_tx.clone())?;
    serial_port_manager.open()?;

    // Main Loop

    let mut last_serial_message_received = Instant::now();
    let mut last_heartbeat = Instant::now();
    let quarter_heartbeat = config.heartbeat_period.div(4);
    loop {
        // Query remote HSM version if remote HSM version is unknown
        // Host only functionality
        let remote_msg_version = serial_port_manager.get_remote_hsm_message_version();
        if remote_msg_version == 0 {
            log!(Info, "Querying for remote version info");
            if let Err(e) = serial_port_manager.send_empty_message(
                Address::ParallelPort,
                Address::ParallelPort,
                Command::HSMGetVersion,
                MESSAGE_VERSION,
            ) {
                log!(Error, "Couldn't send HSM get version via serial: {}", e);
                serial_port_manager.cycle()?;
            }
            log!(Debug, "Sleeping 5 seconds before continuing");
            thread::sleep(Duration::from_secs(5));
        }

        // Poll for any received messages from Serial port

        match message_bus_rx.recv_timeout(quarter_heartbeat) {
            Ok(MessageSource::Socket(message)) => {
                let header = message.header.clone();
                if let Err(e) = serial_port_manager.write_message(message) {
                    log!(Error, "Error forwarding socket message (Command: {:04x}, Address: {:04x}, Return Address: {:04x}) to serial: {}", header.command as u8, header.address as u8, header.return_address as u8, e);

                    serial_port_manager.cycle()?
                }
            }
            Ok(MessageSource::Serial(message)) => {
                last_serial_message_received = Instant::now();

                // On the host side there should be very few messages handled by the parallel port
                // The messages that the HSM side parallel port C implementation currently fields but are excluded from this Rust implementation are recorded in
                // comments below.
                //Command::TamperDetectResponse - apparently not currently being used?
                //Command::TamperDetectEnable
                //Command::HSMInit
                //Command::HSMInitReply
                //Command::HSMGetRtcTime
                //Command::HSMAddEntropy
                //Command::HSMGetSigningKey
                //Command::HSMGetRestoreKey
                //Command::HSMGetVersion
                if message.header.address == Address::ParallelPort {
                    match message.header.command {
                        // NackInternal V1 HSM w/o a RTC sends this in reply to GET_RTC_TIME
                        // HSMRtcTimeReply used for V1 HSM
                        Command::HSMGetVersionReply
                        | Command::NackInternal
                        | Command::HSMRtcTimeReply => (),
                        Command::HsmOnFire => {
                            log!(
                                Error,
                                "Received HSM_ON_FIRE message: {}",
                                message.payload.to_hex()
                            );
                        }
                        Command::HSMHeartbeat => {
                            log!(Debug, "Heartbeat request received");
                            if let Err(e) = serial_port_manager.send_empty_message(
                                message.header.return_address,
                                Address::ParallelPort,
                                Command::HSMHeartbeatReply,
                                remote_msg_version,
                            ) {
                                log!(Error, "Couldn't send heartbeat reply via serial: {}", e);
                                serial_port_manager.cycle()?;
                            }
                        }
                        Command::HSMHeartbeatReply => {
                            log!(Debug, "Heartbeat reply received");
                        }
                        _ => {
                            log!(
                                Error,
                                "Should not receive an unhandled message for Parallel Port: {}",
                                message
                            );
                            if let Err(e) = serial_port_manager.send_empty_message(
                                message.header.return_address,
                                Address::ParallelPort,
                                Command::NackUnsupported,
                                remote_msg_version,
                            ) {
                                log!(Error, "Couldn't send nack unsupported via serial: {}", e);
                                serial_port_manager.cycle()?;
                            }
                        }
                    }
                } else {
                    attempt_forward_message_from_serial(
                        message,
                        remote_msg_version,
                        &mut socket_manager,
                        &mut serial_port_manager,
                    );
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => bail!("Message bus disconnected"),
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        }

        // Check the serial activity watchdog
        if last_serial_message_received.elapsed() > 2 * config.heartbeat_period {
            log!(Info, "Serial port inactivity timeout");
            serial_port_manager.cycle()?;
            last_serial_message_received = Instant::now();
        } else if last_serial_message_received.elapsed() > config.heartbeat_period
            && last_heartbeat.elapsed() > config.heartbeat_period
        {
            log!(Debug, "Sending heartbeat request");
            if let Err(e) = serial_port_manager.send_empty_message(
                Address::ParallelPort,
                Address::ParallelPort,
                Command::HSMHeartbeat,
                remote_msg_version,
            ) {
                log!(Error, "Problem sending heartbeat request: {}", e);
            }
            last_heartbeat = Instant::now();
        }
    }
}

fn main() {
    if let Err(error) = main_inner() {
        // This formatting is based on anyhow's fmt::Debug impl.
        eprintln!("ERROR: {}", error);
        if let Some(cause) = error.source() {
            println!("");
            eprintln!("Caused by:");
            for error in anyhow::Chain::new(cause) {
                eprintln!(" * {}", error);
            }
        }
        ::std::process::exit(EXIT_FAILURE);
    }
    ::std::process::exit(0);
}

fn attempt_forward_message_from_serial(
    message: ParallelPortMessage,
    remote_msg_version: u8,
    socket_manager: &mut SocketManager,
    serial_port_manager: &mut SerialPortManager,
) {
    let return_address = message.header.return_address;
    let command = message.header.command;
    let address = message.header.address;
    if let Err(e) = socket_manager.forward_message(message) {
        log!(Error, "Error forwarding serial message (Command: {:04x}, Address: {:04x}, Return Address: {:04x}) - {}", command as u8, address as u8, return_address as u8, e);
        if let Err(e) = serial_port_manager.send_empty_message(
            return_address,
            Address::ParallelPort,
            Command::NackDeliveryFailed,
            remote_msg_version,
        ) {
            log!(Error, "Error forwarding nack delivery failed via serial: {}", e);
        }
    }
}
