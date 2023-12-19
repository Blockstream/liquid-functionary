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

use crate::error::Error;
use crate::frame_reader::FrameReader;
use crate::{MessageSource, ParallelPortMessage};
use functionary_common::hsm::MESSAGE_VERSION;
use serialport::SerialPort;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

pub struct SerialListener {
    port: Box<dyn SerialPort>,
    message_sender: SyncSender<MessageSource<ParallelPortMessage>>,
    remote_hsm_message_version: Arc<AtomicU8>,
    shutdown_flag: Arc<AtomicBool>,
}

impl SerialListener {
    pub fn new(
        port: Box<dyn SerialPort>,
        message_sender: SyncSender<MessageSource<ParallelPortMessage>>,
        remote_hsm_message_version: Arc<AtomicU8>,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            port,
            message_sender,
            remote_hsm_message_version,
            shutdown_flag,
        }
    }

    pub fn run(self) {
        let mut frame_reader = FrameReader::new(self.port);
        log!(Debug, "Starting serial listener");
        loop {
            match frame_reader.next_frame::<ParallelPortMessage>() {
                Ok(None) => {
                    log!(Warn, "Serial connection closed");
                    break;
                }
                Ok(Some(message)) => {
                    // Remote version check
                    if message.header.version
                        > self.remote_hsm_message_version.load(Ordering::SeqCst)
                    {
                        if message.header.version > MESSAGE_VERSION {
                            log!(Error,"Got a message version that's higher ({}) than supported ({}), this should never happen!", message.header.version, MESSAGE_VERSION);
                        } else {
                            log!(
                                Info,
                                "Ratcheting remote message version from {} to {}",
                                self.remote_hsm_message_version.load(Ordering::SeqCst),
                                message.header.version
                            );
                            self.remote_hsm_message_version
                                .store(message.header.version, Ordering::SeqCst);
                        }
                    }

                    log!(
                        Debug,
                        "Got message from serial port: command {:#04x}, address {:#04x}, length {}",
                        message.header.command as u8,
                        message.header.address as u8,
                        message.header.length
                    );
                    if let Err(e) = message.validate() {
                        log!(Warn, "Received invalid message on serial port: {}", e);
                    }
                    if let Err(e) = self.message_sender.send(MessageSource::Serial(message)) {
                        log!(Error, "Problem forwarding message from serial port: {}", e);
                        break;
                    }
                }
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::TimedOut => {
                    if self.shutdown_flag.load(Ordering::SeqCst) {
                        log!(Warn, "Shutting down serial port listener");
                        break;
                    }
                }
                Err(e) => {
                    log!(Error, "Error reading next message from serial port: {}", e);
                    break;
                }
            }
        }
    }
}
