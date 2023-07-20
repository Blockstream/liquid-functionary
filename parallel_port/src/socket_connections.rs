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

use crate::constants::HSM_NETWORK_MAGIC;
use crate::ParallelPortMessage;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

pub const MAX_SEQUENCE_NUMBER: u8 = 15;

/// A single socket connection for writing too and its current sequence number
pub struct SocketConnection {
    id: u16,
    stream: UnixStream,
    sequence_number: Arc<AtomicU8>,
    open_state: Arc<AtomicBool>,
}

impl SocketConnection {
    pub fn new(id: u16, stream: UnixStream) -> Self {
        Self {
            id,
            stream,
            sequence_number: Arc::new(AtomicU8::new(0u8)),
            open_state: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Get a handle to the state for this connection's sequence number and open status for use in another thread
    pub fn get_state(&self) -> ConnectionState {
        ConnectionState {
            sequence_number: self.sequence_number.clone(),
            open_status: self.open_state.clone(),
        }
    }

    /// Perform a thread-safe read of the this connections current sequence number
    pub fn sequence_number(&self) -> u8 {
        self.sequence_number.load(Ordering::SeqCst)
    }

    /// Is this connection still open?
    pub fn open(&self) -> bool {
        self.open_state.load(Ordering::SeqCst)
    }

    /// Attempt to send a message along this connection
    pub fn send_message(&mut self, message: ParallelPortMessage) -> Result<(), anyhow::Error> {
        self.stream.write_all(HSM_NETWORK_MAGIC.as_bytes())?;
        self.stream.write_all(message.header.serialize().as_slice())?;
        self.stream.write_all(message.payload.as_slice())?;

        Ok(())
    }
    pub fn id(&self) -> u16 {
        self.id
    }
}

pub struct ConnectionState {
    pub sequence_number: Arc<AtomicU8>,
    pub open_status: Arc<AtomicBool>,
}
/// A collection of connections for a given socket including the socket's "global" sequence number
/// counter contained in a thread-safe mutex
pub struct SocketConnections {
    socket_number: u8,
    connections: Vec<SocketConnection>,
    socket_sequence_number: Arc<Mutex<u8>>,
}

impl SocketConnections {
    pub fn new(socket_number: u8) -> Self {
        Self {
            socket_number,
            connections: vec![],
            socket_sequence_number: Arc::new(Mutex::new(0u8)),
        }
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn add_connection(&mut self, id: u16, stream: UnixStream) -> ConnectionState {
        let socket_connection = SocketConnection::new(id, stream);
        let connection_state = socket_connection.get_state();
        self.connections.push(socket_connection);
        connection_state
    }

    pub fn get_socket_sequence_number(&self) -> Arc<Mutex<u8>> {
        self.socket_sequence_number.clone()
    }

    /// Remove all connections which have been marked as closed but setting their sequence numbers to -1
    pub fn cleanup_connections(&mut self) {
        let socket_number = self.socket_number;
        self.connections.retain(|c| {
            if !c.open() {
                log!(Info, "Cleaning up socket {}  connection {}", socket_number, c.id(),);
                false
            } else {
                true
            }
        });
    }

    pub fn forward_message(&mut self, message: ParallelPortMessage) -> Result<(), anyhow::Error> {
        self.cleanup_connections();

        let mut num_forwarded = 0;
        let mut tried = false;
        let message_sequence_number = message.sequence_number.clone();
        for (position, connection) in self.connections.iter_mut().enumerate() {
            let connection_sequence_number = connection.sequence_number() as u8;

            let message_sequence_number_match = match message_sequence_number.as_ref() {
                None => true,
                Some(message_sequence_number) => {
                    connection_sequence_number == *message_sequence_number
                }
            };

            if connection_sequence_number == 0 || message_sequence_number_match {
                tried = true;
                log!(
                    Info,
                    "Sending message on socket {} connection {} with command {:#04x}, length {} and seqnum {}",
                    self.socket_number,
                    position,
                    message.header.command as u8,
                    message.len(),
                    message.sequence_number.unwrap_or(0),
                );
                if let Err(e) = connection.send_message(message.clone()) {
                    log!(
                        Error,
                        "Failed to forward message to socket {} connection {} with error {}",
                        self.socket_number,
                        position,
                        e
                    );
                    continue;
                }
                num_forwarded += 1;
            }
        }
        if !tried {
            log!(
                Debug,
                "Unable to find a corresponding socket connection for message {} on socket {}",
                message,
                self.socket_number
            );
        } else if tried && num_forwarded == 0 {
            // Feels like in this case we should throw an error so a Command::NackDeliveryFailed response is sent back to the HSM
            // but it was posited that the HSM can't do much about this so just going to log it for now.
            log!(
                Warn,
                "Dropped message (Command: {:04x}, Address: {:04x}, Return Address: {:04x}) from serial port to socket {} because of bad sequence number {:?}",
                message.header.command as u8,
                message.header.address as u8,
                message.header.return_address as u8,
                self.socket_number,
                message_sequence_number
            )
        } else {
            log!(
                Info,
                "Successfully forwarded message to {} connections on socket {}",
                num_forwarded,
                self.socket_number
            );
        }
        Ok(())
    }
}
