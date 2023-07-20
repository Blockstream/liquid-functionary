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

use crate::frame_reader::FrameReader;
use crate::message::ParallelPortMessage;
use crate::socket_connections::{ConnectionState, MAX_SEQUENCE_NUMBER};
use crate::MessageSource;
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex};

/// Represents a thread that is listening to an open socket connection stream and parsing the ParallelPortMessages
/// from that stream using a FrameReader and the ParallelPortMessage Decoder trait implemenation.
/// Successfully parsed messages have a sequence number added and are passed to the message reader channel
/// for this Socket.
pub struct ConnectionListener {
    connection_id: u16,
    socket_number: u8,
    message_sender: mpsc::SyncSender<MessageSource<ParallelPortMessage>>,
    frame_reader: FrameReader<UnixStream>,
    socket_sequence_number: Arc<Mutex<u8>>,
    connection_state: ConnectionState,
    increment_sequence_numbers: bool,
}

impl ConnectionListener {
    pub fn new(
        connection_id: u16,
        socket_number: u8,
        stream: UnixStream,
        message_sender: mpsc::SyncSender<MessageSource<ParallelPortMessage>>,
        socket_sequence_number: Arc<Mutex<u8>>,
        connection_state: ConnectionState,
        increment_sequence_numbers: bool,
    ) -> Self {
        Self {
            connection_id,
            socket_number,
            message_sender,
            frame_reader: FrameReader::new(stream),
            socket_sequence_number,
            connection_state,
            increment_sequence_numbers,
        }
    }

    pub fn run(mut self) {
        loop {
            match self.frame_reader.next_frame::<ParallelPortMessage>() {
                Ok(None) => {
                    log!(
                        Debug,
                        "Socket {} connection {} closed",
                        self.socket_number,
                        self.connection_id
                    );

                    break;
                }
                Ok(Some(mut message)) => {
                    if self.increment_sequence_numbers {
                        self.add_sequence_number(&mut message);
                    }
                    log!(Debug, "Got message from socket: command {:#04x}, address {:#04x}, length {}, seqnum: {} (socket {} connection {})",
                            message.header.command as u8, message.header.address as u8, message.header.length, message.sequence_number.unwrap_or(0),  self.socket_number, self.connection_id);
                    if let Err(e) = message.validate() {
                        log!(
                            Warn,
                            "Received invalid message on socket {} connection {} : {}",
                            self.socket_number,
                            self.connection_id,
                            e
                        );
                        continue;
                    }

                    if let Err(e) = self.message_sender.send(MessageSource::Socket(message)) {
                        log!(
                            Warn,
                            "Problem forwarding message from socket {} connection {}: {}",
                            self.socket_number,
                            self.connection_id,
                            e
                        );
                        break;
                    }
                }
                Err(e) => {
                    log!(
                        Error,
                        "Error reading next message from socket {} connection {}: {}",
                        self.socket_number,
                        self.connection_id,
                        e
                    );
                    break;
                }
            }
        }
        // Mark the sender portion of this connection for cleanup
        self.connection_state.open_status.store(false, Ordering::SeqCst);
    }

    pub fn add_sequence_number(&self, message: &mut ParallelPortMessage) {
        let mut socket_sequence_number_guard =
            self.socket_sequence_number.lock().expect("Socket sequence number mutex was poisoned");
        (*socket_sequence_number_guard) += 1;
        if (*socket_sequence_number_guard) > MAX_SEQUENCE_NUMBER {
            (*socket_sequence_number_guard) = 1;
        }

        self.connection_state
            .sequence_number
            .store(*socket_sequence_number_guard, Ordering::SeqCst);

        message.set_sequence_number(*socket_sequence_number_guard);
    }
}
