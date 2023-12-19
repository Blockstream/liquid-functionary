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

use crate::config::MAX_CONNECTIONS_PER_SOCKET;
use crate::message::ParallelPortMessage;
use crate::socket_connection_listener::ConnectionListener;
use crate::socket_connections::SocketConnections;
use crate::MessageSource;
use std::os::unix::net::UnixListener;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

/// Represents a thread that will listen for connections on a given socket, designated by a socket_number
/// When connections are received it will spawn a new thread to listen the new connection and create an
/// entry in the Socket's socket_connections collection for send via this new connection
pub struct SocketListener {
    socket_number: u8,
    listener: UnixListener,
    message_sender: mpsc::SyncSender<MessageSource<ParallelPortMessage>>,
    socket_connections: Arc<Mutex<SocketConnections>>,
    // Used to indicate if sequence numbers are being used or not based on the HSM_SEQNUM_ENABLED
    // environment variable
    increment_sequence_numbers: bool,
    // An ID to help distinguish connections in the logs, it will roll over so IDs will be reused
    // after 2^16 connections
    current_connection_id: u16,
}

impl SocketListener {
    pub fn new(
        socket_number: u8,
        listener: UnixListener,
        message_sender: mpsc::SyncSender<MessageSource<ParallelPortMessage>>,
        socket_connections: Arc<Mutex<SocketConnections>>,
        increment_sequence_numbers: bool,
    ) -> Self {
        Self {
            socket_number,
            listener,
            message_sender,
            socket_connections,
            increment_sequence_numbers,
            current_connection_id: 0,
        }
    }

    pub fn run(mut self) {
        loop {
            match self.listener.accept() {
                Ok((connection, _address)) => {
                    let mut socket_connections_guard =
                        self.socket_connections.lock().expect("Socket Map mutex was poisoned");

                    (*socket_connections_guard).cleanup_connections();
                    if (*socket_connections_guard).len() > MAX_CONNECTIONS_PER_SOCKET {
                        log!(
                            Warn,
                            "Unable to accept connection on socket {}, already have {}",
                            self.socket_number,
                            (*socket_connections_guard).len()
                        );
                        continue;
                    }

                    let connection_id = self.current_connection_id;
                    self.current_connection_id += 1;

                    log!(
                        Debug,
                        "Opening socket {} connection {} ({} open connections on socket)",
                        self.socket_number,
                        connection_id,
                        (*socket_connections_guard).len() + 1,
                    );

                    let connection_state = (*socket_connections_guard).add_connection(
                        connection_id,
                        connection.try_clone().expect("Can't clone socket connection"),
                    );
                    let socket_sequence_number =
                        (*socket_connections_guard).get_socket_sequence_number();

                    let monitor = ConnectionListener::new(
                        connection_id,
                        self.socket_number,
                        connection,
                        self.message_sender.clone(),
                        socket_sequence_number,
                        connection_state,
                        self.increment_sequence_numbers,
                    );

                    thread::Builder::new()
                        .name(format!(
                            "socket {} connection {} listener",
                            self.socket_number, connection_id,
                        ))
                        .spawn(move || monitor.run())
                        .expect("couldn't spawn thread");
                }
                Err(e) => {
                    log!(
                        Warn,
                        "Error accepting connection on socket {}: {}",
                        self.socket_number,
                        e
                    );
                }
            }
        }
    }
}
