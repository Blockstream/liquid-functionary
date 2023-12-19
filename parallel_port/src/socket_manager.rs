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

use crate::constants::HSM_NUM_SOCKETS;
use crate::message::{MessageSource, ParallelPortMessage};
use crate::socket_connections::SocketConnections;
use crate::socket_listener::SocketListener;
use crate::ParallelPortConfig;
use anyhow::{bail, Context};
use functionary_common::hsm::MESSAGE_VERSION;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::{fs, thread};

/// The Socket Manager initializes all the sockets, launches their listener threads and holds a handle
/// to the SocketConnections for each socket which is used to send messages via those connections.
/// The message stream is also held here in a take-only-once Option. All the validate messages received
/// on any connections will be funneled into this message stream for the main program to handle.
pub struct SocketManager {
    socket_connections: Vec<Arc<Mutex<SocketConnections>>>,
}

impl SocketManager {
    pub fn initialize(
        path_str: &str,
        message_bus_tx: SyncSender<MessageSource<ParallelPortMessage>>,
        config: &ParallelPortConfig,
    ) -> Result<Self, anyhow::Error> {
        let path = Path::new(path_str);

        let mut socket_connections = Vec::with_capacity(HSM_NUM_SOCKETS as usize);

        for i in 0..HSM_NUM_SOCKETS {
            let address_path = path.join(i.to_string());
            if address_path.exists() {
                fs::remove_file(&address_path).context(format!(
                    "Couldn't remove old socket path {}",
                    address_path.to_str().unwrap()
                ))?;
            }
            match UnixListener::bind(&address_path) {
                Ok(listener) => {
                    log!(Info, "Socket {} started listening on {:?}", i, address_path.as_os_str());
                    let this_sockets_connections = Arc::new(Mutex::new(SocketConnections::new(i)));
                    let listener = SocketListener::new(
                        i,
                        listener,
                        message_bus_tx.clone(),
                        this_sockets_connections.clone(),
                        config.increment_sequence_numbers,
                    );
                    socket_connections.push(this_sockets_connections);
                    thread::Builder::new()
                        .name(format!("socket {} listener", i))
                        .spawn(move || listener.run())
                        .unwrap_or_else(|_| panic!("Couldn't spawn thread for socket {}", i));
                }
                Err(e) => anyhow::bail!(
                    "Problem opening socket {} on {}: {}",
                    i,
                    address_path.to_str().unwrap(),
                    e
                ),
            }
        }
        Ok(Self {
            socket_connections,
        })
    }

    /// Forward a message to the sockets. The message will be forwarded to the appropriate connections
    /// based on address and sequence number.
    pub fn forward_message(&mut self, message: ParallelPortMessage) -> Result<(), anyhow::Error> {
        if message.header.address as u8 >= HSM_NUM_SOCKETS {
            bail!(
                "Unsupported address: (Command: {:04x}, Address: {:04x}, Return Address: {:04x})",
                message.header.command as u8,
                message.header.address as u8,
                message.header.return_address as u8
            );
        }

        if message.header.version != MESSAGE_VERSION {
            bail!("Internal version mismatch {}, cannot forward message (Command: {:04x}, Address: {:04x}, Return Address: {:04x})",
                message.header.version,
                message.header.command as u8,
                message.header.address as u8,
                message.header.return_address as u8);
        }

        let mut socket_connections_guard = self.socket_connections[message.header.address as usize]
            .lock()
            .expect("Socket Connection collections poisoned");

        (*socket_connections_guard).forward_message(message)?;

        Ok(())
    }
}
