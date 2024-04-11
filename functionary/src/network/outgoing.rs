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


//! # Outgoing Connections
//!
//! Data structures representing outgoing connections to peers
//!

use std::{io, net, thread};
use std::io::Write;
use std::sync::Arc;
use std::time::{Instant, Duration};

use bitcoin::secp256k1;

use super::{NETWORK_MAGIC, Error};
use message;
use network::NetEncodable;
use utils::{self, ClearableQueue};

/// Number of messages that can be buffered to an outgoing-connection
/// thread before they are dropped.
const THREAD_CHANNEL_CAP: usize = 1024;

/// Maximum amount of time to allow for connecting to a peer
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Control message sent from the main networking thread to an outgoing
/// connection thread; not exposed outside of the networking module.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ThreadCtrl {
    /// The sending thread should stop; the peer is no longer part of
    /// consensus
    Shutdown,
    /// Network message to be sent
    Send(message::Message<secp256k1::ecdsa::Signature>),
    /// Signal to kick the `StatusAck` watchdog of the given peer.
    /// Once a `WatchdogKick` is received, the thread must receive
    /// a new one before the kick lifetime is up, or else the thread
    /// will assume its messages are not being received and shut
    /// down. The purpose is to detect stillborn connections.
    ///
    /// The main thread sends a `WatchdogKick` to all sending threads
    /// directed at peers in `Router::new`, and from there onward
    /// sends fresh kicks in response to every `StatusAck` message
    /// received from the peer.
    WatchdogKick(Instant),
}

/// Wrapper around a `SyncSender` which represents a channel into
/// a sending thread
#[derive(Clone)]
pub struct Thread {
    name: String,
    queue: Arc<ClearableQueue<ThreadCtrl>>,
}

/// A thread which maintains a single outgoing connection to a peer
impl Thread {
    /// Spawn a new network-sending thread
    pub fn spawn(name: &str, addr: &str, is_primary: bool, kick_lifetime: Duration) -> Thread {
        let name = format!("netsend_{}_{}", name, addr);
        let queue = ClearableQueue::with_capacity(THREAD_CHANNEL_CAP);

        let queue_ref = queue.clone();
        let addr = addr.to_owned();
        utils::spawn_named_or_die(name.to_owned(), move || {
            while let Err(e) = send_all_messages(kick_lifetime, addr.clone(), is_primary, &queue_ref) {
                log!(Warn, "Send loop failed: {}. Will retry in 30s.", e);
                // If the peer is actually down, we don't want to flood the logs.
                thread::sleep(Duration::from_secs(30));
            }
            log!(Info, "outgoing thread for {} shut down", addr);
        });

        Thread {
            name: name,
            queue: queue,
        }
    }

    /// Dispatch a message to the thread for network sending
    pub fn send_message(&self, msg: message::Message<secp256k1::ecdsa::Signature>) {
        let header = msg.header().clone();
        if let Err(e) = self.queue.send(ThreadCtrl::Send(msg)) {
            slog!(MessageDropped, connection: &self.name, message_type: "std",
                reason: e, header: Some(header.into()),
            );
        }
    }

    pub fn kick(&self) {
        let kick = ThreadCtrl::WatchdogKick(Instant::now());
        if let Err(e) = self.queue.send(kick) {
            slog!(MessageDropped, connection: &self.name, message_type: "kick",
                reason: e, header: None,
            );
        }
    }

    /// Clear the queue of messages.
    ///
    /// Shutdown signals are not cleared.
    pub fn clear(&self, round: u32) {
        let len = self.queue.len();
        self.queue.retain(|data| {
            match data {
                ThreadCtrl::Send(send_msg) => send_msg.header().round == round,
                ThreadCtrl::Shutdown => true,
                ThreadCtrl::WatchdogKick(..) => false,
            }
        });
        if self.queue.len() != len {
            slog!(QueuedMessagesCleared, connection: self.name.clone(),
                cleared_count: len - self.queue.len(), remaining_count: self.queue.len()
            );
        }
    }

    /// Shut down the thread.
    pub fn shutdown(&self) {
        log!(Trace, "shutting down outgoing thread {}", self.name);
        self.queue.clear();
        self.queue.send(ThreadCtrl::Shutdown).unwrap();
    }

    // (Testing only) create a test version of Thread
    #[cfg(test)]
    pub fn new_raw(name: String) -> Thread {
        let queue = ClearableQueue::with_capacity(THREAD_CHANNEL_CAP);
        Thread {
            name,
            queue,
        }
    }

    // (Testing only) accessor for an Arc of the internal queue
    #[cfg(test)]
    pub fn queue(&self) -> Arc<ClearableQueue<ThreadCtrl>> {
        self.queue.clone()
    }

}

/// Utility function to send a single message on a socket
fn send_message(
    msg: &message::Message<secp256k1::ecdsa::Signature>,
    mut sock: impl Write,
) -> Result<(), Error> {
    // http://www.softlab.ntua.gr/facilities/documentation/unix/unix-socket-faq/unix-socket-faq-2.html
    // "If the peer calls close() or exits...I would expect EPIPE, not on the
    // next call, but the one after."
    // That is, to detect a dead connection (so we can requeue the message)
    // we should use at least two calls to `write`.
    sock.write_all(&NETWORK_MAGIC[0..2])?;
    sock.write_all(&NETWORK_MAGIC[2..4])?;
    match msg.encode(&mut sock) {
        Ok(bytes_sent) => {
            let bytes = bytes_sent + NETWORK_MAGIC.len();
            slog!(MessageSent, message_type: msg.header().command.text(), bytes);
            sock.flush()?; // nb In current rustlib this is a no-op
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Utility function to connect to a socket
fn connect_timeout(
    addr: impl net::ToSocketAddrs,
    is_primary: bool,
) -> Result<net::TcpStream, io::Error> {
    let addr_iter = net::ToSocketAddrs::to_socket_addrs(&addr)?;
    let mut connect_err = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no addresses to connect to",
    );
    for addr in addr_iter {
        match net::TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                s.set_nodelay(true)?;
                return Ok(s);
            },
            Err(e) => {
                if is_primary {
                    log!(Warn, "Failed to connect to {}: {}", addr, e);
                } else {
                    log!(Debug, "Failed to connect to secondary address {}: {}", addr, e);
                }
                connect_err = e;
            },
        };
    }
    Err(connect_err)
}

/// Utility function to create a connection and send messages until error
fn send_all_messages(
    kick_lifetime: Duration,
    net_address: impl net::ToSocketAddrs,
    is_primary: bool,
    queue: &Arc<ClearableQueue<ThreadCtrl>>,
) -> Result<(), Error> {
    log!(Trace, "connecting");
    let mut s = connect_timeout(net_address, is_primary)?;
    log!(Debug, "successful outgoing connection established");

    let mut last_kick = Instant::now();

    loop {
        if last_kick.elapsed() > kick_lifetime {
            return Err(Error::WatchdogDied);
        }

        match queue.receive() {
            ThreadCtrl::Shutdown => break,
            ThreadCtrl::WatchdogKick(kick) => {
                last_kick = kick;
                log!(Trace, "kicked watchdog.");
            }
            ThreadCtrl::Send(msg) => {
                let header = msg.header().clone();
                log!(Trace, "sending {:?}", header);
                if let Err(e) = send_message(&msg, &mut s) {
                    if let Err(e) = queue.requeue(ThreadCtrl::Send(msg)) {
                        slog!(MessageDropped, connection: "internal", message_type: "std",
                              reason: e, header: Some(header.into()),
                        );
                    }
                    return Err(e);
                }
            }
        }
    }

    // explicitly shutdown because rust stdlib seems inconsistent about doing it on drop
    let _ = s.shutdown(net::Shutdown::Both);
    Ok(())
}

