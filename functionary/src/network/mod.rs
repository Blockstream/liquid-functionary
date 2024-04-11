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

//! # Networking
//! Code to send and receive network messages
//!

mod outgoing;
mod queue;

use std::io::{self, Read};
use std::{fmt, net, thread};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::{self, Secp256k1};
use time::now_utc;

use common::{network, network::NetEncodable};
use dynafed;
use message;
use peer;
use rotator::MainCtrl;
use utils;

use self::queue::MessageQueue;

/// Network magic bytes
pub static NETWORK_MAGIC: [u8; 4] = [0x4c, 0x6f, 0x52, 0x44];

/// This should ideally be a function of the maximum number of peers supported/expected, the round
/// time, the channel timeout time, and the anticipated number of network transports (tor, vpn,
/// etc.).  For now, 4096 is arbitrarily deemed large enough to handle 15 peers.
const MAXIMUM_INCOMING_PEER_CONNECTIONS: usize = 4096;

/// A network error
#[derive(Debug)]
pub enum Error {
    /// I/O error reading from the network
    Io(io::Error),
    /// Message header had the wrong version
    BadVersion,
    /// Sending-thread watchdog died (did not receive ACKs in time)
    WatchdogDied,
    /// The message itself was bad
    Message(network::Error)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => fmt::Display::fmt(e, f),
            Error::BadVersion => f.write_str("incoming message with wrong version"),
            Error::WatchdogDied => f.write_str("ACK watchdog died"),
            Error::Message(ref e) => fmt::Display::fmt(e, f)
        }
    }
}

#[doc(hidden)]
impl From<network::Error> for Error {
    fn from(e: network::Error) -> Error {
        Error::Message(e)
    }
}

#[doc(hidden)]
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

/// A message sent across a channel to the network thread
#[derive(Debug)]
pub enum NetworkCtrl {
    /// Signals the network thread that the current round number has changed
    NewRoundNumber(u32),
    /// There is a dynamic federation peer list update that the network
    /// thread should wait for
    DynafedUpdate(dynafed::ArcBarrier<::dynafed::UpdateNotif>),
    /// Network message to be sent
    Send(message::Message<message::Unsigned>),
    /// Signal to kick the `StatusAck` watchdog of the given peer
    WatchdogKick(peer::Id),
    /// Network message received from the wire
    IncomingMessage(message::Message<secp256k1::ecdsa::Signature>),
    /// Network connection opened from a peer
    IncomingConnection(net::TcpStream),
}

impl From<message::Message<message::Unsigned>> for NetworkCtrl {
    fn from(msg: message::Message<message::Unsigned>) -> NetworkCtrl {
        NetworkCtrl::Send(msg)
    }
}

/// Network-related peer data
#[derive(Clone)]
struct PeerData {
    /// Peer's communication public key
    comm_pk: secp256k1::PublicKey,
    /// Outgoing direct connection(s) to the peer
    outgoing: Vec<outgoing::Thread>,
}

impl PeerData {
    /// Create a [PeerData] for the given peer description.
    /// Set `connect` to `false` if you don't want to start outgoing
    /// message threads for this peer (f.e. for yourself).
    fn from_desc(desc: &peer::Peer, connect: bool, kick_lifetime: Duration) -> Self {
        PeerData {
            comm_pk: desc.comm_pk,
            outgoing: if connect {
                desc.addresses.iter().enumerate().map(|(n, addr)|
                    outgoing::Thread::spawn(&desc.name, addr, n == 0, kick_lifetime)
                ).collect()
            } else {
                Vec::new()
            },
        }
    }
}

impl peer::VerifySig for PeerData {
    fn verify_sig<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        msghash: &secp256k1::Message,
        signature: &secp256k1::ecdsa::Signature,
    ) -> Result<(), secp256k1::Error> {
        secp.verify_ecdsa(msghash, signature, &self.comm_pk)
    }
}

/// Structure which keeps track of all incoming connections to ensure we are
/// not overwhelmed
struct IncomingConnectionTracker {
    /// Array of receivers used to detect when an incoming connection thread has died
    recv: Vec<Option<mpsc::Receiver<()>>>
}

impl IncomingConnectionTracker {
    /// Creates a connection tracker
    fn new(max_incoming: usize) -> IncomingConnectionTracker {
        let mut vec = Vec::with_capacity(max_incoming);
        for _ in 0..max_incoming {
            vec.push(None);
        }
        IncomingConnectionTracker {
            recv: vec
        }
    }

    /// Attempts to allocate a new incoming connection
    fn allocate(&mut self) -> Result<mpsc::SyncSender<()>, ()> {
        let empty = Err(mpsc::TryRecvError::Empty);
        for slot in &mut self.recv {
            // Look for a slot that is either already `None`, or is occupied
            // by a thread whose sender has been dropped. (If the thread is
            // alive, it will be holding a sender, so when we try to read from
            // it we will get a `TryRecvError::Empty` error; otherwise we will
            // get some other error indicating that the thread has gone away).
            if slot.as_mut().filter(|x| x.try_recv() == empty).is_none() {
                let (tx, rx) = mpsc::sync_channel(0);
                *slot = Some(rx);
                return Ok(tx);
            }
        }
        Err(())
    }
}

/// Utility function to find the start of a network message
pub fn read_and_consume_magic<R: Read>(mut s: R, magic: &[u8], timeout: Duration) -> Result<(), io::Error> {
    let mut i = 0;
    let mut skipped_char_count: u32 = 0;
    let start_time = Instant::now();

    loop {
        let mut buf = [0];
        s.read_exact(&mut buf)?;
        if start_time.elapsed() > timeout {
            log!(Debug, "read_and_consume_magic: timeout after {} skipped characters", skipped_char_count);
            return Err(io::Error::new(io::ErrorKind::TimedOut, "timeout when seeking magic"));
        }
        if buf[0] == magic[i] {
            i += 1;
        } else if buf[0] == magic[0] {
            skipped_char_count = skipped_char_count.saturating_add(1);
            i = 1;
        } else {
            skipped_char_count = skipped_char_count.saturating_add(1);
            i = 0;
        }
        if i == magic.len() {
            if skipped_char_count > 0 {
                log!(Trace, "read_and_consume_magic: success after {} skipped characters", skipped_char_count);
            }
            return Ok(());
        }
    }
}

/// Wrap a socket with a counter
pub struct MeteredSocket<'a> {
    socket: &'a net::TcpStream,
    read_count: usize,
}

impl <'a> MeteredSocket<'a> {
    /// Make a new wrapped socket, initializing count to zero
    pub fn new(socket: &'a net::TcpStream) -> MeteredSocket {
        MeteredSocket {
            socket,
            read_count: 0,
        }
    }

    /// reset count to zero
    pub fn reset_count(&mut self) {
        self.read_count = 0;
    }

    /// return read byte count
    pub fn count(&self) -> usize {
        self.read_count
    }

    /// look at the bytes without removing them from the stream
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.peek(buf)
    }
}

impl <'a> Read for MeteredSocket<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read_size = self.socket.read(buf)?;
        self.read_count += read_size;
        Ok(read_size)
    }
}


/// Peek into the socket to read the first 68 bytes and extract the version field.
pub fn peek_version(sock: &mut MeteredSocket, timeout: Duration, buf: &mut [u8]) -> Result<u32, Error> {
    debug_assert_eq!(buf.len(), 68);
    // The version is encoded as the 4 bytes after the 64-byte signature.
    let start_time = Instant::now();
    loop {
        let n = sock.peek(&mut buf[..])?;
        if n == 68 {
            return Ok(NetEncodable::decode(&buf[64..68])?);
        }
        if start_time.elapsed() > timeout {
            return Err(Error::Io(io::Error::new(io::ErrorKind::TimedOut, "timeout peeking version")));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// The thread that will read messages from a peer stream.
fn peer_read_thread(
    mut sock: net::TcpStream,
    tx: mpsc::SyncSender<NetworkCtrl>,
    read_timeout: Duration,
) {
    let mut version_peek_buf = [0u8; 68];
    let mut metered_socket = MeteredSocket::new(&mut sock);
    let err = loop {
        metered_socket.reset_count();
        if let Err(e) = read_and_consume_magic(&mut metered_socket, &NETWORK_MAGIC, read_timeout) {
            break Error::Io(e);
        }

        match peek_version(&mut metered_socket, read_timeout, &mut version_peek_buf) {
            Ok(v) if v >= message::MESSAGE_VERSION => match message::Message::decode(&mut metered_socket) {
                Ok(msg) => {
                    slog!(MessageReceived, message_type: msg.header().command.text(), bytes: metered_socket.count());
                    tx.send(NetworkCtrl::IncomingMessage(msg)).unwrap()
                }
                Err(e) => break e.into(),
            },
            Ok(v) => log!(Trace, "dropping message with unexpected version: {}", v),
            Err(e) => break e,
        }
    };
    log!(Debug, "Failed to read message from {:?}. Dropping connection (inbound): {}",
        thread::current().name(), err,
    );
    let _ = sock.shutdown(net::Shutdown::Both); // explicitly shutdown because rust stdlib seems inconsistent about doing it on drop
}

fn bind(listener: net::TcpListener, tx: mpsc::SyncSender<NetworkCtrl>) {
    utils::spawn_named_or_die(format!("net_bind_{}", listener.local_addr().unwrap()).to_owned(), move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => tx.send(NetworkCtrl::IncomingConnection(s)).unwrap(),
                Err(e) => {
                    // This only appears to happen in case there is a problem with the local host.
                    // `listener.incoming()` may return the error continuously resulting in a spin
                    // loop (see
                    // https://github.com/rust-lang/rust/issues/29363#issuecomment-185299515).
                    // Therefore the sleep statement below was added to prevent filling the disk
                    // with log lines.
                    log!(Warn, "Failed incoming connection: {}. Not accepting any more for 30s.", e);
                    thread::sleep(Duration::from_secs(30));
                }
            }
        }
    });
}

/// Main interface to the networking code for the rest of the program
pub struct Router {
    /// Network addresses on which to listen
    addresses: Vec<String>,
    /// Set of outgoing connections to peers
    peers: peer::Map<PeerData>,
    /// Secret key used for signing outgoing messages
    signing_context: message::SigningContext<secp256k1::SignOnly>,
    /// Timeout used throughout the blocking network code
    read_timeout: Duration,
}

impl Router {
    /// Create a new connection manager
    pub fn new(
        addresses: Vec<String>,
        my_id: peer::Id,
        timeout: Duration,
        comm_sk: secp256k1::SecretKey,
    ) -> Router {
        let peers = peer::Map::<PeerData>::empty(my_id);

        let secp = Secp256k1::signing_only();

        Router {
            signing_context: message::SigningContext {
                secp: secp,
                comm_sk: comm_sk,
                my_id: peers.my_id(),
            },
            addresses: addresses,
            peers: peers,
            read_timeout: timeout,
        }
    }

    /// Send a message to all connections of the peer_id
    pub fn send_msg_to_peer_id(&self, peer_id: peer::Id, msg: message::Message<secp256k1::ecdsa::Signature>) {
        for conn in &self.peers[peer_id].outgoing {
            conn.send_message(msg.clone());
        }
    }

    /// Send a message to the appropriate threads: the target of the
    /// message, and both relay peers
    pub fn dispatch(&self, msg: message::Message<secp256k1::ecdsa::Signature>) {
        for (peer_id, _peer) in self.peers.without_me() {
            self.send_msg_to_peer_id(peer_id, msg.clone());
        }
    }

    /// Return a set of at-most two backup peer indices, chosen
    /// determistically at random based on a given seed, and such
    /// that `sender` is not chosen (unless there are no non-`sender`
    /// peers).
    ///
    /// The networking code will relay messages destined for other
    /// peers only if it appears in this set; this reduces the amount
    /// of data that gets flooded.
    fn relay_peers(&self, sender: peer::Id, rcvr: peer::Id, msg_hash: &[u8]) -> (peer::Id, peer::Id) {
        let mut seed_engine = sha256d::Hash::engine();
        io::Write::write_all(&mut seed_engine, msg_hash).unwrap();
        io::Write::write_all(&mut seed_engine, &sender[..]).unwrap();
        io::Write::write_all(&mut seed_engine, &rcvr[..]).unwrap();

        let mut id_set: Vec<peer::Id> = self.peers.ids()
            .filter(|&id| id != sender && id != rcvr && self.peers.in_consensus(id))
            .collect();
        id_set.sort_by_cached_key(|id| {
            let mut eng = seed_engine.clone();
            io::Write::write_all(&mut eng, &id[..]).unwrap();
            sha256d::Hash::from_engine(eng)
        });

        match id_set.len() {
            // No peers, return sender as both backups
            0 => (sender, sender),
            // One peer, return it and the sender
            1 => (sender, id_set[0]),
            // Two or more peers, return the first two
            _ => (id_set[0], id_set[1]),
        }
    }

    /// Relay the message to the relay peers.
    fn relay(&self, msg: message::Message<secp256k1::ecdsa::Signature>, sender: peer::Id) {
        // This is quite annoying, but logging is easier split up.
        let now = now_utc().to_timespec();
        slog!(ReceiveForRelay, sender: msg.header().sender, target: peer::Id::ZERO,
            version: msg.header().version, round_no: msg.header().round,
            nonce: msg.header().nonce, skew_ms: (now - msg.header().time).num_milliseconds(),
            command: msg.header().command.text().into(), length: msg.header().length,
            hash: msg.header().hash.into(),
        );


        let mut peers_sent:std::collections::HashSet<common::PeerId> = Default::default();
        // This is a relay of a broadcast message, we need to be careful who we send it to
        for (peer_id, _peer) in self.peers.without_me() {
            if peer_id == sender {
                // We should never relay back the message originator
                continue;
            }
            // Choose two backups who relay; others do not.
            let (id1, id2) = self.relay_peers(sender, peer_id, &msg.header().hash.as_ref());
            log!(Trace, "relay_peers for message {}: {}, {} (sender: {}, receiver: {}, us: {}): relay:{}",
                &msg.header().hash, id1, id2, sender, peer_id, self.peers.my_id(),
                id1 == self.peers.my_id() || id2 == self.peers.my_id(),
            );
            if id1 == self.peers.my_id() || id2 == self.peers.my_id() {
                log!(Trace, "Relaying (relay nodes {} and {})", id1, id2);
                if ! peers_sent.contains(&peer_id) {
                    self.send_msg_to_peer_id(peer_id, msg.clone());
                    peers_sent.insert(peer_id);
                }
                let other_relay = if id1 == self.peers.my_id() {id2} else {id1};
                if other_relay != sender {
                    log!(Trace, "Sending message to the other relay node {})", other_relay);
                    if ! peers_sent.contains(&other_relay) {
                        self.send_msg_to_peer_id(other_relay, msg.clone());
                        peers_sent.insert(other_relay);
                    }
                }
            }
        }
    }

    /// Consumes the router and spawns a new thread which responds to network
    /// action requests. Returns a `SyncSender` that can be used to communicate
    /// with the network thread
    pub fn run(
        mut self,
        main_thread_tx: mpsc::SyncSender<MainCtrl>,
    ) -> mpsc::SyncSender<NetworkCtrl> {
        slog!(ProtocolVersion, version: message::MESSAGE_VERSION);

        // Setup communication with other threads
        let (tx, rx) = mpsc::sync_channel(0);

        // Start threads listening on every interface
        for addr in &self.addresses {
            let listener = match net::TcpListener::bind(&addr[..]) {
                Ok(listener) => listener,
                Err(e) => {
                    log!(Error, "Failed to bind to {:?}: {}", addr, e);
                    panic!();
                }
            };
            bind(listener, tx.clone());
        }
        let tx_for_recv_thread = tx.clone();
        // Start main outgoing connection thread
        utils::spawn_named_or_die("router".to_owned(), move || {
            let mut current_round_no = 0;
            let secp = Secp256k1::new();
            let mut incoming_queue = MessageQueue::empty(self.peers.my_id());
            let mut conn_tracker = IncomingConnectionTracker::new(MAXIMUM_INCOMING_PEER_CONNECTIONS);

            for msg in rx.iter() {
                match msg {
                    NetworkCtrl::NewRoundNumber(n) => {
                        current_round_no = n;

                        // Bump the round in the incoming queue.
                        incoming_queue.update_session(current_round_no);

                        // Clear all outgoing message queues.
                        for peer in self.peers.values() {
                            for conn in &peer.outgoing {
                                conn.clear(current_round_no);
                            }
                        }
                    },
                    NetworkCtrl::DynafedUpdate(update) => {
                        let my_id = self.peers.my_id();
                        let kick_lifetime = 3 * self.read_timeout;
                        self.peers.update_from(
                            &update.peers,
                            |peer| PeerData::from_desc(peer, peer.id() != my_id, kick_lifetime),
                            |peer_data| {
                                for c in &peer_data.outgoing {
                                    c.shutdown();
                                }
                            },
                        );
                        incoming_queue.update_from(
                            &update.peers,
                            |_| queue::IncomingQueue::new(current_round_no),
                            |_| {},
                        );
                    },
                    NetworkCtrl::Send(message) => {
                        log!(Trace, "Network thread sending {:?}", message.header());
                        let signed = message.sign(&self.signing_context);
                        self.dispatch(signed);
                    },
                    NetworkCtrl::WatchdogKick(id) => {
                        for conn in &self.peers[id].outgoing {
                            conn.kick();
                        }
                    },
                    NetworkCtrl::IncomingConnection(sock) => {
                        // First check if we have a slot
                        let thread_liveness_tx = match conn_tracker.allocate() {
                            Ok(tx) => tx,
                            Err(..) => {
                                log!(Warn, "Dropping incoming connection due to too many open connections");
                                let _ = sock.shutdown(net::Shutdown::Both);
                                continue;
                            }
                        };
                        // Set a read timeout so that a hung connection will not cause a stillborn thread
                        sock.set_read_timeout(Some(self.read_timeout)).unwrap();

                        let tx_for_recv_thread = tx_for_recv_thread.clone();
                        let read_timeout = self.read_timeout;
                        let peer_thread_name = sock.peer_addr().as_ref()
                            .map(|addr| format!("netreceive_{:?}", addr))
                            .unwrap_or("net_unknown".to_owned());
                        let spawn_result = utils::spawn_named(peer_thread_name, move || {
                            log!(Debug, "Got connection from {:?}", thread::current().name());
                            peer_read_thread(sock, tx_for_recv_thread, read_timeout);
                            thread_liveness_tx.send(()).unwrap();  // dummy send to ensure this Sender is not dropped
                        });
                        if spawn_result.is_err() {
                            log!(Error, "Failed to spawn thread for incoming connection");
                        }
                    },
                    NetworkCtrl::IncomingMessage(msg) => {
                        // Drop the message if it is not part of the current (or
                        // next) round, to prevent our anti-replay logic from
                        // being gummed up by badly misconfigured clocks.
                        let msg_round = msg.header().round;
                        if msg_round != current_round_no && msg_round != current_round_no + 1 {
                            log!(Warn, "dropping message in {} from round {}: {:?}",
                                current_round_no, msg_round, msg.header(),
                            );
                            continue;
                        }

                        // Validate and extract sender and receiver.
                        if let Err(err) = msg.validate(&secp, &self.peers) {
                            log!(Trace, "dropping new message because signature invalid: {}: {:?}",
                                err, msg.header(),
                            );
                            continue;
                        }
                        let sndr_id = msg.header().sender;

                        if sndr_id == self.peers.my_id() {
                            log!(Error, "received message from myself??: {:?}", msg.header());
                            continue;
                        }


                        // Relay the message only if the nonce is increasing during this round.
                        if incoming_queue.record_nonce(sndr_id, msg.header().nonce) {
                            self.relay(msg.clone(), sndr_id);
                        }

                        // Log when it's an unknown message
                        if let message::Command::Unknown(cmd) = msg.header().command {
                            log!(Debug, "received unknown message from peer {}: {:x}{:x}{:x}{:x}",
                                msg.header().sender, cmd[0], cmd[1], cmd[2], cmd[3],
                            );
                        }

                        // Queue the message for processing.
                        incoming_queue.enqueue(msg.drop_signature());

                        // After (maybe) updating the incoming-message queue,
                        // see if anything is available to be propagated to
                        // the main thread.
                        for msg in &mut incoming_queue {
                            let now = now_utc().to_timespec();
                            // Send it to the main thread
                            slog!(ReceiveForSelf, sender: msg.header().sender,
                                version: msg.header().version, round_no: msg.header().round,
                                skew_ms: (now - msg.header().time).num_milliseconds(),
                                command: msg.header().command.text().into(),
                                length: msg.header().length, nonce: msg.header().nonce,
                                msgid: msg.header().msgid, hash: msg.header().hash.into(),
                            );

                            main_thread_tx.send(MainCtrl::Incoming(msg)).unwrap();
                        }
                    },
                }
            }
            panic!("Failed to receive channel message from main thread.");
        });
        tx
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use bitcoin::secp256k1::SignOnly;
    use common::RoundStage;
    use message::Message;
    use peer::{List, Map, Peer};
    use super::*;

    #[test]
    fn read_magic() {
        let to = Duration::from_secs(1);
        assert!(read_and_consume_magic(&[0x4c, 0x6f, 0x52, 0x44][..], &NETWORK_MAGIC, to).is_ok());
        assert!(read_and_consume_magic(&[0x00, 0x4c, 0x6f, 0x52, 0x44][..], &NETWORK_MAGIC, to).is_ok());
        assert!(read_and_consume_magic(&[0x4c, 0x4c, 0x6f, 0x52, 0x44][..], &NETWORK_MAGIC, to).is_ok());
        assert!(read_and_consume_magic(&[0x4c, 0x6f, 0x4c, 0x6f, 0x52, 0x44][..], &NETWORK_MAGIC, to).is_ok());
        assert!(read_and_consume_magic(&[0x4c, 0x6f, 0x52, 0x4c, 0x6f, 0x52, 0x44][..], &NETWORK_MAGIC, to).is_ok());
        assert!(read_and_consume_magic(&[0x4c, 0x6f, 0x52, 0x40][..], &NETWORK_MAGIC, to).is_err());
        assert!(read_and_consume_magic(&[0x4c, 0x4c, 0x6f, 0x52, 0x00][..], &NETWORK_MAGIC, to).is_err());
        assert!(read_and_consume_magic(&[][..], &NETWORK_MAGIC, to).is_err());
        assert!(read_and_consume_magic(&[0, 0, 0, 0][..], &NETWORK_MAGIC, to).is_err());
    }

    struct TestPeer {
        id: peer::Id,
        comm_sk: secp256k1::SecretKey,
        peer_data: Peer,
        router: Router,
    }

    /// Generate test peers for the `router` tests. This generates peer Ids, comms keys, routers.
    /// The routers have a custom peer map created with raw outgoing queues that don't spawn any Tcp
    /// connection threads but just contain a basic queue we can interogate in the tests.
    fn generate_test_peers(n: u8, secp: &Secp256k1<SignOnly>) -> Vec<TestPeer> {
        let mut test_peers = Vec::new();
        for i in 0u8..n {
            let bytes: [u8; 32] = secp256k1::rand::random();
            let comm_sk = secp256k1::SecretKey::from_slice(&bytes).unwrap();
            let comm_pk = secp256k1::PublicKey::from_secret_key(&secp, &comm_sk);
            let id = peer::Id::from(comm_pk);

            let peer_data = Peer {
                name: format!("Peer {}", i),
                addresses: vec![],
                comm_pk: comm_pk.clone(),
                comm_pk_legacy: None,
                sign_pk: comm_pk,
            };

            test_peers.push(TestPeer {
                id,
                comm_sk: comm_sk.clone(),
                peer_data,
                router: Router::new(vec![], id, Duration::from_secs(60), comm_sk),
            });

            println!("Peer {} - Id {}", i, id);
        }

        //Add peers to each router
        for i in 0..n as usize {
            //Create peer map
            let peer_list = List::from_slice(
                test_peers.iter().map(|p| p.peer_data.clone()).collect::<Vec<_>>().as_slice(),
                |_| true,
                test_peers[i].peer_data.name.as_str(),
            );
            let mut peer_map = Map::empty(test_peers[i].id);

            peer_map.update_from(
                &peer_list,
                |peer| PeerData {
                    comm_pk: peer.comm_pk.clone(),
                    outgoing: vec![outgoing::Thread::new_raw(format!("Peer {}", i))],
                },
                |_| (),
            );
            test_peers[i].router.peers = peer_map.clone();
        }

        test_peers
    }

    /// Test the new broadcast relay heuristic
    /// To see the stdout output run this test with --nocapture i.e. `cargo test broadcast_relay_heuristic -- --nocapture`
    #[test]
    fn broadcast_relay_heuristic() {
        for i in 1..=15 {
            broadcast_relay_heuristic_peers(i);
        }
    }
    fn broadcast_relay_heuristic_peers(
            peer_count: u8,
        ) {
        let secp = Secp256k1::signing_only();

        let peers = generate_test_peers(peer_count, &secp);

        println!("Network contains {} peers", peers.len());
        assert!(peers.len() > 0);

        let signing_context = message::SigningContext {
            secp: secp,
            comm_sk: peers[0].comm_sk.clone(),
            my_id: peers[0].id,
        };

        let original_messages_sent =
            dispatch_and_relay_message(peers[0].id, &peers, &signing_context);

        let relayed_messages_sent = count_relayed_messages(&peers);

        // before dedup, the expected amount of messages sent is 5(N-1)
        // Distribution is as follows:
        // (N-1) for the first round of direct sends, from the originator to the peers
        // 2(N-1) for the second round of sends, relay to destination
        // 2(N-1) for the third round of sends, relay to the other relay
        // When accounting for dedup, during the third round, we can send fewer messages, down to (N-1),
        // so we check that the values fall within that range
        let expected_direct_sent = (peers.len() as i32 - 1i32) as i32;
        let expected_relay_sent_min = match peers.len() {
            1|2 => 0,
            3 => (peers.len() as i32 - 1i32) as i32,
            _ => 2i32 * (peers.len() as i32 - 1i32),
        };
        let expected_relay_sent_max = match peers.len() {
            1|2 => 0,
            3 => (peers.len() as i32 - 1i32) as i32,
            4 => 2i32 * (peers.len() as i32 - 1i32),
            _ => 4i32 * (peers.len() as i32 - 1i32),
        };

        println!(
            "Original messages sent {} - Relay messages sent {} - Total {}",
            original_messages_sent,
            relayed_messages_sent,
            original_messages_sent + relayed_messages_sent
        );

        println!(
            "Expected messages sent {} - Expected relay min {} - Expected relay max {}",
            expected_direct_sent,
            expected_relay_sent_min,
            expected_relay_sent_max
        );

        // Sanity check of the total number of direct messages sent
        assert!(original_messages_sent as i32 == expected_direct_sent);
        // Sanity check of the total number of relayed messages sent
        assert!(relayed_messages_sent as i32 >= expected_relay_sent_min);
        assert!(relayed_messages_sent as i32 <= expected_relay_sent_max);
    }

    /// Dispatch a message to a receiver using the router::dispatch method. Then go through the outgoing
    /// send queues trigger the `relay` method on the recipient routers as if they received the message
    /// `Returns`: the number of originator messages sent
    /// `Assumption`:   A message is only relayed if it's nonce is higher than the last relayed message
    ///                 from that sender. This check is in the `run(...)` method of the Router so this
    ///                 test just assumes this check is enforced.
    fn dispatch_and_relay_message(
        sender: peer::Id,
        peers: &Vec<TestPeer>,
        signing_context: &message::SigningContext<secp256k1::SignOnly>,
    ) -> usize {
        let msg = Message::status_blocksigner(
            RoundStage::default(),
            0,
            vec![],
            vec![],
            elements::BlockHash::all_zeros(),
            0,
            vec![],
            "msg1".to_string(),
        );
        let msg = msg.sign(&signing_context);

        let mut original_messages_sent = 0;

        let sending_peer = peers.iter().find(|p| p.id == sender).unwrap();

        let mut msg_recipients = HashSet::new();
        sending_peer.router.dispatch(msg.clone());
        for (id, to_peer) in sending_peer.router.peers.iter() {
            for t in to_peer.outgoing.iter() {
                if t.queue().len() > 0 {
                    assert_eq!(
                        t.queue().len(),
                        1,
                        "Only one message should be sent per peer at most"
                    );
                    println!("Peer {} sent original message to Peer {}", sending_peer.id, id);
                    original_messages_sent += 1;
                    msg_recipients.insert(id);
                    t.queue().clear();
                }
            }
        }

        // Now all the peers that received the broadcast will check for relay
        for peer in peers.iter().filter(|p| p.id != sender) {
            if msg_recipients.contains(&peer.id) {
                println!(
                    "Original message from Peer {} received by Peer {}",
                    sender,
                    peer.id,
                );
                peer.router.relay(msg.clone(), msg.header().sender);
            }
        }

        original_messages_sent
    }

    /// Go through the outgoing message queues and count how many relayed messages were sent
    /// `Returns:` total number of relayed messages in all outgoing queues
    fn count_relayed_messages(peers: &Vec<TestPeer>) -> usize {
        let mut relayed_messages_sent = 0;

        println!("\n\n");
        for peer in peers.iter() {
            println!("Peer {} relays\n-------------------------", peer.id);
            for (id, to_peer) in peer.router.peers.iter() {
                for t in to_peer.outgoing.iter() {
                    if t.queue().len() > 0 {
                        assert_ne!(
                            id, peers[0].id,
                            "No relay message should be sent to the originator"
                        );
                        println!(
                            "Peer {} relayed {} messages to Peer {}",
                            peer.id,
                            t.queue().len(),
                            id
                        );
                        relayed_messages_sent += t.queue().len();
                    }
                }
            }
            println!("=========================");
        }
        relayed_messages_sent
    }

}

