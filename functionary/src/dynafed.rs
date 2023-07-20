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

//! Dynamic Federations
//!
//! Support for sychnronizing updates to the global peer list

use std::{ops, sync, thread};

use peer;

/// This is a struct to just wrap the [peer::List] with an extra boolean
/// to indicate if this is a dynafed-active peer list.
///
/// This construction is solely intended to accompany the logic in the
/// rotator logic to be compatible with pre-dynafed consensus that uses
/// a different sorting of there peer list. After compatibility with
/// pre-dynafed is no longed needed, this type can again be replaced with
/// a simple [peer::List].
#[derive(Debug, Clone)]
pub struct UpdateNotif {
    /// Whether this peer list is still based on the original pre-dynafed
    /// params (and should preserve legacy ordering) or the result of a
    /// dynafed consensus param (and thus free to use newer ordering)
    pub use_legacy_ordering: bool,
    /// the actual peers
    pub peers: peer::List,
}

impl UpdateNotif {
    /// The sorted peer list for consensus.
    ///
    /// Pre-dynafed, this list is ordered by signing key.
    pub fn sorted_peer_list(&self) -> Vec<peer::Id> {
        if self.use_legacy_ordering {
            let mut ordered: Vec<(Vec<u8>, peer::Id)> = self.peers.consensus().map(
                |(id, peer)| (peer.sign_pk.serialize().to_vec(), id)
            ).collect();
            ordered.sort();
            ordered.into_iter().map(|(_, id)| id).collect()
        } else {
            self.peers.consensus_ordered_ids()
        }
    }
}


/// Hybrid of `sync::Arc` and `sync::Barrier`. Cannot be copied, cloned,
/// or otherwise duplicated. Associated with some `RecoverableBarrier`.
/// When it is dropped, will block the current thread until all other
/// copies of it have been dropped and the `RecoverableBarrier` has had
/// `recover` called on it. (Alternately the `RecoverableBarrier` may
/// just be dropped.)
#[derive(Debug)]
pub struct ArcBarrier<T> {
    /// Number of copies of the `ArcBarrier` which have already been dropped.
    /// Initially set to 0; each thread increments it when it drops its copy
    /// of the `ArcBarrier`, before waiting for the `RecoverableBarrier` to
    /// set the counter to 0.
    barrier: sync::Arc<(
        sync::Mutex<usize>,
        sync::Condvar,
    )>,
    /// The underlying data
    data: Option<sync::Arc<T>>,
}

/// Unique copy of an `ArcBarrier` which has the ability to recover the shared
/// data. Has a method `recover` which will retrieve this data, by first
/// blocking the thread until all the `ArcBarrier`s have been dropped, then
/// calling `Arc::try_unwrap` on the underlying `Arc`.
pub struct RecoverableBarrier<T> {
    /// Number of associated `ArcBarrier`s which have already been dropped.
    barrier: sync::Arc<(
        sync::Mutex<usize>,
        sync::Condvar,
    )>,
    /// Number of `ArcBarrier` copies associated to this `RecoverableBarrier`
    n_to_wait_for: usize,
    /// The underlying data
    data: Option<sync::Arc<T>>,
}

/// Sends data to a bunch of different threads, given a list of methods
/// which are used to send copies of the `ArcBarrier`-wrapped data. These
/// methods are required to either (a) successfully send data to another
/// thread, or (b) panic. If they fail to do one of these, and instead
/// drop the `ArcBarrier`, this will block the current thread forever.
///
/// Returns a `RecoverableBarrier` from which the original data can be
/// recovered after all the `ArcBarrier`s have been dropped.
///
/// Every thread will block when they drop their received `ArcBarrier`s;
/// once all copies have been dropped, and the caller has called `recover`
/// on the `RecoverableBarrier` (or simply dropped it), all threads will
/// come unblocked at once.
pub fn send_arc_barriers<T>(
    data: T,
    targets: &mut [&mut dyn FnMut(ArcBarrier<T>)],
) -> RecoverableBarrier<T> {
    let barrier = sync::Arc::new((sync::Mutex::new(0), sync::Condvar::new()));
    let data = sync::Arc::new(data);

    for target_fn in &mut *targets {
        target_fn(ArcBarrier {
            barrier: barrier.clone(),
            data: Some(data.clone()),
        });
    }
    RecoverableBarrier {
        n_to_wait_for: targets.len(),
        barrier: barrier.clone(),
        data: Some(data.clone()),
    }
}

impl<T> RecoverableBarrier<T> {
    /// Retrieves the original data from a `RecoverableBarrier` once all
    /// associated `ArcBarrier`s have been dropped.
    pub fn recover(mut self) -> T {
        assert!(self.data.is_some());
        // Wait for all other threads to drop their copies of the `Arc`
        let mut lock = self.barrier.0.lock().unwrap();
        while *lock < self.n_to_wait_for {
            lock = self.barrier.1.wait(lock).unwrap();
        }
        // Signal them to wake up
        *lock = 0;
        self.barrier.1.notify_all();
        // Unwrap our reference to the data, knowing it is the only one.
        if let Ok(data) = sync::Arc::try_unwrap(
            self.data.take().expect("`Arc` has not already been taken")
        ) {
            data
        } else {
            panic!(
                "Tried to recover data from an `ArcBarrier` but \
                 another thread still had access to it."
            );
        }
    }
}

impl<T> ops::Deref for ArcBarrier<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &**self.data.as_ref().unwrap()
    }
}

impl<T> Drop for RecoverableBarrier<T> {
    fn drop(&mut self) {
        if self.data.is_some() {
            self.data.take(); // Drop the `Arc`

            let mut lock = self.barrier.0.lock().unwrap();
            while !thread::panicking() && *lock < self.n_to_wait_for {
                lock = self.barrier.1.wait(lock).unwrap();
            }
            *lock = 0;
            self.barrier.1.notify_all();
        }
    }
}

impl<T> Drop for ArcBarrier<T> {
    fn drop(&mut self) {
        assert!(self.data.is_some());
        self.data.take(); // Drop the `Arc`
        // Update lock and signal a change to all other waiting threads
        let mut lock = self.barrier.0.lock().unwrap();
        *lock += 1;
        self.barrier.1.notify_all();
        // Block the thread until the `recover` thread signals, unless
        // we're panicking, in which case just let the panic happen
        while !thread::panicking() && *lock != 0 {
            lock = self.barrier.1.wait(lock).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;
    use std::thread;

    use bitcoin::hashes::hex::FromHex;
    use bitcoin::secp256k1::PublicKey;
    use common::PakList;


    use super::*;

    fn stall100() {
        thread::sleep(Duration::from_millis(100));
    }

    #[test]
    fn barrier_no_threads() {
        let data = String::from("string 1");
        let barrier = send_arc_barriers(data, &mut []);
        assert_eq!(barrier.recover(), "string 1");
    }

    #[test]
    fn barrier_3_threads() {
        let data = String::from("string 1");

        let (tx1, rx1) = mpsc::sync_channel(0);
        let (tx2, rx2) = mpsc::sync_channel(0);
        let (tx3, rx3) = mpsc::sync_channel(0);

        let _ = thread::spawn(move || {
            stall100();
            stall100();
            rx1.recv()
        });
        let _ = thread::spawn(move || rx2.recv());
        let _ = thread::spawn(move || rx3.recv());

        let barrier = send_arc_barriers(
            data,
            &mut [
                &mut |data| tx1.send(data).expect("unwrap 1"),
                &mut |data| tx2.send(data).expect("unwrap 2"),
                &mut |data| tx3.send(data).expect("unwrap 3"),
            ],
        );
        assert_eq!(barrier.recover(), "string 1");
    }

    #[test]
    #[should_panic(expected = "unwrap 1")]
    fn barrier_3_panic() {
        let data = String::from("string 1");

        let (tx1, rx1) = mpsc::sync_channel(0);
        let (tx2, rx2) = mpsc::sync_channel(0);
        let (tx3, rx3) = mpsc::sync_channel(0);

        let _ = thread::spawn(move || {
            let _ = rx1.try_recv();
            stall100();
            stall100();
            panic!("Expected panic");
        });
        let _ = thread::spawn(move || rx2.recv());
        let _ = thread::spawn(move || rx3.recv());

        stall100();
        let barrier = send_arc_barriers(
            data,
            &mut [
                &mut |data| tx1.send(data).expect("unwrap 1"),
                &mut |data| tx2.send(data).expect("unwrap 2"),
                &mut |data| tx3.send(data).expect("unwrap 3"),
            ],
        );
        assert_eq!(barrier.recover(), "string 1");
    }

    #[test]
    #[should_panic(expected = "unwrap 1")]
    fn barrier_3_drop() {
        let data = String::from("string 1");

        let (tx1, rx1) = mpsc::sync_channel(0);
        let (tx2, rx2) = mpsc::sync_channel(0);
        let (tx3, rx3) = mpsc::sync_channel(0);

        let _ = thread::spawn(move || drop(rx1));
        drop(rx2);
        let _ = thread::spawn(move || rx3.recv());

        let barrier = send_arc_barriers(
            data,
            &mut [
                &mut |data| tx1.send(data).expect("unwrap 1"),
                &mut |data| tx2.send(data).expect("unwrap 2"),
                &mut |data| tx3.send(data).expect("unwrap 3"),
            ],
        );

        assert_eq!(barrier.recover(), "string 1");
    }

    #[test]
    fn barrier_3_no_recover() {
        let data = String::from("string 1");

        let (tx1, rx1) = mpsc::sync_channel(0);
        let (tx2, rx2) = mpsc::sync_channel(0);
        let (tx3, rx3) = mpsc::sync_channel(0);

        let _ = thread::spawn(move || rx1.recv());
        let _ = thread::spawn(move || rx2.recv());
        let _ = thread::spawn(move || rx3.recv());

        let _barrier = send_arc_barriers(
            data,
            &mut [
                &mut |data| tx1.send(data).expect("unwrap 1"),
                &mut |data| tx2.send(data).expect("unwrap 2"),
                &mut |data| tx3.send(data).expect("unwrap 3"),
            ],
        );
    }

    #[test]
    #[should_panic(expected = "panic while barrier was live")]
    fn barrier_3_no_recover_panic() {
        let data = String::from("string 1");

        let (tx1, rx1) = mpsc::sync_channel(1);
        let (tx2, rx2) = mpsc::sync_channel(1);
        let (tx3, rx3) = mpsc::sync_channel(1);

        let _ = thread::spawn(move || { stall100(); rx1.recv() });
        let _ = thread::spawn(move || { stall100(); rx2.recv() });
        let _ = thread::spawn(move || { stall100(); rx3.recv() });

        let _barrier = send_arc_barriers(
            data,
            &mut [
                &mut |data| tx1.send(data).expect("unwrap 1"),
                &mut |data| tx2.send(data).expect("unwrap 2"),
                &mut |data| tx3.send(data).expect("unwrap 3"),
            ],
        );
        panic!("panic while barrier was live");
    }

    #[test]
    fn barrier_3_send_works_recv_doesnt() {
        let data = String::from("string 1");

        // This channel has room for 1 message, so sending will work;
        // however the receiving end will panic before receiving it.
        let (tx1, rx1) = mpsc::sync_channel(1);
        let (tx2, rx2) = mpsc::sync_channel(0);
        let (tx3, rx3) = mpsc::sync_channel(0);

        let _ = thread::spawn(move || {
            let _ = rx1;
            stall100();
            stall100();
            stall100();
            stall100();
            panic!("Expected panic");
        });
        let _ = thread::spawn(move || rx2.recv());
        let _ = thread::spawn(move || rx3.recv());

        stall100();
        let barrier = send_arc_barriers(
            data,
            &mut [
                &mut |data| tx1.send(data).expect("unwrap 1"),
                &mut |data| tx2.send(data).expect("unwrap 2"),
                &mut |data| tx3.send(data).expect("unwrap 3"),
            ],
        );
        assert_eq!(barrier.recover(), "string 1");
    }
    #[test]
    fn test_offline_online_from_pairs() {
        // Real keylist is OK
        let keylist = PakList::from_pairs(jsonrpc::serde_json::from_str("[
            [
                \"0344a87dbb392a3829e6e7222c19dcf8b3a06b84032ad51206f465212ce4d62f9e\",
                \"02146846eeb5a7533abb594ba734bc243fc7b6349499b8311c8fc13b0112ba8a77\"
            ]
        ]").unwrap());
        println!("List to send {:?}.", keylist);
        let decodedoffline = Vec::<u8>::from_hex("0344a87dbb392a3829e6e7222c19dcf8b3a06b84032ad51206f465212ce4d62f9e").unwrap();
        let decodedonline  = Vec::<u8>::from_hex("02146846eeb5a7533abb594ba734bc243fc7b6349499b8311c8fc13b0112ba8a77").unwrap();

        println!("Decoded offline: {:?}.", PublicKey::from_slice(&decodedoffline).unwrap());
        println!("Decoded online:  {:?}.", PublicKey::from_slice(&decodedonline).unwrap());
        assert_eq!(keylist.iter().next().unwrap().offline, PublicKey::from_slice(&decodedoffline).unwrap());
        assert_eq!(keylist.iter().next().unwrap().online, PublicKey::from_slice(&decodedonline).unwrap());
    }
}

