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

//! # Utils
//! Helper functions of general usefulness
//!

use std::{cmp, fmt, fs, io};
use std::collections::VecDeque;
use std::thread::{self, JoinHandle};
use std::sync::{mpsc, Arc, Condvar, Mutex};

use bitcoin::hashes::Hash;
use elements::BlockHeader;

use common::BlockHeight;
use watchman;

pub mod serialize {
    //! Module for special serde serialization.
    pub mod hashmap {
        //! Module for serialization of hashmaps because serde_json will
        //! not serialize hashmaps with non-string keys be default.
        #![allow(missing_docs)]

        use std::collections::HashMap;

        pub fn serialize<S, T, U>(v: &HashMap<T, U>, s: S)
            -> Result<S::Ok, S::Error> where
            S: serde::Serializer,
            T: serde::Serialize + ::std::hash::Hash + Eq,
            U: serde::Serialize,
        {
            use serde::ser::SerializeSeq;

            let mut seq = s.serialize_seq(Some(v.len()))?;
            for pair in v.iter() {
                seq.serialize_element(&pair)?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D, T, U>(d: D)
            -> Result<HashMap<T, U>, D::Error> where
            D: serde::Deserializer<'de>,
            T: serde::Deserialize<'de> + ::std::hash::Hash + Eq,
            U: serde::Deserialize<'de>,
        {
            use std::marker::PhantomData;

            struct Visitor<T, U>(PhantomData<(T, U)>);
            impl<'de, T, U> serde::de::Visitor<'de> for Visitor<T, U> where
                T: serde::Deserialize<'de> + ::std::hash::Hash + Eq,
                U: serde::Deserialize<'de>,
            {
                type Value = HashMap<T, U>;

                fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    write!(f, "a sequence of pairs")
                }

                fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A)
                    -> Result<Self::Value, A::Error>
                {
                    let mut ret = HashMap::new();
                    while let Some((key, value)) = a.next_element()? {
                        ret.insert(key, value);
                    }
                    Ok(ret)
                }
            }

            d.deserialize_seq(Visitor(PhantomData))
        }
    }
    pub mod btreemap {
        //! Module for serialization of BTreeMaps because serde_json will
        //! not serialize hashmaps with non-string keys be default.
        #![allow(missing_docs)]

        use std::collections::BTreeMap;

        pub fn serialize<S, T, U>(v: &BTreeMap<T, U>, s: S)
            -> Result<S::Ok, S::Error> where
            S: serde::Serializer,
            T: serde::Serialize + ::std::hash::Hash + Eq + Ord,
            U: serde::Serialize,
        {
            use serde::ser::SerializeSeq;

            let mut seq = s.serialize_seq(Some(v.len()))?;
            for pair in v.iter() {
                seq.serialize_element(&pair)?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D, T, U>(d: D)
            -> Result<BTreeMap<T, U>, D::Error> where
            D: serde::Deserializer<'de>,
            T: serde::Deserialize<'de> + ::std::hash::Hash + Eq + Ord,
            U: serde::Deserialize<'de>,
        {
            use std::marker::PhantomData;

            struct Visitor<T, U>(PhantomData<(T, U)>);
            impl<'de, T, U> serde::de::Visitor<'de> for Visitor<T, U> where
                T: serde::Deserialize<'de> + ::std::hash::Hash + Eq + Ord,
                U: serde::Deserialize<'de>,
            {
                type Value = BTreeMap<T, U>;

                fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    write!(f, "a sequence of pairs")
                }

                fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A)
                    -> Result<Self::Value, A::Error>
                {
                    let mut ret = BTreeMap::new();
                    while let Some((key, value)) = a.next_element()? {
                        ret.insert(key, value);
                    }
                    Ok(ret)
                }
            }

            d.deserialize_seq(Visitor(PhantomData))
        }
    }

    pub mod hex_bytes {
        //! Module for serialization of byte arrays as hex strings.
        #![allow(missing_docs)]

        use bitcoin::hashes::hex::FromHex;
        use bitcoin::hex::DisplayHex;

        pub fn serialize<T, S>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
            where T: AsRef<[u8]>, S: serde::Serializer
        {
            serializer.serialize_str(&bytes.as_ref().as_hex().to_string())
        }

        pub fn deserialize<'de, D, B>(d: D) -> Result<B, D::Error>
            where D: serde::Deserializer<'de>, B: FromHex,
        {
            struct Visitor<B>(std::marker::PhantomData<B>);

            impl<'de, B: FromHex> serde::de::Visitor<'de> for Visitor<B> {
                type Value = B;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where E: serde::de::Error,
                {
                    if let Ok(hex) = std::str::from_utf8(v) {
                        FromHex::from_hex(hex).map_err(E::custom)
                    } else {
                        return Err(E::invalid_value(serde::de::Unexpected::Bytes(v), &self));
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where E: serde::de::Error,
                {
                    FromHex::from_hex(v).map_err(E::custom)
                }
            }

            d.deserialize_str(Visitor(std::marker::PhantomData))
        }
    }

    /// Serde serialization wrapper for the old format of elements::OutPoint.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ElementsOutpointSerdeWrapper(pub elements::OutPoint);

    impl From<ElementsOutpointSerdeWrapper> for elements::OutPoint {
        fn from(o: ElementsOutpointSerdeWrapper) -> elements::OutPoint {
            o.0
        }
    }

    impl<'de> serde::Deserialize<'de> for ElementsOutpointSerdeWrapper {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Visitor;

            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = ElementsOutpointSerdeWrapper;

                fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    write!(f, "an elements outpoint in either new or legacy format")
                }

                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    Ok(ElementsOutpointSerdeWrapper(v.parse().map_err(serde::de::Error::custom)?))
                }

                fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                    Ok(ElementsOutpointSerdeWrapper(v.parse().map_err(serde::de::Error::custom)?))
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error> where
                    A: serde::de::MapAccess<'de>
                {
                    use std::convert::TryInto;

                    let mut txid = None;
                    let mut vout = None;
                    loop {
                        let entry = map.next_entry::<&'de str, serde_json::Value>()?;
                        if entry.is_none() {
                            return Err(serde::de::Error::custom("invalid elements outpoint"));
                        }
                        let (key, value) = entry.unwrap();
                        if key == "txid" {
                            if let Some(s) = value.as_str() {
                                txid.replace(s.parse().map_err(serde::de::Error::custom)?);
                            }
                        }
                        if key == "vout" {
                            if let Some(s) = value.as_i64() {
                                vout.replace(s.try_into().map_err(serde::de::Error::custom)?);
                            }
                        }

                        if txid.is_some() && vout.is_some() {
                            return Ok(ElementsOutpointSerdeWrapper(elements::OutPoint::new(
                                txid.unwrap(), vout.unwrap(),
                            )));
                        }
                    }
                }
            }

            d.deserialize_any(Visitor)
        }
    }
}

/// A block hash and height pair.
#[derive(Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Debug, Hash, Serialize, Deserialize)]
pub struct BlockRef {
    // This is a combination of blockheight and hash in that order because this
    // allows easy ordering by block height and using BlockRef as a key in an
    // ordered map (f.e. in txindex).
    // So note that the order of the fields is important.

    /// The block height.
    pub height: BlockHeight,
    /// The block hash.
    #[serde(default = "bitcoin::BlockHash::all_zeros")]
    pub hash: bitcoin::BlockHash,
}

impl BlockRef {
    /// Create a new [BlockRef].
    pub fn new(height: BlockHeight, hash: bitcoin::BlockHash) -> BlockRef {
        BlockRef {
            height: height,
            hash: hash,
        }
    }
}

impl std::default::Default for BlockRef {
    fn default() -> Self {
        BlockRef {
            height: BlockHeight::default(),
            hash: bitcoin::BlockHash::all_zeros(),
        }
    }
}

impl fmt::Display for BlockRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.height, self.hash)
    }
}

/// Spawn a thread with a supplied name.
pub fn spawn_named<F, T>(name: String, f: F) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new().name(name).spawn(f)
}

/// Spawn a thread with a supplied name; panic on failure.
pub fn spawn_named_or_die<F, T>(name: String, f: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    spawn_named(name, f).unwrap()
}

/// Empties a channel, throwing away whatever's in it
pub fn flush_channel<T: 'static>(chan: &mpsc::Receiver<T>) {
    while let Ok(_) = chan.try_recv() {
        // do nothing
    }
}

/// Iterator through blockheight, to keep track of which blocks have been finalized and which haven't
/// A block is finalized after some number of blocks are built on top of it, which means that we can assume
/// its contents never be removed from the chain. Finalization should happen only once.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]  // no Copy to avoid accidental duplication
pub struct HeightIterator {
    /// Next height that will be returned that hasn't been finalized before
    next_finalized_height: BlockHeight,
    /// Height of the most recent known block
    max_height: BlockHeight,
    /// How many blocks below the max_height a height must be to be "finalized"
    confirm_count: BlockHeight,
    /// The most recent block we returned as confirmed
    last_finalized_height: BlockHeight
}

impl HeightIterator {
    /// Create a new uninitialized height iterator
    pub fn new(start: BlockHeight, confirm_count: BlockHeight) -> HeightIterator {
        HeightIterator {
            next_finalized_height: start,
            max_height: 0,
            confirm_count: confirm_count,
            last_finalized_height: cmp::max(start as isize - confirm_count as isize, 0) as BlockHeight
        }
    }

    /// Calls `getblockcount` over RPC to refresh max_height
    pub fn rpc_update_max_height(&mut self, rpc: &impl ::rpc::Rpc) -> Result<(), jsonrpc::Error> {
        self.max_height = rpc.block_count()?;
        Ok(())
    }

    /// Accessor for the last confirmed block
    pub fn last_finalized_height(&self) -> Option<BlockHeight> {
        if self.last_finalized_height > 0 {
            Some(self.last_finalized_height)
        } else {
            None
        }
    }

    /// Accessor for the highest known block
    pub fn max_height(&self) -> Option<BlockHeight> {
        if self.max_height > 0 { Some(self.max_height)} else { None }
    }

    /// Accessor for the depth needed to consider a block as "confirmed"
    pub fn confirm_count(&self) -> BlockHeight {
        self.confirm_count
    }
}

impl Iterator for HeightIterator {
    type Item = BlockHeight;

    fn next(&mut self) -> Option<BlockHeight> {
        if self.next_finalized_height + self.confirm_count <= self.max_height {
            let ret = self.next_finalized_height;
            self.next_finalized_height += 1;
            self.last_finalized_height = ret;
            Some(ret)
        } else {
            None
        }
    }
}

impl fmt::Display for HeightIterator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ blockcount: {}, next height to confirm: {} }}",
               self.max_height, self.next_finalized_height)
    }
}

/// (Attempt to) export some serializable object to a file
pub fn export_to_file<F>(file: &str, export_fn: F)
    where F: FnOnce(io::BufWriter<fs::File>) -> Result<(), watchman::blockchain::Error>
{
    let mut temp_name = file.to_owned();
    temp_name.push_str(".0");
    match fs::File::create(&temp_name) {
        Ok(fh) => {
            let wr = io::BufWriter::new(fh);
            if let Err(e) = export_fn(wr) {
                slog!(WriteFailed, filename: &temp_name, error: e.to_string());
            } else {
                if let Err(e) = fs::rename(&temp_name, file) {
                    slog!(MoveFailed, old_filename: &temp_name, new_filename: file,
                        error: e.to_string()
                    );
                }
            }
        }
        Err(e) => {
            slog!(CreateFailed, filename: &temp_name, error: e.to_string());
        }
    }
}

/// Convert satoshis to BTC.
pub fn satoshi_to_btc(x: u64) -> f64 {
    x as f64/100000000.0
}

/// Enum for response of `Rpc::block_is_in_chain`
#[derive(Debug)]
pub enum InChain {
    /// Block is in the chain at the expected depth
    Yes,
    /// Block is unknown to the bitcoind
    NotFound,
    /// Block is known to the bitcoind but not in the highest-work chain
    ForkedOff,
    /// Block is in the highest-work chain but not at the expected depth
    WrongDepth(BlockHeight),
    /// Unable to check due to RPC error
    RpcError(jsonrpc::Error)
}


/// Trait to replace `Duration::as_millis` which is not available
/// until rustc 1.33
pub trait DurationExt {
    /// Return the duration as an integer number of milliseconds
    fn as_millis_ext(&self) -> u64;
}

impl DurationExt for std::time::Duration {
    fn as_millis_ext(&self) -> u64 {
        1000 * self.as_secs() + self.subsec_millis() as u64
    }
}

/// A thread-safe queue that can be cleared.
pub struct ClearableQueue<T> {
    capacity: usize,
    queue: Mutex<VecDeque<T>>,
    condvar: Condvar,
}

impl<T> ClearableQueue<T> {
    /// Create a new [ClearableQueue] with the given capacity.
    pub fn with_capacity(capacity: usize) -> Arc<ClearableQueue<T>> {
        Arc::new(ClearableQueue {
            capacity: capacity,
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            condvar: Condvar::new(),
        })
    }

    /// The number of elements in the queue.
    pub fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    /// Requeue the message at the front of the queue.
    pub fn requeue(&self, item: T) -> Result<(), &'static str> {
        let mut queue = self.queue.lock().unwrap();
        if queue.len() == self.capacity {
            return Err("queue is full");
        }
        queue.push_front(item);
        self.condvar.notify_all();
        Ok(())
    }

    /// Send an item on the queue. Returns false when it was full.
    pub fn send(&self, item: T) -> Result<(), &'static str> {
        let mut queue = self.queue.lock().unwrap();
        if queue.len() == self.capacity {
            return Err("queue is full");
        }
        queue.push_back(item);
        self.condvar.notify_all();
        Ok(())
    }

    /// Clear the entire queue.
    pub fn clear(&self) {
        self.queue.lock().unwrap().clear();
    }

    /// Clears all messages for which [false] is returned by the filter.
    pub fn retain<F>(&self, filter: F) where F: Fn(&T) -> bool {
        self.queue.lock().unwrap().retain(|item| filter(item));
    }

    /// A blocking call to receive a message from the queue.
    pub fn receive(&self) -> T {
        let mut queue = self.queue.lock().unwrap();
        loop {
            if let Some(item) = queue.pop_front() {
                return item;
            }
            queue = self.condvar.wait(queue).unwrap();
        }
    }
}

/// Create a default empty elements block after the Default implementation was dropped upstream
pub fn empty_elements_block() -> elements::Block {
    elements::Block {
        header: BlockHeader {
            version: 0,
            prev_blockhash: elements::BlockHash::all_zeros(),
            merkle_root: elements::TxMerkleNode::all_zeros(),
            time: 0,
            height: 0,
            ext: Default::default(),
        },
        txdata: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyRpc(BlockHeight);
    impl_dummy_rpc!(
        DummyRpc,
        dummy,
        "getblockcount" => dummy.0
    );

    fn test_iterator(up_to: BlockHeight, n_confirms: BlockHeight, step_by: BlockHeight) {
        let mut it = HeightIterator::new(0, n_confirms);
        let mut confirm_count = vec![0; up_to as usize];

        assert_eq!(None, it.last_finalized_height());
        assert_eq!(None, it.max_height());

        let mut max_value = 0;
        let mut last_value = 0;
        while max_value < up_to {
            while let Some(value) = it.next() {
                // Check that iterator hits each value in order
                last_value = value;
                confirm_count[value as usize] += 1;
                assert_eq!(value, it.last_finalized_height().unwrap_or(0));
            }
            // Check that it went up to the blockheight - confirmation count
            if max_value >= n_confirms {
                assert_eq!(last_value, max_value - n_confirms);
            } else {
                assert_eq!(last_value, 0);
            }
            // Update blockheight and loop
            max_value += step_by;
            let _ = it.rpc_update_max_height(&DummyRpc(max_value));
        }

        // Check that every confirmed block was confirmed exactly once
        for i in 0..last_value + n_confirms {
            if i <= last_value {
                assert_eq!(confirm_count[i as usize], 1);
            } else {
                assert_eq!(confirm_count[i as usize], 0);
            }
        }
    }

    fn test_iterator_skip() {
        let skip = 11;
        let mut it = HeightIterator::new(skip, 10);
        assert_eq!(it.last_finalized_height().unwrap(), 1);

        let _ = it.rpc_update_max_height(&DummyRpc(12));
        // This should return None as nothing is confirmed
        assert_eq!(true, it.next().is_none());

        let _ =it.rpc_update_max_height(&DummyRpc(21));
        let value = it.next().unwrap();
        assert_eq!(value, 11);
    }

    #[test]
    fn run_test_iterator() {
        test_iterator(100, 10, 15);
        test_iterator(100, 10, 10);
        test_iterator(100, 10, 5);
        test_iterator(100, 10, 1);
        test_iterator_skip();
    }
}

