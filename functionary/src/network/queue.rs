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

//! # Incoming Message Queue
//!
//! Queues up incoming messages, enforcing that (within a round) they arrive
//! in order.
//!

use std::mem;

use peer;
use message;

/// Alias to reduce typing the "signed message" type.
type SignedMsg = message::Message<message::Validated>;

/// Number of out-of-order messages to queue before dropping them.
/// This also represents the maximum number of messages that can
/// be sent from a given peer to another in a single round; it will
/// need to be increased if future protocol revisions involve a lot
/// more communication.
const QUEUE_CAPACITY: usize = 16;

/// The type of what goes into the slots of the queues.
#[derive(Debug)]
enum Slot {
    /// No message placed here yet.
    Empty,
    /// Message is placed and not yet processed.
    QueuedMessage(SignedMsg),
    /// Message was processed and is taken.
    Processed,
    /// Message was invalid and should be skipped.
    ToSkip,
}

impl Slot {
    /// Put a message in the slot only if it has not been processed yet.
    fn put(&mut self, msg: SignedMsg) -> bool {
        match self {
            Slot::Empty => {
                *self = Slot::QueuedMessage(msg);
                true
            }
            _ => false
        }
    }

    /// Take a message from the slot and mark as processed.
    fn take(&mut self) -> Option<SignedMsg> {
        let mut ret = None;
        *self = match mem::replace(self, Slot::Processed) {
            Slot::QueuedMessage(msg) => {
                ret = Some(msg);
                Slot::Processed
            }
            other => other,
        };
        ret
    }

    /// Empty the slot.
    fn empty(&mut self) {
        *self = Slot::Empty;
    }
}

impl Default for Slot {
    fn default() -> Slot {
        Slot::Empty
    }
}

/// Structure to track incoming messages
pub struct IncomingQueue {
    /// Messages that have been received for ourselves, and which
    /// should be reordered before sending to the main thread
    current_queue: [Slot; QUEUE_CAPACITY],
    /// Messages that have been received for the next round.
    next_queue: [Slot; QUEUE_CAPACITY],
    /// The current round number. If we receive a message for a higher
    /// number we will assume a new round has started and reset the queue.
    current_session: u32,
    /// The msgid of the next to-self message that we will return to the
    /// application layer. If no message with this msgid is available
    /// we will simply queue up messages until it is
    next_msgid: u32,
    /// The least nonce of a to-relay message that we will accept into the
    /// queue. Messages with lower nonces we assume are replays and we will
    /// silently drop them.
    lowest_nonce: u32,
}

impl IncomingQueue {
	/// Create a new [IncomingQueue] starting at the current session.
	pub fn new(current_session: u32) -> IncomingQueue {
        IncomingQueue {
            current_queue: Default::default(),
            next_queue: Default::default(),
            current_session: current_session,
            next_msgid: 0,
            lowest_nonce: 0,
        }
	}
}

impl Iterator for IncomingQueue {
    type Item = SignedMsg;

    /// Yield the next in-order message.
    fn next(&mut self) -> Option<SignedMsg> {
        if let Some(slot) = self.current_queue.get_mut(self.next_msgid as usize) {
            match slot {
                slot @ Slot::QueuedMessage(_) => {
                    self.next_msgid += 1;
                    slot.take()
                }
                Slot::ToSkip => {
                    self.next_msgid += 1;
                    self.next()
                }
                Slot::Empty => None,
                Slot::Processed => unreachable!(),
            }
        } else {
            // This should not ever happen under ordinary circumstances.
            log!(Error, "requesting incoming messages exceeding message queue");
            None
        }
    }
}

impl IncomingQueue {
    /// Records a new incoming message to this node
    fn enqueue(&mut self, message: SignedMsg) {
        let msgid = message.header().msgid as usize;
        // Require that the msgid is in range. If not, drop the message.
        if msgid >= QUEUE_CAPACITY {
            log!(Error, "peer {} sent a message with ID outside of valid range: {}",
                message.header().sender, msgid,
            );
            return;
        }

        match message.header().round {
            r if r < self.current_session => {
                log!(Debug, "peer {} sent message for round {} (currently {})",
                    message.header().sender, message.header().round, self.current_session,
                );
            }
            r if r == self.current_session => {
                // Only record the message if we haven't seen one with this msgid before
                if message.is_unknown() {
                    self.current_queue[msgid] = Slot::ToSkip;
                } else {
                    self.current_queue[msgid].put(message);
                }
            }
            r if r == self.current_session + 1 => {
                // Only record the message if we haven't seen one with this msgid before
                if message.is_unknown() {
                    self.next_queue[msgid] = Slot::ToSkip;
                } else {
                    self.next_queue[msgid].put(message);
                }
            }
            r => {
                log!(Warn, "round on message from {} for round out of range: {} (current: {})",
                    message.header().sender, r, self.current_session,
                );
            }
        }
    }

    /// Update the session of the queue.
    pub fn update_session(&mut self, number: u32) {
        if number == self.current_session + 1 {
            // Strict increment, put the next queue in the current and clear new next.
            mem::swap(&mut self.current_queue, &mut self.next_queue);
            self.next_queue.iter_mut().for_each(|o| { o.empty(); });
        } else {
            // Larger increment (round overrun or so), just clear both.
            self.current_queue.iter_mut().for_each(|o| { o.empty(); });
            self.next_queue.iter_mut().for_each(|o| { o.empty(); });
        }

        self.current_session = number;
        self.next_msgid = 0;
        self.lowest_nonce = 0;
    }
}

/// Peer-indexed list of incoming messages
pub type MessageQueue = peer::Map<IncomingQueue>;

impl MessageQueue {
    /// Record the nonce for the given sender.
    /// Returns [true] if the nonce was higher than the highest stored nonce.
    pub fn record_nonce(&mut self, sender: peer::Id, nonce: u32) -> bool {
        let queue = &mut self[sender];
        if queue.lowest_nonce < nonce {
            queue.lowest_nonce = nonce;
            true
        } else {
            false
        }
    }

    /// Records a new incoming message.
    pub fn enqueue(&mut self, message: SignedMsg) {
        self[message.header().sender].enqueue(message);
    }

    /// Update the session of the queue.
    pub fn update_session(&mut self, number: u32) {
        self.values_mut().for_each(|q| q.update_session(number));
    }
}

impl<'a> Iterator for &'a mut MessageQueue {
    type Item = SignedMsg;
    /// Yield the next in-order message
    fn next(&mut self) -> Option<SignedMsg> {
        for queue in self.values_mut() {
            if let Some(msg) = queue.next() {
                return Some(msg);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1;

    fn message(
        send_id: peer::Id,
        recv_id: peer::Id,
        round: u32,
        msgid: u32,
        nonce: u32,
    ) -> message::Message<message::Validated> {
        let mut msg_ser = message::tests::CONST_STATUS_ACK.clone();
        assert_eq!(
            message::MESSAGE_VERSION,
            21,
            "The message version has changed and the message-queue unit \
             tests need to be updated."
        );
        msg_ser[68..74].copy_from_slice(&send_id[..]);
        msg_ser[74..80].copy_from_slice(&recv_id[..]);
        message::NetEncodable::encode(&round, &mut msg_ser[80..84]).unwrap();
        message::NetEncodable::encode(&msgid, &mut msg_ser[84..88]).unwrap();
        message::NetEncodable::encode(&nonce, &mut msg_ser[88..92]).unwrap();

        let msg: message::Message<secp256k1::ecdsa::Signature> = message::NetEncodable::decode(&msg_ser[..])
            .expect("decoding dummy statusack for msg queue unit tests");
        msg.drop_signature()
    }

    #[test]
    fn in_order_dupes() {
        assert_eq!(
            QUEUE_CAPACITY,
            16,
            "queue unit test assumes a capacity of 16"
        );
        let (_, peers) = peer::tests::generate_peers(2, 0);
        let peer_id = peers.consensus_ordered_ids();

        let round_no = 100;
        let nonce = 100; // constant nonce OK for to-self messages
        let mut queue = MessageQueue::empty(peer_id[0]);
        queue.update_from(&peers, |_| IncomingQueue::new(round_no), |_| {});

        // Enqueue the first 5 messages
        for msgid in 0..5 {
            queue.enqueue(message(
                peer_id[1],
                peer_id[0],
                round_no,
                msgid,
                nonce,
            ));
        }
        assert_eq!(queue.count(), 5);
        assert_eq!(queue.count(), 0);

        // Try enqueuing the first 10 messages again
        for msgid in 0..5 {
            queue.enqueue(message(
                peer_id[1],
                peer_id[0],
                round_no,
                msgid,
                nonce,
            ));
        }
        assert_eq!(queue.count(), 0);

        // Try enqueuing the next 5 messages
        for msgid in 5..10 {
            queue.enqueue(message(
                peer_id[1],
                peer_id[0],
                round_no,
                msgid,
                nonce,
            ));
        }
        assert_eq!(queue.count(), 5);
        assert_eq!(queue.count(), 0);

        // Try enqueuing the next 10 messages, with each coming in twice.
        for msgid in 10..15 {
            let message = message(
                peer_id[1],
                peer_id[0],
                round_no,
                msgid,
                nonce,
            );
            queue.enqueue(message.clone());
            queue.enqueue(message.clone());
        }
        assert_eq!(queue.count(), 5);
        assert_eq!(queue.count(), 0);

        // Try enqueuing the next 5 messages. One should succeed, the rest
        // should silently fail sunce we have run into the `QUEUE_CAPACITY`
        // limit
        for msgid in 15..20 {
            queue.enqueue(message(
                peer_id[1],
                peer_id[0],
                round_no,
                msgid,
                nonce,
            ));
        }
        assert_eq!(queue.count(), 1);
        assert_eq!(queue.count(), 0);

        // Try enqueuing out of range messages. All should fail but nothing
        // should crash.
        for msgid in 200..300 {
            queue.enqueue(message(
                peer_id[1],
                peer_id[0],
                round_no,
                msgid * 5000,
                nonce,
            ));
        }
        assert_eq!(queue.count(), 0);
    }

    #[test]
    fn out_of_order() {
        let (_, peers) = peer::tests::generate_peers(2, 0);
        let peer_id = peers.consensus_ordered_ids();

        let round_no = 100;
        let nonce = 100; // constant nonce OK for to-self messages

        let mut queue = MessageQueue::empty(peer_id[0]);
        queue.update_from(&peers, |_| IncomingQueue::new(round_no), |_| {});

        let msgids = vec![
            0, 1, 4, 3, 2,
            1, 1, 1, 1, 1,
            6, 6, 5, 6, 6,
            9, 8, 7, 10, 11,
        ];

        for msgid in msgids {
            queue.enqueue(message(
                peer_id[1],
                peer_id[0],
                round_no,
                msgid,
                nonce,
            ));
        }

        for i in 0..12 {
            assert_eq!((&mut queue).next().unwrap().header().msgid, i);
        }
        assert_eq!(queue.count(), 0);
    }

    #[test]
    fn requeue() {
        let (_, peers) = peer::tests::generate_peers(2, 0);
        let peer_id = peers.consensus_ordered_ids();

        let round_no = 100;
        // constant (and out-of-range) msgid OK for to-other messages
        let msgid = 100;

        let mut queue = MessageQueue::empty(peer_id[1]);
        queue.update_from(&peers, |_| IncomingQueue::new(round_no), |_| {});

        for nonce in 100..200 {
            queue.enqueue(message(
                peer_id[0],
                peer_id[1],
                round_no,
                msgid,
                nonce,
            ));
        }

        // Trying again should fail
        assert_eq!(queue.count(), 0);
        for nonce in 100..200 {
            queue.enqueue(message(
                peer_id[0],
                peer_id[1],
                round_no,
                msgid,
                nonce,
            ));
        }
        assert_eq!(queue.count(), 0);
    }

    #[test]
    fn next_round() {
        let (_, peers) = peer::tests::generate_peers(2, 0);
        let peer_id = peers.consensus_ordered_ids();

        let round_no = 100;
        let nonce = 100; // constant nonce OK for to-self messages

        let mut queue = MessageQueue::empty(peer_id[1]);
        queue.update_from(&peers, |_| IncomingQueue::new(round_no), |_| {});

        queue.enqueue(message(
            peer_id[1],
            peer_id[0],
            round_no,
            0,
            nonce,
        ));
        queue.enqueue(message(
            peer_id[1],
            peer_id[0],
            round_no + 1,
            0,
            nonce + 1,
        ));

        assert_eq!(queue.count(), 1);
        queue.update_session(round_no + 1);
        assert_eq!(queue.count(), 1);
    }
}
