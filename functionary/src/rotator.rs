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

//! # Rotator
//!
//! The main "rotating consensus" loop. Using the current clock time, signals the
//! main thread at the start of each stage within each round. Each round is split
//! into some number of stages whose durations are specified by the configuration
//! file. (Currently both blocksigner and watchman hardcode 3 stages per round.)
//!
//! The timings are maintained by a "heartbeat thread" which simply sleeps for
//! appropriate amounts of time and then signals the main thread at each stage
//! start. The main thread signals the heartbeat thread when it starts and finishes
//! processing each stage, so that it is easy to detect if the main thread is slow
//! or stalled.
//!
//! Within a round, each stage assumes that every stage has been processed before it.
//! Because of this assumption, if the main thread fails to process a stage before
//! the next stage should begin, the heartbeat thread skips to the next round rather
//! than skipping the stage itself (or attempting to start the stage late, which is
//! unlikely to be useful because the network expects stages to be processed at
//! specific times).
//!

use std::sync::mpsc;
use std::{fmt, thread};
use std::time::{Duration, Instant, SystemTime};

use dynafed;
use message::{self, Message};
use network::NetworkCtrl;
use peer;
use utils::{self, DurationExt};

pub use common::RoundStage;

/// Logs a peer action
#[macro_export]
macro_rules! log_peer {
    ($level:ident, $rotator:ident, $peer:expr, $($arg:tt)+) => (
        $crate::rotator::log_rotator(
            filename!(),
            line!(),
            $crate::logs::Severity::$level,
            $rotator,
            $peer,
            &format_args!($($arg)+),
        )
    )
}

/// A message sent across a channel to the main thread
#[derive(Clone, Debug)]
pub enum MainCtrl {
    /// Incoming network message
    Incoming(message::Message<message::Validated>),
    /// Start the first stage of a round
    StartStage(RoundStage, mpsc::SyncSender<()>, bool),
}

/// Abstract trait representing a clock to allow mock testing with
/// an arbitrarily wrong clock
pub trait Clock {
    /// Returns current time
    fn now(&mut self) -> SystemTime;

    /// Lets thread sleep for `dur`
    fn sleep(&mut self, dur: Duration);
}

/// Proper clock that uses system functions
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&mut self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&mut self, dur: Duration) {
        thread::sleep(dur);
    }
}

/// Infinite iterator which times stages/rounds
pub struct StageTimer<C> {
    /// Length of each stage, in milliseconds
    stage_durations: Vec<Duration>,
    /// Ordered list of peer IDs
    peers: Vec<peer::Id>,
    /// Round as of most recent iteration
    round: u64,
    /// Stage within that round
    stage: usize,
    /// Master of that round
    master: peer::Id,
    /// Time struct
    clock: C
}

impl<C: Clock> StageTimer<C> {
    /// Constructs a new stage timer
    pub fn new(
        stage_durations: Vec<Duration>,
        initial_peers: Vec<peer::Id>,
        clock: C,
    ) -> StageTimer<C> {
        StageTimer {
            stage_durations: stage_durations,
            peers: initial_peers,
            stage: 0,
            round: 0,
            master: peer::Id::default(),
            clock: clock,
        }
    }

    /// Accessor for the total length of a round
    fn round_length(&self) -> Duration {
        self.stage_durations.iter().cloned().sum()
    }

    /// Computes and returns the next round/stage number, the `SystemTime`
    /// at which it starts, and the `Duration` between now and that time.
    ///
    /// To compute the next round/stage number, we
    ///     1. Look at the clock time and directly determine which round
    ///        and stage we expect to be starting next.
    ///     2. If this is the stage immediately following our previous
    ///        stage, great! Alternately if this is equal to our previous
    ///        stage, instead return the following stage (assume we slightly
    ///        underslept before calling this function).
    ///     3. If this is after the immediately-following stage, return
    ///        the stage corresponding to the round start following the
    ///        computed stage.
    ///     4. If this is before the previous stage, instead return the
    ///        stage corresponding to the round start following the
    ///        previous stage.
    /// This ensures that (a) this function is always monotonic, regardless
    /// of clock behavior; (b) that it never skips stages within a round;
    /// (c) that it always returns a stage in the future, according to the
    /// current clock time (with a nonnegative sleep duration).
    ///
    /// Callers need to be aware that the returned round number may not
    /// always increment and that they may need to adjust the master iterator.
    fn next_stage(&mut self) -> (u64, usize, SystemTime, Duration) {
        let now = self.clock.now();
        let since_epoch_ms = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("1970 in the past")
            .as_millis_ext();
        let round_length_ms = self.round_length().as_millis_ext();

        // 1. Directly compute next round/stage based on clock.
        let n_rounds = since_epoch_ms / round_length_ms;
        let mut start_time_ms = n_rounds * round_length_ms;
        let mut round_no = n_rounds;

        let mut stage = 0;
        while start_time_ms < since_epoch_ms {
            start_time_ms += self.stage_durations[stage].as_millis_ext();
            stage += 1;
        }

        // 2. Check if it is what we expected (or one less)
        if round_no == self.round && (stage == self.stage || stage == self.stage + 1) {
            stage = self.stage + 1;
        } else if round_no > self.round || (round_no == self.round && stage > self.stage + 1) {
            // 3. If it is *after* the correct stage, adjust and log
            //    an overrun
            if stage > 0 {
                round_no += 1;
                stage = 0;
            }

            // Don't produce an error log when we just started up.
            if self.round != 0 {
                let would_be_round;
                let would_be_stage;
                if self.stage == self.stage_durations.len() - 1 {
                    would_be_round = self.round + 1;
                    would_be_stage = 0;
                } else {
                    would_be_round = self.round;
                    would_be_stage = self.stage + 1;
                }
                let round_time = self.stage_durations[..self.stage + 1].iter()
                    .map(|dur| dur.as_millis_ext())
                    .sum::<u64>();
                let would_be_start_time_ms = round_length_ms * self.round + round_time;

                slog!(StageOverrun, overrun_round: would_be_round, overrun_stage: would_be_stage,
                    overrun_ms: since_epoch_ms - would_be_start_time_ms, next_round: round_no,
                );
            }
        } else if round_no < self.round || (round_no == self.round && stage < self.stage) {
            // 4. If it is *before* the correct stage, adjust and log
            //    an underrun
            round_no = self.round + 1;
            stage = 0;

            let would_be_round;
            let would_be_stage;
            if self.stage == self.stage_durations.len() - 1 {
                would_be_round = self.round + 1;
                would_be_stage = 0;
            } else {
                would_be_round = self.round;
                would_be_stage = self.stage + 1;
            }
            let round_time = self.stage_durations[..self.stage + 1].iter()
                .map(|dur| dur.as_millis_ext())
                .sum::<u64>();
            let would_be_start_time_ms = round_length_ms * self.round + round_time;

            slog!(StageUnderrun, underrun_round: would_be_round,
                underrun_stage: would_be_stage,
                underrun_ms: would_be_start_time_ms - since_epoch_ms, next_round: round_no
            );
        }

        // Return
        if stage == self.stage_durations.len() {
            round_no += 1;
            stage = 0;
        }
        let round_time = self.stage_durations[..stage].iter()
            .map(|dur| dur.as_millis_ext())
            .sum::<u64>();
        start_time_ms = round_length_ms * round_no + round_time;
        let to_wait = Duration::from_millis(
            (start_time_ms - since_epoch_ms) as u64
        );

        (round_no, stage, now + to_wait, to_wait)
    }
}

impl<C: Clock> Iterator for StageTimer<C> {
    type Item = RoundStage;

    /// Waits for the next stage, which should be the next consecutive stage. If the
    /// the clock time indicates we have overrun the next consecutive stage, we
    /// instead wait for the start of the next *round*. After waiting, returns a
    /// `RoundStage` object describing what we waited for.
    fn next(&mut self) -> Option<RoundStage> {
        let (mut next_round, mut next_stage, mut start_time, mut to_wait)
            = self.next_stage();

        // Special-case first call
        if self.master == peer::Id::default() && next_stage != 0 {
            next_round += 1;
            let offset = self.stage_durations[next_stage..].iter().sum();
            to_wait += offset;
            start_time += offset;
            next_stage = 0;
        }

        // Set next round, stage and master
        if next_stage == 0 {
            assert!(!self.peers.is_empty());
            let peer_idx = (next_round % self.peers.len() as u64) as usize;
            self.master = self.peers[peer_idx];
        }
        self.round = next_round;
        self.stage = next_stage;

        slog!(WaitForStage, next_round: next_round, next_stage: next_stage,
            delay_ms: to_wait.as_millis_ext()
        );
        self.clock.sleep(to_wait);

        // Compute the start time of the stage that we actually wind up returning, and return it.
        Some(RoundStage {
            start_time: start_time,
            duration: self.stage_durations[self.stage],
            round: self.round,
            stage: self.stage,
            master: self.master,
        })
    }
}

/// Spin off thread to send heartbeat messages. Returns both ends of a
/// `sync_channel` used to communicate heartbeat messages to the main
/// thread; keeps a copy of the `Sender` for itself. Also returns the
/// sending half of a channel used to communicate dynamic federation
/// updates to the heartbeat thread.
fn start_heartbeat_thread(stage_durations: Vec<Duration>) -> (
    mpsc::SyncSender<MainCtrl>,
    mpsc::Receiver<MainCtrl>,
    mpsc::SyncSender<dynafed::ArcBarrier<dynafed::UpdateNotif>>,
) {
    // Set the main thread's channel to have size 1024; this channel receives both
    // round stage-starting heartbeats and incoming network messages. If it is full
    // we start dropping messages and logging errors until the main thread has had
    // time to catch up, but this should not happen except in case of a deliberate
    // network DoS by another peer.
    let (ret_tx, ret_rx) = mpsc::sync_channel(1024);
    // Channel for dynamic federation updates - this channel has room for a
    // single message; the `ArcBarrier`-based syncing mechanism prevents
    // more than one being sent at once, and having no buffer would cause
    // unwanted blocking of the main thread dispatching updates.
    let (dynafed_tx, dynafed_rx) = mpsc::sync_channel::<dynafed::ArcBarrier<dynafed::UpdateNotif>>(1);

    let tx = ret_tx.clone();
    utils::spawn_named_or_die("heartbeat".to_owned(), move || {
        let peer_list = dynafed_rx.recv().unwrap().sorted_peer_list();
        log!(Trace, "peer_list: {:?}", peer_list);
        let n_stages = stage_durations.len();
        let mut timer = StageTimer::new(stage_durations, peer_list, SystemClock);

        let mut fail_time: Option<Instant> = None;
        while let Some(stage) = timer.next() {
            // Send the main thread a channel on which it can signal "done" so we know
            // it's ready for the next stage. This lets us detect overruns as soon as
            // they happen so we can skip to the next round start. Otherwise, if the
            // main thread was stalled and we had no way to detect it, we would queue up
            // round starts and the resulting logs would be very difficult to read.
            let (done_tx, done_rx) = mpsc::sync_channel(0);
            let expect_dynafed = stage.stage == n_stages - 1;

            if let Err(e) = tx.try_send(MainCtrl::StartStage(stage, done_tx, expect_dynafed)) {
                log!(Error, "Failed to send heartbeat (start round) message to main thread: {}", e);
                if let Some(time) = fail_time {
                    log!(Error, "Unable to send heartbeats for {} ms",
                        (Instant::now() - time).as_millis_ext(),
                    );
                } else {
                    fail_time = Some(Instant::now());
                }
            } else {
                let _ = done_rx.recv();
                log!(Debug, "Main thread started stage");
                let _ = done_rx.recv();
                log!(Debug, "Main thread completed stage");
                fail_time = None;
                // After the last stage, check for a dynafed update
                if expect_dynafed {
                    log!(Debug, "Start heartbeat dynafed update");
                    timer.peers = dynafed_rx.recv().unwrap().sorted_peer_list();
                    log!(Trace, "peer_list: {:?}", timer.peers);
                    log!(Debug, "End heartbeat dynafed update");
                }
            }
        }
    });
    (ret_tx, ret_rx, dynafed_tx)
}

/// The main Rotating Consensus loop trait
pub trait Rotator: Sized {
    /// Run an infinite loop which listens for consensus state changes and network messages
    fn run(&mut self) -> ! {
        // Setup
        let (tx_main, rx_main, heartbeat_dynafed_tx)
            = start_heartbeat_thread(self.stage_durations());

        let net_tx = self.setup_network(tx_main);

        let dynafed_update = |notif| {
            let _ = dynafed::send_arc_barriers(
                notif,
                &mut [
                    &mut |barrier| heartbeat_dynafed_tx
                        .send(barrier)
                        .expect("heartbeat thread to be alive"),
                    &mut |barrier| net_tx
                        .send(NetworkCtrl::DynafedUpdate(barrier))
                        .expect("heartbeat thread to be alive"),
                ],
            );
        };

        // Do initial dynafed update to load initial peer list
        self.dynafed_update(&dynafed_update);

        // Start main loop
        let mut current_stage = None;

        for message in rx_main.iter() {
            match message {
                // Heartbeat
                MainCtrl::StartStage(stage, done_tx, expect_dynafed_update) => {
                    logs::set_round_stage(stage);
                    log!(Debug, "Received start-stage message.");
                    done_tx.send(()).expect("heartbeat thread to be alive");  // signal stage start

                    // If this is a new round, notify the router about it so that it can stop
                    // handling irrelevant messages and clear up outgoing messages.
                    if stage.stage == 0 {
                        net_tx.send(NetworkCtrl::NewRoundNumber(stage.round as u32))
                            .expect("network thread alive");
                    }

                    if let Some(overrun) = stage.is_overrun() {
                        log!(Error, "Skipping stage due to overrun of {} ms.", overrun.as_millis_ext());
                    } else {
                        match stage.stage {
                            0 => {
                                // Do stage 1
                                self.round_stage1(stage);
                                self.send_status(stage);
                            },
                            1 => {
                                self.round_stage2(stage);
                            },
                            2 => {
                                self.round_stage3(stage);
                            }
                            _ => panic!("We only support 3 stages.")
                        }
                        current_stage = Some(stage);
                    }
                    done_tx.send(()).expect("heartbeat thread to be alive");  // signal stage end
                    if expect_dynafed_update {
                        self.dynafed_update(&dynafed_update);
                    }
                },
                // Message from the network
                MainCtrl::Incoming(msg) => {
                    if let Some(stage) = current_stage {
                        log!(Debug, "Received network message {:?}", msg.header());
                        if msg.header().round == stage.round as u32 {
                            self.handle_message(msg, stage);
                        } else {
                            log_peer!(Warn, self, msg.header().sender,
                                "Received network message in wrong round {}; ignoring. Header: {:?}",
                                msg.header().round, msg.header(),
                            );
                        }
                    } else {
                        log!(Debug,
                            "Received {:?} message but we are not in any stage right now, ignoring.",
                            msg.header().command,
                        );
                    }
                },
            }
        }
        panic!("Main thread stopped receiving messages");
    }

    /// Recompute the list of peers, passing it through an `update_fn`
    /// which synchronizes and communicates the new list to other threads
    fn dynafed_update<F>(&mut self, update_fn: F) where F: FnOnce(dynafed::UpdateNotif);

    /// Accessor for the vector of stage timings
    fn stage_durations(&self) -> Vec<Duration>;

    /// Construct a network router capable of sending messages
    /// from the main thread over the wire
    fn setup_network(&mut self, tx_main: mpsc::SyncSender<MainCtrl>) -> mpsc::SyncSender<NetworkCtrl>;

    /// React to the start of a new round
    fn round_stage1(&mut self, stage: RoundStage);

    /// React to a round being 1/3 over
    fn round_stage2(&mut self, stage: RoundStage);

    /// React to a round being 2/3 over
    fn round_stage3(&mut self, stage: RoundStage);

    /// React to a network message
    fn handle_message(&mut self, msg: Message<message::Validated>, stage: RoundStage);

    /// Broadcast a status message to all peers
    fn send_status(&mut self, stage: RoundStage);
}


/// Logs events from a rotator, considering its state
pub fn log_rotator(
    file: &str,
    line: u32,
    level: logs::Severity,
    _rotator: &impl Rotator,
    peer: peer::Id,
    message: impl fmt::Display,
) {
    logs::log::log(
        file,
        line,
        level,
        &format_args!(
            "[{}] {}",
            peer,
            message,
        ),
    );
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{rand, PublicKey};
    use std::str::FromStr;

    use peer;
    use super::*;

    /// A Clock for testing that never sleeps and returns custom values for `now`. On each call to
    /// `now` it returns the next element in the list of `nows`.  When sleep is called its duration
    /// is added to the vector of sleeps.
    struct TestClock {
        nows: Vec<SystemTime>,
        sleeps: Vec<Duration>
    }
    impl TestClock {
        fn new(nows: Vec<SystemTime>) -> TestClock {
            TestClock { nows: nows, sleeps: vec![] }
        }
        /// Returns a vector with the durations of previous `sleep` calls
        fn debug_get_sleeps(&self) -> Vec<Duration> {
            self.sleeps.clone()
        }
        /// Appends a new "now" to a list that will be returned by the `i`-th call to `now`, where `i`
        /// is the the position of "now" in the list.
        fn debug_add_now(&mut self, now: SystemTime) {
            self.nows.push(now);
        }
    }
    impl Clock for TestClock {
        fn now(&mut self) -> SystemTime {
            let now = self.nows[0];
            self.nows = self.nows[1..].to_vec();
            now
        }
        fn sleep(&mut self, dur: Duration) {
            self.sleeps.push(dur);
        }
    }

    #[test]
    fn test_stagetimer() {
        let stage_dur = vec![
            Duration::from_millis(3),
            Duration::from_millis(5),
            Duration::from_millis(7),
        ];
        let round_dur = Duration::from_millis(15);
        let peers = {
            let peer1 = {
                let pk = PublicKey::from_str("023303dedc51b9d227b17c9fb4710f96b844e1ccdc2c776e1b7274bd4e246b6202").unwrap();
                peer::Peer { name: "foo".to_owned(), addresses: vec![], comm_pk: pk, comm_pk_legacy: None, sign_pk: pk }
            };
            let peer2 = {
                let pk = PublicKey::from_str("031540bab86f97cce6a7ab4c6d170439a48da8618eb2e7302a76cc300c0a3edc62").unwrap();
                peer::Peer { name: "bar".to_owned(), addresses: vec![], comm_pk: pk, comm_pk_legacy: None, sign_pk: pk }
            };
            peer::List::from_slice(&vec![peer1, peer2], |_| true, "foo")
        };
        let ids: Vec<_> = peers.consensus_ordered_ids();
        let start_time = SystemTime::UNIX_EPOCH + Duration::from_secs(
            17801 * 3600 * 24 + 71058
        ); // 2018-09-27 19:44:18+0000

        // a closure to reduce the number of times we need to type `.clone()`
        // on the returned `Vec`
        let iterfn = || peers.consensus_ordered_ids();

        // Test 1: time stays constant, stage progresses nonetheless
        let nows = vec![start_time; 4];
        let clock = TestClock::new(nows);
        let mut timer = StageTimer::new(stage_dur.clone(), iterfn(), clock);
        assert_eq!(timer.clock.debug_get_sleeps(), vec![]);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497200);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[0]);
        // If the clock shows we should be one stage behind where we
        // are, ignore it (maybe our sleeps were too short or there
        // was a leap second or something)
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497200);
        assert_eq!(stage.stage, 1);
        // ...but once we're more than one stage ahead of clock, assume
        // something is wrong and start going to the next round start.
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, 0);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497202);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[0]);
        // First sleep is 0 because start time is divisible by round time;
        // then it sleeps til the start of the next stage; then it starts
        // skipping stages to get to the start of the next round. Sleeps are
        // relative to the "current time" (which is unchanging).
        assert_eq!(
            timer.clock.debug_get_sleeps(),
            vec![
                Duration::new(0, 0),
                stage_dur[0],
                round_dur,
                round_dur * 2,
            ]
        );

        // Test 2: Long gap between calls to next() followed by clock going
        // backward. This will cause `stage.round` to ratchet forward, and
        // when the clock goes backward there will be a long delay.
        let nows = vec![
            start_time,
            start_time + round_dur + Duration::from_millis(1),
            start_time + round_dur * 100_000_000,
            start_time,
        ];
        let clock = TestClock::new(nows);
        let mut timer = StageTimer::new(stage_dur.clone(), iterfn(), clock);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497200);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[0]);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497202);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[0]);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102638497200);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[0]);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102638497201);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[1]);
        assert_eq!(
            timer.clock.debug_get_sleeps(),
            vec![
                Duration::new(0, 0),
                round_dur - Duration::from_millis(1),
                Duration::new(0, 0),
                round_dur * 100_000_001,
            ]
        );

        // Test 3: Time should allow for normal switching from 0th to 1st stage
        let nows = vec![
            start_time,
            start_time + stage_dur[0],
        ];
        let clock = TestClock::new(nows);
        let mut timer = StageTimer::new(stage_dur.clone(), iterfn(), clock);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497200);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[0]);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497200);
        assert_eq!(stage.stage, 1);
        assert_eq!(stage.master, ids[0]);

        // Test 4: Iterator skips stage 2
        let nows = vec![
            start_time,
            start_time + stage_dur[0],
            start_time + stage_dur[0] + stage_dur[1] + Duration::from_millis(1),
        ];
        let clock = TestClock::new(nows);
        let mut timer = StageTimer::new(stage_dur.clone(), iterfn(), clock);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497200);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[0]);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497200);
        assert_eq!(stage.stage, 1);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[1]);

        // Test 5: Iterator skips two stages and a full round
        let nows = vec![
            start_time,
            start_time + round_dur + Duration::from_millis(1),
        ];
        let clock = TestClock::new(nows);
        let mut timer = StageTimer::new(stage_dur.clone(), iterfn(), clock);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497200);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[0]);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497202);
        assert_eq!(stage.stage, 0);
        assert_eq!(stage.master, ids[0]);

        // Test 6: Runs two StageTime iterators with randomly but
        // monotonically increasing clocks and checks if they agree
        // on stage and master in the end.
        for _ in 0..1000 {
            fn rand_duration(round_dur: Duration) -> Duration {
                let max_clock_add = 2 * round_dur.as_millis_ext() as u64;
                let rand = rand::random::<u8>() as u64 % max_clock_add;
                Duration::from_millis(rand)
            }

            fn last_sleep_duration(timer: &StageTimer<TestClock>) -> Duration {
                *timer.clock.debug_get_sleeps().last().unwrap()
            }

            // Initialize clock with randomized start time
            let mut now1 = start_time;
            let mut now2 = start_time;
            let clock1 = TestClock::new(vec![]);
            let clock2 = TestClock::new(vec![]);
            let mut timer1 = StageTimer::new(stage_dur.clone(), iterfn(), clock1);
            let mut timer2 = StageTimer::new(stage_dur.clone(), iterfn(), clock2);

            // Add random durations to clock, without taking sleep into account
            let n_stages = 5;
            let mut last_stage1;
            let mut last_stage2;
            loop {
                now1 = now1 + rand_duration(round_dur);
                now2 = now2 + rand_duration(round_dur);
                timer1.clock.debug_add_now(now1);
                timer2.clock.debug_add_now(now2);
                last_stage1 = timer1.next().unwrap();
                last_stage2 = timer2.next().unwrap();
                // Break loop if clock1 exceeds stop time
                if now1 >= start_time + round_dur * n_stages {
                    break;
                }
            }

            // Now just add the sleep duration to the clock without adding
            // randomization. That should synchronize the clocks again.
            now1 = now1 + last_sleep_duration(&timer1);
            now2 = now2 + last_sleep_duration(&timer2);
            timer1.clock.debug_add_now(now1);
            timer2.clock.debug_add_now(now2);
            while now1 < now2 {
                last_stage1 = timer1.next().unwrap();
                now1 = now1 + last_sleep_duration(&timer1);
                timer1.clock.debug_add_now(now1);
            }
            while now2 < now1 {
                last_stage2 = timer2.next().unwrap();
                now2 = now2 + last_sleep_duration(&timer2);
                timer2.clock.debug_add_now(now2);
            }
            assert_eq!(now1, now2);
            assert_eq!(last_stage1.round, last_stage2.round);
            assert_eq!(last_stage1.stage, last_stage2.stage);
            assert_eq!(last_stage1.master, last_stage2.master);
        }
    }
}

