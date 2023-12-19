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
use std::convert::TryFrom;
use std::time::{Duration, Instant, SystemTime};

use dynafed;
use message::{self, Message};
use network::NetworkCtrl;
use peer;
use utils::{self, DurationExt};

pub use common::RoundStage;
use common::Stage;

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
    stage: Stage,
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
            stage: Stage::Stage1,
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
    ///     1.  Look at the clock time and directly determine which round
    ///         and stage we expect to be starting next.
    ///     2.  If this is the stage immediately following our previous
    ///         stage, great! Alternately if this is equal to our previous
    ///         stage, instead return the following stage (assume we slightly
    ///         underslept before calling this function).
    ///     3.  If we believe we are in a stage or round earlier than clock time
    ///         says it is we have overrun.
    ///     3a. If we overrun Stage1 and it is still Stage2 the next stage will be an Alternate
    ///         Stage3 dubbed Stage3b. This stage has the same length as Stage3 and occurs at the
    ///         same starting time but provides an alternate stage logic for a daemon to implement
    ///         some catchup logic if the implementor decides to.
    ///     3b. If we overrun the whole round but end up in Stage1 or Stage2 of the subsequent round
    ///         the next stage will be Stage3b in the subsequent round.
    ///     3c. If we overrun into Stage3 of the current round the next round will be Stage1 of the
    ///         the next round.
    ///     3d. If we overrun into Stage3 of a later round we the next stage will be Stage1 of the
    ///         subsequent round.
    ///     4.  If we believe our round or stage is after the round or stage computed based on the
    ///         clock time, we have underrun a round/stage. If this occurs, the next stage will be
    ///         Stage1 of the round after the current round determined by the clock.
    /// This ensures that (a) this function is always monotonic, regardless
    /// of clock behavior; (b) that it always returns a stage in the future,
    /// according to the current clock time (with a nonnegative sleep duration).
    ///
    /// Callers need to be aware that the returned round number may not
    /// always increment and that they may need to adjust the master iterator.
    fn next_stage(&mut self) -> (u64, Stage, SystemTime, Duration) {
        let now = self.clock.now();
        let now_epoch_ms =
            now.duration_since(SystemTime::UNIX_EPOCH).expect("1970 in the past").as_millis_ext();
        let round_length_ms = self.round_length().as_millis_ext();

        // 1. Directly compute next round/stage based on clock.
        let round_by_time = now_epoch_ms / round_length_ms;
        let mut start_time_ms = round_by_time * round_length_ms;

        let mut stage_by_time = 0i32;
        while start_time_ms <= now_epoch_ms {
            start_time_ms += self.stage_durations[stage_by_time as usize].as_millis_ext();
            stage_by_time += 1;
        }

        let stage_by_time = Stage::try_from(stage_by_time).expect("Must be valid stage");

        use self::Stage::*;
        #[derive(Debug)]
        enum StageEvent {
            Standard,
            Overrun,
            Underrun,
        }

        let local_round = self.round;
        let local_stage = self.stage;
        let (round_result, stage_result, stage_event) = {
            if round_by_time > local_round {
                //round overrun
                if stage_by_time == Stage1 || stage_by_time == Stage2 {
                    // round overrun and in Stage1 or Stage2
                    (round_by_time, Stage3b, StageEvent::Overrun)
                } else {
                    // round overrun in Stage 3 or 3b
                    (round_by_time + 1, Stage1, StageEvent::Overrun)
                }
            } else if round_by_time < local_round {
                //round underrun
                (local_round + 1, Stage1, StageEvent::Underrun)
            } else if local_stage == Stage1 && stage_by_time == Stage2 {
                //stage overrun of Stage 1 and still in Stage 2
                (local_round, Stage3b, StageEvent::Overrun)
            } else if local_stage < stage_by_time {
                //stage overrun in Stage 3 or 3b
                (round_by_time + 1, Stage1, StageEvent::Overrun)
            } else if  (local_stage == Stage2 && stage_by_time == Stage1)
                || (local_stage == Stage3 && stage_by_time == Stage2) {
                //technically a single stage underrun but we tolerate this
                let (next_stage, next_round, _ ) = self.next_stage_and_round();
                (next_round, next_stage, StageEvent::Underrun)
            } else if local_stage > stage_by_time {
                //stage underrun
                (round_by_time + 1, Stage1, StageEvent::Underrun)
            } else if local_stage.as_duration_index() == stage_by_time.as_duration_index() {
                let (next_stage, next_round, _ ) = self.next_stage_and_round();
                (next_round, next_stage, StageEvent::Standard)
            } else {
                panic!("Unknown stage transition")
            }
        };

        let next_stage_time = self.stage_durations[..stage_result.as_duration_index()].iter()
            .map(|dur| dur.as_millis_ext())
            .sum::<u64>();
        start_time_ms = round_length_ms * round_result + next_stage_time;
        let to_wait = Duration::from_millis(
            (start_time_ms - now_epoch_ms) as u64
        );

        // Log overrun or underrun
        if self.round != 0 {
            let (would_be_stage, would_be_round, would_be_start_time_ms)
                = self.next_stage_and_round();
            match stage_event {
                StageEvent::Standard => (),
                StageEvent::Overrun => {
                    slog!(StageOverrun, overrun_round: would_be_round, overrun_stage: i32::from(would_be_stage),
                        overrun_ms: now_epoch_ms - would_be_start_time_ms,
                        next_round: round_result, next_stage: i32::from(stage_result),
                    );
                }
                StageEvent::Underrun => {
                    slog!(StageUnderrun, underrun_round: would_be_round, underrun_stage: i32::from(would_be_stage),
                    underrun_ms: would_be_start_time_ms - now_epoch_ms, next_round: round_result,
                );
                }
            }
        }

        (round_result, stage_result, now + to_wait, to_wait)
    }

    /// Calculate the next stage and round under normal conditions
    fn next_stage_and_round(&self) -> (Stage, u64, u64) {
        let would_be_round;
        let would_be_stage;

        if i32::from(self.stage).abs() >= self.stage_durations.len() as i32{
            would_be_round = self.round + 1;
            would_be_stage = i32::from(Stage::Stage1);
        } else {
            would_be_round = self.round;
            would_be_stage = i32::from(self.stage) + 1;
        }

        let next_stage_time = self.stage_durations[..self.stage.as_duration_index()+1].iter()
            .map(|dur| dur.as_millis_ext())
            .sum::<u64>();
        let would_be_start_time_ms = self.round_length().as_millis_ext() * self.round + next_stage_time;

        (
            Stage::try_from(would_be_stage).expect("Must be valid stage"),
            would_be_round,
            would_be_start_time_ms
        )
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
        if self.master == peer::Id::default() && next_stage != Stage::Stage1 {
            next_round += 1;
            let offset = self.stage_durations[next_stage.as_duration_index()..].iter().sum();
            to_wait += offset;
            start_time += offset;
            next_stage = Stage::Stage1;
        }

        // Set next round, stage and master
        if next_stage == Stage::Stage1 {
            assert!(!self.peers.is_empty());
            let peer_idx = (next_round % self.peers.len() as u64) as usize;
            self.master = self.peers[peer_idx];
        }
        self.round = next_round;
        self.stage = next_stage;

        slog!(WaitForStage, next_round: next_round, next_stage: i32::from(next_stage),
            delay_ms: to_wait.as_millis_ext()
        );
        self.clock.sleep(to_wait);

        let duration = self.stage_durations[self.stage.as_duration_index()];

        // Compute the start time of the stage that we actually wind up returning, and return it.
        Some(RoundStage {
            start_time,
            duration,
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
            let expect_dynafed = stage.stage.as_duration_index() == n_stages - 1;

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

        use common::Stage::*;

        for message in rx_main.iter() {
            match message {
                // Heartbeat
                MainCtrl::StartStage(stage, done_tx, expect_dynafed_update) => {
                    logs::set_round_stage(stage);
                    log!(Debug, "Received start-stage message.");
                    done_tx.send(()).expect("heartbeat thread to be alive");  // signal stage start

                    // If this is a new round, notify the router about it so that it can stop
                    // handling irrelevant messages and clear up outgoing messages.
                    if stage.stage == Stage1 {
                        net_tx.send(NetworkCtrl::NewRoundNumber(stage.round as u32))
                            .expect("network thread alive");
                    }

                    if let Some(overrun) = stage.is_overrun() {
                        log!(Error, "Skipping stage due to overrun of {} ms.", overrun.as_millis_ext());
                    } else {
                        match stage.stage {
                            Stage1=> {
                                // Do stage 1
                                self.round_stage1(stage);
                                self.send_status(stage);
                            },
                            Stage2 => {
                                self.round_stage2(stage);
                            },
                            Stage3 => {
                                self.round_stage3(stage);
                            },
                            Stage3b => {
                                self.round_alternate_stage3(stage);
                            }
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

    /// React to overrunning Stage 1 into Stage 2 and instead executing the alternate
    /// Stage 3
    fn round_alternate_stage3(&mut self, stage: RoundStage) { let _ = stage; }

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
    use bitcoin::secp256k1::PublicKey;
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
        fn _debug_add_now(&mut self, now: SystemTime) {
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
        let start_time_plus_1 = start_time + round_dur;

        // a closure to reduce the number of times we need to type `.clone()`
        // on the returned `Vec`
        let iterfn = || peers.consensus_ordered_ids();

        // Test 1: time stays constant, stage progresses nonetheless
        let nows = vec![start_time, start_time_plus_1, start_time_plus_1, start_time_plus_1, start_time_plus_1];
        let clock = TestClock::new(nows);
        let mut timer = StageTimer::new(stage_dur.clone(), iterfn(), clock);
        assert_eq!(timer.clock.debug_get_sleeps(), vec![]);
        // A new StageTimer will have round = 0 so the first call will have us wait until the next round
        // Stage1
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[1]);
        // Clock and StageTimer agree on round and stage so progress to next stage
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage2);
        // If the clock shows we should be one stage behind where we
        // are, ignore it (maybe our sleeps were too short or there
        // was a leap second or something)
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage3);
        // ...but once we're more than one stage ahead of clock, assume
        // something is wrong and start going to the next round start.
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497202);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[0]);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497203);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[1]);
        // First sleep is 0 because start time is divisible by round time;
        // then it sleeps til the start of the next stage; then it starts
        // skipping stages to get to the start of the next round. Sleeps are
        // relative to the "current time" (which is unchanging).
        assert_eq!(
            timer.clock.debug_get_sleeps(),
            vec![
                round_dur,
                stage_dur[0],
                stage_dur[0] + stage_dur[1],
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
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[1]);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage2);
        assert_eq!(stage.master, ids[1]);
        let stage = timer.next().unwrap();
        //Jump ahead to the far future round but as the Stage would be 1 we go to Stage3b of that round
        assert_eq!(stage.round, 102638497200);
        assert_eq!(stage.stage, Stage::Stage3b);
        assert_eq!(stage.master, ids[1]);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102638497201);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[1]);
        assert_eq!(
            timer.clock.debug_get_sleeps(),
            vec![
                round_dur,
                stage_dur[0] - Duration::from_millis(1),
                stage_dur[0] + stage_dur[1],
                round_dur * 100_000_001,
            ]
        );

        // Test 3: Time should allow for normal switching through the stages
        let nows = vec![
            start_time,
            start_time + round_dur + stage_dur[0] - Duration::from_millis(1),
            start_time + round_dur + stage_dur[0] + stage_dur[1] - Duration::from_millis(1),
            start_time + 2*round_dur - Duration::from_millis(1),
        ];
        let clock = TestClock::new(nows);
        let mut timer = StageTimer::new(stage_dur.clone(), iterfn(), clock);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[1]);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage2);
        assert_eq!(stage.master, ids[1]);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage3);
        assert_eq!(stage.master, ids[1]);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497202);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[0]);

        // Test 4: Iterator skips stage 3
        let nows = vec![
            start_time,
            start_time + round_dur + stage_dur[0] - Duration::from_millis(1),
            start_time + round_dur + stage_dur[0] + stage_dur[1] + Duration::from_millis(1),
        ];
        let clock = TestClock::new(nows);
        let mut timer = StageTimer::new(stage_dur.clone(), iterfn(), clock);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[1]);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage2);
        let stage =  timer.next().unwrap();
        assert_eq!(stage.round, 102538497202);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[0]);

        // Test 5: Iterator skips two stages and a full round
        let nows = vec![
            start_time,
            start_time + 2*round_dur + stage_dur[0] + stage_dur[1] + Duration::from_millis(1),
        ];
        let clock = TestClock::new(nows);
        let mut timer = StageTimer::new(stage_dur.clone(), iterfn(), clock);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497201);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[1]);
        let stage = timer.next().unwrap();
        assert_eq!(stage.round, 102538497203);
        assert_eq!(stage.stage, Stage::Stage1);
        assert_eq!(stage.master, ids[1]);
    }
}

