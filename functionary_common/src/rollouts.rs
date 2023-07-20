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

//!
//! A place to keep track of phased rollouts and necessary cleanups.
//!
//! By commenting out phases in the past, the compiler can point you to places that need to be
//! updated.
//!

/// Introduction of the consensus tracker.
pub const CONSENSUS_TRACKER: () = ();

/// Due to a bug, the legacy HSMs only recognize a tweaked version of the actual
/// change script. The tweak being that the CSV value is changed from 4032 to 2016.
/// When we implement WM dynafed, this hack will be removed. Also, we'll remove the
/// requirement of the hack before the first transition by having the HSM recognize
/// both the tweaked and untweaked version.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum HsmCsvTweak {
    /// HSMs only recognize the "tweaked" address.
    Legacy,

    /// All HSMs recognizes both the tweaked and regular change address.
    /// This also implies all hosts have had this update.
    FullHsmSupport,

    /// A dynafed transition has been made that changed the watchman descriptor
    /// to one that is no longer p2sh-wrapped.
    DynafedTransitionMade,
}

impl Default for HsmCsvTweak {
    fn default() -> Self {
        HsmCsvTweak::Legacy
    }
}

/// Migration to make our network a broadcast network again.
///
/// The phases of this rollout are intended to coincide with those of the
/// statusack message elimination rollout.
///
/// Old behavior:
/// - nodes send messages directed to individual peers
/// - nodes drop messages not intended for themselves
///
/// When this is cleaned up, the receiver field will no longer have any
/// semantic meaning. There are two options:
/// 1. it can be removed from the struct and in (de-)serialization zeroes
///    can be placed in it's place
/// 2. the field can be kept in the header struct with a name like
///    `unused_field_1` and it can be otherwise ignored. This makes sure that
///    it can be repurposed without losing roundtrippability.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum Broadcast {
    /// In this phase, nodes
    /// - still send messages directed to each individual peer, but
    ///   use the exact same msgid on the identical message directed to each peer
    Phase1,

    /// In this phase, nodes
    /// - start considering all messages as directed to themselves, dropping
    ///   duplicates using the msgid mechanism
    Phase2,

    /// In this phase, nodes
    /// - will send each message only once, with a zeroed out recipient
    ///
    /// Additionally,
    /// - the msg recipient field can be removed and ignored on parsing so that
    ///   it can be reused later for another purpose
    Phase3,
}

impl Default for Broadcast {
    fn default() -> Self {
        Broadcast::Phase1
    }
}

/// The status-ack message is the only message that doesn't work well in a
/// network with broadcast topology. For this reason, we'll be eliminating it,
/// in favor of acking messages inside our own status message the next round.
/// In a new version of the status message, we will mention all the peers we
/// have received messages from last round.
///
/// Old behavior:
/// - nodes send a peer-addressed status-ack after receiving a peer's status
/// - nodes only kick the network watchdog for a peer when receiving a status-ack
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum StatusAckElim {
    /// In this phase, nodes will
    /// - no longer send status-acks when receiving a status
    /// - broadcast a (fake) status-ack in round-stage2
    /// - still kick their watchdog when receiving status-acks
    /// - send only old status messages
    /// - also kick their watchdog for in-status acks when they are present in the new status message
    Phase1,

    /// In this phase, nodes start sending new status messages
    Phase2,

    /// In this phase, nodes will
    /// - stop sending status-acks
    /// - stop sending old status messages (they can also be removed)
    Phase3,
}

impl Default for StatusAckElim {
    fn default() -> Self {
        StatusAckElim::Phase1
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Rollouts {
    #[cfg_attr(feature = "serde", serde(default))]
    pub broadcast: Broadcast,
    #[cfg_attr(feature = "serde", serde(default))]
    pub status_ack_elim: StatusAckElim,
    #[cfg_attr(feature = "serde", serde(default))]
    pub hsm_csv_tweak: HsmCsvTweak,
}

impl Default for Rollouts {
    fn default() -> Self {
        Rollouts {
            broadcast: Default::default(),
            status_ack_elim: Default::default(),
            hsm_csv_tweak: Default::default()
        }
    }
}

static mut ROLLOUTS_STATIC: Option<Rollouts> = None;

lazy_static! {
    static ref ROLLOUTS_DEFAULT: Rollouts = Rollouts::default();
}

/// Should only be set ONCE on startup before the program starts running.
pub fn set_rollouts_on_startup(rollouts: Rollouts) {
    unsafe {
        assert!(ROLLOUTS_STATIC.is_none(), "Must not set rollouts more than once");
        ROLLOUTS_STATIC = Some(rollouts);
    }
}

pub struct RolloutsDeref;

impl std::ops::Deref for RolloutsDeref {
    type Target = Rollouts;
    fn deref(&self) -> &Self::Target {
        unsafe {
            match ROLLOUTS_STATIC.as_ref() {
                None => &ROLLOUTS_DEFAULT,
                Some(r) => r,
            }
        }
    }
}

pub const ROLLOUTS: RolloutsDeref = RolloutsDeref;
