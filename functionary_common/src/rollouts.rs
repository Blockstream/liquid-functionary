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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Rollouts {
    #[cfg_attr(feature = "serde", serde(default))]
    pub hsm_csv_tweak: HsmCsvTweak,
}

impl Default for Rollouts {
    fn default() -> Self {
        Rollouts {
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
