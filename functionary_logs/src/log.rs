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


//! # Simple Log
//! Logging infrastructure
//!

use std::{fmt, str};

/// The main logging function
#[cfg(test)]
pub fn log<T: fmt::Display>(_: &str, _: u32, _: crate::Severity, _: &T) {
    // don't log in unit tests
}

/// The main logging function
#[cfg(not(test))]
pub fn log<T: fmt::Display>(file: &str, line: u32, level: crate::Severity, message: &T) {
    // Can't use slog! here since we want the line/file info to come from the original log
    // call's context (vs. from inside this routine).
    // Since these originated from legacy logs, there are no instances of the struct elsewhere;
    // hence, the empty string is passed to log().

    use get_logging_context;
    use LegacyUnconvertedLogTrace;
    use LegacyUnconvertedLogDebug;
    use LegacyUnconvertedLogInfo;
    use LegacyUnconvertedLogWarn;
    use LegacyUnconvertedLogError;
    use LegacyUnconvertedLogFatal;

    match level {
        crate::Severity::Trace => {
            crate::Log::log(
                &LegacyUnconvertedLogTrace{ message: message.to_string() },
                &file, line, "", &get_logging_context(),
            );
        }
        crate::Severity::Debug => {
            crate::Log::log(&LegacyUnconvertedLogDebug{ message: message.to_string() },
                &file, line, "", &get_logging_context(),
            );
        }
        crate::Severity::Info => {
            crate::Log::log(&LegacyUnconvertedLogInfo{ message: message.to_string() },
                &file, line, "", &get_logging_context(),
            );
        }
        crate::Severity::Warn => {
            crate::Log::log(&LegacyUnconvertedLogWarn{ message: message.to_string() },
                &file, line, "", &get_logging_context(),
            );
        }
        crate::Severity::Error => {
            crate::Log::log(&LegacyUnconvertedLogError{ message: message.to_string() },
                &file, line, "", &get_logging_context(),
            );
        }
        crate::Severity::Fatal => {
            crate::Log::log_fatal(&LegacyUnconvertedLogFatal{ message: message.to_string() },
                &file, line, "", &get_logging_context(),
            );
        }
    }
}

/// Macro that infers the file and line number.
#[macro_export]
macro_rules! log {
    ($level:ident, $($arg:tt)+) => ({
        let filename = file!().rsplit("functionary/").next().unwrap();
        $crate::log::log(filename, line!(), $crate::Severity::$level, &format_args!($($arg)+))
    })
}

/// trace!() macro that infers the file and line number.
#[macro_export]
macro_rules! trace {
    ($($arg:tt)+) => ({
        let filename = file!().rsplit("functionary/").next().unwrap();
        $crate::log::log(filename, line!(), $crate::Severity::Trace, &format_args!($($arg)+))
    })
}

/// debug!() macro that infers the file and line number.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => ({
        let filename = file!().rsplit("functionary/").next().unwrap();
        $crate::log::log(filename, line!(), $crate::Severity::Debug, &format_args!($($arg)+))
    })
}

/// info!() macro that infers the file and line number.
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => ({
        let filename = file!().rsplit("functionary/").next().unwrap();
        $crate::log::log(filename, line!(), $crate::Severity::Info, &format_args!($($arg)+))
    })
}

/// Conditions that would merit a warn!(), error!(), or fatal!() instance should really be logged
/// using slog!() since the represent conditions that almost certainly should be noticed by a
/// monitoring system.


/// `try!` equivalent that logs on error
/// Logs to the "General" category.
#[macro_export]
macro_rules! log_try {
    ($level:ident, $e:expr) => ({
        match $e {
            Ok(res) => res,
            Err(e) => {
                let filename = file!().rsplit("functionary/").next().unwrap();
                $crate::log::log(filename, line!(), $crate::Severity::$level, &e);
                return Err(From::from(e));
            }
        }
    })
}

#[cfg(test)]
mod tests {

    fn use_log_try() -> Result<String, String> {
        let good_result: Result<String, String>
                = Ok("This should not be printed".to_string());
        let bad_result: Result<String, String>
                = Err("Test log_try".to_string());
        let r = log_try!(Warn, good_result);
        log_try!(Debug, bad_result);
        return Ok(r);
    }

    #[test]
    fn output() {
        log!(Warn, "Test peer error");
        assert!(use_log_try().is_err());
    }

    #[test]
    fn use_fancy_macros() {
        use std::io;
        crate::initialize(crate::Severity::Trace, None, None, "unit_test", Box::new(io::stderr()));
        let something = 1;
        info!("This is info: {}", something);
        debug!("This is debug: {}", something);
        trace!("This is trace: {}", something);
    }
}
