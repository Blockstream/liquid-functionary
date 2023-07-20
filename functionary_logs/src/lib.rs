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


//! # Blockstream Logs
//!
//! A collection of standard log codes used by various Blockstream software
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

extern crate bitcoin;
extern crate elements;
extern crate jsonrpc;
#[macro_use] extern crate lazy_static;
extern crate miniscript;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate time;

extern crate functionary_common as common;

#[macro_use] pub mod log;
pub mod functionary;
pub use self::functionary::*;
pub mod io_log;
pub use self::io_log::*;
pub mod rpc;
pub use self::rpc::*;
pub mod log_codes;

use std::{fmt, io, sync, thread};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use common::RoundStage;

/// The log ID prefix for blockstream_logs logs.
pub const ID_PREFIX_BLOCKSTREAM: &str = "B";
/// The log ID prefix for functionary logs.
pub const ID_PREFIX_FUNCTIONARY: &str = "F";

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
struct LogIndex {
    file_name: String,
    line_num: u32,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Default)]
pub struct ThrottleCount<'a> {
    pub log_name: &'a str,
    pub log_id: &'a str,
    pub originating_file_name: &'a str,
    pub originating_line_number: u32,
    pub suppressed_count: u32,
}

impl<'a> Log for ThrottleCount<'a> {
    const SEVERITY: Severity = Severity::Warn;
    const LOG_ID: &'static str = "B-9999";

    fn desc(&self) -> &str {
        "suppressed log message"
    }
}

/// Structure representing global log context
pub struct GlobalContext {
    /// Handle to output writer.
    out: Box<dyn io::Write + Send>,
    /// Name of the running process
    name: &'static str,
    /// Minimum severity at which to output a log
    min_severity: Severity,
    /// log message accounting for throttling
    log_accounting: HashMap<LogIndex, u32>,
    /// time since last log-message-accounting pruning
    log_period_start: Instant,
    /// minimum time between log-message-accounting pruning
    minimum_log_period: Duration,
    /// maximum number of emissions for a given log message per pruning interval
    log_emission_limit: u32,
}

lazy_static! {
    static ref GLOBAL_CONTEXT: sync::Mutex<GlobalContext> = sync::Mutex::new(
        GlobalContext {
            #[cfg(not(test))]
            out: Box::new(io::sink()),
            #[cfg(test)]
            out: Box::new(io::stdout()),
            name: "-",
            min_severity: Severity::Trace,
            log_accounting: HashMap::with_capacity(100),
            log_period_start: Instant::now(),
            minimum_log_period: Duration::from_millis(60000),
            log_emission_limit: 1000,
        }
    );
}

/// Initialize the logging infrastructure
pub fn initialize(min_severity: Severity, log_period_ms: Option<u64>, log_emission_limit: Option<u32>, name: &'static str, out: Box<dyn io::Write + Send>) {
    let mut lock = GLOBAL_CONTEXT.lock().unwrap();
    lock.out = out;
    lock.name = name;
    lock.min_severity = min_severity;
    if let Some(value) = log_period_ms { lock.minimum_log_period = Duration::from_millis(value); }
    if let Some(value) = log_emission_limit { lock.log_emission_limit = value; }
}

/// The format string of the log timestamps.
pub const TIME_FORMAT: &str = "%F %T.%f%z";

fn serialize_time<S: serde::Serializer>(t: &time::Tm, s: S) -> Result<S::Ok, S::Error> {
    let tmfmt = t.strftime(TIME_FORMAT).unwrap();
    s.collect_str(&tmfmt)
}

fn deserialize_time<'de, D>(d: D) -> Result<time::Tm, D::Error>
    where D: serde::Deserializer<'de>,
{
    struct TmVisitor;
    impl<'de> serde::de::Visitor<'de> for TmVisitor {
        type Value = time::Tm;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a timestamp")
        }
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: serde::de::Error {
            time::strptime(v, TIME_FORMAT).map_err(serde::de::Error::custom)
        }
    }
    d.deserialize_str(TmVisitor)
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Severity of the log
pub enum Severity {
    /// Trace message (may contain secret data, will not be enabled on
    /// production systems)
    Trace,
    /// Debugging information
    Debug,
    /// Standard operation information
    Info,
    /// Potential problem
    Warn,
    /// Actual problem
    Error,
    /// Serious problem for which the program should be terminated.
    /// Logging such an error will cause the program to terminate.
    Fatal,
}

impl Severity {
    /// Severity in uppercase.
    pub fn upper(self) -> &'static str {
        match self {
            Severity::Trace => "TRACE",
            Severity::Debug => "DEBUG",
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
            Severity::Fatal => "FATAL",
        }
    }
}

/// A log message as generated by this crate. This can be used by the user to
/// interpret the log with zero-copy deserialization.
///
/// For an owned version, use [OwnedLogMessage] via the [to_owned] method.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogMessage<'a> {
    #[serde(serialize_with = "serialize_time", deserialize_with = "deserialize_time")]
    pub time: time::Tm,
    pub process: &'a str,
    #[serde(default)]
    pub thread: Option<&'a str>,
    pub severity: Severity,
    pub log_id: &'a str,
    pub desc: &'a str,
    pub name: &'a str,
    pub file: &'a str,
    pub line: u32,
    #[serde(borrow)]
    pub context: &'a serde_json::value::RawValue,
    #[serde(borrow)]
    pub data: &'a serde_json::value::RawValue,
}

impl<'a> LogMessage<'a> {
    /// Parse the internal data, suggested to be used with explicit type parameter.
    pub fn parse<T: serde::Deserialize<'a>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(self.data.get())
    }

    /// Parse the internal data, suggested to be used with explicit type parameter.
    pub fn parse_owned<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(self.data.get())
    }

    /// Try interpret the log as the given log type.
    pub fn try_as<T: Log + serde::Deserialize<'a>>(&self) -> Option<T> {
        if self.log_id == T::LOG_ID {
            Some(self.parse().expect(&format!("log msg {} doesn't roundtrip", T::LOG_ID)))
        } else {
            None
        }
    }

    /// Try interpret the log as the given log type.
    pub fn try_as_owned<T: Log + serde::de::DeserializeOwned>(&self) -> Option<T> {
        if self.log_id == T::LOG_ID {
            Some(self.parse().expect(&format!("log msg {} doesn't roundtrip", T::LOG_ID)))
        } else {
            None
        }
    }

    /// Convert this borrowed log message into an owned version.
    pub fn to_owned<C, D>(&self) -> Result<OwnedLogMessage<C, D>, serde_json::error::Error>
    where
        C: serde::de::DeserializeOwned,
        D: serde::de::DeserializeOwned,
    {
        Ok(OwnedLogMessage {
            time: self.time,
            process: self.process.to_owned(),
            thread: self.thread.map(|s| s.to_owned()),
            severity: self.severity,
            log_id: self.log_id.to_owned(),
            desc: self.desc.to_owned(),
            name: self.name.to_owned(),
            file: self.file.to_owned(),
            line: self.line,
            context: serde_json::from_str(self.context.get())?,
            data: serde_json::from_str(self.data.get())?,
        })
    }
}

/// An owned version of the log message structure.
///
/// Note: It's possible to use this structure with `serde_json::Value` or
/// `Box<serde_json::value::RawValue>` as the generic parameter to catch all
/// different structures for the [data] field.
#[derive(Debug, Serialize, Deserialize)]
pub struct OwnedLogMessage<C, D> {
    // Make sure this struct is always compatible with [LogMessage].
    #[serde(serialize_with = "serialize_time", deserialize_with = "deserialize_time")]
    pub time: time::Tm,
    pub process: String,
    #[serde(default)]
    pub thread: Option<String>,
    pub severity: Severity,
    pub log_id: String,
    pub desc: String,
    pub name: String,
    pub file: String,
    pub line: u32,
    pub context: C,
    pub data: D,
}

/// Internal generic version of [LogMessage].
#[derive(Serialize)]
struct InternalLogMessage<'process, 'thread, 'desc, 'file, 'name, 'ctx, 'data, C: serde::Serialize + 'ctx, D: serde::Serialize + 'data> {
    // Make sure this struct is always compatible with [LogMessage].
    #[serde(serialize_with = "serialize_time")]
    time: time::Tm,
    process: &'process str,
    #[serde(default)]
    thread: Option<&'thread str>,
    severity: Severity,
    log_id: &'static str,
    desc: &'desc str,
    name: &'name str,
    file: &'file str,
    line: u32,
    context: &'ctx C,
    data: &'data D,
}

/// Main log structure
pub trait Log: serde::Serialize + Sized {
    /// Severity level
    const SEVERITY: Severity;

    /// Unique log ID
    const LOG_ID: &'static str;

    /// Human-readable description
    fn desc(&self) -> &str;

    fn log_inner<C>(&self, mut output_sink: &mut Box<dyn io::Write + Send>,
        process: &str, file: &str, line: u32, name: &str, context: &C)
    where
        C: serde::Serialize,
    {
        debug_assert!(match &Self::LOG_ID[0..1] {
            ID_PREFIX_BLOCKSTREAM => true,
            ID_PREFIX_FUNCTIONARY => true,
            _ => false,
        });

        serde_json::to_writer(
            &mut output_sink,
            &InternalLogMessage {
                time: time::now(),
                process: process,
                thread: thread::current().name(),
                severity: Self::SEVERITY,
                log_id: Self::LOG_ID,
                desc: self.desc(),
                name: name,
                file: file,
                line: line,
                context: context,
                data: self,
            },
        ).expect("writing log line");
        writeln!(output_sink, "").expect("writing newline");
    }

    /// Output the log line
    fn log<C: serde::Serialize>(&self, file: &str, line: u32, name: &str, ctx: &C) {
        let mut gctx = GLOBAL_CONTEXT.lock().unwrap();
        let gctx = &mut *gctx;  // coach borrowck on individual fields resulting from MutexGuard

        if Self::SEVERITY < gctx.min_severity {
            return;
        }

        let accounting_index = LogIndex{file_name: file.to_string(), line_num: line};
        let log_count_element = gctx.log_accounting.entry(accounting_index).or_insert(0);
        *log_count_element += 1;

        // Doing this check here means that we might throttle this message
        // longer than the current period, but that'd only be if there
        // were no other intervening logs (and is thus arguably better).
        if *log_count_element > gctx.log_emission_limit {
            return;
        }

        // Lock both stdout and stderr to synchronize logging.
        let stdout = io::stdout();
        let _stdout_lock = stdout.lock();
        let stderr = io::stderr();
        let _stderr_lock = stderr.lock();

        let process = gctx.name;

        if Instant::now() > gctx.log_period_start + gctx.minimum_log_period {
            for (index, count) in gctx.log_accounting.drain() {
                if count <= gctx.log_emission_limit {
                    continue;
                }
                let tc = ThrottleCount {
                    log_name: name,
                    log_id: Self::LOG_ID,
                    originating_file_name: &index.file_name,
                    originating_line_number: index.line_num,
                    suppressed_count: count - gctx.log_emission_limit,
                };
                tc.log_inner(&mut gctx.out, process, file!(), line!(), "ThrottleCount", ctx);
            }

            gctx.log_period_start = Instant::now();
        }

        self.log_inner(&mut gctx.out, process, file, line, name, ctx);

        assert!(Self::SEVERITY != Severity::Fatal,
            "fatal log was not called with slog_fatal: {}", Self::LOG_ID,
        );
    }

    /// Output the log line and abort the program
    fn log_fatal<C: serde::Serialize>(&self, file: &str, line: u32, name: &str, ctx: &C) -> ! {
        {
            let mut gctx = GLOBAL_CONTEXT.lock().unwrap();

            // Lock both stdout and stderr to synchronize logging.
            let stdout = io::stdout();
            let _stdout_lock = stdout.lock();
            let stderr = io::stderr();
            let _stderr_lock = stderr.lock();

            let process = gctx.name;
            self.log_inner(&mut gctx.out, process, file, line, name, ctx);
        }

        // Include log code in panic message to aid unit testing.
        panic!("Encountered fatal log {}.", Self::LOG_ID);
    }
}


lazy_static! {
    static ref GLOBAL_ROUND_STAGE: sync::Mutex<RoundStage> = sync::Mutex::new(
        Default::default()
    );
}

/// Set the global roundstage to some new value
pub fn set_round_stage(new_stage: RoundStage) {
    let mut lock = GLOBAL_ROUND_STAGE.lock().unwrap();
    *lock = new_stage;
}

pub fn get_round_stage() -> RoundStage {
    *GLOBAL_ROUND_STAGE.lock().unwrap()
}

fn serialize_display<S: serde::Serializer>(
    d: impl fmt::Display,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.collect_str(&d)
}

/// Obtain the filename of the source file a log is coming from,
/// with the long path stripped
#[macro_export]
macro_rules! filename {
    () => (file!().rsplit("functionary/").next().unwrap())
}

/// Create a structured log.
///
/// Usage:
/// ```rust,ignore
/// slog!(ProposingParams, cpe: proposed.clone());
/// ```
#[macro_export]
macro_rules! slog {
    ($struct:ident) => {{
        $crate::Log::log(&$crate::$struct { }, $crate::filename!(), line!(), stringify!($struct), &$crate::get_round_stage())
    }};
    ($struct:ident, $( $args:tt )*) => {{
        $crate::Log::log(&$crate::$struct {
            $( $args )*
        }, $crate::filename!(), line!(), stringify!($struct), &$crate::get_round_stage())
    }};
}

/// Create a fatal structured log.
///
/// Usage similar to slog!.
#[macro_export]
macro_rules! slog_fatal {
    ($struct:ident, $( $args:tt )*) => {{
        $crate::Log::log_fatal(&$crate::$struct {
            $( $args )*
        }, $crate::filename!(), line!(), stringify!($struct), &$crate::get_round_stage())
    }}
}

/// A legacy unstructured log message generated by code that has not converted
/// to using the new mechanism. Trace-level.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Default)]
pub struct LegacyUnconvertedLogTrace {
    /// Legacy output
    pub message: String,
}

/// A legacy unstructured log message generated by code that has not converted
/// to using the new mechanism. Debug-level.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub struct LegacyUnconvertedLogDebug {
    /// Legacy output
    pub message: String,
}

/// A legacy unstructured log message generated by code that has not converted
/// to using the new mechanism. Info-level.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub struct LegacyUnconvertedLogInfo {
    /// Legacy output
    pub message: String,
}

/// A legacy unstructured log message generated by code that has not converted
/// to using the new mechanism. Warn-level.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub struct LegacyUnconvertedLogWarn {
    /// Legacy output
    pub message: String,
}

/// A legacy unstructured log message generated by code that has not converted
/// to using the new mechanism. Error-level.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub struct LegacyUnconvertedLogError {
    /// Legacy output
    pub message: String,
}

/// A legacy unstructured log message generated by code that has not converted
/// to using the new mechanism. Fatal-level.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Default)]
pub struct LegacyUnconvertedLogFatal {
    /// Legacy output
    pub message: String,
}

/// Trait with functionary-specific utility methods on log messages.
pub trait LogMessageExt {
    /// Get the roundstage context.
    fn round_stage(&self) -> common::SerializedRoundStage;
}

impl<'a> LogMessageExt for LogMessage<'a> {
    fn round_stage(&self) -> common::SerializedRoundStage {
        serde_json::from_str(self.context.get()).expect("message with broken context")
    }
}
