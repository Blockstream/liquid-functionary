//{{ Liquid }}
//Copyright (C) {{ 2019 }}  {{ Blockstream }}

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

//! # HSM update tool
//!
//! Sends a file (e.g. rpm package) to a connected hsm via parallel_port for processing (e.g. installation).
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

use functionary_common::hsm;
use std::fmt;
use std::fmt::Formatter;

// Error type for updates
#[derive(Debug)]
pub enum MessageError {
    HSMError(hsm::Error),
    ConversionError(std::num::TryFromIntError),
    IOError(std::io::Error),
    HashError(bitcoin::hashes::FromSliceError),
    ReceivedNACK,
    Timeout,
    BadValue,
}

impl std::error::Error for MessageError {}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            MessageError::HSMError(ref err) => write!(f, "HSMError: {}", err),
            MessageError::ConversionError(ref err) => write!(f, "Int Conversion Error: {}", err),
            MessageError::IOError(ref err) => write!(f, "IOError: {}", err),
            MessageError::HashError(ref err) => write!(f, "HashError: {}", err),
            MessageError::ReceivedNACK => write!(f, "Message send was NACK'ed"),
            MessageError::Timeout => write!(f, "Message send timed out"),
            MessageError::BadValue => write!(f, "Bad Value received in message"),
        }
    }
}

impl From<hsm::Error> for MessageError {
    fn from(err: hsm::Error) -> MessageError {
        MessageError::HSMError(err)
    }
}
impl From<std::num::TryFromIntError> for MessageError {
    fn from(err: std::num::TryFromIntError) -> MessageError {
        MessageError::ConversionError(err)
    }
}

impl From<std::io::Error> for MessageError {
    fn from(err: std::io::Error) -> Self {
        MessageError::IOError(err)
    }
}

impl From<bitcoin::hashes::FromSliceError> for MessageError {
    fn from(err: bitcoin::hashes::FromSliceError) -> Self {
        MessageError::HashError(err)
    }
}
