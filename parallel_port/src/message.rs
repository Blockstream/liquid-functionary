//{{ Liquid }}
//Copyright (C) {{ 2022 }}  {{ Blockstream }}

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

use crate::constants::HSM_MAX_MESSAGE_SIZE;
use crate::error::Error;
use crate::frame_reader::Decoder;
use anyhow::Context;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256d, Hash};
use byteorder::{LittleEndian, ReadBytesExt};
use functionary_common::hsm::{Address, Command, Header, HEADER_LEN};
use std::fmt::{Display, Formatter};
use std::io::Read;

/// An HSM message struct that includes the sequence number, or lack there of, as a separate field so it can be handled correctly
#[derive(Clone, Debug)]
pub struct ParallelPortMessage {
    pub header: Header,
    pub payload: Vec<u8>,
    // This sequence number will be present when forwarding a message from Host > HSM and when
    // receiving a response from HSM > Host.
    pub sequence_number: Option<u8>,
}

impl ParallelPortMessage {
    pub fn new(header: Header, payload: Vec<u8>) -> Self {
        Self {
            header,
            payload,
            sequence_number: None,
        }
    }

    pub fn set_sequence_number(&mut self, sequence_number: u8) {
        self.sequence_number = Some(sequence_number);
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.header.length != self.payload.len() as u32 {
            return Err(Error::InvalidMessage(
                format!(
                    "Header length and body length do not match (Expected: {}, Actual: {})",
                    self.header.length,
                    self.payload.len()
                ),
            ));
        }
        let hash = sha256d::Hash::hash(self.payload.as_slice());
        if hash != self.header.hash {
            return Err(Error::InvalidMessage("Invalid hash".to_string()));
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }
}

/// V2 Message Deserialization with custom sequence number handling. This trait is used by the FrameReader to
/// parse messages from a byte stream.
impl Decoder for ParallelPortMessage {
    type Item = Self;
    type Error = Error;

    fn decode<R: Read>(buffer: &mut R) -> Result<Self::Item, Self::Error> {
        // Parse header
        let version = version_decode(buffer.read_u8()?);

        // Check for presence of Sequence number embedded in the address before parsing into a Address enum
        let address_byte = buffer.read_u8()?;

        let (address, sequence_number) = if address_byte == Address::ParallelPort as u8 {
            (Address::from_byte(Address::ParallelPort as u8)?, None)
        } else if address_byte & 0xf0 != 0 {
            let sequence_number = address_byte >> 4;
            (
                Address::from_byte(address_byte).context(format!(
                    "Problem parsing address field from {}u8 after sequence number shift",
                    address_byte
                ))?,
                Some(sequence_number),
            )
        } else {
            (
                Address::from_byte(address_byte)
                    .context(format!("Problem parsing address field from {}u8", address_byte))?,
                None,
            )
        };

        let return_address_byte = buffer.read_u8()?;
        let return_address = Address::from_byte(return_address_byte).context(format!(
            "Problem parsing return_address field from {}u8",
            return_address_byte
        ))?;
        let command_byte = buffer.read_u8()?;
        let command = Command::from_byte(command_byte)
            .context(format!("Problem parsing command field from {}u8", command_byte))?;

        let length = buffer.read_u32::<LittleEndian>()?;

        let mut hash = [0u8; 32];
        buffer.read_exact(&mut hash)?;

        if length > HSM_MAX_MESSAGE_SIZE as u32 {
            log!(Error, "Bad length: {}", length);
            return Err(Error::InvalidMessage("Message too long".to_string()));
        }

        //Read body
        let mut payload = vec![0u8; length as usize];
        buffer.read_exact(payload.as_mut_slice())?;

        let header =
            Header::for_data(version, address, return_address, command, payload.as_slice());

        Ok(Self {
            header,
            payload,
            sequence_number,
        })
    }
}

impl Display for ParallelPortMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, ", self.header)?;
        write!(f, "Sequence Number: {:?}, ", self.sequence_number)?;
        write!(f, "Payload: {}", self.payload.to_hex())
    }
}

// Shift bits so it won't conflict with pre v2 messages:
// These macros encode and decode the message version for message versions > 1.
// V1 message don't have a version field but instead store the address in the first
// field. The address values for v1 messages are one of either 0xff, 0x00, or 0x01 so if we store
// the version in the top 6 bits we avoid conflicts with v1 messages.
fn version_decode(version: u8) -> u8 {
    ((version) >> 2) & 0x3F
}

pub enum MessageSource<T> {
    Socket(T),
    Serial(T),
}
