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

use crate::constants::{HSM_MAX_MESSAGE_SIZE, HSM_NETWORK_MAGIC};
use crate::error::Error;
use bitcoin::hex::DisplayHex;
use std::io;
use std::io::{Cursor, Read};

/// This trait will be implemented to deserialize a given message version from a buffer of bytes.
/// A Cursor is used to hold the stream buffer to keep track of how many bytes were read during the
/// deserialization process. This number will vary depending on where the magic bytes were found
/// and the message data length. Once the message has been deserialized the caller will handle
/// consuming the read bytes in the steam buffer based on the cursor position.
pub trait Decoder {
    type Item;
    type Error: From<Error>;

    fn decode<R: Read>(buffer: &mut R) -> Result<Self::Item, Self::Error>;
}

/// An object that reads from a byte Stream and parses frames that can be parsed using implementations
/// of the Decoder trait. Internally keeps track of a cursor of what bytes have been read in the stream
/// and discards data that has been read to produce a frame.
pub struct FrameReader<S>
where
    S: Read,
{
    stream: S,
    buffer: Vec<u8>,
    cursor: usize,
}

impl<S> FrameReader<S>
where
    S: Read,
{
    pub fn new(stream: S) -> Self {
        Self {
            buffer: vec![0u8; 2 * HSM_MAX_MESSAGE_SIZE],
            stream,
            cursor: 0,
        }
    }

    pub fn next_frame<D: Decoder<Error = Error>>(&mut self) -> Result<Option<D::Item>, Error> {
        loop {
            if let Some(magic_byte_position) = find_magic_bytes(self.buffer.as_slice()) {
                if magic_byte_position != 0 {
                    log!(
                        Error,
                        "Stray bytes while looking for message header: {}",
                        self.buffer[0..magic_byte_position].as_hex()
                    );
                    // Discard stray bytes
                    self.buffer.drain(..magic_byte_position);
                    self.cursor -= magic_byte_position;
                }

                let mut buffer = Cursor::new(&self.buffer[HSM_NETWORK_MAGIC.len()..self.cursor]);
                match D::decode(&mut buffer) {
                    Ok(message) => {
                        let position = buffer.position() as usize;
                        self.buffer.drain(..(position + HSM_NETWORK_MAGIC.len()));
                        self.cursor -= HSM_NETWORK_MAGIC.len();
                        self.cursor -= position;
                        return Ok(Some(message));
                    }
                    Err(Error::Io(err)) if err.kind() == io::ErrorKind::UnexpectedEof => (),
                    Err(Error::ByteOrder(byteorder::Error::UnexpectedEOF)) => (),
                    Err(e) => {
                        return Err(e);
                    }
                }
            };
            self.buffer.resize_with(2 * HSM_MAX_MESSAGE_SIZE, || 0);
            let num_bytes = self.stream.read(&mut self.buffer[self.cursor..])?;
            self.cursor += num_bytes;
            if num_bytes == 0 {
                if self.cursor == 0 {
                    return Ok(None);
                } else {
                    return Err(Error::ConnectionResetByPeer);
                }
            }
        }
    }
}

pub fn find_magic_bytes(data: &[u8]) -> Option<usize> {
    let mut index = 0;
    loop {
        if data.len().saturating_sub(index) < HSM_NETWORK_MAGIC.len() {
            return None;
        }
        if &data[index..index + HSM_NETWORK_MAGIC.len()] == HSM_NETWORK_MAGIC.as_bytes() {
            return Some(index);
        } else {
            index += 1;
        }
    }
}
