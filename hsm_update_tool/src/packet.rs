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

extern crate bitcoin;
extern crate byteorder;

use self::bitcoin::secp256k1;
use self::bitcoin::hashes::{sha256, Hash};
use self::byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::mem::size_of;

use message_error::MessageError;
use std::fmt::{Formatter, Error};

const UPDATE_MESSAGE_PROTOCOL_VERSION: u8 = 1;
const UPDATE_MESSAGE_FILENAME_FIELD_LENGTH: usize = 128;
pub const MAX_PACKET_SIZE: usize = 8192;

pub const fn max_filename_length() -> usize {
    UPDATE_MESSAGE_FILENAME_FIELD_LENGTH
}

//////////// Marshaling Interface ////////////////////

/// MarshalingInterface definition - implement for any type that needs to be marshaled.
pub trait MarshalingIntf {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error>;

    fn unmarshal(r: &mut dyn Read) -> Result<Self, MessageError>
    where Self: Sized;
}

///////////// Basic marshaling/unmarshaling Impls ////////////////
impl MarshalingIntf for u32 {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        w.write_u32::<LittleEndian>(*self)?;
        Ok(4)
    }

    fn unmarshal(r: &mut dyn Read) -> Result<Self, MessageError>
    where
        Self: Sized,
    {
        Ok(r.read_u32::<LittleEndian>()?)
    }
}

impl MarshalingIntf for u8 {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        w.write_u8(*self)?;
        Ok(1)
    }

    fn unmarshal(r: &mut dyn Read) -> Result<Self, MessageError>
    where
        Self: Sized,
    {
        Ok(r.read_u8()?)
    }
}

impl MarshalingIntf for sha256::Hash {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        w.write(&self[..])?;
        Ok(size_of::<sha256::Hash>() as u32)
    }

    fn unmarshal(r: &mut dyn Read) -> Result<Self, MessageError>
    where
        Self: Sized,
    {
        let mut sl = [0; 32];
        r.read_exact(&mut sl[..])?;
        Ok(sha256::Hash::from_slice(&sl[..])?)
    }
}

// TBD: Change this to impl for a slice
impl MarshalingIntf for Vec<u8> {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        for iter in self {
            iter.marshal(w)?;
        }
        Ok(self.len() as u32)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

impl MarshalingIntf for [u8; 64] {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        for (_iter, elem) in self.iter().enumerate() {
            elem.marshal(w)?;
        }
        Ok(64)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError> where Self: Sized {
        unimplemented!()
    }
}

impl MarshalingIntf for Option<secp256k1::ecdsa::Signature> {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
         match self {
            Some(sig) => Ok(sig.serialize_compact().marshal(w)?),
            None => Ok(vec![0;64].marshal(w)?)
         }
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError> where Self: Sized {
        unimplemented!()
    }
}

impl MarshalingIntf for Vec<Option<secp256k1::ecdsa::Signature>> {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        let mut sig_size = 0;
        for iter in self {
            sig_size += iter.marshal(w)?;
        }
        Ok(sig_size)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError> where Self: Sized {
        unimplemented!()
    }
}

///////////// Packet Type Defs ///////////////////
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PacketType {
    SyncSequenceId = 0x01,
    BeginFileTransfer = 0x02,
    FileChunk = 0x03,
    EndFileTransfer = 0x04,
    BeginInstall = 0x05,
    AuthorizeUpgrade = 0x06,
    // One off operations
    GetFirmwareVersion = 0x10,
    // Response types
    Reply = 0x80,

}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u8> for PacketType {
    type Error = MessageError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(PacketType::SyncSequenceId),
            0x02 => Ok(PacketType::BeginFileTransfer),
            0x03 => Ok(PacketType::FileChunk),
            0x04 => Ok(PacketType::EndFileTransfer),
            0x05 => Ok(PacketType::BeginInstall),
            0x06 => Ok(PacketType::AuthorizeUpgrade),
            0x80 => Ok(PacketType::Reply),
            _ => Err(MessageError::BadValue),
        }
    }
}

impl MarshalingIntf for PacketType {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        w.write_u8(*self as u8)?;
        Ok(1)
    }

    fn unmarshal(r: &mut dyn Read) -> Result<Self, MessageError>
    where
        Self: Sized,
    {
        Ok(PacketType::try_from(r.read_u8()?)?)
    }
}

///////////// Packet accessor Interface ////////////////
pub trait UpdatePacketIntf: MarshalingIntf {
    fn get_packet_type(&self) -> PacketType;
    fn get_id(&self) -> u32;
    fn set_id(&mut self, sequenced_id: u32);
}

///////////// Common Header Elements ////////////////
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CommonUpdatePacketHeader {
    pub version: u8,
    pub sequenced_id: u32,
    pub packet_type: PacketType,
}

impl CommonUpdatePacketHeader {
    pub fn new(packet_type: PacketType/*, length: u32*/) -> CommonUpdatePacketHeader {
        CommonUpdatePacketHeader {
            version: UPDATE_MESSAGE_PROTOCOL_VERSION,
            sequenced_id: 0,
            packet_type: packet_type,
        }
    }
}

impl MarshalingIntf for CommonUpdatePacketHeader {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        let mut size = self.version.marshal(w)?;
        size += self.sequenced_id.marshal(w)?;
        size += self.packet_type.marshal(w)?;
        Ok(size)
    }

    fn unmarshal(r: &mut dyn Read) -> Result<Self, MessageError> {
        let header = CommonUpdatePacketHeader {
            version: u8::unmarshal(r)?,
            sequenced_id: u32::unmarshal(r)?,
            packet_type: PacketType::unmarshal(r)?,
        };
        Ok(header)
    }
}

///////////// File Header Packet ////////////////
#[derive(Clone, Copy)]
pub struct FileNameType {
    pub data: [u8; UPDATE_MESSAGE_FILENAME_FIELD_LENGTH],
}

impl std::fmt::Debug for FileNameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.data.fmt(f)
    }
}

impl MarshalingIntf for FileNameType {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        w.write_all(&self.data[..])?;
        Ok(self.data.len() as u32)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError>
    where
        Self: Sized,
    {
        // No need for unmarshaling and this time.
        unimplemented!()
    }
}

///////////// Sync Sequence ID ////////////////
pub struct SyncSequenceIdOpPacket {
    header: CommonUpdatePacketHeader,
}

impl SyncSequenceIdOpPacket {
    pub fn new() -> SyncSequenceIdOpPacket {
        let packet = SyncSequenceIdOpPacket {
            header: CommonUpdatePacketHeader::new(PacketType::SyncSequenceId),
        };
        packet
    }
}

impl MarshalingIntf for SyncSequenceIdOpPacket {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        let size = self.header.marshal(w)?;
        Ok(size)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError> {
        // No need for unmarshaling at this time.
        unimplemented!()
    }
}

impl UpdatePacketIntf for SyncSequenceIdOpPacket {
    fn get_packet_type(&self) -> PacketType {
        self.header.packet_type
    }

    fn get_id(&self) -> u32 {
        self.header.sequenced_id
    }

    fn set_id(&mut self, sequenced_id: u32) {
        self.header.sequenced_id = sequenced_id;
    }
}

///////////// Sync Sequence ID ////////////////
pub struct GetFirmwareVersionOpPacket {
    header: CommonUpdatePacketHeader,
}

impl GetFirmwareVersionOpPacket {
    pub fn new() -> GetFirmwareVersionOpPacket {
        let packet = GetFirmwareVersionOpPacket {
            header: CommonUpdatePacketHeader::new(PacketType::GetFirmwareVersion),
        };
        packet
    }
}

impl MarshalingIntf for GetFirmwareVersionOpPacket {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        let size = self.header.marshal(w)?;
        Ok(size)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError> {
        // No need for unmarshaling at this time.
        unimplemented!()
    }
}

impl UpdatePacketIntf for GetFirmwareVersionOpPacket {
    fn get_packet_type(&self) -> PacketType {
        self.header.packet_type
    }

    fn get_id(&self) -> u32 {
        self.header.sequenced_id
    }

    fn set_id(&mut self, sequenced_id: u32) {
        self.header.sequenced_id = sequenced_id;
    }
}

///////////// Install Message Packet ////////////////
#[derive(Clone, Debug)]
pub struct BeginInstallOpPacket {
    header: CommonUpdatePacketHeader,
    filename: FileNameType,
    hash: sha256::Hash, //mu-sig info
}

impl BeginInstallOpPacket {
    pub fn new(filename: &FileNameType, hash: &sha256::Hash) -> BeginInstallOpPacket {
        let packet = BeginInstallOpPacket {
            header: CommonUpdatePacketHeader::new(PacketType::BeginInstall),
            filename: *filename,
            hash: *hash,
        };
        packet
    }
}

impl MarshalingIntf for BeginInstallOpPacket {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        let mut size = self.header.marshal(w)?;
        size += self.filename.marshal(w)?;
        size += self.hash.marshal(w)?;
        Ok(size)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError> {
        // No need for unmarshaling at this time.
        unimplemented!()
    }
}

impl UpdatePacketIntf for BeginInstallOpPacket {
    fn get_packet_type(&self) -> PacketType {
        self.header.packet_type
    }

    fn get_id(&self) -> u32 {
        self.header.sequenced_id
    }

    fn set_id(&mut self, sequenced_id: u32) {
        self.header.sequenced_id = sequenced_id;
    }
}

///////////// Begin File Transfer Op Packet ////////////////
#[derive(Clone, Copy, Debug)]
pub struct BeginFileTransferOpPacket {
    pub header: CommonUpdatePacketHeader,
    pub filename: FileNameType,
    pub file_length: u32,
    pub hash: sha256::Hash, //Sha256 of the file
}

impl BeginFileTransferOpPacket {
    pub fn new(
        remote_filename: &FileNameType,
        file_length: u32,
        hash: &sha256::Hash,
    ) -> BeginFileTransferOpPacket {
        let packet = BeginFileTransferOpPacket {
            header: CommonUpdatePacketHeader::new(PacketType::BeginFileTransfer),
            filename: *remote_filename,
            file_length: file_length,
            hash: *hash,
        };
        packet
    }
}

impl MarshalingIntf for BeginFileTransferOpPacket {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        let mut size = self.header.marshal(w)?;
        size += self.filename.marshal(w)?;
        size += self.file_length.marshal(w)?;
        size += self.hash.marshal(w)?;
        Ok(size)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError> {
        // No need for unmarshaling at this time.
        unimplemented!()
    }
}

impl UpdatePacketIntf for BeginFileTransferOpPacket {
    fn get_packet_type(&self) -> PacketType {
        self.header.packet_type
    }

    fn get_id(&self) -> u32 {
        self.header.sequenced_id
    }

    fn set_id(&mut self, sequenced_id: u32) {
        self.header.sequenced_id = sequenced_id;
    }
}

///////////// Begin File Transfer Op Packet ////////////////
#[derive(Clone, Copy, Debug)]
pub struct EndFileTransferOpPacket {
    pub header: CommonUpdatePacketHeader,
    pub hash: sha256::Hash, //Sha256 of the file
}

impl EndFileTransferOpPacket {
    pub fn new(hash: &sha256::Hash) -> EndFileTransferOpPacket {
        let packet = EndFileTransferOpPacket {
            header: CommonUpdatePacketHeader::new(PacketType::EndFileTransfer),
            hash: *hash,
        };
        packet
    }
}

impl MarshalingIntf for EndFileTransferOpPacket {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        let mut size = self.header.marshal(w)?;
        size += self.hash.marshal(w)?;
        Ok(size)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError> {
        // No need for unmarshaling at this time.
        unimplemented!()
    }
}

impl UpdatePacketIntf for EndFileTransferOpPacket {
    fn get_packet_type(&self) -> PacketType {
        self.header.packet_type
    }

    fn get_id(&self) -> u32 {
        self.header.sequenced_id
    }

    fn set_id(&mut self, sequenced_id: u32) {
        self.header.sequenced_id = sequenced_id;
    }
}

///////////// File Chunk Packet ////////////////
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileChunkPacket {
    pub header: CommonUpdatePacketHeader,
    pub data: Vec<u8>,
}

impl MarshalingIntf for FileChunkPacket {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        let mut size = self.header.marshal(w)?;
        size += self.data.marshal(w)?;
        Ok(size)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError> {
        // No need for unmarshaling at this time.
        unimplemented!()
    }
}

impl UpdatePacketIntf for FileChunkPacket {
    fn get_packet_type(&self) -> PacketType {
        self.header.packet_type
    }

    fn get_id(&self) -> u32 {
        self.header.sequenced_id
    }

    fn set_id(&mut self, sequenced_id: u32) {
        self.header.sequenced_id = sequenced_id;
    }
}

impl FileChunkPacket {
    pub fn new(data: &[u8]) -> Result<FileChunkPacket, MessageError> {
        let file_chunk = FileChunkPacket {
            header: CommonUpdatePacketHeader::new(PacketType::FileChunk),
            data: data.to_vec(),
        };

        Ok(file_chunk)
    }
}

///////////// Authorize Upgrade Packet ////////////////
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthorizeUpgradePacket {
    pub header: CommonUpdatePacketHeader,
    pub message: Vec<u8>,
    pub signatures: Vec<Option<secp256k1::ecdsa::Signature>>
}

impl MarshalingIntf for AuthorizeUpgradePacket {
    fn marshal(&self, w: &mut dyn Write) -> Result<u32, io::Error> {
        let mut size = self.header.marshal(w)?;
        size += self.message.marshal(w)?;
        size += self.signatures.marshal(w)?;
        Ok(size)
    }

    fn unmarshal(_r: &mut dyn Read) -> Result<Self, MessageError> {
        unimplemented!()
    }
}

impl UpdatePacketIntf for AuthorizeUpgradePacket {
    fn get_packet_type(&self) -> PacketType {
        self.header.packet_type
    }

    fn get_id(&self) -> u32 {
        self.header.sequenced_id
    }

    fn set_id(&mut self, sequenced_id: u32) {
        self.header.sequenced_id = sequenced_id;
    }
}

impl AuthorizeUpgradePacket {
    pub fn new(message: &[u8], signatures: &Vec<Option<secp256k1::ecdsa::Signature>>) -> AuthorizeUpgradePacket {
        let packet =  AuthorizeUpgradePacket{
            header: CommonUpdatePacketHeader::new( PacketType::AuthorizeUpgrade),
            message: message.to_vec(),
            signatures: signatures.to_vec()
        };
        packet
    }
}
#[cfg(test)]
pub mod tests {
    use super::bitcoin::hashes::{sha256, Hash};
    use message_error::MessageError;
    use packet::{
        max_filename_length, BeginFileTransferOpPacket, BeginInstallOpPacket,
        CommonUpdatePacketHeader, EndFileTransferOpPacket, FileChunkPacket, FileNameType,
        MarshalingIntf, PacketType, SyncSequenceIdOpPacket,
    };
    use std::convert::TryFrom;
    use std::io;
    use std::io::Write;

    #[test]
    fn test_packet_type_u8_conversion() -> Result<(), MessageError> {
        assert_eq!(
            PacketType::Reply,
            PacketType::try_from(PacketType::Reply as u8)?
        );
        assert_eq!(
            PacketType::SyncSequenceId,
            PacketType::try_from(PacketType::SyncSequenceId as u8)?
        );
        assert_eq!(
            PacketType::BeginFileTransfer,
            PacketType::try_from(PacketType::BeginFileTransfer as u8)?
        );
        assert_eq!(
            PacketType::FileChunk,
            PacketType::try_from(PacketType::FileChunk as u8)?
        );
        assert_eq!(
            PacketType::EndFileTransfer,
            PacketType::try_from(PacketType::EndFileTransfer as u8)?
        );
        assert_eq!(
            PacketType::AuthorizeUpgrade,
            PacketType::try_from(PacketType::AuthorizeUpgrade as u8)?
        );

        Ok(())
    }

    #[test]
    fn test_basic_marshaling() -> Result<(), io::Error> {
        let mut buffer: Vec<u8> = Vec::with_capacity(32);
        let value: u8 = 42;
        let len = value.marshal(&mut buffer)?;
        assert_eq!(len, 1);
        assert_eq!(buffer[0], 42);

        buffer.clear();
        let value: u32 = 42;
        let len = value.marshal(&mut buffer)?;
        assert_eq!(len, 4);
        assert_eq!(buffer[..4], [42, 0, 0, 0]);

        buffer.clear();
        let value: Vec<u8> = vec![1, 2, 3, 4, 5];
        let len = value.marshal(&mut buffer)?;
        assert_eq!(len, 5);
        assert_eq!(buffer[..5], [1, 2, 3, 4, 5]);

        buffer.clear();
        let bytes: Vec<u8> = vec![1, 2, 3, 4, 5];
        let mut engine = sha256::Hash::engine();
        engine.write_all(bytes.as_slice()).unwrap();
        let value = sha256::Hash::from_engine(engine);
        let len = value.marshal(&mut buffer)?;
        assert_eq!(len, 32);
        assert_eq!(value[..], buffer[..]);
        Ok(())
    }

    #[test]
    fn test_common_header_marshaling() -> Result<(), MessageError> {
        let mut buffer: Vec<u8> = Vec::with_capacity(100);
        let value = PacketType::FileChunk;
        let len = value.marshal(&mut buffer)?;
        assert_eq!(len, 1);
        assert_eq!(buffer[0], PacketType::FileChunk as u8);

        buffer.clear();
        let mut value = CommonUpdatePacketHeader::new(PacketType::FileChunk);
        value.sequenced_id = 23;
        let len = value.marshal(&mut buffer)?;
        assert_eq!(len, 6);
        assert_eq!(buffer[0], 1);
        assert_eq!(buffer[1..5], [23, 0, 0, 0]);
        assert_eq!(buffer[5], PacketType::FileChunk as u8);

        // Round Trip
        let round_trip_value = CommonUpdatePacketHeader::unmarshal(&mut &buffer[..])?;
        assert_eq!(value, round_trip_value);

        Ok(())
    }

    #[test]
    fn test_op_marshaling() -> Result<(), io::Error> {
        let header_size : u32 = 6;
        let mut buffer: Vec<u8> = Vec::with_capacity(100);
        let value = SyncSequenceIdOpPacket::new();
        let mut len = value.marshal(&mut buffer)?;
        assert_eq!(len, header_size);
        assert_eq!(buffer[..header_size as usize], [1, 0, 0, 0, 0, PacketType::SyncSequenceId as u8]);

        let bytes: Vec<u8> = vec![1, 2, 3, 4, 5];
        let mut engine = sha256::Hash::engine();
        engine.write_all(bytes.as_slice()).unwrap();
        let hash = sha256::Hash::from_engine(engine);
        let mut filename = FileNameType {
            data: [0; max_filename_length()],
        };
        let fname = "FooBar";
        filename.data[..fname.len()].clone_from_slice(fname.as_bytes());

        buffer.clear();
        let value = BeginInstallOpPacket::new(&filename, &hash);
        len = value.marshal(&mut buffer)?;
        assert_eq!(len, header_size + (max_filename_length() as u32) + 32);
        assert_eq!(buffer[..header_size as usize], [1, 0, 0, 0, 0, PacketType::BeginInstall as u8]);
        let iafn = header_size as usize + max_filename_length();
        assert_eq!(buffer[header_size as usize..iafn], filename.data[..]);
        assert_eq!((buffer[iafn..]), hash[..]);

        buffer.clear();
        let value = BeginFileTransferOpPacket::new(&filename, 42, &hash);
        len = value.marshal(&mut buffer)?;
        assert_eq!(len, header_size + (max_filename_length() as u32) + 4 + 32);
        assert_eq!(buffer[..header_size as usize], [1, 0, 0, 0, 0, PacketType::BeginFileTransfer as u8]);
        let iafn = header_size as usize + max_filename_length();
        assert_eq!(buffer[header_size as usize..iafn], filename.data[..]);
        assert_eq!((buffer[iafn..iafn + 4]), [42, 0, 0, 0]);
        assert_eq!((buffer[iafn + 4..]), hash[..]);

        buffer.clear();
        let value = EndFileTransferOpPacket::new(&hash);
        len = value.marshal(&mut buffer)?;
        assert_eq!(len, header_size + 32);
        assert_eq!(buffer[..header_size as usize], [1, 0, 0, 0, 0, PacketType::EndFileTransfer as u8]);
        assert_eq!(buffer[header_size as usize..], hash[..]);

        //future: Write test for AuthorizeUpgrade
//        buffer.clear();
//        let message = Vec!();
//        let signatures = Vec!();
//        let value = AuthorizeUpgrade::new(&message, signatures);
//        len = value.marshal_len();
//        assert_eq!(len, header_size + 32);
//        len = value.marshal(&mut buffer)?;
//        assert_eq!(len, header_size + 32);
//        assert_eq!(buffer[..header_size], [1, 0, 0, 0, 0, PacketType::AuthorizeUpgrade as u8, (len as u8) - 10, 0, 0, 0]);
//        assert_eq!(buffer[header_size..], hash[..]);

        Ok(())
    }

    #[test]
    fn test_file_chunk_marshaling() -> Result<(), MessageError> {
        let header_size: u32 = 6;
        let mut buffer: Vec<u8> = Vec::with_capacity(100);
        let data = [42; 10];
        let value = FileChunkPacket::new(&data)?;
        let len = value.marshal(&mut buffer)?;
        assert_eq!(len, header_size + data.len() as u32);
        assert_eq!(buffer[..header_size as usize], [1, 0, 0, 0, 0, 3]);
        assert_eq!(buffer[header_size as usize..], data[..]);

        Ok(())
    }
}
