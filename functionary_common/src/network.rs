use std::{fmt, mem};
use std::io::{self, Read, Write};
use bitcoin::{Amount, consensus};
use bitcoin::hashes::{self, Hash, sha256d};
use bitcoin::secp256k1::{self, PublicKey};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
extern crate time;
use self::time::Timespec;

use functionary::PeerId;

/// Message-related error
#[derive(Debug)]
pub enum Error {
    /// byteorder de/serialization error
    ByteOrder(byteorder::Error),
    /// bitcoin_hashes de/serialization error
    BitcoinHashes(hashes::FromSliceError),
    /// Key error.
    Key(bitcoin::key::Error),
    /// Parse finished but more data was expected
    IncompleteRead(u64),
    /// I/O error reading from the network
    Io(io::Error),
    /// Received message from a peer we don't recognize
    UnknownPeerId(PeerId),
    /// Bitcoin transaction couldn't be parsed, or something
    BadParse(bitcoin::consensus::encode::Error),
    /// Sidechain block couldn't be parsed, or something
    BadParseElements(elements::encode::Error),
    /// Payload hash did not match what was in the header
    BadMessageHash,
    /// Payload size was invalid for the command we received
    BadPayloadSize(usize, &'static str),
    /// secp error
    Secp(secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ByteOrder(ref e) => write!(f, "byteorder: {}", e),
            Error::BitcoinHashes(ref e) => write!(f, "bitcoin_hashes: {}", e),
            Error::Key(ref e) => write!(f, "bitcoin key error: {}", e),
            Error::IncompleteRead(n) => write!(f, "{} more bytes expected", n),
            Error::Io(ref e) => write!(f, "io: {}", e),
            Error::BadParse(ref e) => write!(f, "bitcoin: {}", e),
            Error::BadParseElements(ref e) => write!(f, "elements: {}", e),
            Error::UnknownPeerId(ref id) => write!(f, "peer ID {:?} not known", id),
            Error::BadMessageHash => f.write_str("bad message hash"),
            Error::BadPayloadSize(n, tp) => write!(f, "size {} not supported for message type {}", n, tp),
            Error::Secp(ref e) => write!(f, "secp256k1: {}", e),
        }
    }
}

#[doc(hidden)]
impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(e: bitcoin::consensus::encode::Error) -> Error { Error::BadParse(e) }
}

#[doc(hidden)]
impl From<elements::encode::Error> for Error {
    fn from(e: elements::encode::Error) -> Error { Error::BadParseElements(e) }
}

#[doc(hidden)]
impl From<hashes::FromSliceError> for Error {
    fn from(e: hashes::FromSliceError) -> Error { Error::BitcoinHashes(e) }
}

#[doc(hidden)]
impl From<bitcoin::key::Error> for Error {
    fn from(e: bitcoin::key::Error) -> Error { Error::Key(e) }
}

#[doc(hidden)]
impl From<byteorder::Error> for Error {
    fn from(e: byteorder::Error) -> Error { Error::ByteOrder(e) }
}

#[doc(hidden)]
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error { Error::Io(e) }
}

#[doc(hidden)]
impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error { Error::Secp(e) }
}


/// Trait defining wire encoding for network messages
pub trait NetEncodable: Sized {
    /// Encode data into a writer, returning the number of bytes written
    fn encode<W: Write>(&self, w: W) -> Result<usize, Error>;
    /// Decode data from a reader
    fn decode<R: Read>(r: R) -> Result<Self, Error>;
}


// Wrap elements consensus encoding to allow dynafed params
// to be transferred over the network protocol
impl NetEncodable for elements::dynafed::Params {
    fn encode<W: io::Write>(&self, w: W) -> Result<usize, Error> {
        elements::encode::Encodable::consensus_encode(self, w)
            .map_err(Error::BadParseElements)
    }

    fn decode<R: io::Read>(r: R) -> Result<Self, Error> {
        elements::encode::Decodable::consensus_decode(r)
            .map_err(Error::BadParseElements)
    }
}

// Primitives
impl NetEncodable for u64 {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_u64::<LittleEndian>(*self)?;
        Ok(8)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(r.read_u64::<LittleEndian>()?)
    }
}

impl NetEncodable for Amount {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_u64::<LittleEndian>(self.to_sat())?;
        Ok(8)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(Amount::from_sat(r.read_u64::<LittleEndian>()?))
    }
}

impl NetEncodable for [u64; 5] {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        for val in self.iter() {
            w.write_u64::<LittleEndian>(*val)?;
        }
        Ok(8 * 5)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok([
            r.read_u64::<LittleEndian>()?,
            r.read_u64::<LittleEndian>()?,
            r.read_u64::<LittleEndian>()?,
            r.read_u64::<LittleEndian>()?,
            r.read_u64::<LittleEndian>()?,
        ])
    }
}

impl NetEncodable for u32 {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_u32::<LittleEndian>(*self)?;
        Ok(4)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(r.read_u32::<LittleEndian>()?)
    }
}

impl NetEncodable for u16 {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_u16::<LittleEndian>(*self)?;
        Ok(2)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(r.read_u16::<LittleEndian>()?)
    }
}

impl NetEncodable for u8 {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_u8(*self)?;
        Ok(1)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(r.read_u8()?)
    }
}

impl NetEncodable for bitcoin::VarInt {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).encode(w)?;
                Ok(1)
            },
            0xFD..=0xFFFF => {
                0xFDu8.encode(&mut w)?;
                (self.0 as u16).encode(w)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                0xFEu8.encode(&mut w)?;
                (self.0 as u32).encode(w)?;
                Ok(5)
            },
            _ => {
                0xFFu8.encode(&mut w)?;
                self.0.encode(w)?;
                Ok(9)
            },
        }
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(consensus::Decodable::consensus_decode(&mut r)?)
    }
}

impl<T: NetEncodable> NetEncodable for Vec<T> {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let mut len = 0;
        len += bitcoin::VarInt(self.len() as u64).encode(&mut w)?;
        for c in self.iter() {
            len += c.encode(&mut w)?;
        }
        Ok(len)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        const MAX_LEN: u64 = 1_000_000;
        let len = bitcoin::VarInt::decode(&mut r)?.0;
        if len > MAX_LEN || len * mem::size_of::<T>() as u64 > MAX_LEN {
            return Err(Error::BadPayloadSize(len as usize, "Vec<T>"));
        }
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(NetEncodable::decode(&mut r)?);
        }
        Ok(ret)
    }
}

impl NetEncodable for elements::OutPoint {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        self.txid.encode(&mut w)?;
        self.vout.encode(&mut w)?;
        Ok(36)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(elements::OutPoint {
            txid: NetEncodable::decode(&mut r)?,
            vout: NetEncodable::decode(&mut r)?,
        })
    }
}

impl NetEncodable for bitcoin::OutPoint {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        self.txid.encode(&mut w)?;
        self.vout.encode(&mut w)?;
        Ok(36)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(bitcoin::OutPoint {
            txid: NetEncodable::decode(&mut r)?,
            vout: NetEncodable::decode(&mut r)?,
        })
    }
}

impl NetEncodable for Timespec {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_i64::<LittleEndian>(self.sec)?;
        w.write_i32::<LittleEndian>(self.nsec)?;
        Ok(12)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        Ok(Timespec {
            sec: r.read_i64::<LittleEndian>()?,
            nsec: r.read_i32::<LittleEndian>()?,
        })
    }
}

impl NetEncodable for PeerId {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        w.write_all(&self[..])?;
        Ok(self[..].len())
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut sl = [0; 6];
        r.read_exact(&mut sl[..])?;
        Ok(PeerId::from(&sl[..]))
    }
}

macro_rules! net_encodable_hash {
    ($hash:ty) => {
        impl NetEncodable for $hash {
            fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
                w.write_all(&self[..])?;
                Ok(<$hash as Hash>::LEN)
            }

            fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
                let mut sl = [0; 32];
                r.read_exact(&mut sl[..])?;
                Ok(<$hash>::from_slice(&sl[..])?)
            }
        }
    };
}
net_encodable_hash!(bitcoin::BlockHash);
net_encodable_hash!(bitcoin::Txid);
net_encodable_hash!(sha256d::Hash);
net_encodable_hash!(elements::Txid);
net_encodable_hash!(elements::BlockHash);

impl NetEncodable for secp256k1::ecdsa::Signature {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let sig = self.serialize_compact();
        w.write_all(&sig[..])?;
        Ok(secp256k1::constants::COMPACT_SIGNATURE_SIZE)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut sl = [0; 64];
        r.read_exact(&mut sl[..])?;
        Ok(secp256k1::ecdsa::Signature::from_compact(&sl[..])?)
    }
}

impl NetEncodable for (secp256k1::ecdsa::Signature, bitcoin::EcdsaSighashType) {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let sig = self.0.serialize_der();
        let vi_len = bitcoin::VarInt(1 + sig.len() as u64).encode(&mut w)?;
        w.write_all(&sig)?;
        w.write_u8(self.1.to_u32() as u8)?;
        Ok(vi_len + sig.len() + 1)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut sl = [0; 74];
        let bitcoin::VarInt(len) = NetEncodable::decode(&mut r)?;
        let len = len as usize;
        if len == 0 || len > sl.len() {
            return Err(Error::BadPayloadSize(len, "(Signature, SigHashType)"));
        }
        r.read_exact(&mut sl[..len])?;

        Ok((
            secp256k1::ecdsa::Signature::from_der(&sl[..len - 1])?,
            bitcoin::EcdsaSighashType::from_consensus(sl[len - 1] as u32),
        ))
    }
}

impl NetEncodable for (PeerId, PublicKey, PublicKey) {
    fn encode<W: Write>(&self, mut w: W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.0.encode(&mut w)?;
        len += 33u8.encode(&mut w)?;
        w.write_all(&self.1.serialize())?;
        len += 33;
        len += 33u8.encode(&mut w)?;
        w.write_all(&self.2.serialize())?;
        len += 33;
        Ok(len)
    }

    fn decode<R: Read>(mut r: R) -> Result<Self, Error> {
        let id = NetEncodable::decode(&mut r)?;
        let mut key_buf = [0; 65];
        let key1 = match r.read_u8()? {
            33 => {
                r.read_exact(&mut key_buf[..33])?;
                PublicKey::from_slice(&key_buf[..33])?
            },
            65 => {
                r.read_exact(&mut key_buf[..65])?;
                PublicKey::from_slice(&key_buf[..65])?
            },
            x => return Err(Error::BadPayloadSize(x as usize, "(Id, PublicKey, PublicKey)")),
        };
        let key2 = match r.read_u8()? {
            33 => {
                r.read_exact(&mut key_buf[..33])?;
                PublicKey::from_slice(&key_buf[..33])?
            },
            65 => {
                r.read_exact(&mut key_buf[..65])?;
                PublicKey::from_slice(&key_buf[..65])?
            },
            x => return Err(Error::BadPayloadSize(x as usize, "(Id, PublicKey, PublicKey)")),
        };
        Ok((id, key1, key2))
    }
}