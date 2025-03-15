use std::io::Read;

use byteorder::{ReadBytesExt, BE};

use super::Error;

/// Represents a raw p2p packet usually wrapping an FSDP layer payload.
pub struct Packet {
    /// Seems to be size of raw packet itself. This data is read from the packets contents
    /// and needs to be validated (cannot be trusted).
    pub raw_size: u32,
    /// Only checked if size == 14 in games code.
    /// The nonces are used to encrypt the packets for the rest of the session.
    /// Both ends specify one half of the nonce, after that the nonces are sorted
    /// and ANDed to each other to make up a u64 nonce like: high << 32 | low.
    pub is_nonce_exchange: bool,
    /// Are packets contents encrypted?
    pub is_encrypted: bool,
    /// Raw bytes making up the rest of this packet.
    pub body: Vec<u8>,
}

impl Packet {
    pub fn read<R: Read>(mut r: R) -> Result<Self, Error> {
        let b1 = r.read_u8()?;
        let b2 = r.read_u8()?;

        let raw_size = ((b2 & 0b00000111) as u32 * 0x100) + b1 as u32;
        let is_nonce_exchange = b2 & 0b01000000 != 0;
        let is_encrypted = b2 & 0b10000000 != 0;

        let mut body = vec![];
        r.read_to_end(&mut body)?;

        Ok(Self {
            raw_size,
            is_nonce_exchange,
            is_encrypted,
            body,
        })
    }

    /// High-level representation of the packets contents.
    pub fn content(&self) -> Result<PacketContent, Error> {
        let mut reader = self.body.as_slice();

        // Nonce exchange packets are exempt from the rest of the protocol.
        if self.raw_size == 14 && self.body.len() == 14 - 2 && self.is_nonce_exchange {
            let nonce = reader.read_u32::<BE>()?;
            return Ok(PacketContent::Nonce(nonce));
        }

        if self.is_encrypted {
            return Ok(PacketContent::Encrypted(reader));
        }

        Ok(PacketContent::Unknown)
    }
}

#[derive(Debug)]
pub enum PacketContent<'a> {
    Nonce(u32),
    Encrypted(&'a [u8]),
    Unknown,
}
