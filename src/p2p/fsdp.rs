/// This code
use std::{
    cmp::{max, min},
    io::Read,
};

use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes128,
};
use byteorder::{ReadBytesExt, BE, LE};

use super::Error;

pub struct FsdpPayload {
    pub sequence: u16,
    pub last_received_remote_sequence: Option<u16>,
    pub payload_type: u8,
    pub window_size: u8,
    pub body: Vec<u8>,
}

impl FsdpPayload {
    pub fn read<R: Read>(mut r: R) -> Result<Self, Error> {
        let _ = r.read_u8()?;
        let sequence = r.read_u16::<BE>()?;
        let sequence_last_received_remote = r.read_u16::<BE>()?;

        let b1 = r.read_u8()?;
        let last_received_remote_sequence =
            (b1 & 0b11110000 == 0b00110000).then_some(sequence_last_received_remote);
        let payload_type = b1 & 0b00001111;
        let window_size = r.read_u8()?;

        let mut body = vec![];
        r.read_to_end(&mut body)?;

        Ok(Self {
            sequence,
            last_received_remote_sequence,
            payload_type,
            window_size,
            body,
        })
    }

    pub fn content(&self) -> Result<FsdpPayloadContent, Error> {
        Ok(match self.payload_type {
            0x0 => FsdpPayloadContent::Empty,
            0x1 => FsdpPayloadContent::Handshake(Handshake::read(self.body.as_slice())?),
            0x3 => FsdpPayloadContent::DataUnfragmented(self.body.as_slice()),
            0x5 => FsdpPayloadContent::Disconnect,
            0x6 => FsdpPayloadContent::HardDisconnect,
            _ => FsdpPayloadContent::Unknown(self.body.as_slice()),
        })
    }
}

pub enum FsdpPayloadContent<'a> {
    Empty,
    Handshake(Handshake),
    DataUnfragmented(&'a [u8]),
    Disconnect,
    HardDisconnect,
    Unknown(&'a [u8]),
}

#[repr(u8)]
#[derive(Debug)]
pub enum FsdpPayloadType {
    Empty = 0x0,
    Handshake = 0x1,
    DataUnfragmented = 0x3,
    Disconnect = 0x5,
    HardDisconnect = 0x6,
    DataFragmented = 0x7,
    Unknown(u8),
}

impl From<u8> for FsdpPayloadType {
    fn from(value: u8) -> Self {
        match value {
            0x0 => Self::Empty,
            0x1 => Self::Handshake,
            0x3 => Self::DataUnfragmented,
            0x5 => Self::Disconnect,
            0x6 => Self::HardDisconnect,
            0x7 => Self::DataFragmented,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug)]
pub struct Handshake {
    pub receive_buffer_size: u32,
    pub steam_id: u64,
}

impl Handshake {
    pub fn read<R: Read>(mut r: R) -> Result<Self, Error> {
        let magic = r.read_u16::<BE>()?;
        if magic != 0x1311 {
            return Err(Error::IncorrectHandshakeMagic);
        }

        let receive_buffer_size = r.read_u32::<BE>()?;
        let steam_id = r.read_u64::<BE>()?;

        Ok(Self {
            receive_buffer_size,
            steam_id,
        })
    }
}
