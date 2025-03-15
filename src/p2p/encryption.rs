use std::{cmp::{max, min}, io::Read};

use aes::{cipher::{KeyIvInit, StreamCipher}, Aes128};
use byteorder::{BE, LE, ReadBytesExt};
use crc::{Crc, CRC_32_ISO_HDLC};
use ctr::Ctr128BE;

use super::{connection::Origin, Error};

/// Key as embedded in the game.
const KEY: [u8; 16] = *b"he2WGvQXWXzeQxL2";

const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

pub const CTR_TOP_THIRD: u16 = 0xAAAB;
pub const CTR_LOW_THIRD: u16 = 0x5554;

pub const DECRYPT_BUFFER_SIZE: usize = 0x800;

/// Handles the decryption of low-level game packets.
pub struct CryptoSession {
    nonce: Option<u64>,
    local: CryptoParty,
    remote: CryptoParty,
}

impl Default for CryptoSession {
    fn default() -> Self {
        Self {
            nonce: Default::default(),
            local: Default::default(),
            remote: Default::default(),
        }
    }
}

impl CryptoSession {
    /// Are we ready to encrypt/decrypt messages for this connection?
    pub fn ready(&self) -> bool {
        self.nonce.is_some()
    }

    fn party_for_side(&mut self, side: Origin) -> &mut CryptoParty {
        match side {
            Origin::Local => &mut self.local,
            Origin::Remote => &mut self.remote,
        }
    }

    pub fn process_received_nonce(&mut self, nonce: u32, side: Origin) -> Result<(), Error> {
        if self.nonce.is_some() {
            tracing::debug!("Nonce exchange was already completed. Ignoring nonce message.");
            return Ok(());
        }

        let party = self.party_for_side(side);
        if party.nonce_halve.is_some() {
            tracing::debug!("Party has already supplied their nonce. Ignoring nonce message.");
            return Ok(());
        }

        party.nonce_halve = Some(nonce);

        // Form final session nonce once both ends are in.
        match (self.local.nonce_halve, self.remote.nonce_halve) {
            (Some(local), Some(remote)) => {
                // Final nonce is determined by ordering both nonce halves and shifting
                // them to one.
                let low = min(local, remote) as u64;
                let high = max(local, remote) as u64;
                let nonce = high << 32 | low;

                tracing::info!("Derived session nonce {nonce:x}");
                self.nonce = Some(nonce);
            }
            _ => {}
        }

        Ok(())
    }

    /// Decrypt a message using the sessions parameters.
    pub fn decrypt<R: Read>(&mut self, mut data: R, side: Origin) -> Result<Vec<u8>, Error> {
        let Some(nonce) = self.nonce.clone() else {
            return Err(Error::ProtocolViolation("Sending encrypted data before KX was finalized."));
        };

        let party = self.party_for_side(side);
        let sequence = data.read_u16::<BE>()?;
        let sequence = Self::wrap_packet_seq(sequence, party.sequence_latest)?;
        tracing::debug!("Packet seq {sequence} (latest: {}, highest: {})", party.sequence_latest, party.sequence_highest);

        let iv = Self::generate_iv(sequence, nonce);
        tracing::debug!("IV {iv:x?}");
        let mut cipher = Ctr128BE::<Aes128>::new((&KEY).into(), (&iv).into());

        let mut buf = Vec::with_capacity(DECRYPT_BUFFER_SIZE);
        data.read_to_end(&mut buf)?;

        cipher.apply_keystream(&mut buf);

        let decrypted = &mut buf.as_slice();
        let expected_crc = decrypted.read_u32::<LE>()?;
        let data = decrypted.to_vec();
        let crc = CRC.checksum(&data);
        tracing::debug!("Expected CRC = {expected_crc:x}. Calculated CRC = {crc:x}");

        // TODO: validate CRC
        party.update_packet_counters(sequence);

        Ok(data)
    }

    /// Generate an IV based on sequence and nonce
    fn generate_iv(sequence: u64, nonce: u64) -> [u8; 16] {
        ((nonce as u128) << 64 | (sequence << 16) as u128).to_be_bytes()
    }

    fn wrap_packet_seq(packet_seq: u16, latest_seq: u64) -> Result<u64, Error> {
        let local_low: u16 = (latest_seq & 0xFFFF) as u16;
        let local_top: u64 = (latest_seq & !0xFFFF) as u64;

        let c = [local_low, packet_seq];
        if c.iter().any(|&n| CTR_LOW_THIRD < n)
            && c.iter().any(|&n| n < CTR_TOP_THIRD)
            && c.iter()
                .all(|&n| CTR_LOW_THIRD + 1 < n.wrapping_add(CTR_TOP_THIRD))
        {
            if local_low < CTR_TOP_THIRD || CTR_LOW_THIRD < packet_seq {
                local_top
                    .checked_sub(0x10000)
                    .and_then(|n| Some(n | packet_seq as u64))
                    .ok_or_else(|| Error::PacketSequence)
            } else {
                Ok(local_top + 0x10000 | packet_seq as u64)
            }
        } else {
            Ok(local_top | packet_seq as u64)
        }
    }
}

#[derive(Default)]
struct CryptoParty {
    /// Nonce halve sent in by this party.
    pub nonce_halve: Option<u32>,
    /// Latest sequence number we've received.
    pub sequence_latest: u64,
    /// Highest sequence number we've seen.
    sequence_highest: u64,
    /// Bitfield that represents what packets were and were not received.
    /// Already received = (received >> (highest - sequence)) & 1 == 1
    received: u64,
}

impl CryptoParty {
    pub fn update_packet_counters(&mut self, sequence: u64) -> () {
        let mut dist = self.sequence_highest.wrapping_sub(sequence) as u32;
        if sequence >= self.sequence_highest {
            dist = (sequence - self.sequence_highest) as u32;
            self.sequence_highest = sequence;
        }
        self.received = self.received.checked_shl(dist).unwrap_or(0) | 1;
        self.sequence_latest = sequence;
    }

    pub fn late_or_duplicate_packet_check(&self, sequence: u64) -> Result<(), Error> {
        let window_end = self.sequence_highest;
        let bitmask = self.received;
        let dist = window_end.wrapping_sub(sequence);

        if sequence > window_end {
            Ok(())
        } else if dist >= 64 {
            Err(Error::LatePacket(sequence, window_end))
        } else if ((bitmask >> dist) & 1) == 1 {
            Err(Error::DuplicatePacket(sequence))
        } else {
            Ok(())
        }
    }
}
