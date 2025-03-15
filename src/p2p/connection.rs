use std::{
    cmp::{max, min},
    time::Instant,
};

use crate::p2p::fsdp::{FsdpPayload, FsdpPayloadType};

use super::{
    encryption::CryptoSession,
    fsdp::{FsdpPayloadContent, Handshake},
    packet::{Packet, PacketContent},
    Error,
};

#[derive(Default)]
pub struct PlayerConnection {
    /// Has this session seen a disconnect message from either party?
    disconnected: bool,
    crypto: CryptoSession,
    remote_handshake: Option<Handshake>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Origin {
    Local,
    Remote,
}

impl PlayerConnection {
    /// Is the connection ready to accept game packets?
    pub fn ready(&self) -> bool {
        self.crypto.ready() && self.remote_handshake.is_some()
    }

    pub fn handle_session_control_packet(
        &mut self,
        remote: u64,
        data: &[u8],
        side: Origin,
    ) -> Result<(), Error> {
        let packet = Packet::read(data)?;

        match packet.content()? {
            PacketContent::Nonce(nonce) => {
                if data.len() != 14 {
                    return Err(Error::ProtocolViolation("Nonce message of wrong size."))
                }

                tracing::info!("Nonce message: {nonce:x}");
                self.crypto.process_received_nonce(nonce, side)?;
            }
            PacketContent::Encrypted(encrypted) => {
                let decrypted = self.crypto.decrypt(encrypted, side)?;
                let payload = FsdpPayload::read(decrypted.as_slice())?;

                if let FsdpPayloadContent::Handshake(handshake) = payload.content()? {
                    tracing::info!("Handshake {side:?} -> {handshake:x?}");

                    if side == Origin::Remote {
                        // Validate the received steam ID against the one we got from steam to
                        // prevent spoofing.
                        if handshake.steam_id != remote {
                            return Err(Error::ProtocolViolation("Handshake steam ID mismatch"));
                        }

                        self.remote_handshake = Some(handshake);
                    }

                    return Ok(());
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn log_content(payload: &FsdpPayload) -> Result<(), Error> {
        match payload.content()? {
            FsdpPayloadContent::Empty => tracing::info!("Empty"),
            FsdpPayloadContent::Handshake(a) => tracing::info!("Handshake: {a:#?}"),
            FsdpPayloadContent::DataUnfragmented(a) => tracing::info!("Unfragmented data: {a:x?}"),
            FsdpPayloadContent::Disconnect => tracing::info!("Disconnect"),
            FsdpPayloadContent::HardDisconnect => tracing::info!("Hard disconnect"),
            FsdpPayloadContent::Unknown(a) => tracing::info!("Unknown contents {a:?}"),
        }

        Ok(())
    }
}
