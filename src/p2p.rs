/// Completely replaces the games P2P connection with our own implementation based on steamworks
/// messaging API. This should significantly improve latency for Elden Ring and AC6 since it
/// bypasses the reliability and fragmentation/batching layer that From Software uses for these
/// titles.
///
/// Since there's a fair bit of misconception about this code: we swap out on seperate levels, one for the
/// gamepackets which ordinarily get wrapped in a different, lower level, messaging format (FSDP).
/// The other level is aforementioned FSDP messaging which in combo with the other swap only facilitates
/// messaging about disconnects and announcing yourself to peers, as otherwise the game still resorts to
/// the legacy ISteamNetworking API for that (and we want everything on ISteamNetworkingMessages for privacy
/// reasons).
///
/// IMPORTANT!!
/// If you're writing a mod and you're looking for these hooks to sync some data or coordinate some
/// multi-party action I highly suggest using steam's networking messages API (https://partner.steamgames.com/doc/api/ISteamNetworkingMessages)
/// instead. It wont conflict with other mods and it prevents you from having to intercept your own
/// networking such that the game doesn't try to handle it by accident.
use connection::{Origin, PlayerConnection};
use queue::GamePacketQueue;
use retour::static_detour;
use std::{
    collections::HashMap,
    ptr::NonNull,
    sync::{mpsc::channel, Arc},
};

use message::Message;
use pelite::pattern::Atom;
use pelite::pe::{Pe, PeView};
use serde::{Deserialize, Serialize};
use steamworks::{Client, ClientManager};
use steamworks_sys::k_nSteamNetworkingSend_AutoRestartBrokenSession;
use steamworks_sys::{
    SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser,
    SteamAPI_ISteamNetworkingMessages_SendMessageToUser,
    SteamAPI_SteamNetworkingMessages_SteamAPI_v002,
};
use thiserror::Error;

use crate::singleton::get_instance;
use crate::steam::{self, networking_identity};
use crate::task::{CSTaskGroupIndex, CSTaskImp, FD4TaskData, TaskRuntime};
use crate::{InitError, APP_ID};

mod connection;
mod encryption;
mod packet;
mod queue;

pub(crate) mod fsdp;
pub(crate) mod message;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Io {0}")]
    Io(#[from] std::io::Error),
    #[error("Checksummed data does not match expected CRC")]
    CRC,
    #[error("Packet buffer size was different than advertised")]
    PacketSizeIncorrect,
    #[error("Did not read expected magic for handshake")]
    IncorrectHandshakeMagic,
    #[error("Packet sequence?")]
    PacketSequence,
    #[error("Duplicate packet received (seq = {0})")]
    DuplicatePacket(u64),
    #[error("Late packet received (seq = {0} window_end = {0})")]
    LatePacket(u64, u64),
    #[error("Protocol violation. {0}")]
    ProtocolViolation(&'static str),
}

static_detour! {
    static P2P_PACKET_DEQUEUE: extern "C" fn(
        NonNull<MTInternalThreadSteamConnection>,
        u8,
        NonNull<u8>,
        u32,
        NonNull<u8>
    ) -> u32;

    static P2P_PACKET_SEND: extern "C" fn(
        usize,
        usize,
        NonNull<u64>,
        u8,
        NonNull<u8>,
        u32,
        u8
    ) -> usize;
}

#[repr(C)]
struct MTInternalThreadSteamConnection {
    _unk0: [u8; 0x128],
    steam_id: u64,
}

const P2P_PACKET_DEQUEUE_PATTERN: &[Atom] =
    pelite::pattern!("48 8B 09 48 85 C9 75 03 33 C0 C3 E9 $ { ' }");
const P2P_PACKET_SEND_PATTERN: &[Atom] =
    pelite::pattern!("88 44 24 30 44 89 4C 24 28 44 0F B6 CA 48 8B D1 4C 89 44 24 20 49 8B CA 4C 8D 44 24 50 E8 $ { ' }");

/// Determines the steam messages channel used for the p2p swap.
const MESSAGES_CHANNEL: i32 = 69420;
/// The max batch read size for a given player session per frame.
const PACKET_BATCH_SIZE: usize = 0x10;
/// How many packets do we expect in the queue on average for any distinct packet type?
const PACKET_QUEUE_INITIAL_CAPACITY: usize = 255;

pub fn hook(module: &PeView, steam: Client) -> Result<(), InitError> {
    let messaging = Arc::new(SteamMessaging::new(steam));
    let game_packet_queue = Arc::new(GamePacketQueue::default());
    let (p2p_send_tx, p2p_send_rx) = channel();
    let (p2p_receive_tx, p2p_receive_rx) = channel();
    let (close_tx, close_rx) = channel();

    let packet_dequeue_va = {
        let mut matches = [0u32; 2];
        if !module
            .scanner()
            .finds_code(P2P_PACKET_DEQUEUE_PATTERN, &mut matches)
        {
            return Err(InitError::FlakyPattern("P2P_PACKET_DEQUEUE"));
        }

        module
            .rva_to_va(matches[1])
            .map_err(InitError::AddressConversion)?
    };

    let packet_send_va = {
        let mut matches = [0u32; 2];
        if !module
            .scanner()
            .finds_code(P2P_PACKET_SEND_PATTERN, &mut matches)
        {
            return Err(InitError::FlakyPattern("P2P_PACKET_SEND"));
        }

        module
            .rva_to_va(matches[1])
            .map_err(InitError::AddressConversion)?
    };

    unsafe {
        let queue = game_packet_queue.clone();
        P2P_PACKET_DEQUEUE
            .initialize(
                std::mem::transmute(packet_dequeue_va),
                move |connection: NonNull<MTInternalThreadSteamConnection>,
                      packet_type: u8,
                      output: NonNull<u8>,
                      max_size: u32,
                      flags_out: NonNull<u8>| {
                    let remote = connection.as_ref().steam_id;

                    let Some((flags, packet)) = queue.pop(remote, packet_type) else {
                        return 0;
                    };

                    // Ensure we're not about to write out-of-bounds.
                    if (max_size as usize) < packet.len() {
                        return 0;
                    }

                    // Copy received data to the output buffer
                    std::ptr::copy_nonoverlapping(packet.as_ptr(), output.as_ptr(), packet.len());

                    *flags_out.as_ptr() = flags;

                    packet.len() as u32
                },
            )?
            .enable()?;
    }

    unsafe {
        let messaging = messaging.clone();

        P2P_PACKET_SEND
            .initialize(
                std::mem::transmute(packet_send_va),
                move |_p1: usize,
                      _p2: usize,
                      steam_id: NonNull<u64>,
                      packet_type: u8,
                      buffer: NonNull<u8>,
                      packet_size: u32,
                      flags: u8| {
                    let remote = steam_id.as_ref();
                    let contents =
                        std::slice::from_raw_parts(buffer.as_ptr(), packet_size as usize);

                    if let Err(e) = messaging.send(
                        *remote,
                        &Message::GamePacket(packet_type, flags, contents.to_vec()),
                    ) {
                        tracing::error!("Could not send game packet {e}");

                        0
                    } else {
                        packet_size as usize
                    }
                },
            )?
            .enable()?;
    }

    // Retool the session control packets to also use ISteamNetworkingMessages.
    unsafe { steam::hook(p2p_send_tx, p2p_receive_rx, close_tx) };
    let mut connections = HashMap::<u64, PlayerConnection>::new();

    let cs_task = get_instance::<CSTaskImp>().unwrap().unwrap();
    let task = cs_task.run_task(
        move |_: &FD4TaskData| {
            // Process any pending session closes
            while let Ok(remote) = close_rx.try_recv() {
                tracing::info!("Dropping session with {remote}");
                connections.remove(&remote);
                game_packet_queue.remove(remote);
                if let Err(e) = messaging.close(remote) {
                    tracing::error!("Could not close steam messaging session with {remote}: {e}");
                }
            }

            // Process incoming messages from remote parties.
            for message in messaging.receive().into_iter() {
                let Ok((remote, message)) = message else {
                    tracing::error!("Could not figure out remote. e = {message:?}");
                    continue;
                };

                if steam::is_blocked(remote) {
                    tracing::debug!("Dropping message from blocked remote {remote}");
                    continue;
                }

                let Ok(message) = message else {
                    tracing::error!("Could not deserialize incoming waygate p2p message.");
                    continue;
                };

                let connection = connections.entry(remote).or_default();
                match message {
                    // Push raw packets down the sink for the steam API to dequeue
                    Message::RawPacket(data) => {
                        if let Err(e) = connection.handle_session_control_packet(remote, &data, Origin::Remote) {
                            tracing::error!("PlayerConnection could not not handle received packet {e}");
                        }

                        p2p_receive_tx
                            .send((remote, data))
                            .expect("Could not push down raw packet channel");
                    }

                    // Send game packets appropriate channel for dequeueing by hook.
                    Message::GamePacket(packet_type, flags, data) => {
                        if !connection.ready() {
                            tracing::warn!("Connection sent game packets before session setup was finalized. Skipping message.");
                            continue;
                        }

                        game_packet_queue.push(remote, packet_type, flags, data)
                    }
                }
            }

            // Send any outbound messages that the game has enqueued since the last frame.
            while let Ok((remote, message)) = p2p_send_rx.try_recv() {
                if let Err(e) = messaging.send(remote, &message) {
                    tracing::error!("Could not send message to steam. e = {e}");
                    continue;
                }

                if let Message::RawPacket(data) = &message {
                    let connection = connections.entry(remote).or_default();
                    if let Err(e) = connection.handle_session_control_packet(remote, data, Origin::Local) {
                        tracing::error!("FsdpConnection could not handle sent packet {e}");
                    }
                };
            }
        },
        CSTaskGroupIndex::FrameBegin,
    );

    std::mem::forget(task);

    Ok(())
}

#[derive(Debug, Error)]
pub enum SteamMessagingError {
    #[error("Bincode error: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("Steam error: {0}")]
    SteamError(#[from] steamworks::SteamError),
    #[error("Passed networking identity was not a steam ID")]
    IdentityNotASteamId,
}

pub struct SteamMessaging {
    /// Determines the messages channel used for communication.
    channel: i32,
    /// Holds the steam client.
    client: Client<ClientManager>,
}

impl SteamMessaging {
    pub fn new(client: Client<ClientManager>) -> Self {
        Self {
            channel: MESSAGES_CHANNEL,
            client,
        }
    }

    pub fn send(&self, remote: u64, message: &Message) -> Result<(), SteamMessagingError> {
        let data = bincode::serialize(message)?;

        steam::send_message_to_user(
            remote,
            &data,
            message.send_flags() | k_nSteamNetworkingSend_AutoRestartBrokenSession,
            self.channel,
        );

        Ok(())
    }

    pub fn receive(
        &self,
    ) -> Vec<Result<(u64, Result<Message, SteamMessagingError>), SteamMessagingError>> {
        self.client
            .networking_messages()
            .receive_messages_on_channel(self.channel as u32, PACKET_BATCH_SIZE)
            .iter()
            .map(|m| {
                let message =
                    bincode::deserialize::<Message>(m.data()).map_err(SteamMessagingError::from);

                let steam_id = m
                    .identity_peer()
                    .steam_id()
                    .ok_or(SteamMessagingError::IdentityNotASteamId)?;

                Ok((steam_id.raw(), message))
            })
            .collect()
    }

    pub fn close(&self, remote: u64) -> Result<(), SteamMessagingError> {
        steam::close_session_with_user(remote);
        Ok(())
    }
}
