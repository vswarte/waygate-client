use std::{
    collections::{hash_map::Entry, HashMap},
    sync::RwLock,
    time::{Duration, Instant},
};

use crossbeam::queue::ArrayQueue;
use serde::{Deserialize, Serialize};
use steamworks::{Client, ClientManager};
use steamworks_sys::{
    k_nSteamNetworkingSend_AutoRestartBrokenSession, k_nSteamNetworkingSend_Reliable,
    k_nSteamNetworkingSend_UnreliableNoNagle,
    SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser,
    SteamAPI_ISteamNetworkingMessages_SendMessageToUser,
    SteamAPI_SteamNetworkingMessages_SteamAPI_v002,
};
use thiserror::Error;

use crate::steam::{is_blocked, networking_identity};

/// Determines the capacity of a packet queue. The client DLL will crash if this capacity is ever
/// exceeced.
/// Set to 2048 to help ERR with their packet 36 spam. Vanilla cap is 256.
const PACKET_QUEUE_CAPACITY: usize = 2048;
/// The max batch read size for a given player session.
const PACKET_BATCH_SIZE: usize = 0x20;
/// Amount of time to ignore traffic from a disconnected party for. This ensures that we're not
/// handling stale events causing reinsertion of the session into the session map.
const DISCONNECT_IGNORE_TIMEOUT: Duration = Duration::from_secs(5);
const BLOCKED_IGNORE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum PlayerNetworkingError<T: MessageTransport> {
    #[error("Connection map lock poisoned")]
    SessionMapPoison,
    #[error("Disconnect map lock poisoned")]
    DisconnectMapPoison,
    #[error("Player packet queue has reached its bounds. packet_type = {0}")]
    PacketQueueBounds(u8),
    #[error("Transport error. {0}")]
    Transport(T::TransportError),
    #[error("Unknown lobby participant")]
    UnknownParticipant,
}

/// Container for all the session of all connected players.
pub struct PlayerNetworking<T: MessageTransport> {
    /// All current sessions with other players.
    sessions: RwLock<HashMap<u64, PlayerNetworkingSession>>,
    /// Holds disconnects, used to ensure we dont handle anything for disconnected players.
    disconnects: RwLock<HashMap<u64, Instant>>,
    /// Holds the low-level transport used for actually sending and receiving data.
    transport: T,
    /// Received raw packets.
    raw_inbound: ArrayQueue<InboundRawPacket>,
}

pub struct InboundRawPacket {
    pub sender: u64,
    pub data: Vec<u8>,
}

impl<T: MessageTransport> PlayerNetworking<T> {
    pub fn new(transport: T) -> Self {
        Self {
            sessions: Default::default(),
            disconnects: Default::default(),
            transport,
            raw_inbound: ArrayQueue::new(0x20),
        }
    }

    /// Updates the PlayerNetworking structure, pumps and handles the
    /// received messages and pushes inbound game packets to their respective queues.
    pub fn update(&self) -> Result<(), PlayerNetworkingError<T>> {
        // Pump incoming messages
        for message in self.transport.receive().iter() {
            match message {
                Ok((remote, message)) => {
                    if self.remote_in_cooldown(*remote) {
                        tracing::debug!("Received data from disconnected remote. Ignoring.");
                        continue;
                    }

                    match message {
                        Ok(message) => {
                            if let Err(e) = self.handle_message(*remote, message) {
                                tracing::error!(
                                    "Could not handle message from {remote:?}. e = {e}"
                                );
                            }
                        }
                        Err(e) => tracing::error!(
                            "Could not deserialize message from {remote:?}. e = {e}"
                        ),
                    }
                }
                Err(e) => tracing::error!("Could not figure out remote. e = {e}"),
            }
        }

        Ok(())
    }

    /// Handles receiving of a message for a given remote player. This handles both received game
    /// packets as well.
    fn handle_message(
        &self,
        remote: u64,
        message: &Message,
    ) -> Result<(), PlayerNetworkingError<T>> {
        // TODO: We can save on some locking here

        // Create player session entry if the player hasn't recently disconnected and doesn't exist
        // yet in our session map.
        {
            // Take out read guard explicitly so we can drop it if we need to do an insert.
            let read_guard = self
                .sessions
                .read()
                .map_err(|_| PlayerNetworkingError::SessionMapPoison)?;

            if !read_guard.contains_key(&remote) {
                // Drop the guard to prevent deadlocking here
                drop(read_guard);

                // Block traffic from this remote for a while.
                if is_blocked(remote) {
                    self.ignore_blocked(remote);
                    tracing::info!("Got traffic from blocked remote {remote:?}. Blocking traffic for a while.");
                    return Ok(());
                }

                let session = PlayerNetworkingSession::new();
                if let Entry::Vacant(v) = self
                    .sessions
                    .write()
                    .map_err(|_| PlayerNetworkingError::SessionMapPoison)?
                    .entry(remote)
                {
                    v.insert(session);
                }
            }
        }

        let sessions = self
            .sessions
            .read()
            .map_err(|_| PlayerNetworkingError::SessionMapPoison)?;
        let session = sessions
            .get(&remote)
            .ok_or(PlayerNetworkingError::UnknownParticipant)?;

        match message {
            Message::RawPacket(channel, data) => {
                tracing::info!("Received raw packet {channel} -> {data:?}");
                self.raw_inbound
                    .push(InboundRawPacket {
                        sender: remote,
                        data: data.clone(),
                    })
                    .map_err(|_| PlayerNetworkingError::PacketQueueBounds(254))?;
            }
            Message::GamePacket(packet_type, data) => {
                session.inbound[*packet_type as usize]
                    .push(data.clone())
                    .map_err(|_| PlayerNetworkingError::PacketQueueBounds(*packet_type))?;
            }
        }

        Ok(())
    }

    /// Sends a message through the contained transport.
    pub fn send_message(
        &self,
        remote: u64,
        message: &Message,
    ) -> Result<(), PlayerNetworkingError<T>> {
        self.transport
            .send(remote, message)
            .map_err(PlayerNetworkingError::Transport)
    }

    /// Dequeues a game packet for a given remote.
    pub fn dequeue_raw_packet(&self) -> Option<InboundRawPacket> {
        self.raw_inbound.pop()
    }

    /// Dequeues a game packet for a given remote.
    pub fn dequeue_game_packet(
        &self,
        remote: u64,
        packet_type: u8,
    ) -> Result<Option<Vec<u8>>, PlayerNetworkingError<T>> {
        self.sessions
            .read()
            .map(|m| m.get(&remote)?.inbound[packet_type as usize].pop())
            .map_err(|_| PlayerNetworkingError::SessionMapPoison)
    }

    /// Check if the specified remote party is on disconnect cooldown.
    pub fn remote_in_cooldown(&self, remote: u64) -> bool {
        self.disconnects.read().unwrap().get(&remote).is_some_and(|i| &Instant::now() < i)
    }

    /// Clears out residual data for a player session.
    pub fn remove_session(&self, remote: u64) -> Result<(), PlayerNetworkingError<T>> {
        {
            self.disconnects
                .write()
                .map_err(|_| PlayerNetworkingError::DisconnectMapPoison)?
                .insert(remote, Instant::now() + DISCONNECT_IGNORE_TIMEOUT);
            tracing::info!("Added closed connection to ignore map");
        }

        // TODO: maybe err if there is no such entry?
        if let Some(_session) = self
            .sessions
            .write()
            .map_err(|_| PlayerNetworkingError::SessionMapPoison)?
            .remove(&remote)
        {
            self.transport.close(remote).unwrap();
        }

        Ok(())
    }

    /// Temporarily add user to 
    pub fn ignore_blocked(&self, remote: u64) {
        self.disconnects
            .write()
            .unwrap()
            .insert(remote, Instant::now() + BLOCKED_IGNORE_TIMEOUT);
        self.transport.close(remote).unwrap();
    }
}

/// Represents an individual players connection.
pub struct PlayerNetworkingSession {
    /// Host the inbound packets for the session with this player.
    inbound: [ArrayQueue<Vec<u8>>; u8::MAX as usize],
}

impl PlayerNetworkingSession {
    pub fn new() -> Self {
        Self {
            inbound: std::array::from_fn(|_| ArrayQueue::new(PACKET_QUEUE_CAPACITY)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Message {
    RawPacket(i32, Vec<u8>),
    /// Packet originating from the game.
    GamePacket(u8, Vec<u8>),
}

impl Message {
    /// Determines the appropriate reliability and nagle layer properties for a given message.
    pub fn send_flags(&self) -> i32 {
        match self {
            Message::RawPacket(_, _) => k_nSteamNetworkingSend_Reliable,

            // TODO: figure out more packet types and determine appropriate send flags.
            #[cfg(feature = "eldenring")]
            Message::GamePacket(packet_type, _) => match packet_type {
                1 => k_nSteamNetworkingSend_UnreliableNoNagle,
                4 => k_nSteamNetworkingSend_UnreliableNoNagle,
                7 => k_nSteamNetworkingSend_Reliable,
                8 => k_nSteamNetworkingSend_Reliable,
                10 => k_nSteamNetworkingSend_Reliable,
                12 => k_nSteamNetworkingSend_UnreliableNoNagle,
                13 => k_nSteamNetworkingSend_UnreliableNoNagle,
                14 => k_nSteamNetworkingSend_UnreliableNoNagle,
                16 => k_nSteamNetworkingSend_UnreliableNoNagle,
                20 => k_nSteamNetworkingSend_Reliable,
                24 => k_nSteamNetworkingSend_UnreliableNoNagle,
                26 => k_nSteamNetworkingSend_Reliable,
                31 => k_nSteamNetworkingSend_Reliable,
                34 => k_nSteamNetworkingSend_Reliable,
                38 => k_nSteamNetworkingSend_Reliable,
                45 => k_nSteamNetworkingSend_Reliable,
                63 => k_nSteamNetworkingSend_Reliable,
                78 => k_nSteamNetworkingSend_Reliable,
                79 => k_nSteamNetworkingSend_Reliable,
                82 => k_nSteamNetworkingSend_Reliable,
                83 => k_nSteamNetworkingSend_Reliable,
                105 => k_nSteamNetworkingSend_Reliable,
                106 => k_nSteamNetworkingSend_Reliable,
                107 => k_nSteamNetworkingSend_Reliable,
                112 => k_nSteamNetworkingSend_UnreliableNoNagle,
                250 => k_nSteamNetworkingSend_Reliable,
                _ => k_nSteamNetworkingSend_Reliable,
            },

            #[cfg(feature = "armoredcore6")]
            Message::GamePacket(packet_type, _) => match packet_type {
                1 => k_nSteamNetworkingSend_UnreliableNoNagle,
                23 => k_nSteamNetworkingSend_UnreliableNoNagle,
                _ => k_nSteamNetworkingSend_Reliable,
            },
        }
    }
}

/// Represents the low-level transport used for sending and receiving messages.
pub trait MessageTransport {
    type TransportError: std::error::Error + 'static;

    /// Sends a singular message to a given remote.
    fn send(&self, remote: u64, message: &Message) -> Result<(), Self::TransportError>;

    /// Retrieves all messages from transport.
    fn receive(
        &self,
    ) -> Vec<Result<(u64, Result<Message, Self::TransportError>), Self::TransportError>>;

    /// Closes the transport.
    fn close(&self, remote: u64) -> Result<(), Self::TransportError>;
}

#[derive(Debug, Error)]
pub enum SteamMessageError {
    #[error("Bincode error: {0}")]
    Bincode(#[from] bincode::Error),

    #[error("Steam error: {0}")]
    SteamError(#[from] steamworks::SteamError),

    #[error("Passed networking identity was not a steam ID")]
    IdentityNotASteamId,
}

pub struct SteamMessageTransport {
    /// Determines the messages channel used for communication.
    messages_channel: i32,

    /// Holds the steam client.
    client: Client<ClientManager>,
}

impl SteamMessageTransport {
    pub fn new(messages_channel: i32, client: Client<ClientManager>) -> Self {
        Self {
            messages_channel,
            client,
        }
    }
}

impl MessageTransport for SteamMessageTransport {
    type TransportError = SteamMessageError;

    fn send(&self, remote: u64, message: &Message) -> Result<(), Self::TransportError> {
        let data = bincode::serialize(message)?;

        unsafe {
            SteamAPI_ISteamNetworkingMessages_SendMessageToUser(
                SteamAPI_SteamNetworkingMessages_SteamAPI_v002() as _,
                &networking_identity(remote),
                data.as_ptr() as _,
                data.len() as u32,
                message.send_flags() | k_nSteamNetworkingSend_AutoRestartBrokenSession,
                self.messages_channel,
            );
        }

        Ok(())
    }

    fn receive(
        &self,
    ) -> Vec<Result<(u64, Result<Message, Self::TransportError>), Self::TransportError>> {
        self.client
            .networking_messages()
            .receive_messages_on_channel(self.messages_channel as u32, PACKET_BATCH_SIZE)
            .iter()
            .map(|m| {
                let message =
                    bincode::deserialize::<Message>(m.data()).map_err(SteamMessageError::from);

                let steam_id = m
                    .identity_peer()
                    .steam_id()
                    .ok_or(SteamMessageError::IdentityNotASteamId)?;

                Ok((steam_id.raw(), message))
            })
            .collect()
    }

    fn close(&self, remote: u64) -> Result<(), Self::TransportError> {
        // Why the fuck isn't this in steamworks as an explicit fn?
        unsafe {
            let messages = SteamAPI_SteamNetworkingMessages_SteamAPI_v002();
            let identity = networking_identity(remote);
            SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser(messages, &identity as _);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crossbeam::queue::ArrayQueue;
    use thiserror::Error;

    use super::{Message, MessageTransport, PlayerNetworking};

    #[derive(Debug, Error)]
    enum MockMessageError {}

    #[derive(Debug)]
    struct MockMessageTransport {
        inbound: Vec<(u64, Message)>,
        outbound: ArrayQueue<(u64, Message)>,
    }

    impl MockMessageTransport {
        pub fn new(inbound: Vec<(u64, Message)>) -> Self {
            Self {
                inbound,
                outbound: ArrayQueue::new(0x10),
            }
        }
    }

    impl MessageTransport for MockMessageTransport {
        type TransportError = MockMessageError;

        fn send(&self, remote: u64, message: &super::Message) -> Result<(), Self::TransportError> {
            self.outbound.push((*remote, message.clone())).unwrap();
            Ok(())
        }

        fn receive(
            &self,
        ) -> Vec<Result<(u64, Result<Message, Self::TransportError>), Self::TransportError>>
        {
            self.inbound
                .iter()
                .map(|m| Ok((m.0, Ok(m.1.clone()))))
                .collect()
        }

        fn close(&self, _remote: u64) -> Result<(), Self::TransportError> {
            Ok(())
        }
    }

    #[test]
    /// Verify that messages from transport containing a game packet are dequeuable as game packets.
    fn can_read_incoming_game_packets() {
        let gaben = 76561197960287930;
        let johncena = 76561197963843357;

        let transport = MockMessageTransport::new(vec![
            (gaben, Message::GamePacket(0x12, vec![0x12])),
            (johncena, Message::GamePacket(0x08, vec![0x34])),
            (gaben, Message::GamePacket(0x12, vec![0x56])),
        ]);

        let networking = PlayerNetworking::new(transport);
        networking.update();

        // Retrieve the packets like the game would
        let first = networking
            .dequeue_game_packet(&gaben, 0x12)
            .expect("Session error")
            .expect("Did not receive game packet");
        assert_eq!(vec![0x12], first);

        let second = networking
            .dequeue_game_packet(&gaben, 0x12)
            .expect("Session error")
            .expect("Did not receive game packet");
        assert_eq!(vec![0x56], second);

        let third = networking
            .dequeue_game_packet(&johncena, 0x08)
            .expect("Session error")
            .expect("Did not receive game packet");
        assert_eq!(vec![0x34], third);
    }

    #[test]
    /// Attempts to verify that no reordering of the messages happens compared to how they came in
    /// from the transport.
    fn incoming_game_packet_order_is_consistent() {
        let gaben = 76561197960287930;

        let transport = MockMessageTransport::new(vec![
            (gaben, Message::GamePacket(0x12, vec![0x01])),
            (gaben, Message::GamePacket(0x12, vec![0x02])),
            (gaben, Message::GamePacket(0x12, vec![0x03])),
            (gaben, Message::GamePacket(0x12, vec![0x04])),
            (gaben, Message::GamePacket(0x12, vec![0x05])),
            (gaben, Message::GamePacket(0x12, vec![0x06])),
            (gaben, Message::GamePacket(0x12, vec![0x07])),
            (gaben, Message::GamePacket(0x12, vec![0x08])),
            (gaben, Message::GamePacket(0x12, vec![0x09])),
        ]);

        let networking = PlayerNetworking::new(transport);
        networking.update();

        assert_eq!(
            Some(vec![0x01]),
            networking.dequeue_game_packet(&gaben, 0x12).unwrap()
        );
        assert_eq!(
            Some(vec![0x02]),
            networking.dequeue_game_packet(&gaben, 0x12).unwrap()
        );
        assert_eq!(
            Some(vec![0x03]),
            networking.dequeue_game_packet(&gaben, 0x12).unwrap()
        );
        assert_eq!(
            Some(vec![0x04]),
            networking.dequeue_game_packet(&gaben, 0x12).unwrap()
        );
        assert_eq!(
            Some(vec![0x05]),
            networking.dequeue_game_packet(&gaben, 0x12).unwrap()
        );
        assert_eq!(
            Some(vec![0x06]),
            networking.dequeue_game_packet(&gaben, 0x12).unwrap()
        );
        assert_eq!(
            Some(vec![0x07]),
            networking.dequeue_game_packet(&gaben, 0x12).unwrap()
        );
        assert_eq!(
            Some(vec![0x08]),
            networking.dequeue_game_packet(&gaben, 0x12).unwrap()
        );
        assert_eq!(
            Some(vec![0x09]),
            networking.dequeue_game_packet(&gaben, 0x12).unwrap()
        );
    }

    #[test]
    /// Verify that sent messages are passed on to the transport
    fn send_calls_transport() {
        let gaben = 76561197960287930;

        let transport = MockMessageTransport::new(vec![]);
        let networking = PlayerNetworking::new(transport);

        networking
            .send_message(&gaben, &Message::GamePacket(0x12, vec![0x34]))
            .unwrap();

        let message = networking
            .transport
            .outbound
            .pop()
            .expect("Could not pop sent message");

        assert_eq!(gaben, message.0);
        assert_eq!(Message::GamePacket(0x12, vec![0x34]), message.1);
    }

    #[test]
    /// Verify that the game can no longer dequeue packets after a session has ended.
    fn disconnect_prevents_game_packet_dequeueing() {
        let gaben = 76561197960287930;

        let transport =
            MockMessageTransport::new(vec![(gaben, Message::GamePacket(0x12, vec![0x01]))]);

        let networking = PlayerNetworking::new(transport);
        networking.update();
        networking.remove_session(&gaben).unwrap();
        assert_eq!(None, networking.dequeue_game_packet(&gaben, 0x12).unwrap());
    }
}
