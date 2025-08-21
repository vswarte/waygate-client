use serde::{Deserialize, Serialize};
use steamworks_sys::{k_nSteamNetworkingSend_Reliable, k_nSteamNetworkingSend_ReliableNoNagle, k_nSteamNetworkingSend_UnreliableNoNagle};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Message {
    /// Low-level packet, normally wraps the game packets too but now just does session control.
    RawPacket(Vec<u8>),
    /// High-level packet used for stuff like syncing position, spawning bullets, etc.
    GamePacket(u8, u8, Vec<u8>),
}

impl Message {
    /// Determines the appropriate reliability and nagle layer properties for a given message.
    pub fn send_flags(&self) -> i32 {
        match self {
            Message::RawPacket(_) => k_nSteamNetworkingSend_Reliable,

            // TODO: figure out more packet types and determine appropriate send flags.
            #[cfg(feature = "eldenring")]
            Message::GamePacket(packet_type, flags, _) => match packet_type {
                // Player pos updates
                1 => k_nSteamNetworkingSend_UnreliableNoNagle,
                // NPC pos updates
                4 => k_nSteamNetworkingSend_UnreliableNoNagle,
                // World entry initial player data
                7 => k_nSteamNetworkingSend_Reliable,
                // Player data (levels, etc)
                8 => k_nSteamNetworkingSend_Reliable,
                // Requests a world sync
                10 => k_nSteamNetworkingSend_Reliable,
                // Set chr type
                11 => k_nSteamNetworkingSend_ReliableNoNagle,
                // Player equipment and armstyle
                12 => k_nSteamNetworkingSend_ReliableNoNagle,
                // Player weapon state
                13 => k_nSteamNetworkingSend_ReliableNoNagle,
                14 => k_nSteamNetworkingSend_UnreliableNoNagle,
                // Initial world sync
                16 => k_nSteamNetworkingSend_Reliable,
                // Hit
                20 => k_nSteamNetworkingSend_Reliable,
                // Player animation state sync
                24 => k_nSteamNetworkingSend_UnreliableNoNagle,
                // Set singular event flag
                26 => k_nSteamNetworkingSend_Reliable,
                // Mimic veil enter
                31 => k_nSteamNetworkingSend_Reliable,
                // Quickmatch world ready
                33 => k_nSteamNetworkingSend_Reliable,
                // "Volatile event flag"
                34 => k_nSteamNetworkingSend_Reliable,
                // Player SpEffect
                38 => k_nSteamNetworkingSend_ReliableNoNagle,
                // Kick remote player at boss end
                39 => k_nSteamNetworkingSend_Reliable,
                // Map item sync
                44 => k_nSteamNetworkingSend_Reliable,
                // Object act
                45 => k_nSteamNetworkingSend_Reliable,
                // NPC summon
                50 => k_nSteamNetworkingSend_Reliable,
                // NPC leave
                51 => k_nSteamNetworkingSend_Reliable,
                // Initial SpEffect sync
                60 => k_nSteamNetworkingSend_Reliable,
                // Player speffect list update
                61 => k_nSteamNetworkingSend_ReliableNoNagle,
                // Bullet hit sync
                62 => k_nSteamNetworkingSend_ReliableNoNagle,
                // Bullet spawn
                63 => k_nSteamNetworkingSend_ReliableNoNagle,
                // Enemy kill sync
                69 => k_nSteamNetworkingSend_Reliable,
                // Block check result
                73 => k_nSteamNetworkingSend_Reliable,
                // Spirit ash spawn
                78 => k_nSteamNetworkingSend_Reliable,
                // Spirit ash despawn
                79 => k_nSteamNetworkingSend_Reliable,
                // World area weather sync
                82 => k_nSteamNetworkingSend_Reliable,
                // World area time sync
                83 => k_nSteamNetworkingSend_Reliable,
                // Request world area weather and time sync 
                84 => k_nSteamNetworkingSend_Reliable,
                // Multiplay start area ID
                90 => k_nSteamNetworkingSend_Reliable,
                // Multiplay area bounds warp character toggle
                96 => k_nSteamNetworkingSend_Reliable,
                // Rebreakin (phantom bloody finger teleport)
                101 => k_nSteamNetworkingSend_Reliable,
                // Request EAC user info 
                105 => k_nSteamNetworkingSend_Reliable,
                // EAC user info
                106 => k_nSteamNetworkingSend_Reliable,
                // EAC heartbeat
                107 => k_nSteamNetworkingSend_Reliable,
                // NPC updates health
                112 => k_nSteamNetworkingSend_Reliable,
                // Pseudo invasion host enter
                117 => k_nSteamNetworkingSend_Reliable,
                // Pseudo invasion client ready
                118 => k_nSteamNetworkingSend_Reliable,
                // Session control
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
