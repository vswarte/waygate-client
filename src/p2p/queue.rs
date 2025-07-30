use std::collections::VecDeque;

use dashmap::DashMap;

use super::PACKET_QUEUE_INITIAL_CAPACITY;

pub struct PlayerGamePacketQueue([VecDeque<(u8, Vec<u8>)>; u8::MAX as usize]);

impl Default for PlayerGamePacketQueue {
    fn default() -> Self {
        Self(std::array::from_fn(|_| {
            VecDeque::with_capacity(PACKET_QUEUE_INITIAL_CAPACITY)
        }))
    }
}

#[derive(Default)]
pub struct GamePacketQueue {
    inbound: DashMap<u64, PlayerGamePacketQueue>,
}

impl GamePacketQueue {
    pub fn push(&self, remote: u64, packet_type: u8, flags: u8, data: Vec<u8>) {
        self.inbound.entry(remote).or_default().0[packet_type as usize].push_back((flags, data))
    }

    pub fn pop(&self, remote: u64, packet_type: u8) -> Option<(u8, Vec<u8>)> {
        self.inbound.entry(remote).or_default().0[packet_type as usize].pop_front()
    }

    pub fn remove(&self, remote: u64) -> Option<PlayerGamePacketQueue> {
        self.inbound.remove(&remote).map(|entry| entry.1)
    }
}
