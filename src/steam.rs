use std::{
    ffi::c_void,
    ptr::copy_nonoverlapping,
    sync::{
        mpsc::{Receiver, Sender},
        Mutex, OnceLock,
    },
};

use crate::p2p::message::Message;
use retour::static_detour;
use steamworks_sys::{
    EFriendRelationship, ESteamNetworkingIdentityType, P2PSessionState_t, SNetListenSocket_t,
    SNetSocket_t, SteamAPI_ISteamFriends_GetFriendRelationship,
    SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser,
    SteamAPI_ISteamNetworkingMessages_SendMessageToUser, SteamAPI_ISteamUser_GetAuthSessionTicket,
    SteamAPI_ISteamUser_GetSteamID, SteamAPI_RegisterCallback, SteamAPI_SteamFriends_v017,
    SteamAPI_SteamNetworkingIdentity_Clear, SteamAPI_SteamNetworkingIdentity_SetSteamID,
    SteamAPI_SteamNetworkingMessages_SteamAPI_v002, SteamAPI_SteamNetworking_v006,
    SteamAPI_SteamUser_v021, SteamNetworkingIdentity, SteamNetworkingIdentity__bindgen_ty_2,
};
use vtable_rs::{vtable, VPtr};
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

/// Returns true if the steam ID is on the local users block list.
pub fn is_blocked(steam_id: u64) -> bool {
    let friends = unsafe { SteamAPI_SteamFriends_v017() };
    let relationship = unsafe { SteamAPI_ISteamFriends_GetFriendRelationship(friends, steam_id) };

    relationship == EFriendRelationship::k_EFriendRelationshipIgnored
        || relationship == EFriendRelationship::k_EFriendRelationshipIgnoredFriend
}

/// Retrieve an auth session ticket for the local user.
pub fn get_auth_ticket() -> (u64, Vec<u8>) {
    unsafe {
        let user = SteamAPI_SteamUser_v021();

        let steam_id = SteamAPI_ISteamUser_GetSteamID(user);
        let mut ticket_buffer = vec![0; 1024];
        let mut ticket_len = 0;
        let _auth_ticket = SteamAPI_ISteamUser_GetAuthSessionTicket(
            user,
            ticket_buffer.as_mut_ptr() as *mut _,
            1024,
            &mut ticket_len,
        );
        (steam_id, ticket_buffer)
    }
}

/// Send message to remote using ISteamNetworking.
pub fn send_message_to_user(remote: u64, data: &[u8], send_flags: i32, channel: i32) {
    unsafe {
        SteamAPI_ISteamNetworkingMessages_SendMessageToUser(
            SteamAPI_SteamNetworkingMessages_SteamAPI_v002() as _,
            &networking_identity(remote),
            data.as_ptr() as _,
            data.len() as u32,
            send_flags,
            channel,
        );
    }
}

/// Close messaging session with user using ISteamNetworking.
pub fn close_session_with_user(remote: u64) {
    unsafe {
        SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser(
            SteamAPI_SteamNetworkingMessages_SteamAPI_v002(),
            &networking_identity(remote) as _,
        );
    }
}

pub fn networking_identity(steam_id: u64) -> SteamNetworkingIdentity {
    let mut id = SteamNetworkingIdentity {
        m_eType: ESteamNetworkingIdentityType::k_ESteamNetworkingIdentityType_Invalid,
        m_cbSize: 0,
        __bindgen_anon_1: SteamNetworkingIdentity__bindgen_ty_2 { m_steamID64: 0 },
    };

    unsafe {
        SteamAPI_SteamNetworkingIdentity_Clear(&mut id);
        SteamAPI_SteamNetworkingIdentity_SetSteamID(&mut id, steam_id);
    };

    id
}

static_detour! {
    static STEAM_SEND_P2P_PACKET: extern "C" fn(
        *const SteamNetworking006,
        u64,
        *const u8,
        u32,
        i32,
        i32
    ) -> bool;

    static STEAM_READ_P2P_PACKET: extern "C" fn(
        *const SteamNetworking006,
        *mut u8,
        u32,
        *mut u32,
        *mut u64,
        i32
    ) -> bool;

    static STEAM_ACCEPT_P2P_SESSION_WITH_USER: extern "C" fn(*const SteamNetworking006, u64) -> bool;

    static STEAM_CLOSE_P2P_CHANNEL_WITH_USER: extern "C" fn(*const SteamNetworking006, u64, i32) -> bool;
}

pub unsafe fn hook(
    send_tx: Sender<(u64, Message)>,
    receive_rx: Receiver<(u64, Vec<u8>)>,
    close_tx: Sender<u64>,
) {
    SEND_P2P_CHANNEL.set(send_tx).unwrap();
    READ_P2P_CHANNEL.set(Mutex::new(receive_rx)).unwrap();
    CLOSE_P2P_CHANNEL.set(close_tx).unwrap();

    let networking = SteamAPI_SteamNetworking_v006() as *mut SteamNetworking006;
    let networking_vmt = networking.as_mut().unwrap().vmt.as_mut().unwrap();

    let mut protect = PAGE_PROTECTION_FLAGS::default();
    VirtualProtect(
        networking_vmt as *const SteamNetworking006Vmt as _,
        0x100,
        PAGE_EXECUTE_READWRITE,
        &mut protect as _,
    );
    networking_vmt.send_p2p_packet = send_p2p_packet_hook;
    networking_vmt.read_p2p_packet = read_p2p_packet_hook;
    networking_vmt.accept_p2p_session_with_user = accept_p2p_session_with_user_hook;
    networking_vmt.close_p2p_channel_with_user = close_p2p_channel_with_user_hook;
    VirtualProtect(
        networking_vmt as *const SteamNetworking006Vmt as _,
        0x100,
        protect,
        std::ptr::null_mut(),
    );
}

static READ_P2P_CHANNEL: OnceLock<Mutex<Receiver<(u64, Vec<u8>)>>> = OnceLock::new();
static SEND_P2P_CHANNEL: OnceLock<Sender<(u64, Message)>> = OnceLock::new();
static CLOSE_P2P_CHANNEL: OnceLock<Sender<u64>> = OnceLock::new();

extern "C" fn send_p2p_packet_hook(
    _networking: *const SteamNetworking006,
    remote: u64,
    data: *const u8,
    data_size: u32,
    _send_type: i32,
    channel: i32,
) -> bool {
    let size = data_size as usize;
    let data = unsafe { std::slice::from_raw_parts(data, size) };

    SEND_P2P_CHANNEL
        .get()
        .unwrap()
        .send((remote, Message::RawPacket(data.to_vec())))
        .expect("Could not send raw p2p packet onto channel.");

    true
}

extern "C" fn read_p2p_packet_hook(
    _networking: *const SteamNetworking006,
    data_out: *mut u8,
    alloc_size: u32,
    size_out: *mut u32,
    remote_out: *mut u64,
    _channel: i32,
) -> bool {
    let Ok((remote, data)) = READ_P2P_CHANNEL.get().unwrap().lock().unwrap().try_recv() else {
        return false;
    };

    // SAFETY: Per steamworks SDK docs we're guaranteed to get valid pointers for the remote out
    // and the data.
    unsafe {
        *size_out = data.len() as u32;
        *remote_out = remote;

        copy_nonoverlapping(
            data.as_ptr(),
            data_out,
            // SAFETY: We truncate the copy to the allocation size. This prevents overflows and is
            // how the steamworks SDK describes how the original function behaves.
            usize::min(data.len(), alloc_size as usize),
        );
    }

    true
}

extern "C" fn accept_p2p_session_with_user_hook(
    _networking: *const SteamNetworking006,
    remote: u64,
) -> bool {
    tracing::warn!("ISteamNetworking::AcceptP2PSessionWithUser. remote = {remote}.");
    true
}

extern "C" fn close_p2p_channel_with_user_hook(
    _networking: *const SteamNetworking006,
    remote: u64,
    channel: i32,
) -> bool {
    tracing::info!(
        "ISteamNetworking::CloseP2PChannelWithUser. remote = {remote}. channel = {channel}."
    );
    if let Err(e) = CLOSE_P2P_CHANNEL
        .get()
        .expect("CLOSE_P2P_CHANNEL not initialized")
        .send(remote) {
        tracing::error!("Could not send disconnect details down close channel");
    }
    true
}

/// Model VMT so we can swap stuff
#[repr(C)]
pub struct SteamNetworking006Vmt {
    pub send_p2p_packet: extern "C" fn(
        *const SteamNetworking006,
        remote: u64,
        data: *const u8,
        data_size: u32,
        send_type: i32,
        channel: i32,
    ) -> bool,

    pub is_p2p_packet_available:
        extern "C" fn(*const SteamNetworking006, size_out: *mut u32, channel: u32) -> bool,

    pub read_p2p_packet: extern "C" fn(
        *const SteamNetworking006,
        data_out: *mut u8,
        alloc_size: u32,
        size_out: *mut u32,
        remote_out: *mut u64,
        channel: i32,
    ) -> bool,

    pub accept_p2p_session_with_user: extern "C" fn(*const SteamNetworking006, remote: u64) -> bool,

    pub close_p2p_session_with_user: extern "C" fn(*const SteamNetworking006, remote: u64) -> bool,

    pub close_p2p_channel_with_user:
        extern "C" fn(*const SteamNetworking006, remote: u64, channel: i32) -> bool,

    pub get_p2p_session_state: extern "C" fn(
        *const SteamNetworking006,
        remote: u64,
        result: *mut P2PSessionState_t,
    ) -> bool,

    pub allow_p2p_packet_relay: extern "C" fn(*const SteamNetworking006, allow: bool) -> bool,

    pub create_listen_socket: extern "C" fn(
        *const SteamNetworking006,
        virtual_port: i32,
        ip: u32,
        port: u16,
        allow_use_of_packet_relay: bool,
    ) -> SNetListenSocket_t,

    pub create_p2p_connection_socket: extern "C" fn(
        *const SteamNetworking006,
        remote: u64,
        virtual_port: i32,
        timeout: i32,
        allow_use_of_packet_relay: bool,
    ) -> SNetSocket_t,

    pub create_connection_socket:
        extern "C" fn(*const SteamNetworking006, ip: u32, port: u16, timeout: i32) -> SNetSocket_t,

    pub destroy_socket: extern "C" fn(
        *const SteamNetworking006,
        socket: SNetSocket_t,
        notify_remove_end: bool,
    ) -> bool,

    pub destroy_listen_socket: extern "C" fn(
        *const SteamNetworking006,
        socket: SNetListenSocket_t,
        notify_remove_end: bool,
    ) -> bool,

    pub send_data_on_socket: extern "C" fn(
        *const SteamNetworking006,
        socket: SNetSocket_t,
        data: *const u8,
        length: u32,
        reliable: bool,
    ) -> bool,

    pub is_data_available_on_socket:
        extern "C" fn(*const SteamNetworking006, socket: SNetSocket_t, length: *mut u32) -> bool,

    pub retrieve_data_from_socket: extern "C" fn(
        *const SteamNetworking006,
        socket: SNetSocket_t,
        data: *mut u8,
        capacity: u32,
        length: *mut u32,
    ) -> bool,

    pub is_data_available: extern "C" fn(
        *const SteamNetworking006,
        listen_socket: SNetListenSocket_t,
        length: *mut u32,
        socket: *mut SNetSocket_t,
    ) -> bool,

    pub retrieve_data: extern "C" fn(
        *const SteamNetworking006,
        listen_socket: SNetListenSocket_t,
        data: *mut u8,
        capacity: u32,
        length: *mut u32,
        socket: *mut SNetSocket_t,
    ) -> bool,

    pub get_socket_info: extern "C" fn(
        *const SteamNetworking006,
        socket: SNetSocket_t,
        remote: *const u64,
        status: *mut i32,
        ip: *mut u32,
        port: *mut u16,
    ) -> bool,

    pub get_listen_socket_info: extern "C" fn(
        *const SteamNetworking006,
        socket: SNetListenSocket_t,
        ip: *mut u32,
        port: *mut u16,
    ) -> bool,

    pub get_socket_connection_type:
        extern "C" fn(*const SteamNetworking006, socket: SNetSocket_t) -> u32,
}

#[repr(C)]
pub struct SteamNetworking006 {
    pub vmt: *mut SteamNetworking006Vmt,
}

/// Some code to turn rust closures into steam callbacks.
#[vtable]
pub trait SteamCallbackVmt {
    fn run(&mut self, data: *const c_void);

    fn run_other(&mut self, data: *const c_void, p3: u64, p4: bool);

    fn get_callback_size_bytes(&mut self) -> u32;
}

#[repr(C)]
pub struct SteamCallback<D>
where
    D: Sized + 'static,
{
    vftable: VPtr<dyn SteamCallbackVmt, Self>,
    closure: Box<dyn FnMut(&D)>,
}

impl<D> SteamCallbackVmt for SteamCallback<D>
where
    D: Sized + 'static,
{
    extern "C" fn run(&mut self, data: *const c_void) {
        unsafe {
            (self.closure)(&*(data as *const D));
        }
    }

    extern "C" fn run_other(&mut self, data: *const c_void, _p3: u64, _p4: bool) {
        unsafe {
            (self.closure)(&*(data as *const D));
        }
    }

    extern "C" fn get_callback_size_bytes(&mut self) -> u32 {
        std::mem::size_of::<D>() as u32
    }
}

impl<F, D> From<F> for SteamCallback<D>
where
    F: FnMut(&D) + 'static + Send,
    D: Sized + 'static,
{
    fn from(value: F) -> Self {
        Self {
            vftable: Default::default(),
            closure: Box::new(value),
        }
    }
}

pub fn register_callback<D, F>(callback: i32, f: F)
where
    D: Sized + 'static,
    F: FnMut(&D) + 'static + Send,
{
    let callback_fn: &mut SteamCallback<D> = {
        let tmp: SteamCallback<D> = f.into();
        Box::leak(Box::new(tmp))
    };

    unsafe {
        SteamAPI_RegisterCallback(callback_fn as *mut SteamCallback<D> as _, callback);
    }
}
