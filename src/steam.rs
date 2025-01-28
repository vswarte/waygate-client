use std::{ffi::c_void, mem::transmute};

use retour::static_detour;
use steamworks_sys::{
    EFriendRelationship, ESteamNetworkingIdentityType,
    SteamAPI_ISteamFriends_GetFriendRelationship, SteamAPI_ISteamUser_GetAuthSessionTicket,
    SteamAPI_ISteamUser_GetSteamID, SteamAPI_RegisterCallback, SteamAPI_SteamFriends_v017,
    SteamAPI_SteamNetworkingIdentity_Clear, SteamAPI_SteamNetworkingIdentity_SetSteamID,
    SteamAPI_SteamNetworking_v006, SteamAPI_SteamUser_v021, SteamNetworkingIdentity,
    SteamNetworkingIdentity__bindgen_ty_2,
};
use vtable_rs::{vtable, VPtr};
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

use crate::{p2p::Message, PLAYER_NETWORKING};

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

// Is the specified account blocked?
pub fn is_blocked(steam_id: u64) -> bool {
    let friends = unsafe { SteamAPI_SteamFriends_v017() };
    let relationship = unsafe { SteamAPI_ISteamFriends_GetFriendRelationship(friends, steam_id) };

    relationship == EFriendRelationship::k_EFriendRelationshipIgnored
        || relationship == EFriendRelationship::k_EFriendRelationshipIgnoredFriend
}

pub unsafe fn set_hooks() {
    let networking = SteamAPI_SteamNetworking_v006() as *mut SteamNetworking006;
    let vmt = networking.as_mut().unwrap().vmt.as_mut().unwrap();

    let mut protect = PAGE_PROTECTION_FLAGS::default();
    VirtualProtect(
        vmt as *const SteamNetworking006Vmt as _,
        0x100,
        PAGE_EXECUTE_READWRITE,
        &mut protect as _,
    );

    vmt.send_p2p_packet = send_p2p_packet_hook;
    vmt.read_p2p_packet = read_p2p_packet_hook;
    vmt.accept_p2p_session_with_user = accept_p2p_session_with_user_hook;
    vmt.close_p2p_session_with_user = close_p2p_channel_with_user_hook;

    VirtualProtect(
        vmt as *const SteamNetworking006Vmt as _,
        0x100,
        protect,
        std::ptr::null_mut(),
    );
}

pub unsafe fn get_auth_ticket() -> (u64, Vec<u8>) {
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

extern "C" fn send_p2p_packet_hook(
    _networking: *const SteamNetworking006,
    remote: u64,
    data: *const u8,
    data_size: u32,
    _send_type: i32,
    channel: i32,
) -> bool {
    {
        let size = data_size as usize;
        let data = unsafe { std::slice::from_raw_parts(data, size) };

        tracing::debug!("SendP2PPacket. channel = {channel}. size = {size}. remote = {remote}. data = {data:?}.");
    }

    let data = unsafe { std::slice::from_raw_parts(data, data_size as usize) };
    if let Err(err) = PLAYER_NETWORKING
        .get()
        .unwrap()
        .send_message(remote, &Message::RawPacket(channel, data.to_vec()))
    {
        tracing::error!("Could not send raw packet to {remote}. {err}");
        false
    } else {
        true
    }
}

extern "C" fn read_p2p_packet_hook(
    _networking: *const SteamNetworking006,
    data_out: *mut u8,
    data_alloc_size: u32,
    data_size_out: *mut u32,
    remote_out: *mut u64,
    channel: i32,
) -> bool {
    let Some(packet) = PLAYER_NETWORKING.get().unwrap().dequeue_raw_packet() else {
        return false;
    };

    tracing::debug!(
        "ReadP2PPacket. channel = {channel}. size = {}. remote = {}",
        packet.data.len(),
        packet.sender
    );

    unsafe {
        if (data_alloc_size as usize) < packet.data.len() {
            return false;
        }

        *data_size_out = packet.data.len() as u32;
        *remote_out = transmute(packet.sender);

        std::ptr::copy_nonoverlapping(packet.data.as_ptr(), data_out, packet.data.len());
    }

    true
}

extern "C" fn accept_p2p_session_with_user_hook(
    _networking: *const SteamNetworking006,
    _remote: u64,
) -> bool {
    tracing::warn!("AcceptP2PSessionWithUser called. This means that not all messaging is happening using the messages API");
    false
}

extern "C" fn close_p2p_channel_with_user_hook(
    _networking: *const SteamNetworking006,
    remote: u64,
    // channel: i32,
) -> bool {
    tracing::info!("CloseP2PChannelWithUser. remote = {remote}");

    PLAYER_NETWORKING
        .get()
        .unwrap()
        .remove_session(remote)
        .is_ok()
}

// #[vtable]
// pub trait SteamNetworking006Vmt {
//     // virtual unknown_ret SendP2PPacket(CSteamID, void const*, unsigned int, EP2PSend, int) = 0;
//     // virtual unknown_ret IsP2PPacketAvailable(unsigned int*, int) = 0;
//     // virtual unknown_ret ReadP2PPacket(void*, unsigned int, unsigned int*, CSteamID*, int) = 0;
//     // virtual unknown_ret AcceptP2PSessionWithUser(CSteamID) = 0;
//     // virtual unknown_ret CloseP2PSessionWithUser(CSteamID) = 0;
//     // virtual unknown_ret CloseP2PChannelWithUser(CSteamID, int) = 0;
//
//     fn send_p2p_packet(
//         &self,
//         remote: CSteamID,
//         data: *const u8,
//         data_size: u32,
//         send_type: EP2PSend,
//         channel: i32,
//     ) -> bool;
//
//     fn is_p2p_packet_available(&self, size_out: *mut u32, channel: u32) -> bool;
//
//     fn read_p2p_packet(
//         &self,
//         data_out: *mut u8,
//         data_alloc_size: u32,
//         data_size_out: *mut u32,
//         remote_out: *const CSteamID,
//         channel: i32,
//     ) -> bool;
//
//     fn accept_p2p_session_with_user(&self, remote: CSteamID) -> bool;
//
//     fn close_p2p_session_with_user(&self, remote: CSteamID) -> bool;
//
//     fn close_p2p_channel_with_user(&self, remote: CSteamID, channel: i32) -> bool;
//
//     // virtual unknown_ret GetP2PSessionState(CSteamID, P2PSessionState_t*) = 0;
//     // virtual unknown_ret AllowP2PPacketRelay(bool) = 0;
//     // virtual unknown_ret CreateListenSocket(int, SteamIPAddress_t, unsigned short, bool) = 0;
//     // virtual unknown_ret CreateP2PConnectionSocket(CSteamID, int, int, bool) = 0;
//     // virtual unknown_ret CreateConnectionSocket(SteamIPAddress_t, unsigned short, int) = 0;
//     // virtual unknown_ret DestroySocket(unsigned int, bool) = 0;
//     // virtual unknown_ret DestroyListenSocket(unsigned int, bool) = 0;
//     // virtual unknown_ret SendDataOnSocket(unsigned int, void*, unsigned int, bool) = 0;
//     // virtual unknown_ret IsDataAvailableOnSocket(unsigned int, unsigned int*) = 0;
//     // virtual unknown_ret RetrieveDataFromSocket(unsigned int, void*, unsigned int, unsigned int*) = 0;
//     // virtual unknown_ret IsDataAvailable(unsigned int, unsigned int*, unsigned int*) = 0;
//     // virtual unknown_ret RetrieveData(unsigned int, void*, unsigned int, unsigned int*, unsigned int*) = 0;
//     // virtual unknown_ret GetSocketInfo(unsigned int, CSteamID*, int*, SteamIPAddress_t*, unsigned short*) = 0;
//     // virtual unknown_ret GetListenSocketInfo(unsigned int, SteamIPAddress_t*, unsigned short*) = 0;
//     // virtual unknown_ret GetSocketConnectionType(unsigned int) = 0;
//     // virtual unknown_ret GetMaxPacketSize(unsigned int) = 0;
// }

#[repr(C)]
#[derive(Debug)]
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
        data_alloc_size: u32,
        data_size_out: *mut u32,
        remote_out: *mut u64,
        channel: i32,
    ) -> bool,

    pub accept_p2p_session_with_user: extern "C" fn(*const SteamNetworking006, remote: u64) -> bool,

    pub close_p2p_session_with_user: extern "C" fn(*const SteamNetworking006, remote: u64) -> bool,

    pub close_p2p_channel_with_user:
        extern "C" fn(*const SteamNetworking006, remote: u64, channel: i32) -> bool,
    // virtual unknown_ret GetP2PSessionState(CSteamID, P2PSessionState_t*) = 0;
    // virtual unknown_ret AllowP2PPacketRelay(bool) = 0;
    // virtual unknown_ret CreateListenSocket(int, SteamIPAddress_t, unsigned short, bool) = 0;
    // virtual unknown_ret CreateP2PConnectionSocket(CSteamID, int, int, bool) = 0;
    // virtual unknown_ret CreateConnectionSocket(SteamIPAddress_t, unsigned short, int) = 0;
    // virtual unknown_ret DestroySocket(unsigned int, bool) = 0;
    // virtual unknown_ret DestroyListenSocket(unsigned int, bool) = 0;
    // virtual unknown_ret SendDataOnSocket(unsigned int, void*, unsigned int, bool) = 0;
    // virtual unknown_ret IsDataAvailableOnSocket(unsigned int, unsigned int*) = 0;
    // virtual unknown_ret RetrieveDataFromSocket(unsigned int, void*, unsigned int, unsigned int*) = 0;
    // virtual unknown_ret IsDataAvailable(unsigned int, unsigned int*, unsigned int*) = 0;
    // virtual unknown_ret RetrieveData(unsigned int, void*, unsigned int, unsigned int*, unsigned int*) = 0;
    // virtual unknown_ret GetSocketInfo(unsigned int, CSteamID*, int*, SteamIPAddress_t*, unsigned short*) = 0;
    // virtual unknown_ret GetListenSocketInfo(unsigned int, SteamIPAddress_t*, unsigned short*) = 0;
    // virtual unknown_ret GetSocketConnectionType(unsigned int) = 0;
    // virtual unknown_ret GetMaxPacketSize(unsigned int) = 0;
}

#[repr(C)]
pub struct SteamNetworking006 {
    pub vmt: *mut SteamNetworking006Vmt,
}

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
