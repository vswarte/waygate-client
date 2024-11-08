use steamworks_sys::{SteamAPI_ISteamUser_GetAuthSessionTicket, SteamAPI_ISteamUser_GetSteamID, SteamAPI_SteamUser_v021};

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
