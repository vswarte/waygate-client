use std::ffi::CString;

use windows::core::{HSTRING, PCSTR, PCWSTR};
use windows::w;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_FLAGS};

use retour::static_detour;

pub(crate) fn resolve_eos_symbol(name: impl AsRef<str> + std::fmt::Display) -> usize {
    unsafe {
        let module_handle = GetModuleHandleW(w!("eossdk-win64-shipping.dll")).unwrap();

        let symbol = CString::new(name.as_ref()).unwrap();
        GetProcAddress(module_handle, PCSTR::from_raw(symbol.as_ptr() as *const u8))
            .unwrap() as usize
    }
}

mod eos;
mod hook;
mod peer;

static_detour! {
    static HOOK_EOS_ANTICHEATCLIENT_ADDNOTIFYMESSAGETOPEER: fn() -> usize;
    static HOOK_EOS_ANTICHEATCLIENT_ADDNOTIFYPEERACTIONREQUIRED: fn() -> usize;
    static HOOK_EOS_ANTICHEATCLIENT_ADDNOTIFYPEERAUTHSTATUSCHANGED: fn(usize, usize, usize, usize) -> usize;
    static HOOK_EOS_ANTICHEATCLIENT_BEGINSESSION: fn() -> eos::EOS_EResult;
    static HOOK_EOS_ANTICHEATCLIENT_ENDSESSION: fn() -> eos::EOS_EResult;
    static HOOK_EOS_ANTICHEATCLIENT_POLLSTATUS: fn() -> eos::EOS_EResult;
    static HOOK_EOS_ANTICHEATCLIENT_RECEIVEMESSAGEFROMPEER: fn() -> eos::EOS_EResult;
    static HOOK_EOS_ANTICHEATCLIENT_REGISTERPEER: fn(usize, *const eos::EOS_AntiCheatClient_RegisterPeerOptions) -> eos::EOS_EResult;
    static HOOK_EOS_ANTICHEATCLIENT_REMOVENOTIFYPEERACTIONREQUIRED: fn();
    static HOOK_EOS_ANTICHEATCLIENT_REMOVENOTIFYPEERAUTHSTATUSCHANGED: fn();
    static HOOK_EOS_ANTICHEATCLIENT_UNREGISTERPEER: fn() -> eos::EOS_EResult;

    static HOOK_EOS_CONNECT_ADDNOTIFYAUTHEXPIRATION: fn() -> usize;
    static HOOK_EOS_CONNECT_ADDNOTIFYLOGINSTATUSCHANGED: fn() -> usize;
    static HOOK_EOS_CONNECT_CREATEUSER: fn();
    static HOOK_EOS_CONNECT_GETLOGINSTATUS: fn() -> usize;
    static HOOK_EOS_CONNECT_LOGIN: fn(usize, usize, usize, usize);
    static HOOK_EOS_CONNECT_REMOVENOTIFYAUTHEXPIRATION: fn();
    static HOOK_EOS_CONNECT_REMOVENOTIFYLOGINSTATUSCHANGED: fn();

    static HOOK_EOS_INITIALIZE: fn() -> eos::EOS_EResult;

    static HOOK_EOS_LOGGING_SETCALLBACK: fn() -> eos::EOS_EResult;
    static HOOK_EOS_LOGGING_SETLOGLEVEL: fn() -> eos::EOS_EResult;

    static HOOK_EOS_PLATFORM_CREATE: fn() -> usize;
    static HOOK_EOS_PLATFORM_GETANTICHEATCLIENTINTERFACE: fn() -> usize;
    static HOOK_EOS_PLATFORM_GETCONNECTINTERFACE: fn() -> usize;
    static HOOK_EOS_PLATFORM_GETREPORTSINTERFACE: fn() -> usize;
    static HOOK_EOS_PLATFORM_RELEASE: fn();
    static HOOK_EOS_PLATFORM_TICK: fn();

    static HOOK_EOS_PRODUCTUSERID_FROMSTRING: fn() -> usize;
    static HOOK_EOS_PRODUCTUSERID_ISVALID: fn() -> bool;
    static HOOK_EOS_PRODUCTUSERID_TOSTRING: fn(usize, usize, usize) -> eos::EOS_EResult;

    static HOOK_EOS_REPORTS_SENDPLAYERBEHAVIORREPORT: fn(usize, usize, usize, usize);

    static HOOK_EOS_SHUTDOWN: fn() -> eos::EOS_EResult;
}

pub unsafe fn hook() {
    load_eos_dll();

    hook::set_result_success_hook("EOS_Initialize", &HOOK_EOS_INITIALIZE);
    hook::set_result_success_hook("EOS_Shutdown", &HOOK_EOS_SHUTDOWN);

    hook::set_true_hook("EOS_ProductUserId_IsValid", &HOOK_EOS_PRODUCTUSERID_ISVALID);
    hook::set_deadbeef_hook(
        "EOS_ProductUserId_FromString",
        &HOOK_EOS_PRODUCTUSERID_FROMSTRING,
    );
    hook::set_productuserid_to_string_hook(
        "EOS_ProductUserId_ToString",
        &HOOK_EOS_PRODUCTUSERID_TOSTRING,
    );

    hook::set_connect_login_hook("EOS_Connect_Login", &HOOK_EOS_CONNECT_LOGIN);
    hook::set_deadbeef_hook(
        "EOS_Connect_AddNotifyAuthExpiration",
        &HOOK_EOS_CONNECT_ADDNOTIFYAUTHEXPIRATION,
    );
    hook::set_deadbeef_hook(
        "EOS_Connect_AddNotifyLoginStatusChanged",
        &HOOK_EOS_CONNECT_ADDNOTIFYLOGINSTATUSCHANGED,
    );
    hook::set_void_hook("EOS_Connect_CreateUser", &HOOK_EOS_CONNECT_CREATEUSER);
    hook::set_void_hook(
        "EOS_Connect_RemoveNotifyAuthExpiration",
        &HOOK_EOS_CONNECT_REMOVENOTIFYAUTHEXPIRATION,
    );
    hook::set_void_hook(
        "EOS_Connect_RemoveNotifyLoginStatusChanged",
        &HOOK_EOS_CONNECT_REMOVENOTIFYLOGINSTATUSCHANGED,
    );
    hook::set_loginstatus_loggedin_hook(
        "EOS_Connect_GetLoginStatus",
        &HOOK_EOS_CONNECT_GETLOGINSTATUS,
    );

    hook::set_deadbeef_hook("EOS_Platform_Create", &HOOK_EOS_PLATFORM_CREATE);
    hook::set_deadbeef_hook(
        "EOS_Platform_GetAntiCheatClientInterface",
        &HOOK_EOS_PLATFORM_GETANTICHEATCLIENTINTERFACE,
    );
    hook::set_deadbeef_hook(
        "EOS_Platform_GetConnectInterface",
        &HOOK_EOS_PLATFORM_GETCONNECTINTERFACE,
    );
    hook::set_deadbeef_hook(
        "EOS_Platform_GetReportsInterface",
        &HOOK_EOS_PLATFORM_GETREPORTSINTERFACE,
    );
    hook::set_void_hook("EOS_Platform_Tick", &HOOK_EOS_PLATFORM_TICK);
    hook::set_void_hook("EOS_Platform_Release", &HOOK_EOS_PLATFORM_RELEASE);

    hook::set_result_success_hook("EOS_Logging_SetCallback", &HOOK_EOS_LOGGING_SETCALLBACK);
    hook::set_result_success_hook("EOS_Logging_SetLogLevel", &HOOK_EOS_LOGGING_SETLOGLEVEL);

    hook::set_deadbeef_hook(
        "EOS_AntiCheatClient_AddNotifyMessageToPeer",
        &HOOK_EOS_ANTICHEATCLIENT_ADDNOTIFYMESSAGETOPEER,
    );
    hook::set_deadbeef_hook(
        "EOS_AntiCheatClient_AddNotifyPeerActionRequired",
        &HOOK_EOS_ANTICHEATCLIENT_ADDNOTIFYPEERACTIONREQUIRED,
    );
    hook::set_result_success_hook(
        "EOS_AntiCheatClient_BeginSession",
        &HOOK_EOS_ANTICHEATCLIENT_BEGINSESSION,
    );
    hook::set_result_success_hook(
        "EOS_AntiCheatClient_EndSession",
        &HOOK_EOS_ANTICHEATCLIENT_ENDSESSION,
    );
    hook::set_result_success_hook(
        "EOS_AntiCheatClient_ReceiveMessageFromPeer",
        &HOOK_EOS_ANTICHEATCLIENT_RECEIVEMESSAGEFROMPEER,
    );
    hook::set_void_hook(
        "EOS_AntiCheatClient_RemoveNotifyPeerActionRequired",
        &HOOK_EOS_ANTICHEATCLIENT_REMOVENOTIFYPEERACTIONREQUIRED,
    );
    hook::set_void_hook(
        "EOS_AntiCheatClient_RemoveNotifyPeerAuthStatusChanged",
        &HOOK_EOS_ANTICHEATCLIENT_REMOVENOTIFYPEERAUTHSTATUSCHANGED,
    );
    hook::set_result_success_hook(
        "EOS_AntiCheatClient_UnregisterPeer",
        &HOOK_EOS_ANTICHEATCLIENT_UNREGISTERPEER,
    );
    hook::set_result_not_found_hook(
        "EOS_AntiCheatClient_PollStatus",
        &HOOK_EOS_ANTICHEATCLIENT_POLLSTATUS,
    );

    hook::set_report_player_behavior_hook(
        "EOS_Reports_SendPlayerBehaviorReport",
        &HOOK_EOS_REPORTS_SENDPLAYERBEHAVIORREPORT,
    );

    peer::set_anticheatclient_addnotifypeerauthstatuschanged_hook(
        "EOS_AntiCheatClient_AddNotifyPeerAuthStatusChanged",
        &HOOK_EOS_ANTICHEATCLIENT_ADDNOTIFYPEERAUTHSTATUSCHANGED,
    );
    peer::set_anticheatclient_registerpeer_hook(
        "EOS_AntiCheatClient_RegisterPeer",
        &HOOK_EOS_ANTICHEATCLIENT_REGISTERPEER,
    );
}

unsafe fn load_eos_dll() {
    LoadLibraryExW(
        w!("eossdk-win64-shipping.dll"),
        HANDLE::default(),
        LOAD_LIBRARY_FLAGS(0x00000001),
    )
    .expect("Could not load EOS SDK DLL");
}
