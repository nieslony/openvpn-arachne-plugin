use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::collections::{HashMap,LinkedList};
use std::ptr;
use std::ffi::CStr;
use va_list::VaList;
use derive_try_from_primitive::TryFromPrimitive;

pub const OPENVPN_PLUGIN_FUNC_SUCCESS: c_int = 0;
pub const OPENVPN_PLUGIN_FUNC_ERROR: c_int = 1;
pub const OPENVPN_PLUGIN_FUNC_DEFERRED: c_int = 2;

#[repr(C)]
pub enum OvpnSslapi {
    #[allow(dead_code)]
    None,
    #[allow(dead_code)]
    OpenSsl,
    #[allow(dead_code)]
    MbedTls,
}

#[repr(C)]
pub enum OpenvpnPluginLogFlags {
    PlogErr    = (1 << 0),/* Error condition message */
    PlogWarn   = (1 << 1),/* General warning message */
    PlogNote   = (1 << 2),/* Informational message */
    PlogDebug  = (1 << 3),/* Debug message, displayed if verb >= 7 */

    PlogErrno  = (1 << 8),/* Add error description to message */
    PlogNoMute = (1 << 9), /* Mute setting does not apply for message */
}

pub type PluginLog = unsafe extern "C" fn(
    flags: OpenvpnPluginLogFlags,
    plugin_name: *const c_char,
    format: *const c_char, ...
);

pub type PluginVLog = unsafe extern "C" fn(
    flags: OpenvpnPluginLogFlags,
    plugin_name: *const c_char,
    format: *const c_char,
    va_list: VaList
);

pub type PluginSecureMemzero = unsafe extern "C" fn(
    data: *mut c_void,
    len: isize
);

pub type PluginBase64Encode = unsafe extern "C" fn(
    date: *const c_void,
    size: isize,
    str: *mut *mut c_char
);

pub type PluginBase64Decode = unsafe extern "C" fn(
    str: *const c_char,
    data: *const c_void,
    len: isize
);

#[repr(C)]
pub struct Callbacks {
    pub plugin_log: PluginLog,
    plugin_vlog: PluginVLog,
    plugin_secure_memzero: PluginSecureMemzero,
    plugin_base64_encode: PluginBase64Encode,
    plugin_base64_decode: PluginBase64Decode
}

#[repr(C)]
pub struct OpenvpnPluginArgsOpenIn {
    pub type_mask: c_int,
    pub argv: *const *const c_char,
    pub envp: *const *const c_char,
    pub callbacks: *const Callbacks,
    ssl_api: OvpnSslapi,
    ovpn_version: *const c_char,
    ovpn_version_major: c_uint,
    ovpn_version_minor: c_uint,
    ovpn_version_patch: *const c_char,
}

#[repr(C)]
pub struct OpenvpnPluginArgsOpenReturn {
    pub type_mask: c_int,
    pub handle: *const c_void,
    return_list: *const c_void,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, TryFromPrimitive)]
#[non_exhaustive]
#[repr(i32)]
pub enum EventType {
    Up = 0,
    Down = 1,
    RouteUp = 2,
    IpChange = 3,
    TlsVerify = 4,
    AuthUserPassVerify = 5,
    ClientConnect = 6,
    ClientDisconnect = 7,
    LearnAddress = 8,
    ClientConnectV2 = 9,
    TlsFinal = 10,
    EnablePf = 11, // NOTE: feature has been removed as of OpenVPN 2.6
    RoutePredown = 12,
    ClientConnectDefer = 13,
    ClientConnectDeferV2 = 14,
    ClientCrresponse = 15,
    AuthFailed = 16,
}

#[repr(C)]
pub struct OpenvpnPluginArgsFuncIn {
    pub event_type: EventType,
    pub argv: *const *const c_char,
    pub envp: *const *const c_char,
    pub handle: *const c_void,
    pub per_client_context: *const c_void,
    current_cert_depth: c_int,
    current_cert: *const c_void,
}

#[repr(C)]
pub struct OpenvpnPluginArgsFuncReturn {
    return_list: *const c_void,
}

pub fn events_to_bitmask(events: &[EventType]) -> c_int {
    let mut bitmask: c_int = 0;
    for event in events {
        bitmask |= 1 << (*event as i32);
    }
    bitmask
}

pub fn argv_to_list(argv: *const *const c_char, list: &mut LinkedList<String>) {
    let mut next_arg = argv;
    unsafe {
        while (*next_arg) != ptr::null() {
            let c_str: &CStr = CStr::from_ptr(*next_arg);
            let str_slice: &str = c_str.to_str().unwrap();
            list.push_back(str_slice.to_string());

            next_arg = next_arg.add(1);
        }
    }
}

pub fn env_to_map(argv: *const *const c_char, map: &mut HashMap<String,String>) {
    let mut next_arg = argv;
    unsafe {
        while (*next_arg) != ptr::null() {
            let env_str = CStr::from_ptr(*next_arg).to_str().unwrap();
            let key_val: Vec<&str> = env_str.split('=').collect();
            map.insert(key_val[0].to_string(), key_val[1].to_string());

            next_arg = next_arg.add(1);
        }
    }
}
