// https://docs.rs/openvpn-plugin/latest/openvpn_plugin/
// https://github.com/mullvad/openvpn-plugin-rs/blob/main/src/lib.rs

mod firewall;
mod handle;
mod types;

use firewall::*;
use handle::*;
use std::collections::HashMap;
use std::fs::read_to_string;
use std::fs::File;
use std::io::Write;
use std::os::raw::{c_int, c_void};
use types::*;
use zbus::blocking::Connection as DbusConnection;

use reqwest::blocking::Client as HttpClient;
use reqwest::StatusCode;

const FN_IP_FORWATD: &str = "/proc/sys/net/ipv4/ip_forward";

#[no_mangle]
pub unsafe extern "C" fn openvpn_plugin_open_v3(
    _version: c_int,
    args: *const OpenvpnPluginArgsOpenIn,
    retptr: *mut OpenvpnPluginArgsOpenReturn,
) -> c_int {
    let mut handle = Handle::new(args);
    handle.note("Plugin Open");
    handle.note(format!("environment: {:?}", handle.env()).as_str());
    if !handle.read_config() {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    match DbusConnection::system() {
        Ok(c) => handle.dbus_connection.insert(c),
        Err(msg) => {
            handle.error(format!("Cannot connect to system bus: {}", msg).as_str());
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    };

    let events = vec![
        EventType::Up,
        EventType::Down,
        EventType::AuthUserPassVerify,
        EventType::ClientConnect,
        EventType::ClientDisconnect,
    ];

    (*retptr).type_mask = types::events_to_bitmask(&events);
    (*retptr).handle = Box::into_raw(Box::new(handle)) as *const c_void;

    OPENVPN_PLUGIN_FUNC_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn openvpn_plugin_close_v1(handle_ptr: *mut c_void) {
    let handle: &mut Handle = unsafe { &mut *(handle_ptr as *mut Handle) };
    handle.note("Plugin Close");

    unsafe {
        drop(Box::from_raw(handle_ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn openvpn_plugin_client_constructor_v1(
    handle_ptr: *mut c_void,
) -> *const c_void {
    let handle: &mut Handle = unsafe { &mut *(handle_ptr as *mut Handle) };
    let client: VpnClient = VpnClient::new(handle);
    client.note("Client Constructor");

    Box::into_raw(Box::new(client)) as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn openvpn_plugin_client_destructor_v1(
    _handle_ptr: *mut c_void,
    client_ptr: *mut c_void,
) {
    let client: &mut VpnClient = unsafe { &mut *(client_ptr as *mut VpnClient) };
    client.note("Client Destructor");

    unsafe {
        drop(Box::from_raw(client_ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn openvpn_plugin_func_v3(
    _version: c_int,
    args: *const OpenvpnPluginArgsFuncIn,
    _retptr: *const OpenvpnPluginArgsFuncReturn,
) -> c_int {
    let handle: &mut Handle = unsafe { &mut *((*args).handle as *mut Handle) };
    let client: &mut VpnClient = unsafe { &mut *((*args).per_client_context as *mut VpnClient) };
    let event_type = (*args).event_type;

    let mut env: HashMap<String, String> = HashMap::<String, String>::new();
    env_to_map((*args).envp, &mut env);
    client.debug(format!("env for func {:?}: {:?}", event_type, &env).as_str());

    match match event_type {
        EventType::Up => on_plugin_up(handle, client, &env),
        EventType::Down => on_plugin_down(handle, client, &env),
        EventType::AuthUserPassVerify => on_auth_user_pass(handle, client, &env),
        EventType::ClientConnect => on_client_connect(handle, client, &env),
        EventType::ClientDisconnect => on_client_disconnect(handle, client, &env),
        _ => {
            client.warn(format!("Unhandled event: {:?}", event_type).as_str());
            Ok(())
        }
    } {
        Ok(()) => OPENVPN_PLUGIN_FUNC_SUCCESS,
        Err(msg) => {
            client.error(msg.as_str());
            OPENVPN_PLUGIN_FUNC_ERROR
        }
    }
}

fn on_auth_user_pass(
    handle: &mut Handle,
    client: &mut VpnClient,
    env: &HashMap<String, String>,
) -> Result<(), String> {
    client.note("Auth User with Password");
    let username = env
        .get("username")
        .ok_or("No Username supplied.".to_string())?;
    let password = env
        .get("password")
        .ok_or("No Password supplied.".to_string())?;
    let &auth_url = &handle
        .config
        .auth_url
        .as_ref()
        .ok_or("No auth url in plugin configuration")?;

    client.note(format!("Connecting to {} ...", auth_url).as_str());
    let http_client = HttpClient::new();
    let response = http_client
        .get(auth_url)
        .basic_auth(username, Some(password))
        .send()
        .or_else(|e| Err(e.to_string()))?;

    match response.status() {
        StatusCode::OK => {
            client.note(format!("User {} successfuly authenticated", username).as_str());
        }
        _ => return Err("Authentication failed".to_string()),
    };

    let body: String = response.text().unwrap();
    let j =
        json::parse(&body).or_else(|err| Err(format!("Cannot parse json: {}", err.to_string())))?;

    client.api_auth_token = j["apiAuthToken"].as_str().map(ToOwned::to_owned);
    client.username = Some(username.to_owned());

    Ok(())
}

fn on_client_connect(
    handle: &mut Handle,
    client: &VpnClient,
    env: &HashMap<String, String>,
) -> Result<(), String> {
    if handle.config.enable_firewall.is_some_and(|x| x) {
        firewalld_update_rules(handle, client, env)
    } else {
        client.note("Firewall not activated, don't adding rules");
        Ok(())
    }
}

fn on_client_disconnect(
    handle: &mut Handle,
    client: &VpnClient,
    env: &HashMap<String, String>,
) -> Result<(), String> {
    if handle.config.enable_firewall.is_some_and(|x| x) {
        firewall_remove_client_rules(handle, client, env)
    } else {
        client.note("Firewall not activated, don't adding rules");
        Ok(())
    }
}

fn enable_forwarding(content: &String) -> Result<(), String> {
    let mut f = match File::create(FN_IP_FORWATD) {
        Ok(f) => f,
        Err(msg) => {
            return Err(msg.to_string());
        }
    };
    match f.write(content.as_bytes()) {
        Ok(_) => {}
        Err(msg) => return Err(msg.to_string()),
    }

    Ok(())
}

fn on_plugin_up(
    handle: &mut Handle,
    client: &VpnClient,
    env: &HashMap<String, String>,
) -> Result<(), String> {
    client.note("Bringing plugin up ");

    configure_forwarding(handle, client)?;

    match handle.config.enable_firewall {
        Some(true) => {
            firewall_zone_up(handle, client, env)?;
            firewall_cleanup_rules(handle, client)?;
        }
        Some(_) => {}
        None => {}
    };

    Ok(())
}

fn configure_forwarding(handle: &mut Handle, client: &VpnClient) -> Result<(), String> {
    match handle.config.enable_routing.as_deref() {
        Some("OFF") => {
            client.note("Dont't enable roting");
            Ok(())
        }
        Some("ENABLE") => {
            client.note("Enabling forwarding");
            enable_forwarding(&"1\n".to_string())
        }
        Some("RESTORE_ON_EXIT") => {
            let cur_forwarding_status = match read_to_string(FN_IP_FORWATD) {
                Ok(s) => s,
                Err(msg) => return Err(format!("{:?}", msg)),
            }
            .replace("\n", "");
            client.note(
                format!("Enabling forwarding and restore current value {cur_forwarding_status}")
                    .as_str(),
            );
            let _ = handle.forwading_status.insert(cur_forwarding_status);
            enable_forwarding(&"1\n".to_string())
        }
        Some(&_) => Err(String::from("enable_routing has invalid value")),
        None => {
            client.note("enable_routing not specified, leaving untouched.");
            Ok(())
        }
    }
}

fn on_plugin_down(
    handle: &mut Handle,
    client: &VpnClient,
    _env: &HashMap<String, String>,
) -> Result<(), String> {
    client.note("Bringing plugin down");

    match &handle.forwading_status {
        Some(v) => {
            client.note(format!("Restoring forwarding status {v}").as_str());
            enable_forwarding(v)?
        }
        None => {
            client.note("Dont't restoring forwarding status");
        }
    };
    if handle.config.enable_firewall.is_some_and(|x| x) {
        firewall_zone_down(handle, client)?;
    };

    Ok(())
}
