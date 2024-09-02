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

    match event_type {
        EventType::Up => on_plugin_up(handle, client, &env),
        EventType::Down => on_plugin_down(handle, client, &env),
        EventType::AuthUserPassVerify => on_auth_user_pass(handle, client, &env),
        EventType::ClientConnect => on_client_connect(handle, client, &env),
        EventType::ClientDisconnect => on_client_disconnect(handle, client, &env),
        _ => OPENVPN_PLUGIN_FUNC_DEFERRED,
    }
}

fn on_auth_user_pass(
    handle: &mut Handle,
    client: &mut VpnClient,
    env: &HashMap<String, String>,
) -> c_int {
    client.note("Auth User with Password");
    let username = match env.get("username") {
        Some(v) => v,
        None => {
            client.error("No Username supplied.");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    };
    let password = match env.get("password") {
        Some(v) => v,
        None => {
            client.error("No Password supplied.");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    };
    let auth_url = match &handle.config.auth_url {
        Some(v) => v,
        None => {
            client.error("No auth url in plugin configuration");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    };

    client.note(format!("Connecting to {} ...", auth_url).as_str());
    let http_client = HttpClient::new();
    let response = match http_client
        .get(auth_url)
        .basic_auth(username, Some(password))
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            client.error(format!("Error connecting to {}: {}", auth_url, e).as_str());
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    };

    match response.status() {
        StatusCode::OK => {
            client.note(format!("User {} successfuly authenticated", username).as_str());
        }
        _ => {
            client.error("Authentication failed");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    };

    let body: String = response.text().unwrap();
    let j = match json::parse(&body) {
        Ok(j) => j,
        Err(err) => {
            client.error(format!("Cannot parse json: {}", err).as_str());
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    };
    client.api_auth_token = Some(match j["apiAuthToken"].as_str() {
        Some(t) => String::from(t),
        None => {
            client.error("No API token found in response");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    });

    OPENVPN_PLUGIN_FUNC_SUCCESS
}

fn on_client_connect(
    handle: &mut Handle,
    client: &VpnClient,
    _env: &HashMap<String, String>,
) -> c_int {
    if handle.config.enable_firewall.is_some_and(|x| x) {
        if !firewalld_update_everybody_rules(handle, client) {
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    } else {
        client.note("Firewall not activated, don't adding rules");
    }

    OPENVPN_PLUGIN_FUNC_SUCCESS
}

fn on_client_disconnect(
    handle: &mut Handle,
    client: &VpnClient,
    _env: &HashMap<String, String>,
) -> c_int {
    if handle.config.enable_firewall.is_some_and(|x| x) {
        firewall_zone_down(handle, client);
    };

    OPENVPN_PLUGIN_FUNC_SUCCESS
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

fn on_plugin_up(handle: &mut Handle, client: &VpnClient, env: &HashMap<String, String>) -> c_int {
    client.note("Bringing plugin up ");

    if !configure_forwarding(handle, client) {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    match handle.config.enable_firewall {
        Some(true) => {
            if !firewall_zone_up(handle, client, env) {
                return OPENVPN_PLUGIN_FUNC_ERROR;
            }
        }
        Some(_) => {}
        None => {}
    }

    OPENVPN_PLUGIN_FUNC_SUCCESS
}

fn configure_forwarding(handle: &mut Handle, client: &VpnClient) -> bool {
    match handle.config.enable_routing.as_deref() {
        Some("OFF") => {
            client.note("Dont't enable roting");
        }
        Some("ENABLE") => {
            client.note("Enabling forwarding");
            match enable_forwarding(&"1\n".to_string()) {
                Ok(_) => {}
                Err(msg) => {
                    client.error(msg.as_str());
                    return false;
                }
            };
        }
        Some("RESTORE_ON_EXIT") => {
            let cur_forwarding_status = match read_to_string(FN_IP_FORWATD) {
                Ok(s) => s,
                Err(msg) => {
                    client.error(msg.to_string().as_str());
                    return false;
                }
            }
            .replace("\n", "");
            client.note(
                format!(
                    "Enabling forwarding and restore current value {}",
                    cur_forwarding_status
                )
                .as_str(),
            );
            let _ = handle.forwading_status.insert(cur_forwarding_status);
            match enable_forwarding(&"1\n".to_string()) {
                Ok(_) => {}
                Err(msg) => {
                    client.error(msg.as_str());
                    return false;
                }
            };
        }
        Some(&_) => {
            client.error(format!("enable_routing has invalid value").as_str());
            return false;
        }
        None => client.note("enable_routing not specified, leaving untouched."),
    };

    true
}

fn on_plugin_down(
    handle: &mut Handle,
    client: &VpnClient,
    _env: &HashMap<String, String>,
) -> c_int {
    client.note("Bringing plugin down");

    match &handle.forwading_status {
        Some(v) => {
            client.note(format!("Restoring forwarding status {v}").as_str());
            match enable_forwarding(v) {
                Ok(_) => {}
                Err(msg) => {
                    client.error(msg.as_str());
                    return OPENVPN_PLUGIN_FUNC_ERROR;
                }
            };
        }
        None => {
            client.note("Dont't restoring forwarding status");
        }
    };

    OPENVPN_PLUGIN_FUNC_SUCCESS
}
