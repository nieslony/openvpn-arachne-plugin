use crate::handle::*;
use crate::types::*;
#[path = "firewalld/config.rs"] mod firewalld_config;
use firewalld_config::configProxyBlocking;
#[path = "firewalld/policy.rs"] mod firewalld_policy;
use firewalld_policy::policyProxyBlocking;

use zbus::zvariant::Value;
use reqwest::StatusCode;
use reqwest::blocking::Client as HttpClient;
use std::collections::HashMap;
use std::os::raw::c_int;

pub fn firewall_zone_up(
    handle: &mut Handle,
    client: &VpnClient,
    env: &HashMap<String,String>
) -> bool {
    let dev_name = env.get("dev").unwrap();
    match &handle.config.firewall_zone {
        Some(zone_name) => {
            client.note(format!(
                "Creating firewall zone \"{zone_name}\" with device \"{dev_name}\"")
                    .as_str()
            );
            let fw_config = match configProxyBlocking::new(
                    &handle.dbus_connection.as_ref().unwrap()
            ) {
                Ok(c) => c,
                Err(msg) => {
                    client.error(format!("Cannot get firewall config: {}", msg).as_str());
                    return false
                }
            };
            let zone_names = match fw_config.get_zone_names() {
                Ok(zn) => zn,
                Err(msg) => {
                    client.error(format!("Cannot get firewall zones: {}", msg).as_str());
                    return false
                }
            };
            client.note(format!("Exiting zones: {:?}", zone_names).as_str());
            if !zone_names.contains(&zone_name) {
                let set_target = Value::new("DROP");
                let set_interfaces = Value::new(vec!(dev_name.as_str()));
                client.note("create settings");
                let mut settings:HashMap<&str, &Value<'_>> = HashMap::<&str, &Value>::new();
                settings.insert("target", &set_target);
                settings.insert("interfaces", &set_interfaces);
                client.note(format!("add zone {:?}", &settings).as_str());
                let obj_path = match fw_config.add_zone2(&zone_name, settings) {
                    Ok(o) => o,
                    Err(msg) => {
                        client.error(format!("Cannot add firewall zone: {}", msg).as_str());
                        return false
                    }
                };
                client.note(format!("object path: {:?}", obj_path).as_str());
            }
            else {
                client.note(format!("Firewall zone {zone_name} already exists.").as_str());
            }
        },
        None => {
            client.error("Error in plugin configuration: firewall_zone required");
            return false
        }
    };

    true
}

pub fn firewall_zone_down(
    handle: &mut Handle,
    client: &VpnClient
) -> c_int {
    let _fw_config = match configProxyBlocking::new(&handle.dbus_connection.as_ref().unwrap()) {
        Ok(c) => c,
        Err(msg) => {
            client.error(format!("Cannot get firewall config: {}", msg).as_str());
            return OPENVPN_PLUGIN_FUNC_ERROR
        }
    };

    OPENVPN_PLUGIN_FUNC_SUCCESS
}

pub fn firewalld_update_everybody_rules(
    handle: &mut Handle,
    client: &VpnClient
) -> bool {
    let url = match &handle.config.firewall_url_everybody {
        Some(u) => u,
        None => {
            client.error("No firewall url configured");
            return true
        }
    };

    client.note(format!("Connecting to {} ...", url).as_str());
    let http_client = HttpClient::new();
    let response = match http_client
        .get(url)
        .bearer_auth(client.api_auth_token.as_ref().unwrap())
        .send() {
            Ok(r) => r,
            Err(e) => {
                client.error(format!("Error connecting to {}: {}", url, e).as_str());
                return false
            }
        };
    match response.status() {
         StatusCode::OK => {
             client.note("User successfuly authenticated")
         },
         _ => {
             client.error("Authentication failed");
             return false
         }
    };
    let body: String = response.text().unwrap();
    client.note(body.as_str());
    let j = match json::parse(&body) {
        Ok(j) => j,
        Err(err) => {
            client.error(format!("Cannot parse json: {}", err).as_str());
            return false
        }
    };

    let fw_policy = match policyProxyBlocking::new(
            &handle.dbus_connection.as_ref().unwrap()
    ) {
        Ok(c) => c,
        Err(msg) => {
            client.error(format!("Cannot get firewall policy: {}", msg).as_str());
            return false
        }
    };



    true
}
