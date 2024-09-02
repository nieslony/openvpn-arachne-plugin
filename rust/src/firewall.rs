use crate::handle::*;
use crate::types::*;
#[path = "firewalld/config.rs"]
mod firewalld_config;
use firewalld_config::configProxyBlocking;
#[path = "firewalld/policy.rs"]
mod firewalld_policy;
use firewalld_policy::policyProxyBlocking;
#[path = "firewalld/firewall_d1.rs"]
mod firewalld_firewall_d1;
use firewalld_firewall_d1::FirewallD1ProxyBlocking;

use json::JsonValue;
use reqwest::blocking::Client as HttpClient;
use reqwest::StatusCode;
use std::collections::HashMap;
use std::collections::HashSet;
use std::os::raw::c_int;
use zbus::zvariant::{Array, OwnedValue, Value};

fn policy_name_incoming(zone_name: &String) -> String {
    format!("{zone_name}-in")
}

fn policy_name_outgoing(zone_name: &String) -> String {
    format!("{zone_name}-out")
}

fn create_zone(
    client: &VpnClient,
    fw_config: &configProxyBlocking,
    zone_name: &String,
    dev_name: &String,
) -> bool {
    let zone_names = match fw_config.get_zone_names() {
        Ok(zn) => zn,
        Err(msg) => {
            client.error(format!("Cannot get firewall zones: {}", msg).as_str());
            return false;
        }
    };
    client.debug(format!("Exiting zones: {:?}", zone_names).as_str());
    if !zone_names.contains(&zone_name) {
        let set_target = Value::new("DROP");
        let set_interfaces = Value::new(vec![dev_name.as_str()]);
        client.note("create settings");
        let mut settings: HashMap<&str, &Value<'_>> = HashMap::<&str, &Value>::new();
        settings.insert("target", &set_target);
        settings.insert("interfaces", &set_interfaces);
        client.note(format!("add zone {:?}", &settings).as_str());
        let obj_path = match fw_config.add_zone2(&zone_name, settings) {
            Ok(o) => o,
            Err(msg) => {
                client.error(format!("Cannot add firewall zone: {}", msg).as_str());
                return false;
            }
        };
        client.note(format!("Zone created as: {:?}", obj_path).as_str());
    } else {
        client.note(format!("Firewall zone {zone_name} already exists.").as_str());
    }

    true
}

fn create_policies(
    client: &VpnClient,
    fw_config: &configProxyBlocking,
    zone_name: &String,
) -> bool {
    client.note("Create firewall policies");
    let policy_names = match fw_config.get_policy_names() {
        Ok(pn) => pn,
        Err(msg) => {
            client.error(format!("Cannot get policy names: {}", msg).as_str());
            return false;
        }
    };
    client.debug(format!("Exiting policies: {:?}", policy_names).as_str());
    let my_zones = vec![
        policy_name_incoming(zone_name),
        policy_name_outgoing(zone_name),
    ];
    for policy_name in my_zones.iter() {
        if !policy_names.contains(policy_name) {
            let mut settings: HashMap<&str, &Value<'_>> = HashMap::<&str, &Value>::new();
            let set_target = Value::new("CONTINUE");
            let set_ingress_zones = Value::new(vec![zone_name]);
            let set_egress_zones = Value::new(vec!["ANY"]);
            settings.insert("target", &set_target);
            settings.insert("ingress_zones", &set_ingress_zones);
            settings.insert("egress_zones", &set_egress_zones);
            client.note(
                format!(
                    "Creating policy {:?} with settings {:?}",
                    policy_name, settings
                )
                .as_str(),
            );
            let obj_path = match fw_config.add_policy(&policy_name, settings) {
                Ok(o) => o,
                Err(msg) => {
                    client.error(format!("Cannot add firewall zone: {}", msg).as_str());
                    return false;
                }
            };
            client.note(format!("Policy created as: {:?}", obj_path).as_str());
        } else {
            client.note(format!("Policy {:?} already exists", policy_name).as_str());
        }
    }

    true
}

fn create_rich_rule(rule: &JsonValue) -> String {
    let source_address: String = match &rule["sourceAddress"].as_str() {
        Some(sa) => format!(" source address=\"{sa}\""),
        None => String::new(),
    };
    let destination_address: String = match &rule["destinationAddress"].as_str() {
        Some(da) => format!(" destination address=\"{da}\""),
        None => String::new(),
    };
    let service_name: String = match &rule["serviceName"].as_str() {
        Some(sn) => format!(" service name=\"{sn}\""),
        None => String::new(),
    };
    let port: String = match &rule["port"].as_str() {
        Some(p) => format!(" {p}"),
        None => String::new(),
    };

    format!("rule family=\"ipv4\"{source_address}{destination_address}{service_name}{port}")
}

pub fn firewall_zone_up(
    handle: &mut Handle,
    client: &VpnClient,
    env: &HashMap<String, String>,
) -> bool {
    let dev_name = env.get("dev").unwrap();
    match &handle.config.firewall_zone {
        Some(zone_name) => {
            client.note(
                format!("Creating firewall zone \"{zone_name}\" with device \"{dev_name}\"")
                    .as_str(),
            );
            let fw_config =
                match configProxyBlocking::new(&handle.dbus_connection.as_ref().unwrap()) {
                    Ok(c) => c,
                    Err(msg) => {
                        client.error(format!("Cannot get firewall config: {}", msg).as_str());
                        return false;
                    }
                };
            if !create_zone(client, &fw_config, zone_name, dev_name)
                || !create_policies(client, &fw_config, zone_name)
                || !firewall_reload(handle, client)
            {
                return false;
            }
        }
        None => {
            client.error("Error in plugin configuration: firewall_zone required");
            return false;
        }
    };

    true
}

pub fn firewall_zone_down(handle: &mut Handle, client: &VpnClient) -> c_int {
    let _fw_config = match configProxyBlocking::new(&handle.dbus_connection.as_ref().unwrap()) {
        Ok(c) => c,
        Err(msg) => {
            client.error(format!("Cannot get firewall config: {}", msg).as_str());
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    };

    OPENVPN_PLUGIN_FUNC_SUCCESS
}

pub fn firewalld_update_everybody_rules(handle: &mut Handle, client: &VpnClient) -> bool {
    let url = match &handle.config.firewall_url_everybody {
        Some(u) => u,
        None => {
            client.error("No firewall url configured");
            return false;
        }
    };
    let zone_name = match &handle.config.firewall_zone {
        Some(zn) => zn,
        None => {
            client.error("Error in plugin configuration: firewall_zone required");
            return false;
        }
    };
    let pol_name_in = policy_name_incoming(zone_name);

    client.note(format!("Get everybody firewall rules from {} ...", url).as_str());
    let http_client = HttpClient::new();
    let response = match http_client
        .get(url)
        .bearer_auth(client.api_auth_token.as_ref().unwrap())
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            client.error(format!("Error connecting to {}: {}", url, e).as_str());
            return false;
        }
    };
    match response.status() {
        StatusCode::OK => client.note("User successfuly authenticated with token"),
        _ => {
            client.error("Authentication failed");
            return false;
        }
    };
    let body: String = response.text().unwrap();
    client.note(format!("Got verybody rules: {}", body.as_str()).as_str());
    let j = match json::parse(&body) {
        Ok(j) => j,
        Err(err) => {
            client.error(format!("Cannot parse json: {}", err).as_str());
            return false;
        }
    };

    let fw_policy = match policyProxyBlocking::new(&handle.dbus_connection.as_ref().unwrap()) {
        Ok(c) => c,
        Err(msg) => {
            client.error(format!("Cannot get firewall policy object: {}", msg).as_str());
            return false;
        }
    };
    let policy = match fw_policy.get_policy_settings(pol_name_in.as_str()) {
        Ok(p) => p,
        Err(msg) => {
            client.error(format!("Cannot get firewall policy {}: {}", pol_name_in, msg).as_str());
            return false;
        }
    };
    client.note(format!("got policy: {:?}", policy).as_str());

    let masq_ov: &OwnedValue = match &policy.get("masquerade") {
        Some(s) => s,
        None => {
            client.error("No masquarade");
            return false;
        }
    };
    let masq: bool = match <&OwnedValue as TryInto<bool>>::try_into(masq_ov) {
        Ok(b) => b,
        Err(msg) => {
            client.error("masuqrade is not bool");
            return false;
        }
    };
    client.note(format!("Got masquerade {:?} {:?}", masq_ov, masq).as_str());

    let target_ov: &OwnedValue = match &policy.get("target") {
        Some(s) => s,
        None => {
            client.error("No target");
            return false;
        }
    };
    let target: &str = match <&OwnedValue as TryInto<&str>>::try_into(target_ov) {
        Ok(b) => b,
        Err(msg) => {
            client.error("target is not string");
            return false;
        }
    };
    client.note(format!("Got target {:?} {:?}", target_ov, target).as_str());

    let mut rules = match &j["richRules"] {
        JsonValue::Array(a) => {
            let mut arr = a.clone();
            arr.retain_mut(|r| true);
            arr
        }
        _ => Vec::<JsonValue>::new(),
    };
    for r in rules.iter() {
        client.note(format!("{:?}", r["destinationAddress"]).as_str());
    }

    true
}

pub fn firewall_reload(handle: &mut Handle, client: &VpnClient) -> bool {
    let firewall = match FirewallD1ProxyBlocking::new(&handle.dbus_connection.as_ref().unwrap()) {
        Ok(f) => f,
        Err(msg) => {
            client.error(format!("Cannot get firewall object: {msg}").as_str());
            return false;
        }
    };
    match firewall.reload() {
        Ok(_) => {
            client.note("Firewall reloaded");
            true
        }
        Err(msg) => {
            client.error(format!("Error reloading firewall: {msg}").as_str());
            false
        }
    }
}
