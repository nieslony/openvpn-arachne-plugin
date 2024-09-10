use crate::handle::*;
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
use std::convert::*;
use zbus::zvariant::{Array as ZBusArray, Value};

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
) -> Result<(), String> {
    let zone_names = match fw_config.get_zone_names() {
        Ok(zn) => zn,
        Err(msg) => return Err(format!("Cannot get firewall zones: {msg}")),
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
            Err(msg) => return Err(format!("Cannot add firewall zone: {msg}")),
        };
        client.note(format!("Zone created as: {:?}", obj_path).as_str());
    } else {
        client.note(format!("Firewall zone {zone_name} already exists.").as_str());
    }

    Ok(())
}

fn create_policies(
    client: &VpnClient,
    fw_config: &configProxyBlocking,
    zone_name: &String,
) -> Result<(), String> {
    client.note("Creating firewall policies");
    let policy_names = match fw_config.get_policy_names() {
        Ok(pn) => pn,
        Err(msg) => return Err(format!("Cannot get policy names: {msg}")),
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
                Err(msg) => return Err(format!("Cannot add firewall zone: {msg}")),
            };
            client.note(format!("Policy created as: {:?}", obj_path).as_str());
        } else {
            client.note(format!("Policy {:?} already exists", policy_name).as_str());
        }
    }

    Ok(())
}

fn create_rich_rule(rule: &JsonValue, client_ip: Option<&String>) -> String {
    let source_address = match client_ip {
        Some(ip) => format!(" source address=\"{ip}\""),
        None => String::from(""),
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

    format!("rule family=\"ipv4\"{source_address}{destination_address}{service_name}{port} accept")
}

pub fn firewall_zone_up(
    handle: &mut Handle,
    client: &VpnClient,
    env: &HashMap<String, String>,
) -> Result<(), String> {
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
                    Err(msg) => return Err(format!("Cannot get firewall config: {msg}")),
                };

            create_zone(client, &fw_config, zone_name, dev_name)?;
            create_policies(client, &fw_config, zone_name)?;
            firewall_reload(handle, client)
        }
        None => Err(String::from(
            "Error in plugin configuration: firewall_zone required",
        )),
    }
}

pub fn firewall_zone_down(handle: &mut Handle, client: &VpnClient) -> Result<(), String> {
    firewall_cleanup_rules(handle, client)?;

    Ok(())
}

fn get_everybody_rules(handle: &mut Handle, client: &VpnClient) -> Result<JsonValue, String> {
    let url = handle
        .config
        .firewall_url_everybody
        .clone()
        .ok_or("No firewall url configured".to_string())?;

    client.note(format!("Get everybody firewall rules from {url} ...").as_str());
    let http_client = HttpClient::new();
    let response = http_client
        .get(url)
        .bearer_auth(client.api_auth_token.as_ref().unwrap())
        .send()
        .or_else(|e| Err(e.to_string()))?;
    match response.status() {
        StatusCode::OK => client.debug("User successfuly authenticated with token"),
        _ => return Err("Authentication failed".to_string()),
    };
    let body: String = response.text().unwrap();
    client.debug(format!("Got everybody rules: {}", body.as_str()).as_str());

    json::parse(&body).or_else(|e| Err(format!("Cannot parse json: {}", e.to_string())))
}

fn get_user_rules(handle: &mut Handle, client: &VpnClient) -> Result<JsonValue, String> {
    let url = handle
        .config
        .firewall_url_user
        .clone()
        .ok_or("No firewall url configured".to_string())?;
    let username = client
        .username
        .clone()
        .ok_or("Dont't have your username.".to_string())?;

    client.note(format!("Get {username}'s firewall rules from {url} ...").as_str());
    let http_client = HttpClient::new();
    let response = http_client
        .get(url)
        .bearer_auth(client.api_auth_token.as_ref().unwrap())
        .send()
        .or_else(|e| Err(e.to_string()))?;
    match response.status() {
        StatusCode::OK => client.debug("User successfuly authenticated with token"),
        _ => return Err("Authentication failed".to_string()),
    };
    let body: String = response.text().unwrap();
    client.debug(format!("Got user rules: {}", body.as_str()).as_str());

    json::parse(&body).or_else(|e| Err(format!("Cannot parse json: {}", e.to_string())))
}

pub fn firewalld_update_rules(
    handle: &mut Handle,
    client: &VpnClient,
    env: &HashMap<String, String>,
) -> Result<(), String> {
    let client_ip = env
        .get("ifconfig_pool_remote_ip")
        .ok_or("Didn't get client IP from environment".to_string())?;
    let zone_name = &handle
        .config
        .firewall_zone
        .clone()
        .ok_or("Error in plugin configuration: firewall_zone required".to_string())?;
    let pol_name_in = policy_name_incoming(zone_name);

    let fw_policy = policyProxyBlocking::new(&handle.dbus_connection.as_ref().unwrap())
        .or_else(|e| Err(format!("Cannot get firewall policy object: {e}")))?;
    let policy = fw_policy
        .get_policy_settings(pol_name_in.as_str())
        .or_else(|e| Err(format!("Cannot get firewall policy {pol_name_in}: {e}")))?;

    let everybody_rules = get_everybody_rules(handle, client)?;
    let user_rules = get_user_rules(handle, client)?;

    let mut new_rich_rules: Vec<String> = vec![];
    match policy.get("rich_rules") {
        Some(rr) => {
            let rules_arr = <&ZBusArray>::try_from(rr).or_else(|e| Err(format!("{:?}", e)))?;
            for rule in rules_arr.iter() {
                let rule_str = <&str>::try_from(rule).or_else(|e| Err(format!("{:?}", e)))?;
                if rule_str.contains("source address") {
                    client.debug(format!("Keeping rule {rule_str}").as_str());
                    new_rich_rules.push(rule_str.to_string());
                } else {
                    client.debug(format!("Keeping removing rule {rule_str}").as_str());
                }
            }
        }
        None => {}
    };
    for rule in everybody_rules["richRules"].members() {
        let r = create_rich_rule(rule, None);
        new_rich_rules.push(r);
    }
    for rule in user_rules.members() {
        let r = create_rich_rule(rule, Some(client_ip));
        new_rich_rules.push(r);
    }
    new_rich_rules.sort();

    client.debug(format!("all new rules: {:?}", new_rich_rules).as_str());
    let mut settings: HashMap<&str, &Value<'_>> = HashMap::<&str, &Value>::new();
    let rich_rules_value = Value::new(new_rich_rules);
    settings.insert("rich_rules", &rich_rules_value);
    fw_policy
        .set_policy_settings(pol_name_in.as_str(), settings)
        .or_else(|e| Err(format!("Cannot update firewall rules: {e}")))?;
    client.note("Firewall rules successfuly updated");

    Ok(())
}

pub fn firewall_remove_client_rules(
    handle: &mut Handle,
    client: &VpnClient,
    env: &HashMap<String, String>,
) -> Result<(), String> {
    let username = client
        .username
        .clone()
        .ok_or("Dont't have your username.".to_string())?;
    let client_ip = env
        .get("ifconfig_pool_remote_ip")
        .ok_or("Didn't get client IP from environment".to_string())?;
    client.note(format!("Removing {username}'s firewall rules with IP {client_ip}").as_str());
    let zone_name = &handle
        .config
        .firewall_zone
        .clone()
        .ok_or("Error in plugin configuration: firewall_zone required".to_string())?;
    let pol_name_in = policy_name_incoming(zone_name);

    let fw_policy = policyProxyBlocking::new(&handle.dbus_connection.as_ref().unwrap())
        .or_else(|e| Err(format!("Cannot get firewall policy object: {e}")))?;
    let policy = fw_policy
        .get_policy_settings(pol_name_in.as_str())
        .or_else(|e| Err(format!("Cannot get firewall policy {pol_name_in}: {e}")))?;

    let mut new_rich_rules: Vec<String> = vec![];
    let mut removed_rules = 0;
    let mut kept_rules = 0;
    match policy.get("rich_rules") {
        Some(rr) => {
            let rules_arr = <&ZBusArray>::try_from(rr).or_else(|e| Err(format!("{:?}", e)))?;
            for rule in rules_arr.iter() {
                let rule_str = <&str>::try_from(rule).or_else(|e| Err(format!("{:?}", e)))?;
                if !rule_str.contains(format!("source address=\"{client_ip}\"").as_str()) {
                    client.debug(format!("Keeping rule {rule_str}").as_str());
                    new_rich_rules.push(rule_str.to_string());
                    kept_rules = kept_rules + 1;
                } else {
                    client.debug(format!("Removing rule {rule_str}").as_str());
                    removed_rules = removed_rules + 1;
                }
            }
        }
        None => {}
    };

    let mut settings: HashMap<&str, &Value<'_>> = HashMap::<&str, &Value>::new();
    let rich_rules_value = Value::new(new_rich_rules);
    settings.insert("rich_rules", &rich_rules_value);
    fw_policy
        .set_policy_settings(pol_name_in.as_str(), settings)
        .or_else(|e| Err(format!("Cannot update firewall rules: {e}")))?;
    client.note(
        format!(
            "Firewall rules successfuly updated. {removed_rules} removed, {kept_rules} rules kept."
        )
        .as_str(),
    );

    Ok(())
}

pub fn firewall_reload(handle: &mut Handle, client: &VpnClient) -> Result<(), String> {
    let firewall = FirewallD1ProxyBlocking::new(&handle.dbus_connection.as_ref().unwrap())
        .or_else(|e| Err(format!("Cannot get firewall object: {}", e.to_string())))?;
    client.note("Reloading firewall");
    firewall
        .reload()
        .or_else(|e| Err(format!("Error reloading firewall: {}", e.to_string())))?;
    Ok(())
}

pub fn firewall_cleanup_rules(handle: &mut Handle, client: &VpnClient) -> Result<(), String> {
    client.note("Cleaning up firewall rules");
    let zone_name = &handle
        .config
        .firewall_zone
        .clone()
        .ok_or("Error in plugin configuration: firewall_zone required".to_string())?;
    let pol_name_in = policy_name_incoming(zone_name);

    let fw_policy = policyProxyBlocking::new(&handle.dbus_connection.as_ref().unwrap())
        .or_else(|e| Err(format!("Cannot get firewall policy object: {e}")))?;

    let mut settings: HashMap<&str, &Value<'_>> = HashMap::<&str, &Value>::new();
    let empty_rules: Vec<String> = vec![];
    let rich_rules_value = Value::new(empty_rules);
    settings.insert("rich_rules", &rich_rules_value);
    fw_policy
        .set_policy_settings(pol_name_in.as_str(), settings)
        .or_else(|e| Err(format!("Cannot update firewall rules: {e}")))?;

    Ok(())
}
