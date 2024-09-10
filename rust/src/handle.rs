use crate::types::*;

use serde::Deserialize;
use std::collections::{HashMap, LinkedList};
use std::ffi::CString;
use std::fs;
use toml;
use zbus::blocking::Connection as DbusConnection;

const PLUGIN_NAME: &str = "Arachne";

#[derive(Deserialize, Default)]
pub struct PluginConfig {
    pub auth_url: Option<String>,
    pub enable_firewall: Option<bool>,
    pub enable_routing: Option<String>,
    pub firewall_zone: Option<String>,
    pub firewall_url_user: Option<String>,
    pub firewall_url_everybody: Option<String>,
}

pub struct Handle {
    log_func: PluginLog,
    next_session_id: i32,
    arguments: LinkedList<String>,
    environment: HashMap<String, String>,
    pub config: PluginConfig,
    pub forwading_status: Option<String>,
    pub dbus_connection: Option<DbusConnection>,
}

impl Handle {
    pub fn new(args: *const OpenvpnPluginArgsOpenIn) -> Self {
        let callbacks = unsafe { (*args).callbacks };
        let plog = unsafe { (*callbacks).plugin_log };

        let mut arg_list: LinkedList<String> = LinkedList::<String>::new();
        unsafe { argv_to_list((*args).argv, &mut arg_list) };
        arg_list.pop_front();

        let mut env_map = HashMap::new();
        unsafe { env_to_map((*args).envp, &mut env_map) };

        Self {
            log_func: plog,
            next_session_id: 0,
            arguments: arg_list,
            environment: env_map,
            config: PluginConfig::default(),
            forwading_status: None,
            dbus_connection: None,
        }
    }

    pub fn log(&self, level: OpenvpnPluginLogFlags, msg: &str) {
        let msg_str = CString::new(msg).expect("");
        let plugin_str = CString::new(PLUGIN_NAME).unwrap();
        unsafe {
            (self.log_func)(level, plugin_str.as_ptr(), msg_str.as_ptr());
        }
    }

    pub fn note(&self, msg: &str) {
        self.log(OpenvpnPluginLogFlags::PlogNote, msg);
    }

    pub fn error(&self, msg: &str) {
        self.log(OpenvpnPluginLogFlags::PlogErr, msg);
    }

    pub fn next_id(&mut self) -> i32 {
        self.next_session_id = self.next_session_id + 1;
        self.next_session_id
    }

    pub fn env(&self) -> &HashMap<String, String> {
        &self.environment
    }

    pub fn read_config(&mut self) -> bool {
        let filename = match self.arguments.front() {
            Some(v) => v,
            None => {
                self.error("Parameter missing: configuration file not supplied");
                return false;
            }
        };
        self.note(format!("Reading configuration from {filename}").as_str());
        let contents = match fs::read_to_string(filename) {
            Ok(c) => c,
            Err(msg) => {
                let msg_str = format!(
                    "Cannot read plugin configuration from {}: {}",
                    filename, msg
                );
                self.error(msg_str.as_str());
                return false;
            }
        };
        let config: PluginConfig = match toml::from_str(&contents) {
            Ok(d) => d,
            Err(msg) => {
                self.error(format!("Cannot parse toml file {}: {}", filename, msg).as_str());
                return false;
            }
        };
        self.config = config;

        true
    }
}

pub struct VpnClient {
    id: i32,
    log_func: PluginLog,
    pub api_auth_token: Option<String>,
    pub username: Option<String>,
}

impl VpnClient {
    pub fn new(handle: &mut Handle) -> Self {
        Self {
            id: handle.next_id(),
            log_func: handle.log_func,
            api_auth_token: None,
            username: None,
        }
    }

    pub fn log(&self, level: OpenvpnPluginLogFlags, msg: &str) {
        let msg_str = CString::new(msg).expect("");
        let plugin_session = format!("{}_{}", PLUGIN_NAME, self.id);
        let plugin_str = CString::new(plugin_session).unwrap();
        unsafe {
            (self.log_func)(level, plugin_str.as_ptr(), msg_str.as_ptr());
        }
    }

    pub fn debug(&self, msg: &str) {
        self.log(
            OpenvpnPluginLogFlags::PlogDebug,
            format!("DEBUG {msg}").as_str(),
        );
    }

    pub fn note(&self, msg: &str) {
        self.log(
            OpenvpnPluginLogFlags::PlogNote,
            format!("NOTE {msg}").as_str(),
        );
    }

    pub fn warn(&self, msg: &str) {
        self.log(
            OpenvpnPluginLogFlags::PlogWarn,
            format!("WARNING {msg}").as_str(),
        );
    }

    pub fn error(&self, msg: &str) {
        self.log(
            OpenvpnPluginLogFlags::PlogErr,
            format!("ERROR {msg}").as_str(),
        );
    }
}
