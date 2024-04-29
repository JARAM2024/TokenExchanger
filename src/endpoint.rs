use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;
use pingora_core::upstreams::peer::HttpPeer;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct MyEndpointEntry {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub is_ssl: bool,
    pub headers: Vec<(String, String)>,
}

impl MyEndpointEntry {
    pub fn new(
        name: String,
        address: String,
        port: u16,
        is_ssl: bool,
        headers: Vec<(String, String)>,
    ) -> MyEndpointEntry {
        return MyEndpointEntry {
            name,
            address: address.to_owned(),
            port,
            is_ssl,
            headers,
        };
    }
}

pub struct MyEndpoint {}

impl MyEndpoint {
    pub fn load_configuration(&self, file_path: &str) {
        let content = fs::read_to_string(file_path);
        let entries: Vec<MyEndpointEntry> =
            match serde_json::from_str(content.as_deref().ok().unwrap()) {
                Ok(data) => data,
                Err(_) => return,
            };
        for entry in entries.iter() {
            let mut unlocked_map = ENDPOINT_MAP.lock().unwrap();
            unlocked_map.insert(entry.name.clone().leak(), entry.clone());
        }
    }

    pub fn get_peer(&self, key: &str) -> Option<HttpPeer> {
        let unlocked_map = ENDPOINT_MAP.lock().unwrap();
        unlocked_map.get(key).map(|endpoint| {
            let sni = endpoint.address.to_owned();
            HttpPeer::new(
                (endpoint.address.to_owned(), endpoint.port),
                endpoint.is_ssl,
                sni,
            )
        })
    }
}

lazy_static! {
    static ref ENDPOINT_MAP: Arc<Mutex<HashMap<&'static str, MyEndpointEntry>>> = {
        let map = Arc::new(Mutex::new(HashMap::new()));

        let mut unlocked_map = map.lock().unwrap();

        unlocked_map.insert(
            "haksul-proxy",
            MyEndpointEntry::new(
                "haksul-proxy".to_owned(),
                "127.0.0.1".to_owned(),
                80 as u16,
                false,
                vec![],
            ),
        );

        return map.to_owned();
    };
}
