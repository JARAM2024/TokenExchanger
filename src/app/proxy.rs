use async_trait::async_trait;

use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

use http;

use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
struct EndpointEntry {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub is_ssl: bool,
    pub is_outer: bool,
    pub headers: Vec<(String, String)>,
}

impl EndpointEntry {
    pub fn new(
        name: String,
        address: String,
        port: u16,
        is_ssl: bool,
        is_outer: bool,
        headers: Vec<(String, String)>,
    ) -> EndpointEntry {
        return EndpointEntry {
            name,
            address: address.to_owned(),
            port,
            is_ssl,
            is_outer,
            headers,
        };
    }
}

pub struct Endpoint {
    endpoint_map: Arc<Mutex<HashMap<&'static str, EndpointEntry>>>,
}

impl Endpoint {
    pub fn new() -> Endpoint {
        Endpoint {
            endpoint_map: {
                let map = Arc::new(Mutex::new(HashMap::new()));

                let mut unlocked_map = map.lock().unwrap();

                unlocked_map.insert(
                    "haksul-proxy",
                    EndpointEntry::new(
                        "haksul-proxy".to_owned(),
                        "127.0.0.1".to_owned(),
                        80 as u16,
                        false,
                        false,
                        vec![],
                    ),
                );

                map.to_owned()
            },
        }
    }

    pub fn load_configuration(&self, file_path: &str) {
        let content = fs::read_to_string(file_path);
        let entries: Vec<EndpointEntry> =
            match serde_json::from_str(match content.as_deref().ok() {
                Some(data) => data,
                None => return,
            }) {
                Ok(data) => data,
                Err(_) => return,
            };
        for entry in entries.iter() {
            let mut unlocked_map = self.endpoint_map.lock().unwrap();
            unlocked_map.insert(entry.name.clone().leak(), entry.clone());
        }
    }

    pub fn get_peer(&self, key: &str, ctx: &mut ProxyCTX) -> Option<HttpPeer> {
        let unlocked_map = self.endpoint_map.lock().unwrap();
        unlocked_map.get(key).map(|endpoint| {
            let sni = endpoint.address.to_owned();
            if endpoint.is_outer {
                ctx.sni = Some(sni.clone());
            }

            HttpPeer::new(
                (endpoint.address.to_owned(), endpoint.port),
                endpoint.is_ssl,
                sni,
            )
        })
    }
}

pub struct ProxyApp {
    endpoint: Endpoint,
    proxy_password: String,
}

impl ProxyApp {
    pub fn new(endpoint: Endpoint, proxy_password: String) -> ProxyApp {
        return ProxyApp {
            endpoint,
            proxy_password,
        };
    }

    pub fn get_host(&self, session: &Session) -> String {
        if let Some(host) = session.get_header(http::header::HOST) {
            if let Ok(host_str) = host.to_str() {
                return host_str.to_string();
            }
        }

        if let Some(host) = session.req_header().uri.host() {
            return host.to_string();
        }

        "".to_string()
    }

    pub fn is_control_message(&self, session: &Session) -> bool {
        let headers = &session.req_header().headers;

        match headers
            .get(http::header::PROXY_AUTHORIZATION)
            .map(|v| v.to_str())
        {
            Some(v) => match v {
                Ok(v) => v == self.proxy_password,
                Err(_) => false,
            },
            None => false,
        }
    }
}

pub struct ProxyCTX {
    host: String,
    is_control: bool,
    sni: Option<String>,
}

#[async_trait]
impl ProxyHttp for ProxyApp {
    type CTX = ProxyCTX;
    fn new_ctx(&self) -> Self::CTX {
        return ProxyCTX {
            host: "jaram.net".to_string(),
            is_control: false,
            sni: None,
        };
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        ctx.is_control = self.is_control_message(session);

        let endpoint_host = {
            let host = self.get_host(session);
            let host_split: Vec<&str> = host.split(".").collect();
            let host_len = host_split.len();
            if host_split.len() < 2
                || (host_split[host_len - 2] != "jaram" && host_split[host_len - 1] != "net")
            {
                None
            } else {
                Some(host_split[0..host_len - 2].join("-"))
            }
        };

        let endpoint_key = session
            .get_header("X-Jaram-Container")
            .map(|v| v.to_str())
            .map(|v| v.ok().unwrap());

        ctx.host = match endpoint_key {
            Some(key) => key.to_string(),
            None => endpoint_host.unwrap_or("haksul-proxy".to_string()),
        };

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let not_found = Err(pingora_core::Error::new(pingora_core::ErrorType::Custom(
            "Cannot found such container",
        )));

        match self.endpoint.get_peer(&ctx.host.to_owned(), ctx) {
            Some(peer) => {
                println!("Peer to {}", peer);
                Ok(Box::new(peer))
            }
            None => not_found,
        }
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.sni.as_ref().map(|sni| {
            upstream_request
                .insert_header(http::header::HOST, sni.to_owned())
                .unwrap();
        });

        upstream_request.remove_header(&http::header::PROXY_AUTHORIZATION);
        upstream_request.remove_header("X-Jaram-Container");

        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_response
            .insert_header("Server", "HaksulProxy")
            .unwrap();

        upstream_response
            .insert_header(http::header::HOST, ctx.host.to_owned())
            .unwrap();

        upstream_response.remove_header("alt-svc");

        Ok(())
    }
}
