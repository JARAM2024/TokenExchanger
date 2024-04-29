use std::env;

use async_trait::async_trait;

use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_core::{server::Server, Error};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

use dotenv::dotenv;

use endpoint::MyEndpoint;
use gpt::MyGPTProxy;
use limiter::MyGateWayLimiter;
use validator::MyValidator;

mod endpoint;
mod gpt;
mod limiter;
mod validator;

pub struct MyGateWay {
    endpoint: MyEndpoint,
    gpt: MyGPTProxy,
    proxy_password: String,
    limiter: MyGateWayLimiter,
}

impl MyGateWay {
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

        match headers.get("Proxy-Authorization").map(|v| v.to_str()) {
            Some(v) => match v {
                Ok(v) => v == self.proxy_password,
                Err(_) => false,
            },
            None => false,
        }
    }
}

pub struct MyCTX {
    host: String,
    is_openai: bool,
    is_control: bool,
}

#[async_trait]
impl ProxyHttp for MyGateWay {
    type CTX = MyCTX;
    fn new_ctx(&self) -> Self::CTX {
        return MyCTX {
            host: "jaram.net".to_string(),
            is_openai: false,
            is_control: false,
        };
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        ctx.is_openai = self.gpt.is_gpt(session);
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

        Ok(self.limiter.block(session).await)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let not_found = Err(pingora_core::Error::new(pingora_core::ErrorType::Custom(
            "Cannot found such container",
        )));

        let peer = self.endpoint.get_peer(&ctx.host.to_owned(), ctx);
        match peer {
            Some(peer) => {
                println!("Peer to {}", peer);
                Ok(Box::new(peer))
            }
            None => not_found,
        }
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if ctx.is_openai {
            if self.gpt.validate(session).await {
                self.gpt.update_token(upstream_request);
            } else {
                return Err(Error::new_str("Cannot validate token"));
            }
        }

        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_response
            .insert_header("Server", "MyGateWay")
            .unwrap();

        upstream_response.remove_header("alt-svc");
        upstream_response.remove_header("X-Jaram-Container");

        Ok(())
    }
}

fn main() {
    dotenv().expect("Please use .env file for configurations.");

    let mut my_server = Server::new(None).unwrap();
    my_server.bootstrap();

    let proxy_endpoint =
        env::var("PROXY_ENDPOINT").expect("Please append PROXY_ENDPOINT env variable.");
    let proxy_password =
        env::var("PROXY_PASSWORD").expect("Please append PROXY_PASSWORD env variable.");

    let gpt = MyGPTProxy::new();

    let endpoint = MyEndpoint {};
    endpoint.load_configuration(".entries.json");

    let my_gateway = MyGateWay {
        endpoint,
        proxy_password,
        gpt,
        limiter: MyGateWayLimiter { max_req_ps: 1 },
    };

    let cert_path = format!(
        "{}/proxy.crt",
        env::var("PROXY_MANIFEST_DIR").expect("PROXY_MANIFEST_DIR should exist in .env")
    );
    let key_path = format!(
        "{}/proxy.key",
        env::var("PROXY_MANIFEST_DIR").expect("PROXY_MANIFEST_DIR should exist in .env")
    );

    let mut tls_settings =
        pingora_core::listeners::TlsSettings::intermediate(&cert_path, &key_path).unwrap();
    tls_settings.enable_h2();

    let mut my_proxy = pingora_proxy::http_proxy_service(&my_server.configuration, my_gateway);
    my_proxy.add_tls_with_settings(&proxy_endpoint, None, tls_settings);
    my_server.add_service(my_proxy);
    my_server.run_forever();
}
