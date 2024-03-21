use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use lazy_static::lazy_static;

use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_limits::rate::Rate;
use pingora_proxy::{ProxyHttp, Session};

use dotenv::dotenv;

use endpoint::MyEndpoint;
use validator::MyValidator;

mod endpoint;
mod validator;

pub struct MyGateWayLimiter {
    max_req_ps: isize,
}

pub struct MyGateWay {
    endpoint: MyEndpoint,
    validator: MyValidator,
    api_key: String,
    proxy_password: String,
    limiter: MyGateWayLimiter,
}

lazy_static! {
    static ref RATE_LIMITER_MAP: Arc<Mutex<HashMap<String, Rate>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

impl MyGateWay {
    pub fn get_request_token(&self, session: &Session) -> Option<String> {
        let headers = &session.req_header().headers;

        match headers.get("Authorization").map(|v| v.to_str()) {
            Some(v) => match v {
                Ok(v) => Some(v.to_string()),
                Err(_) => None,
            },
            None => None,
        }
    }

    pub fn is_control_message(&self, session: &Session) -> bool {
        let headers = &session.req_header().headers;

        match headers.get("X-Proxy-Authorization").map(|v| v.to_str()) {
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
}

#[async_trait]
impl ProxyHttp for MyGateWay {
    type CTX = MyCTX;
    fn new_ctx(&self) -> Self::CTX {
        return MyCTX {
            host: "server.jaram.net".to_string(),
            is_openai: false,
        };
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let token = match self.get_request_token(session) {
            Some(v) => v,
            None => {
                session.respond_error(403).await;
                println!("No Token");
                return Ok(true);
            }
        };

        if self.validator.validate(&token).await {
            session.respond_error(403).await;
            println!("Cannot connect validator server");
            return Ok(true);
        }

        let curr_window_requests = {
            let mut rate_limiter_map = RATE_LIMITER_MAP.lock().unwrap();
            let rate_limiter = match rate_limiter_map.get(&token) {
                Some(limiter) => limiter,
                None => {
                    let limiter = Rate::new(Duration::from_secs(1));
                    rate_limiter_map.insert(token.clone(), limiter);
                    rate_limiter_map.get(&token).unwrap()
                }
            };

            rate_limiter.observe(&token, 1)
        };

        if curr_window_requests > self.limiter.max_req_ps {
            let mut header = ResponseHeader::build(429, None).unwrap();
            header
                .insert_header("X-Rate-Limit-Limit", self.limiter.max_req_ps.to_string())
                .unwrap();
            header.insert_header("X-Rate-Limit-Remaining", "0").unwrap();
            header.insert_header("X-Rate-Limit-Reset", "1").unwrap();
            session.set_keepalive(None);
            session.write_response_header(Box::new(header)).await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let headers = &session.req_header().headers;
        let not_found = Err(pingora_core::Error::new(pingora_core::ErrorType::Custom(
            "Cannot found such container",
        )));

        let endpoint_key = match headers.get("X-Jaram-Container").map(|v| v.to_str()) {
            Some(v) => match v {
                Ok(v) => v,
                Err(_) => return not_found,
            },
            None => return not_found,
        };

        let peer = self.endpoint.get_peer(endpoint_key, ctx);
        match peer {
            Some(peer) => Ok(Box::new(peer)),
            None => not_found,
        }
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request
            .insert_header("Host", ctx.host.to_owned())
            .unwrap();

        if ctx.is_openai {
            upstream_request
                .insert_header("Authorization", ["Bearer", &self.api_key].join(" "))
                .unwrap();
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
        upstream_response.remove_header("X-Proxy-Authorization");
        upstream_response.remove_header("X-Jaram-Container");

        Ok(())
    }
}

fn main() {
    if dotenv().is_err() {
        println!("Please use .env file for configurations.");
        return;
    }

    let mut my_server = Server::new(None).unwrap();
    my_server.bootstrap();

    let validator_endpoint = env::var("VALIDATOR");
    if validator_endpoint.is_err() {
        println!("Please append VALIDATOR[<ip>:<port>] env variable.");
        return;
    }

    let api_key = env::var("OPENAI_API_KEY");
    if api_key.is_err() {
        println!("Please append OPENAI_API_KEY env variable.");
        return;
    }

    let server_endpoint = env::var("PROXY_ENDPOINT");
    if server_endpoint.is_err() {
        println!("Please append PROXY_ENDPOINT env variable.");
        return;
    }

    let server_password = env::var("PROXY_PASSWORD");
    if server_password.is_err() {
        println!("Please append PROXY_PASSWORD env variable.");
        return;
    }

    let validator = MyValidator {
        endpoint: validator_endpoint.ok().unwrap(),
    };

    let endpoint = MyEndpoint {};
    endpoint.load_configuration(".entries.json");

    let my_gateway = MyGateWay {
        endpoint,
        validator,
        api_key: api_key.ok().unwrap(),
        proxy_password: server_password.ok().unwrap(),
        limiter: MyGateWayLimiter { max_req_ps: 1 },
    };

    let mut my_proxy = pingora_proxy::http_proxy_service(&my_server.configuration, my_gateway);
    my_proxy.add_tcp(&server_endpoint.ok().unwrap());
    my_server.add_service(my_proxy);
    my_server.run_forever();
}
