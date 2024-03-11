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

pub struct MyGateWayLimiter {
    max_req_ps: isize,
}

pub struct MyGateWay {
    endpoint: String,
    validator_endpoint: String,
    api_key: String,
    limiter: MyGateWayLimiter,
}

lazy_static! {
    static ref RATE_LIMITER_MAP: Arc<Mutex<HashMap<String, Rate>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

impl MyGateWay {
    pub fn get_request_token(&self, session: &Session) -> Option<String> {
        match session
            .req_header()
            .headers
            .get("Authorization")
            .map(|v| v.to_str())
        {
            None => None,
            Some(v) => match v {
                Ok(v) => Some(v.to_string()),
                Err(_) => None,
            },
        }
    }
}

#[async_trait]
impl ProxyHttp for MyGateWay {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let token = match self.get_request_token(session) {
            Some(v) => v,
            None => {
                session.respond_error(403).await;
                println!("No Token");
                return Ok(true);
            }
        };

        let validate_data = reqwest::Client::new()
            .post(self.validator_endpoint.to_owned())
            .body(token.to_owned())
            .send()
            .await;
        if validate_data.is_err() {
            session.respond_error(403).await;
            println!("Cannot connect validator server");
            return Ok(true);
        }

        if validate_data.ok().unwrap().status() != 200 {
            session.respond_error(403).await;
            println!("Not Valid Token");
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
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let addr = (self.endpoint.clone(), 443);

        let peer = Box::new(HttpPeer::new(addr, true, self.endpoint.clone()));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request
            .insert_header("Host", self.endpoint.clone())
            .unwrap();
        upstream_request
            .insert_header("Authorization", ["Bearer", &self.api_key].join(" "))
            .unwrap();
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

        Ok(())
    }
}

fn main() {
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

    let server_endpoint = env::var("ENDPOINT");
    if server_endpoint.is_err() {
        println!("Please append ENDPOINT env variable.");
        return;
    }

    let my_gateway = MyGateWay {
        endpoint: "api.openai.com".to_string(),
        validator_endpoint: validator_endpoint.ok().unwrap(),
        api_key: api_key.ok().unwrap(),
        limiter: MyGateWayLimiter { max_req_ps: 1 },
    };

    let mut my_proxy = pingora_proxy::http_proxy_service(&my_server.configuration, my_gateway);
    my_proxy.add_tcp(&server_endpoint.ok().unwrap());
    my_server.add_service(my_proxy);
    my_server.run_forever();
}
