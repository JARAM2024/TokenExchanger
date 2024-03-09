use std::env;

use async_trait::async_trait;

use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

fn check_valid_token(req: &pingora_http::RequestHeader, password: &String) -> bool {
    req.headers.get("Authorization").map(|v| v.as_bytes()) == Some(password.as_bytes())
}

pub struct MyGateWay {
    endpoint: String,
    password: String,
    api_key: String,
}

#[async_trait]
impl ProxyHttp for MyGateWay {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        if !check_valid_token(session.req_header(), &self.password) {
            let _ = session.respond_error(403).await;

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

    let password = env::var("TE_PASSWORD");
    if password.is_err() {
        println!("Please append TE_PASSWORD env variable.");
        return;
    }

    let api_key = env::var("OPENAI_API_KEY");
    if api_key.is_err() {
        println!("Please append OPENAI_API_KEY env variable.");
        return;
    }

    let my_gateway = MyGateWay {
        endpoint: "api.openai.com".to_string(),
        password: password.ok().unwrap(),
        api_key: api_key.ok().unwrap(),
    };

    let mut my_proxy = pingora_proxy::http_proxy_service(&my_server.configuration, my_gateway);
    my_proxy.add_tcp("127.0.0.1:6191");
    my_server.add_service(my_proxy);
    my_server.run_forever();
}
