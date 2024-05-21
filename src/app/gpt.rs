use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{self, HeaderValue, StatusCode};
use pingora::{connectors::http::Connector, upstreams::peer::HttpPeer, Result};
use pingora_http::RequestHeader;
use pingora_proxy::Session;

pub struct GPT {
    host: String,
    validator: Validator,
}

impl GPT {
    fn get_validator_body(&self, user_token: &HeaderValue) -> BytesMut {
        let mut bytes = BytesMut::new();
        bytes.put(&b"{token: "[..]);
        bytes.put(user_token.as_bytes());
        bytes.put(&b"}"[..]);

        bytes
    }
}

struct Validator {
    host: String,
    port: u16,
    path: String,
}

impl GPT {
    pub fn new() -> Self {
        return GPT {
            host: "api.openai.com".to_string(),
            validator: Validator {
                host: "haksulapi.jaram.net".to_string(),
                port: 443,
                path: "/api/gpt/validate".to_string(),
            },
        };
    }

    pub fn is_gpt(&self, session: &Session) -> bool {
        let Some(host) = session.get_header("X-Jaram-Container") else {
            let Some(host) = session.get_header(http::header::HOST) else {
                return false;
            };

            return self.host.eq(host);
        };
        host.eq("openai-api")
    }

    pub async fn is_valid(&self, session: &mut Session) -> Result<bool> {
        let Some(auth) = session.get_header("Authorization") else {
            return Ok(false);
        };

        let connector = Connector::new(None);
        let mut peer = HttpPeer::new(
            (self.validator.host.to_owned(), self.validator.port),
            true,
            self.validator.host.to_owned(),
        );
        peer.options.set_http_version(2, 1);
        peer.options.verify_cert = false;
        println!("Validator => {}", peer);
        let (mut http, _reused) = connector.get_http_session(&peer).await?;

        let mut new_request = RequestHeader::build("POST", self.validator.path.as_bytes(), None)?;
        new_request.insert_header("Host", &self.validator.host)?;
        new_request.insert_header("X-Jaram-Container", "haksulapi")?;
        http.write_request_header(Box::new(new_request)).await?;

        let body = self.get_validator_body(auth);
        http.write_request_body(Bytes::from(body), true).await?;
        http.finish_request_body().await?;
        http.read_response_header().await?;

        let Some(response) = http.read_response_body().await? else {
            return Ok(false);
        };

        let Some(header) = http.response_header() else {
            return Ok(false);
        };

        if header.status == StatusCode::OK {
            session
                .req_header_mut()
                .append_header(
                    "Authorization",
                    format!("Bearer: {}", String::from_utf8_lossy(response.chunk())),
                )
                .unwrap();

            return Ok(true);
        }

        Ok(false)
    }
}
