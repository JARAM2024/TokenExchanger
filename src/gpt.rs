use std::env;

use pingora_proxy::Session;

use crate::MyValidator;

pub struct MyGPTProxy {
    server_token: String,
    validator: MyValidator,
}

impl MyGPTProxy {
    pub fn new() -> Option<Self> {
        let api_key = env::var("OPENAI_API_KEY");
        if api_key.is_err() {
            println!("Please append OPENAI_API_KEY env variable.");
            return None;
        }

        let validator_endpoint = env::var("VALIDATOR");
        if validator_endpoint.is_err() {
            println!("Please append VALIDATOR[<ip>:<port>] env variable.");
            return None;
        }

        Some(MyGPTProxy {
            server_token: api_key.ok().unwrap(),
            validator: MyValidator {
                endpoint: validator_endpoint.ok().unwrap(),
            },
        })
    }

    pub fn is_gpt(self: &Self, session: &Session) -> bool {
        let headers = &session.req_header().headers;

        let openai_endpoint_str = "openai-api";

        match headers.get("X-Jaram-Container").map(|v| v.to_str()) {
            Some(v) => match v {
                Ok(v) => v == openai_endpoint_str,
                Err(_) => false,
            },
            None => {
                let path = session.req_header().uri.path();
                let paths: Vec<&str> = path.split("/").collect();
                match paths[1] {
                    "" => false,
                    _ => paths[1] == openai_endpoint_str,
                }
            }
        }
    }

    fn get_request_token(&self, session: &Session) -> Option<String> {
        let headers = &session.req_header().headers;

        match headers.get("Authorization").map(|v| v.to_str()) {
            Some(v) => match v {
                Ok(v) => Some(v.to_string()),
                Err(_) => None,
            },
            None => None,
        }
    }

    pub async fn validate(self: &Self, session: &mut Session) -> bool {
        let token = match self.get_request_token(session) {
            Some(v) => v,
            None => {
                session.respond_error(403).await;
                println!("No Token");
                return true;
            }
        };

        if self.validator.validate(&token).await {
            session.respond_error(403).await;
            println!("Cannot connect validator server");
            return true;
        }

        false
    }

    pub fn update_token(self: &Self, upstream_request: &mut pingora_http::RequestHeader) {
        upstream_request
            .insert_header("Authorization", "Bearer ".to_owned() + &self.server_token)
            .unwrap();
    }
}
