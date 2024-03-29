use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingora_http::ResponseHeader;
use pingora_limits::rate::Rate;
use pingora_proxy::Session;

use lazy_static::lazy_static;

pub struct MyGateWayLimiter {
    pub max_req_ps: isize,
}

lazy_static! {
    static ref RATE_LIMITER_MAP: Arc<Mutex<HashMap<String, Rate>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

impl MyGateWayLimiter {
    fn get_id(self: &Self, session: &Session) -> Option<String> {
        match session
            .req_header()
            .headers
            .get("Authorization")
            .map(|v| v.to_str())
        {
            Some(v) => match v {
                Ok(v) => return Some(v.to_string()),
                Err(_) => return None,
            },
            None => None,
        }
    }

    pub async fn block(self: &Self, session: &mut Session) -> bool {
        let id = match self.get_id(session) {
            Some(v) => v,
            None => return false,
        };
        let curr_window_requests = {
            let mut rate_limiter_map = RATE_LIMITER_MAP.lock().unwrap();
            let rate_limiter = match rate_limiter_map.get(&id) {
                Some(limiter) => limiter,
                None => {
                    let limiter = Rate::new(Duration::from_secs(1));
                    rate_limiter_map.insert(id.to_owned(), limiter);
                    rate_limiter_map.get(&id).unwrap()
                }
            };

            rate_limiter.observe(&id, 1)
        };

        if curr_window_requests > self.max_req_ps {
            let mut header = ResponseHeader::build(429, None).unwrap();
            header
                .insert_header("X-Rate-Limit-Limit", self.max_req_ps.to_string())
                .unwrap();
            header.insert_header("X-Rate-Limit-Remaining", "0").unwrap();
            header.insert_header("X-Rate-Limit-Reset", "1").unwrap();
            session.set_keepalive(None);
            session
                .write_response_header(Box::new(header))
                .await
                .unwrap();
            return true;
        }

        return false;
    }
}
