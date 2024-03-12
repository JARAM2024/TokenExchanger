use std::string::String;

pub struct MyValidator {
    pub endpoint: String,
}

impl MyValidator {
    pub async fn validate(self: &Self, token: &String) -> bool {
        let validate_data = reqwest::Client::new()
            .post(self.endpoint.to_owned())
            .body(token.to_owned())
            .send()
            .await;

        if validate_data.is_err() {
            return false;
        }

        if validate_data.ok().unwrap().status() != 200 {
            return false;
        }

        true
    }
}
