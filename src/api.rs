use serde_json::{Value, json};

use crate::credential::Credential;
use crate::error::{Error, Result};
use crate::http;

const GRAPHQL_URL: &str = "https://api.linear.app/graphql";

pub struct Client {
    authorization: String,
}

impl Client {
    pub fn new(cred: &Credential) -> Client {
        Client {
            authorization: cred.authorization_header(),
        }
    }

    /// Run a GraphQL operation and return its `data`.
    pub fn graphql(&self, query: &str, variables: Value) -> Result<Value> {
        let mut resp = http::agent()
            .post(GRAPHQL_URL)
            .header("Authorization", &self.authorization)
            .send_json(json!({ "query": query, "variables": variables }))?;
        let status = resp.status();
        let body = resp.body_mut().read_to_string()?;
        let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        extract_data(status.as_u16(), parsed)
    }

    pub fn viewer(&self) -> Result<Value> {
        let data = self.graphql(
            "query { viewer { id name email } organization { name urlKey } }",
            json!({}),
        )?;
        Ok(json!({ "user": data["viewer"], "organization": data["organization"] }))
    }
}

fn extract_data(status: u16, body: Value) -> Result<Value> {
    if let Some(errors) = body.get("errors").and_then(Value::as_array)
        && !errors.is_empty()
    {
        let message = errors[0]["message"]
            .as_str()
            .unwrap_or("unknown error")
            .to_string();
        return Err(Error::Api {
            message,
            details: Value::Array(errors.clone()),
        });
    }
    if !(200..300).contains(&status) {
        return Err(Error::Api {
            message: format!("HTTP {status}"),
            details: body,
        });
    }
    Ok(body.get("data").cloned().unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_is_returned() {
        let v = extract_data(200, json!({ "data": { "viewer": { "id": "u1" } } })).unwrap();
        assert_eq!(v["viewer"]["id"], "u1");
    }

    #[test]
    fn graphql_errors_become_api_errors() {
        let e = extract_data(
            400,
            json!({ "errors": [{ "message": "Authentication required" }] }),
        )
        .unwrap_err();
        assert_eq!(e.code(), "api_error");
        assert!(e.to_string().contains("Authentication required"));
        assert_eq!(
            e.to_json()["error"]["details"][0]["message"],
            "Authentication required"
        );
    }

    #[test]
    fn non_json_failure() {
        let e = extract_data(502, Value::Null).unwrap_err();
        assert!(e.to_string().contains("502"));
    }
}
