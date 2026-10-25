use serde_json::{Value, json};

use crate::credential::Credential;
use crate::error::{Error, Result};
use crate::http;

const GRAPHQL_URL: &str = "https://api.linear.app/graphql";

/// The two kinds of HTTP call `lin` makes. Behind a trait so command tests
/// can replay recorded Linear responses without a network.
pub trait Transport {
    /// POST a GraphQL body; returns the HTTP status and parsed JSON (or Null).
    fn graphql(&self, body: &Value) -> Result<(u16, Value)>;
    /// PUT raw bytes to a pre-signed upload URL; returns the HTTP status.
    fn put(&self, url: &str, headers: &[(String, String)], bytes: &[u8]) -> Result<u16>;
}

struct HttpTransport {
    authorization: String,
}

impl Transport for HttpTransport {
    fn graphql(&self, body: &Value) -> Result<(u16, Value)> {
        let mut resp = http::agent()
            .post(GRAPHQL_URL)
            .header("Authorization", &self.authorization)
            .send_json(body)?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string()?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    fn put(&self, url: &str, headers: &[(String, String)], bytes: &[u8]) -> Result<u16> {
        let mut req = http::agent().put(url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        Ok(req.send(bytes)?.status().as_u16())
    }
}

pub struct Client {
    transport: Box<dyn Transport>,
}

impl Client {
    pub fn new(cred: &Credential) -> Client {
        Client::with_transport(HttpTransport {
            authorization: cred.authorization_header(),
        })
    }

    pub fn with_transport(t: impl Transport + 'static) -> Client {
        Client {
            transport: Box::new(t),
        }
    }

    /// Run a GraphQL operation and return its `data`.
    pub fn graphql(&self, query: &str, variables: Value) -> Result<Value> {
        let (status, body) = self
            .transport
            .graphql(&json!({ "query": query, "variables": variables }))?;
        extract_data(status, body)
    }

    pub fn put(&self, url: &str, headers: &[(String, String)], bytes: &[u8]) -> Result<u16> {
        self.transport.put(url, headers, bytes)
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
        // OAuth logins default to narrow scopes; say how to widen them.
        let message = if message.to_lowercase().contains("scope") {
            format!("{message} (to allow this, run `lin auth login --scope write`)")
        } else {
            message
        };
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
    fn scope_errors_suggest_relogin() {
        let e = extract_data(
            400,
            json!({ "errors": [{ "message": "Invalid scope: `write` required" }] }),
        )
        .unwrap_err();
        assert!(e.to_string().contains("--scope write"));
    }

    #[test]
    fn non_json_failure() {
        let e = extract_data(502, Value::Null).unwrap_err();
        assert!(e.to_string().contains("502"));
    }
}
