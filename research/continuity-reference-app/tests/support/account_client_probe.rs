// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Qualification-only real HTTP client. Software test passkeys stay in memory;
//! no cookie, private key, issuer or account-login bypass is exported.
#[path = "account_http.rs"]
mod account_http;
use account_http::{Authenticator, Client, Endpoint, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Read, Write},
    net::{Ipv4Addr, SocketAddr},
};
use webauthn_rs::prelude::Url;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Register {
        account: String,
    },
    Login {
        account: String,
    },
    Request {
        account: String,
        route: String,
        body: Option<Value>,
        disconnect_before_body: bool,
    },
    Finish,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u16,
    command: Action,
}
struct Account {
    client: Client,
    authenticator: Authenticator,
}

fn endpoint() -> Result<Endpoint> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("Usage: account-client-probe <isolated-test-http://localhost:port>".into());
    }
    let url = Url::parse(&args[1])?;
    let port = url
        .port()
        .filter(|p| *p != 0)
        .ok_or("Explicit local port required")?;
    if url.scheme() != "http"
        || url.host_str() != Some("localhost")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.origin().ascii_serialization() != args[1]
    {
        return Err("Qualification endpoint must be a canonical loopback origin".into());
    }
    Ok(Endpoint {
        address: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        origin: args[1].clone(),
    })
}
async fn execute(
    endpoint: &Endpoint,
    accounts: &mut BTreeMap<String, Account>,
    command: Action,
) -> Result<Value> {
    match command {
        Action::Register { account } => {
            if accounts.len() >= 4 || accounts.contains_key(&account) {
                return Err("Test account identity already retained or capacity reached".into());
            }
            let mut client = Client::default();
            let authenticator = client.register(endpoint, &account).await?;
            accounts.insert(
                account,
                Account {
                    client,
                    authenticator,
                },
            );
            Ok(json!({"authenticated":"registered_software_test_passkey"}))
        }
        Action::Login { account } => {
            let selected = accounts
                .get_mut(&account)
                .ok_or("Original test authenticator absent")?;
            selected
                .client
                .login(endpoint, &account, &mut selected.authenticator)
                .await?;
            Ok(json!({"authenticated":"original_software_test_passkey"}))
        }
        Action::Request {
            account,
            route,
            body,
            disconnect_before_body,
        } => {
            if route != "/api/me" && !route.starts_with("/api/enrollment/") {
                return Err("Test client only dispatches enrollment routes".into());
            }
            let client = &mut accounts
                .get_mut(&account)
                .ok_or("Test account is not authenticated")?
                .client;
            let response = match (body, disconnect_before_body) {
                (None, false) => client.get(endpoint, &route).await?,
                (Some(body), false) => client.post(endpoint, &route, body).await?,
                (Some(body), true) => {
                    client
                        .disconnect_before_body(endpoint, &route, body)
                        .await?
                }
                (None, true) => return Err("Lost body probe requires an explicit POST".into()),
            };
            Ok(
                json!({"status":response.code,"body":String::from_utf8(response.body)?,"content_type":response.content_type}),
            )
        }
        Action::Finish => Err("Finish must close the command loop".into()),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result {
    let endpoint = endpoint()?;
    let mut input = io::stdin().lock();
    let mut accounts = BTreeMap::new();
    for expected in 1..=256u16 {
        let mut raw = Vec::new();
        // Limit before JSON parsing or allocation beyond one bounded command.
        let size = (&mut input)
            .take(128 * 1024 + 1)
            .read_until(b'\n', &mut raw)?;
        if size == 0 {
            return Err("Probe EOF before explicit finish".into());
        }
        if raw.len() > 128 * 1024 || raw.last() != Some(&b'\n') {
            return Err("Probe command bound or framing".into());
        }
        let request: Request = serde_json::from_slice(&raw)?;
        if request.id != expected {
            return Err("Probe command identity differs".into());
        }
        let finish = matches!(request.command, Action::Finish);
        let result = if finish {
            json!({"finished":true})
        } else {
            execute(&endpoint, &mut accounts, request.command).await?
        };
        println!(
            "{}",
            serde_json::to_string(&json!({"id":request.id,"result":result}))?
        );
        io::stdout().flush()?;
        if finish {
            return Ok(());
        }
    }
    Err("Probe command capacity exceeded".into())
}
