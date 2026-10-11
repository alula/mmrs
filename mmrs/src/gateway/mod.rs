mod close;
mod connection;
mod opcode;
mod payload;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{CloseFrame, Message, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use close::CloseCode;
use connection::Connection;

/// Discord answers HELLO with 8 to clients requesting 9 or 10.
const MAX_VERSION: u8 = 8;

#[derive(Deserialize)]
pub struct VersionQuery {
    v: Option<String>,
}

pub async fn handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    Query(query): Query<VersionQuery>,
    headers: HeaderMap,
) -> Response {
    let requested = match query.v.as_deref().map(str::parse::<u8>) {
        None => 1,
        Some(Ok(v)) => v,
        Some(Err(_)) => return (StatusCode::BAD_REQUEST, "invalid gateway version").into_response(),
    };
    if requested < state.config.min_gateway_version {
        return (StatusCode::BAD_REQUEST, "gateway version too old").into_response();
    }

    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or_default();
    let tenant = state.tenants.by_host(host);

    ws.on_upgrade(move |mut socket| async move {
        match tenant {
            Some(tenant) => {
                let version = requested.min(MAX_VERSION);
                Connection::new(socket, state, tenant, version, client_addr).run().await;
            }
            None => {
                let _ = socket.send(close_message(CloseCode::ServerNotFound)).await;
            }
        }
    })
}

fn close_message(code: CloseCode) -> Message {
    Message::Close(Some(CloseFrame { code: code as u16, reason: code.reason().into() }))
}
