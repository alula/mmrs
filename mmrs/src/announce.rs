use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use mmrs_protocol::{NodeAnnounce, NodeState};

use crate::AppState;
use crate::tenant::Tenant;

const INTERVAL: Duration = Duration::from_secs(10);
const TTL_SECS: u32 = 30;

pub fn spawn(state: &Arc<AppState>) {
    for tenant in state.tenants.iter() {
        tokio::spawn(run(state.clone(), tenant.clone()));
    }
}

/// Announces on startup, every [`INTERVAL`] and on every discover request,
/// then `gone` once on shutdown.
async fn run(state: Arc<AppState>, tenant: Arc<Tenant>) {
    let mut discover = match tenant.subscribe_discover().await {
        Ok(subscriber) => Some(subscriber),
        Err(error) => {
            tracing::warn!(%error, tenant = %tenant.name, "failed to subscribe to node discovery");
            None
        }
    };
    let mut interval = tokio::time::interval(INTERVAL);
    let mut shutdown = state.shutdown.clone();

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            Some(_) = next(&mut discover) => {}
            _ = shutdown.wait_for(|stop| *stop) => break,
        }

        tenant
            .announce(&announcement(&state, &tenant, NodeState::Ready))
            .await;
    }

    tenant
        .announce(&announcement(&state, &tenant, NodeState::Gone))
        .await;
    tenant.flush().await;
}

async fn next(subscriber: &mut Option<async_nats::Subscriber>) -> Option<async_nats::Message> {
    match subscriber {
        Some(subscriber) => subscriber.next().await,
        None => std::future::pending().await,
    }
}

fn announcement(state: &AppState, tenant: &Tenant, node_state: NodeState) -> NodeAnnounce {
    NodeAnnounce {
        node_id: state.config.node_id.clone(),
        endpoint: tenant.endpoint.clone(),
        region: state.config.region.clone(),
        state: node_state,
        participants: state.sessions.count() as u32,
        capacity: state.config.capacity,
        ttl_secs: TTL_SECS,
    }
}
