use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use mmrs_protocol::{Event, NodeAnnounce, TicketRequest, TicketResponse, VoiceToken, subjects};

use crate::config::{TenantConfig, strip_port};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Tenant {
    pub name: String,
    pub endpoint: String,
    node_id: String,
    prefix: String,
    nats: async_nats::Client,
}

impl Tenant {
    async fn connect(config: &TenantConfig, node_id: &str) -> anyhow::Result<Self> {
        let mut options = async_nats::ConnectOptions::new()
            .name(format!("mmrs {node_id}"))
            .request_timeout(Some(RESOLVE_TIMEOUT))
            .retry_on_initial_connect();

        if let Some(path) = &config.nats_creds {
            options = options
                .credentials_file(path)
                .await
                .with_context(|| format!("tenant {}: reading {}", config.name, path.display()))?;
        }

        let nats = options
            .connect(config.nats_url.as_str())
            .await
            .with_context(|| format!("tenant {}: connecting to NATS", config.name))?;

        Ok(Self {
            name: config.name.clone(),
            endpoint: config.endpoint.clone(),
            node_id: node_id.to_owned(),
            prefix: config.subject_prefix.clone(),
            nats,
        })
    }

    pub async fn resolve(&self, token: VoiceToken) -> anyhow::Result<TicketResponse> {
        let request = TicketRequest {
            token,
            node_id: self.node_id.clone(),
        };

        let reply = self
            .nats
            .request(
                subjects::ticket_resolve(&self.prefix),
                serde_json::to_vec(&request)?.into(),
            )
            .await?;

        Ok(serde_json::from_slice(&reply.payload)?)
    }

    pub async fn publish(&self, event: &Event) {
        self.publish_json(subjects::events(&self.prefix, &self.node_id), event)
            .await;
    }

    pub async fn announce(&self, announce: &NodeAnnounce) {
        self.publish_json(subjects::nodes_announce(&self.prefix), announce)
            .await;
    }

    pub async fn subscribe_discover(&self) -> anyhow::Result<async_nats::Subscriber> {
        Ok(self
            .nats
            .subscribe(subjects::nodes_discover(&self.prefix))
            .await?)
    }

    pub async fn flush(&self) {
        if let Err(error) = self.nats.flush().await {
            tracing::warn!(%error, tenant = %self.name, "failed to flush NATS");
        }
    }

    async fn publish_json(&self, subject: String, value: &impl serde::Serialize) {
        let payload = match serde_json::to_vec(value) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(%error, tenant = %self.name, "failed to serialize payload");
                return;
            }
        };

        if let Err(error) = self.nats.publish(subject, payload.into()).await {
            tracing::warn!(%error, tenant = %self.name, "failed to publish");
        }
    }
}

pub struct Tenants {
    by_host: HashMap<String, Arc<Tenant>>,
}

impl Tenants {
    pub async fn connect(configs: &[TenantConfig], node_id: &str) -> anyhow::Result<Self> {
        let mut by_host = HashMap::new();
        for config in configs {
            let tenant = Tenant::connect(config, node_id).await?;
            tracing::info!(tenant = %config.name, endpoint = %config.endpoint, "tenant configured");

            by_host.insert(config.host.clone(), Arc::new(tenant));
        }
        Ok(Self { by_host })
    }

    /// `host` is a `Host` header value, possibly with a port.
    pub fn by_host(&self, host: &str) -> Option<Arc<Tenant>> {
        self.by_host
            .get(&strip_port(host).to_ascii_lowercase())
            .cloned()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Tenant>> {
        self.by_host.values()
    }
}
