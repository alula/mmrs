use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, bail};

use crate::encryption::EncryptionMode;
use crate::proxy::TrustedProxies;

pub struct Config {
    pub node_id: String,
    pub voice_bind: SocketAddr,
    pub tls: Option<TlsConfig>,
    pub trusted_proxies: TrustedProxies,
    pub media_ipv4: Ipv4Addr,
    pub media_ipv6: Option<Ipv6Addr>,
    pub media_port: u16,
    pub enable_ipv6: bool,
    pub enable_dave: bool,
    pub require_dave: bool,
    pub min_gateway_version: u8,
    pub encryption_modes: Vec<EncryptionMode>,
    pub region: Option<String>,
    pub capacity: Option<u32>,
    pub tenants: Vec<Arc<TenantConfig>>,
}

pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

pub struct TenantConfig {
    pub name: String,
    /// `host(:port)` handed to clients. The host also selects the tenant.
    pub endpoint: String,
    pub host: String,
    pub nats_url: String,
    pub nats_creds: Option<PathBuf>,
    pub subject_prefix: String,
    pub require_dave: bool,
    pub min_gateway_version: u8,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let encryption_modes = match optional("ENCRYPTION_MODES") {
            Some(modes) => list(&modes)
                .map(str::parse)
                .collect::<Result<Vec<_>, _>>()?,
            None => EncryptionMode::DEFAULT.to_vec(),
        };
        if encryption_modes.is_empty() {
            bail!("ENCRYPTION_MODES is empty");
        }

        let enable_dave = parse_or("ENABLE_DAVE", true)?;
        let require_dave = parse_or("REQUIRE_DAVE", false)?;

        if require_dave && !enable_dave {
            bail!("cannot enforce DAVE when it's not enabled");
        }
        let tls = match (optional("TLS_CERT"), optional("TLS_KEY")) {
            (Some(cert), Some(key)) => Some(TlsConfig {
                cert: cert.into(),
                key: key.into(),
            }),
            (None, None) => None,
            _ => bail!("TLS_CERT and TLS_KEY must be set together"),
        };

        let trusted_proxies = match optional("TRUSTED_PROXIES").as_deref() {
            Some("all") => TrustedProxies::All,
            Some(proxies) => {
                let mut ips = Vec::new();
                for entry in list(proxies) {
                    let Ok(ip) = entry.parse::<IpAddr>() else {
                        bail!("invalid TRUSTED_PROXIES entry {entry}");
                    };
                    ips.push(ip.to_canonical());
                }
                TrustedProxies::Only(ips)
            }
            None => TrustedProxies::Only(Vec::new()),
        };

        let mut config = Self {
            node_id: required("NODE_ID")?,
            voice_bind: parse_or("VOICE_BIND", SocketAddr::from(([0, 0, 0, 0], 8080)))?,
            tls,
            trusted_proxies,
            media_ipv4: parse("MEDIA_IPV4")?.context("MEDIA_IPV4 is required")?,
            media_ipv6: parse("MEDIA_IPV6")?,
            media_port: parse_or("MEDIA_PORT", 50000)?,
            enable_ipv6: parse_or("ENABLE_IPV6", true)?,
            enable_dave: parse_or("ENABLE_DAVE", true)?,
            require_dave: parse_or("REQUIRE_DAVE", false)?,
            min_gateway_version: parse_or("MIN_GATEWAY_VERSION", 1)?,
            encryption_modes,
            region: optional("REGION"),
            capacity: parse("CAPACITY")?,
            tenants: Vec::new(),
        };

        let tenants = list(&required("TENANTS")?)
            .map(|name| TenantConfig::from_env(&config, name))
            .collect::<anyhow::Result<Vec<_>>>()?;

        if tenants.is_empty() {
            bail!("no tenants configured");
        }

        for (i, tenant) in tenants.iter().enumerate() {
            if tenants[..i].iter().any(|other| other.host == tenant.host) {
                bail!("tenants share the host {}", tenant.host);
            }
        }

        config.tenants = tenants;

        Ok(config)
    }
}

impl TenantConfig {
    fn from_env(base_config: &Config, name: &str) -> anyhow::Result<Arc<Self>> {
        let var = |suffix: &str| format!("TENANT_{}_{suffix}", name.to_ascii_uppercase());
        let endpoint = required(&var("ENDPOINT"))?.to_ascii_lowercase();

        Ok(Arc::new(Self {
            name: name.to_owned(),
            host: strip_port(&endpoint).to_owned(),
            endpoint,
            nats_url: required(&var("NATS_URL"))?,
            nats_creds: optional(&var("NATS_CREDS")).map(PathBuf::from),
            subject_prefix: optional(&var("SUBJECT_PREFIX"))
                .unwrap_or_else(|| mmrs_protocol::subjects::DEFAULT_PREFIX.to_owned()),
            // todo: invalid values should probably explicitly bail out
            require_dave: optional(&var("REQUIRE_DAVE"))
                .map(|v| v.parse().unwrap_or(base_config.require_dave))
                .unwrap_or(base_config.require_dave),
            min_gateway_version: optional(&var("MIN_GATEWAY_VERSION"))
                .map(|v| v.parse().unwrap_or(base_config.min_gateway_version))
                .unwrap_or(base_config.min_gateway_version),
        }))
    }
}

/// Strips the port from `host:port`, `host` or `[ipv6]:port`.
pub fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(addr, _)| addr);
    }
    host.rsplit_once(':').map_or(host, |(name, _)| name)
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn required(name: &str) -> anyhow::Result<String> {
    optional(name).with_context(|| format!("{name} is required"))
}

fn parse<T: FromStr>(name: &str) -> anyhow::Result<Option<T>>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    optional(name)
        .map(|v| v.parse().with_context(|| format!("invalid {name}")))
        .transpose()
}

fn parse_or<T: FromStr>(name: &str, default: T) -> anyhow::Result<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    Ok(parse(name)?.unwrap_or(default))
}

#[cfg(test)]
mod tests {
    use super::strip_port;

    #[test]
    fn strips_port() {
        assert_eq!(
            strip_port("mooncord-n1.example.com:2096"),
            "mooncord-n1.example.com"
        );
        assert_eq!(
            strip_port("mooncord-n1.example.com"),
            "mooncord-n1.example.com"
        );
        assert_eq!(strip_port("[::1]:8080"), "::1");
    }
}
