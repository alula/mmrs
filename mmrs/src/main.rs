mod announce;
mod config;
mod encryption;
mod gateway;
mod media;
mod mls;
mod room;
mod session;
mod tenant;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, watch};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use config::Config;
use gateway::Parking;
use media::Media;
use room::Rooms;
use session::Sessions;
use tenant::Tenants;

const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct AppState {
    pub config: Config,
    pub tenants: Tenants,
    pub sessions: Sessions,
    pub rooms: Arc<Rooms>,
    pub parking: Parking,
    pub media: Arc<Media>,
    pub shutdown: watch::Receiver<bool>,
    /// Dropped with the last connection, which closes the drain channel in `main`.
    _alive: mpsc::Sender<()>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(fmt::layer())
        .init();

    let config = Config::from_env()?;
    let tls = config
        .tls
        .as_ref()
        .map(|tls| tls::load(&tls.cert, &tls.key))
        .transpose()?;

    let media = Media::bind(&config).await?;
    tokio::spawn(media.clone().run());
    tokio::spawn(media.clone().report());
    tokio::spawn(media.clone().tick());

    let tenants = Tenants::connect(&config.tenants, &config.node_id).await?;
    let bind = config.voice_bind;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (alive_tx, mut alive_rx) = mpsc::channel(1);

    let state = Arc::new(AppState {
        config,
        tenants,
        sessions: Sessions::default(),
        rooms: Arc::default(),
        parking: Parking::default(),
        media,
        shutdown: shutdown_rx.clone(),
        _alive: alive_tx,
    });

    announce::spawn(&state);

    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutting down");
        let _ = shutdown_tx.send(true);
    });

    let stopped = async move {
        let mut shutdown = shutdown_rx;
        let _ = shutdown.wait_for(|stop| *stop).await;
    };

    let app = Router::new()
        .route("/", get(gateway::handler))
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    match tls {
        Some(tls) => {
            let handle = axum_server::Handle::new();

            tokio::spawn({
                let handle = handle.clone();
                async move {
                    stopped.await;
                    handle.graceful_shutdown(Some(DRAIN_TIMEOUT));
                }
            });

            tracing::info!(%bind, "voice gateway listening with TLS");
            axum_server::bind_rustls(bind, tls)
                .handle(handle)
                .serve(app)
                .await?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(bind).await?;

            tracing::info!(%bind, "voice gateway listening");
            axum::serve(listener, app)
                .with_graceful_shutdown(stopped)
                .await?;
        }
    }

    // Upgraded WebSockets are not tracked by the graceful shutdown above.
    if tokio::time::timeout(DRAIN_TIMEOUT, alive_rx.recv())
        .await
        .is_err()
    {
        tracing::warn!("voice connections still open after the drain timeout");
    }
    Ok(())
}

async fn shutdown_signal() {
    let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}
