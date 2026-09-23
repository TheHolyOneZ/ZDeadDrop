use std::sync::{Arc, Mutex};

use zdd_core::checkin::RelayKeypair;
use zdd_core::secret::Key32;

use zdd_relay::{api, notify, schedule, store};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    zdd_core::harden_process();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zdd_relay=info,tower_http=warn".into()),
        )
        .init();

    if std::env::args().any(|a| a == "--healthcheck") {
        let data = std::env::var("ZDD_RELAY_DATA").unwrap_or_else(|_| "/var/lib/zdd-relay".into());
        return match std::fs::metadata(&data) {
            Ok(m) if m.is_dir() => Ok(()),
            _ => Err(format!("data directory {data} is not reachable").into()),
        };
    }

    let data = std::env::var("ZDD_RELAY_DATA").unwrap_or_else(|_| "/var/lib/zdd-relay".into());
    let data = std::path::PathBuf::from(data);
    std::fs::create_dir_all(&data)?;

    let keypair = load_or_create_key(&data.join("relay.key"))?;
    tracing::info!(
        verifying_key = %zdd_core::codec::to_hex(&keypair.verifying()),
        "relay identity"
    );

    let db = store::open(&data.join("relay.db"))?;
    let state = Arc::new(api::Relay {
        db: Mutex::new(db),
        keypair,
        clock: zdd_core::clock::SystemClock,
    });

    let app = api::router(Arc::clone(&state)).layer(
        tower::ServiceBuilder::new()
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .layer(tower_http::limit::RequestBodyLimitLayer::new(256 * 1024))
            .layer(tower_http::timeout::TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                std::time::Duration::from_secs(30),
            )),
    );

    let base_url =
        std::env::var("ZDD_RELAY_URL").unwrap_or_else(|_| "http://localhost:8787".into());
    tokio::spawn(schedule::run(
        Arc::clone(&state),
        notify::Sender::from_env(),
        base_url,
    ));

    let bind = std::env::var("ZDD_RELAY_BIND").unwrap_or_else(|_| "0.0.0.0:8787".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

fn load_or_create_key(path: &std::path::Path) -> std::io::Result<RelayKeypair> {
    if path.exists() {
        let hex = std::fs::read_to_string(path)?;
        let bytes = zdd_core::codec::from_hex(hex.trim()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed relay key")
        })?;
        let seed = Key32::from_slice(&bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "relay key is the wrong length",
            )
        })?;
        return Ok(RelayKeypair::from_seed(&seed));
    }

    let seed = Key32::random();
    std::fs::write(path, zdd_core::codec::to_hex(seed.expose()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::warn!(path = %path.display(), "generated a new relay signing key");
    Ok(RelayKeypair::from_seed(&seed))
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
