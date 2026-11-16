use std::{fs, path::PathBuf, sync::Arc};

use clap::Parser;
use echo_server::router::EchoRouter;
use rootcause::prelude::ResultExt;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sqlx::postgres::PgPoolOptions;

#[derive(clap::Parser)]
struct Cli {
    /// The PostgreSQL database URL to connect to.
    #[arg(long)]
    database_url: String,

    /// How many PostgreSQL connections to allow.
    /// Default is 30.
    #[arg(long)]
    db_connection_limit: Option<u32>,

    /// The assets directory to interact with.
    #[arg(long)]
    assets_dir: PathBuf,

    /// The host IP to run the server on.
    /// By default, this is 0.0.0.0
    #[arg(long)]
    host: Option<String>,

    /// The port to run the server on.
    /// By default, it is 53815.
    #[arg(short, long)]
    port: Option<u16>,

    /// Path to TLS certificate in PEM format
    #[arg(long)]
    cert: PathBuf,

    /// Path to TLS private key in PEM format
    #[arg(long)]
    key: PathBuf,

    /// How many separate QUIC connections to accept.
    /// Default is 100.
    #[arg(long)]
    connection_limit: Option<usize>,

    /// What file to log to.
    /// If not mentioned, this will log to stderr.
    #[arg(long)]
    log_path: Option<PathBuf>
}

#[tokio::main]
async fn main() -> rootcause::Result<()> {
    let cli = Cli::parse();

    let certs = if cli.cert.extension().is_some_and(|x| x == "der") {
        let content = fs::read(&cli.cert)
            .context("failed to read certificate chain file")?;

        vec![CertificateDer::from(content)]
    }
    else {
        CertificateDer::pem_file_iter(&cli.cert)
            .context("failed to read PEM from certificate chain file")?
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?
    };

    let key = PrivateKeyDer::from_pem_file(cli.key)?;

    let pool = PgPoolOptions::new()
        .max_connections(cli.db_connection_limit.unwrap_or(30))
        .connect_lazy(&cli.database_url)?;

    echo_server::runner::run(
        cli.host.as_deref().unwrap_or("0.0.0.0"),
        certs,
        key,
        cli.connection_limit.unwrap_or(100),
        Arc::new(EchoRouter::new()),
        pool,
        cli.assets_dir
    ).await?;

    Ok(())
}
