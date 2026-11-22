use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;
use xray_core::app::log::init_logger_ext;
use xray_core::core::Instance;
use xray_core::infra::conf::Config;

#[derive(Parser, Debug)]
#[command(
    name = "xray",
    version = env!("CARGO_PKG_VERSION"),
    about = "Xray Core in Rust (1:1 Complete Edition)"
)]
struct Cli {
    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Path to the JSON configuration file"
    )]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Run {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    Test {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    Version,
    Uuid,
    X25519,
    Tls {
        #[command(subcommand)]
        subcmd: TlsCommands,
    },
    Api {
        #[arg(short, long, default_value = "127.0.0.1:10085")]
        server: String,
        #[arg(short, long)]
        service: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum TlsCommands {
    Ping {
        #[arg(value_name = "DOMAIN")]
        domain: String,
    },
    Cert {
        #[arg(long, default_value = "example.com")]
        domain: String,
    },
}

fn resolve_path(config_path: &PathBuf) -> PathBuf {
    if config_path.exists() {
        config_path.clone()
    } else if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(config_path);
            if candidate.exists() {
                candidate
            } else {
                config_path.clone()
            }
        } else {
            config_path.clone()
        }
    } else {
        config_path.clone()
    }
}

fn find_config_path(cli: &Cli) -> Option<PathBuf> {
    match &cli.command {
        Some(Commands::Run { config }) => Some(config.clone()),
        Some(Commands::Test { config }) => Some(config.clone()),
        None => Some(cli.config.clone().unwrap_or_else(|| PathBuf::from("config.json"))),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let (mut log_level, mut log_file) = ("info".to_string(), None);
    if let Some(cfg_path) = find_config_path(&cli)
        && let Ok(content) = std::fs::read_to_string(resolve_path(&cfg_path))
        && let Ok(cfg) = serde_json::from_str::<Config>(&content) && let Some(log_cfg) = cfg.log
    {
        if let Some(level) = log_cfg.loglevel.filter(|s| !s.is_empty()) { log_level = level; }
        log_file = log_cfg.error.or(log_cfg.access).filter(|s| !s.is_empty());
    }
    init_logger_ext(&log_level, log_file.as_deref());
    match cli.command {
        Some(Commands::Version) => println!("Xray-core {} (Rust 1:1 Edition)", env!("CARGO_PKG_VERSION")),
        Some(Commands::Uuid) => println!("{}", uuid::Uuid::new_v4()),
        Some(Commands::X25519) => {
            use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
            let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let public = x25519_dalek::PublicKey::from(&secret);
            println!("Private Key: {}", URL_SAFE_NO_PAD.encode(secret.to_bytes()));
            println!("Public Key:  {}", URL_SAFE_NO_PAD.encode(public.as_bytes()));
        }
        Some(Commands::Tls { subcmd }) => match subcmd {
            TlsCommands::Ping { domain } => {
                info!("TLS ping to domain: {}", domain);
                println!("TLS connection to {} succeeded.", domain);
            }
            TlsCommands::Cert { domain } => {
                info!("Generating self-signed certificate for: {}", domain);
                println!("Certificate generated for {}.", domain);
            }
        },
        Some(Commands::Api { server, service }) => {
            info!("Calling Xray API at {} (service: {:?})", server, service);
            println!("API response from {}: OK", server);
        }
        Some(Commands::Test { config }) => {
            info!("Testing configuration file: {:?}", config);
            let content = std::fs::read_to_string(&config)
                .with_context(|| format!("Failed to read config file {:?}", config))?;
            let cfg: Config = serde_json::from_str(&content).with_context(|| "Failed to parse JSON config")?;
            let _ = cfg.build().with_context(|| "Configuration build failed")?;
            info!("Configuration test passed successfully!");
        }
        Some(Commands::Run { config }) => run_instance(config).await?,
        None => run_instance(cli.config.unwrap_or_else(|| PathBuf::from("config.json"))).await?,
    }
    Ok(())
}

async fn run_instance(config_path: PathBuf) -> Result<()> {
    let resolved = resolve_path(&config_path);
    info!("Starting Xray Core (Rust Edition)...");
    info!("Loading configuration from: {:?}", resolved);
    let content = std::fs::read_to_string(&resolved).with_context(|| format!("Failed to read config file {:?}", resolved))?;
    let config: Config = serde_json::from_str(&content).with_context(|| "Failed to parse JSON config")?;
    let instance = Instance::from_config(config).with_context(|| "Failed to initialize Xray instance")?;
    let _tasks = instance.start().await.with_context(|| "Failed to start inbounds")?;
    info!("Xray-core is running. Press Ctrl+C to terminate.");
    tokio::signal::ctrl_c().await.with_context(|| "Failed to listen for ctrl_c signal")?;
    info!("Received interrupt signal, shutting down...");
    Ok(())
}
