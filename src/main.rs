use clap::Parser;
use libp2p::PeerId;
use proof_broadcast::{Cli, network::keypair_from_seed, run};
use tracing_subscriber::EnvFilter;

// A single-threaded runtime: under Shadow every guest thread is simulated on a
// deterministic scheduler, so a multi-threaded runtime only adds simulated
// context-switch overhead.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    if !cli.dump_peer_ids.is_empty() {
        for seed in &cli.dump_peer_ids {
            println!("{}", PeerId::from(keypair_from_seed(*seed).public()));
        }
        return;
    }
    if let Err(error) = cli.validate() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
    run(cli).await;
}
