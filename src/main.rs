use clap::Parser;
use proof_broadcast_tree::network::peer_id_from_seed;
use proof_broadcast_tree::node::dump_tree;
use proof_broadcast_tree::{Cli, run};
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
    if cli.dump_tree {
        if let Err(error) = cli.validate() {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
        println!("{}", dump_tree(&cli, &cli.dump_peer_ids));
        return;
    }
    if !cli.dump_peer_ids.is_empty() {
        for seed in &cli.dump_peer_ids {
            println!("{}", peer_id_from_seed(*seed));
        }
        return;
    }
    if let Err(error) = cli.validate() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
    run(cli).await;
}
