#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "kdft-ai-broker",
    about = "Offline KDFT local-model verifier (does not download or run models)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify a pinned local model manifest, all model files, its license text,
    /// and a hash-pinned runtime executable. Nothing is downloaded or started.
    VerifyLocal {
        /// JSON config path. Relative paths inside it resolve against this
        /// config file's directory.
        #[arg(long)]
        config: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::VerifyLocal { config } => {
            let report = kdft_ai_broker::verify_config_file(config)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}
