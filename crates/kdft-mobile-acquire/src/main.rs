mod acquisition;
mod android;
mod command;
mod hashing;
mod ios;
mod models;

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};

use acquisition::{acquire_android, acquire_ios};
use android::probe_android;
use ios::probe_ios;
use models::Profile;

#[derive(Debug, Parser)]
#[command(name = "kdft-mobile-acquire")]
#[command(version)]
#[command(about = "Forensic-first Android/iOS acquisition orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Detect connected devices and report acquisition capabilities without modifying them.
    Probe {
        #[arg(long, value_enum, default_value = "all")]
        platform: PlatformArg,
    },

    /// Acquire a connected device using a non-destructive profile.
    Acquire {
        #[arg(long, value_enum)]
        platform: PlatformArg,

        /// Android serial or iOS UDID. Required when multiple devices are connected.
        #[arg(long)]
        device: Option<String>,

        #[arg(long, value_enum, default_value = "quick")]
        profile: ProfileArg,

        #[arg(long)]
        case_id: String,

        #[arg(long)]
        evidence_id: String,

        #[arg(long)]
        examiner: String,

        #[arg(long, default_value = ".")]
        output: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PlatformArg {
    All,
    Android,
    Ios,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileArg {
    Quick,
    Logical,
}

impl From<ProfileArg> for Profile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Quick => Profile::Quick,
            ProfileArg::Logical => Profile::Logical,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Probe { platform } => match platform {
            PlatformArg::All => {
                println!("=== Android ===");
                probe_android(None)?;
                println!("\n=== iOS ===");
                probe_ios(None)?;
            }
            PlatformArg::Android => probe_android(None)?,
            PlatformArg::Ios => probe_ios(None)?,
        },
        Commands::Acquire {
            platform,
            device,
            profile,
            case_id,
            evidence_id,
            examiner,
            output,
        } => {
            let profile: Profile = profile.into();
            match platform {
                PlatformArg::Android => acquire_android(
                    device.as_deref(),
                    profile,
                    &case_id,
                    &evidence_id,
                    &examiner,
                    &output,
                )?,
                PlatformArg::Ios => acquire_ios(
                    device.as_deref(),
                    profile,
                    &case_id,
                    &evidence_id,
                    &examiner,
                    &output,
                )?,
                PlatformArg::All => bail!("--platform all is valid only for probe"),
            }
        }
    }

    Ok(())
}
