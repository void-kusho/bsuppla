//! Runtime configuration: CLI arguments merged with `BSUPPLA_*` env vars.

use clap::Parser;

use crate::error::Result;

const ENV_SKIP_DOCKER: &str = "BSUPPLA_SKIP_DOCKER";
const ENV_SKIP_SCAN: &str = "BSUPPLA_SKIP_SCAN";
const ENV_OUTPUT_DIR: &str = "BSUPPLA_OUTPUT_DIR";
const DEFAULT_OUTPUT_DIR: &str = "container_fs";

#[derive(Parser, Debug)]
#[command(
    name = "bsuppla",
    version = "1.0",
    about = "Static scanner for Docker images",
    arg_required_else_help = true
)]
struct CliArgs {
    /// Docker image name (e.g., alpine:latest)
    image: String,
    /// Output tar path for docker save
    tar: String,
    /// Optional allowlist file (one path per line)
    allowlist: Option<String>,
    /// Optional baseline findings file (lines from previous scan)
    baseline: Option<String>,
    /// Write current findings to this baseline file
    #[arg(long)]
    baseline_out: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub image: String,
    pub tar: String,
    pub allowlist: Option<String>,
    pub baseline: Option<String>,
    pub baseline_out: Option<String>,
    /// Directory where the image filesystem is reconstructed
    pub output_dir: String,
    /// Skip `docker pull` / `docker save` (scan an existing tar)
    pub skip_docker: bool,
    /// Skip scanning after extraction
    pub skip_scan: bool,
}

impl Config {
    pub fn from_args() -> Result<Self> {
        let args = CliArgs::parse();
        Ok(Self {
            image: args.image,
            tar: args.tar,
            allowlist: args.allowlist,
            baseline: args.baseline,
            baseline_out: args.baseline_out,
            output_dir: std::env::var(ENV_OUTPUT_DIR)
                .unwrap_or_else(|_| DEFAULT_OUTPUT_DIR.to_string()),
            skip_docker: env_flag(ENV_SKIP_DOCKER),
            skip_scan: env_flag(ENV_SKIP_SCAN),
        })
    }

    /// Output dir as the user would type it (absolute stays absolute).
    pub fn output_display(&self) -> String {
        if std::path::Path::new(&self.output_dir).is_absolute() {
            self.output_dir.clone()
        } else {
            format!("./{}", self.output_dir)
        }
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}
