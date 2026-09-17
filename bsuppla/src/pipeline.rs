//! Application wiring: stage orchestration (acquire -> import -> extract -> scan).
//!
//! This is the composition root — the only place allowed to call into
//! [`crate::ingest`] and [`crate::scan`] together. New pipeline stages
//! are inserted here.

use crate::config::Config;
use crate::error::Result;
use crate::{ingest, scan};

pub fn run(cfg: &Config) -> Result<()> {

    println!("Welcome to bsuppla!");

    ingest::is_docker_installed()?;
    ingest::is_docker_deamon_runnig()?;

    if !cfg.skip_docker {
        ingest::pull(&cfg.image)?;
        println!("[+] Image ready for scanning");

        ingest::save(&cfg.image, &cfg.tar)?;
        println!("[+] Tar ready for scanning");
    }

    let manifest_json = ingest::read_manifest_from_image(&cfg.tar)?;
    let entries = ingest::parse_manifest(&manifest_json)?;

    for entry in entries {
        println!("Building filesystem...");

        let layers = ingest::locate_layers(&cfg.tar, &entry.layers)?;
        ingest::build_filesystem(&cfg.tar, &layers, &cfg.output_dir)?;

        println!("Filesystem ready at {}", cfg.output_display());
        if !cfg.skip_scan {
            scan::scan_filesystem(
                &cfg.output_dir,
                cfg.allowlist.as_deref(),
                cfg.baseline.as_deref(),
                cfg.baseline_out.as_deref(),
            )?;
        }
    }
    Ok(())
}
