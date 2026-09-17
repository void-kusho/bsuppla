//! Docker daemon interaction: `docker pull` and `docker save`.

use std::process::Command;

use crate::error::{Error, Result};
use which::which;


// Check if docker is installed
pub fn is_docker_installed() -> Result<()> {
    let is_installed =  which("docker").is_ok();
    if is_installed {
        Ok(())
    } else {
        Err(Error::Docker("Docker not installed or not found".to_string()))
    }
}

// Check if docker deamon is runnig
pub fn is_docker_deamon_runnig() -> Result<()> {
    let output = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if output {
        Ok(())
    } else {
        Err(Error::Docker("Deamon is not running".to_string()))
    }
}


/// Pull an image from a registry.
pub fn pull(image: &str) -> Result<()> {

    println!("[+] Image: {image}");

    let output = Command::new("docker")
        .args(["pull", image])
        .output()
        .map_err(|e| Error::Docker(format!("Failed to run docker pull: {e}")))?;

    if output.status.success() {
        println!("[+] Image pulled");
        Ok(())
    } else {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::Docker(format!(
            "Docker pull failed (code {code}): {stderr}"
        )))
    }
}

/// Save an image to a tar file for offline analysis.
pub fn save(image: &str, tar: &str) -> Result<()> {
    println!("[+] Saving tar file");
    let output = Command::new("docker")
        .args(["save", image, "-o", tar])
        .output()
        .map_err(|e| Error::Docker(format!("Failed to run docker save: {e}")))?;

    if output.status.success() {
        println!("[+] Tar file saved");
        Ok(())
    } else {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::Docker(format!(
            "Docker save failed (code {code}): {stderr}"
        )))
    }
}
