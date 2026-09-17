//! Image ingest: acquire an image and reconstruct its filesystem.
//!
//! Two sub-goals:
//! - `docker.rs` talks to the Docker daemon (pull / save).
//! - the tar chain (`image`, `manifest`, `layers`, `extract`) turns the
//!   image tar into a local filesystem, fully offline.

mod docker;
mod extract;
mod image;
mod layers;
mod manifest;

pub use docker::{pull, save, is_docker_deamon_runnig, is_docker_installed};
pub use extract::build_filesystem;
pub use image::read_manifest_from_image;
pub use layers::locate_layers;
pub use manifest::parse_manifest;
