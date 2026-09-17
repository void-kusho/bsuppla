//! Shared domain model and the detector extension API.
//!
//! Everything here depends on nothing else in the crate, so detectors,
//! filters, and reporters can all build on these types.

use std::path::PathBuf;

// Defines the severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn score(self) -> u32 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: String,
    pub path: PathBuf,
    pub detail: String,
    pub severity: Severity,
}

impl Finding {
    pub fn new(kind: &'static str, path: PathBuf, detail: String, severity: Severity) -> Self {
        Self {
            kind: kind.to_string(),
            path,
            detail,
            severity,
        }
    }

    /// Key used in baseline files: `<kind>: <path>`.
    pub fn key(&self) -> String {
        format!("{}: {}", self.kind, self.path.display())
    }
}

#[derive(Debug, Clone)]
pub struct FileContext<'a> {
    /// Real filesystem path inside the reconstructed image (use to read bytes)
    pub path: &'a PathBuf,
    /// Path relative to the image root
    pub relative_path: &'a PathBuf,
    pub mode: u32,
    pub is_executable: bool,
    pub is_world_writable: bool,
    pub is_world_readable: bool,
    pub is_suid: bool,
    pub is_sgid: bool,
}

impl<'a> FileContext<'a> {
    pub fn normalized_path(&self) -> String {
        let s = self.relative_path.to_string_lossy();
        if s.starts_with('/') {
            s.to_string()
        } else {
            format!("/{s}")
        }
    }

    pub fn file_name(&self) -> Option<&std::ffi::OsStr> {
        self.relative_path.file_name()
    }

    pub fn file_name_str(&self) -> Option<String> {
        self.file_name().and_then(|n| n.to_str().map(String::from))
    }
}

/// A detector inspects one file in the reconstructed image filesystem.
///
/// To add a new signal:
/// 1. Implement `Detector` in `detectors/` (or reuse [`PathRule`]).
/// 2. Register it with one line in `detectors::default_registry()`.
pub trait Detector: Send + Sync {
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
    fn detect(&self, ctx: &FileContext) -> Option<Finding>;
    fn severity(&self) -> Severity {
        Severity::Medium
    }
}

pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    pub fn detect(&self, ctx: &FileContext) -> Vec<Finding> {
        self.detectors
            .iter()
            .filter_map(|d| d.detect(ctx))
            .collect()
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Zero-boilerplate detector: pair a finding rule with a path predicate.
///
/// Most simple signals (a file matches a path pattern) need no custom
/// struct and no custom impl. Just build a rule and register it:
///
/// ```
/// # use bsuppla::core::{PathRule, Severity};
/// let rule = PathRule::new(
///     "docker_socket_present",
///     Severity::Critical,
///     "docker socket exposed",
///     |ctx| ctx.normalized_path() == "/var/run/docker.sock",
/// );
/// ```
pub type RuleFn = fn(&FileContext) -> bool;

pub struct PathRule {
    kind: &'static str,
    severity: Severity,
    detail: &'static str,
    matcher: RuleFn,
}

impl PathRule {
    pub fn new(
        kind: &'static str,
        severity: Severity,
        detail: &'static str,
        matcher: RuleFn,
    ) -> Self {
        Self {
            kind,
            severity,
            detail,
            matcher,
        }
    }
}

impl Detector for PathRule {
    fn name(&self) -> &'static str {
        self.kind
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        (self.matcher)(ctx).then(|| {
            Finding::new(
                self.kind,
                ctx.relative_path.clone(),
                self.detail.to_string(),
                self.severity,
            )
        })
    }
}
