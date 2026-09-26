use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use bsuppla::core::{Detector, FileContext};
use bsuppla::detectors::{
    credentials::{authorized_keys_rule, CredentialFileDetector, PrivateKeyDetector},
    elf::ElfAnalyzerDetector,
    package_managers::{ApkKeyDetector, ApkRepositoryDetector, LockfileDetector, PackageManagerConfigDetector},
    permissions::{
        ExecutableInWritableDirDetector, HiddenExecutableDetector, InsecureShadowPermissionsDetector,
        SuidSgidDetector, WorldWritableExecutableDetector,
    },
    risky::{CryptoMinerDetector, RiskyToolDetector, startup_script_rule},
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tempfile::tempdir;

fn create_file_context<'a>(path: &'a PathBuf, rel_path: &'a PathBuf, mode: u32) -> FileContext<'a> {
    let is_exec = (mode & 0o111) != 0;
    let is_world_writable = (mode & 0o002) != 0;
    let is_world_readable = (mode & 0o004) != 0;
    let is_suid = (mode & 0o4000) != 0;
    let is_sgid = (mode & 0o2000) != 0;

    FileContext {
        path,
        relative_path: rel_path,
        mode,
        is_executable: is_exec,
        is_world_writable,
        is_world_readable,
        is_suid,
        is_sgid,
    }
}

fn create_test_file(path: &std::path::Path, content: &[u8], mode: u32) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms).unwrap();
}

fn bench_permissions_detectors(c: &mut Criterion) {
    let mut group = c.benchmark_group("permissions_detectors");

    let detectors: Vec<(&str, Box<dyn Detector>)> = vec![
        ("SuidSgid", Box::new(SuidSgidDetector)),
        ("WorldWritable", Box::new(WorldWritableExecutableDetector)),
        ("ExecutableInWritableDir", Box::new(ExecutableInWritableDirDetector)),
        ("HiddenExecutable", Box::new(HiddenExecutableDetector)),
        ("InsecureShadow", Box::new(InsecureShadowPermissionsDetector)),
    ];

    for (name, detector) in detectors {
        let path = PathBuf::from("/bin/test");
        let rel_path = PathBuf::from("/bin/test");
        group.bench_function(name, move |b| {
            b.iter(|| {
                let ctx = create_file_context(&path, &rel_path, 0o4755);
                black_box(detector.detect(&ctx))
            });
        });
    }
    group.finish();
}

fn bench_elf_detector(c: &mut Criterion) {
    let mut group = c.benchmark_group("elf_detector");
    let detector = ElfAnalyzerDetector;

    let temp = tempdir().unwrap();
    let elf_path = temp.path().join("test_binary");

    create_test_file(&elf_path, &[0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00], 0o755);

    let rel_path = PathBuf::from("/usr/bin/test_binary");
    let path = elf_path.clone();
    group.bench_function("parse_elf_header", move |b| {
        b.iter(|| {
            let ctx = create_file_context(&path, &rel_path, 0o755);
            black_box(detector.detect(&ctx))
        });
    });
    group.finish();
}

fn bench_credentials_detectors(c: &mut Criterion) {
    let mut group = c.benchmark_group("credentials_detectors");

    let detectors: Vec<(&str, Box<dyn Detector>, PathBuf, u32)> = vec![
        ("AuthorizedKeys", Box::new(authorized_keys_rule()), PathBuf::from("/root/.ssh/authorized_keys"), 0o644),
        ("PrivateKey", Box::new(PrivateKeyDetector), PathBuf::from("/root/.ssh/id_rsa"), 0o644),
        ("CredentialFile", Box::new(CredentialFileDetector), PathBuf::from("/app/.env"), 0o644),
    ];

    for (name, detector, path, mode) in detectors {
        let rel_path = path.clone();
        group.bench_function(name, move |b| {
            b.iter(|| {
                let ctx = create_file_context(&path, &rel_path, mode);
                black_box(detector.detect(&ctx))
            });
        });
    }
    group.finish();
}

fn bench_package_manager_detectors(c: &mut Criterion) {
    let mut group = c.benchmark_group("package_manager_detectors");

    let temp = tempdir().unwrap();

    let npmrc_path = temp.path().join("npmrc");
    create_test_file(&npmrc_path, b"registry=http://evil.example\n", 0o644);

    let pip_path = temp.path().join("pip.conf");
    create_test_file(&pip_path, b"index-url=http://evil.example/simple\n", 0o644);

    let lockfile_path = temp.path().join("package-lock.json");
    create_test_file(&lockfile_path, br#"{"dependencies": {"pkg": "git+https://github.com/user/repo"}}"#, 0o644);

    let apk_repo_path = temp.path().join("repositories");
    create_test_file(&apk_repo_path, b"http://evil.example/alpine\n", 0o644);

    let apk_key_path = temp.path().join("key.pub");
    create_test_file(&apk_key_path, b"not-a-valid-key", 0o644);

    let detectors: Vec<(&str, Box<dyn Detector>, PathBuf, u32)> = vec![
        (
            "PackageManagerConfig",
            Box::new(PackageManagerConfigDetector),
            npmrc_path,
            0o644,
        ),
        (
            "LockfileDetector",
            Box::new(LockfileDetector),
            lockfile_path,
            0o644,
        ),
        (
            "ApkRepositoryDetector",
            Box::new(ApkRepositoryDetector),
            apk_repo_path,
            0o644,
        ),
        (
            "ApkKeyDetector",
            Box::new(ApkKeyDetector),
            apk_key_path,
            0o644,
        ),
    ];

    for (name, detector, path, mode) in detectors {
        let rel_path = PathBuf::from("/etc/test");
        group.bench_function(name, move |b| {
            b.iter(|| {
                let ctx = create_file_context(&path, &rel_path, mode);
                black_box(detector.detect(&ctx))
            });
        });
    }
    group.finish();
}

fn bench_risky_detectors(c: &mut Criterion) {
    let mut group = c.benchmark_group("risky_detectors");

    let detectors: Vec<(&str, Box<dyn Detector>, PathBuf, u32)> = vec![
        (
            "RiskyToolDetector",
            Box::new(RiskyToolDetector),
            PathBuf::from("/usr/bin/curl"),
            0o755,
        ),
        (
            "CryptoMinerDetector",
            Box::new(CryptoMinerDetector),
            PathBuf::from("/usr/bin/xmrig"),
            0o755,
        ),
        (
            "StartupScriptRule",
            Box::new(startup_script_rule()),
            PathBuf::from("/etc/init.d/service"),
            0o755,
        ),
    ];

    for (name, detector, path, mode) in detectors {
        let rel_path = path.clone();
        group.bench_function(name, move |b| {
            b.iter(|| {
                let ctx = create_file_context(&path, &rel_path, mode);
                black_box(detector.detect(&ctx))
            });
        });
    }
    group.finish();
}

fn bench_detector_throughput(c: &mut Criterion) {
    let registry = bsuppla::detectors::default_registry();
    let mut group = c.benchmark_group("detector_throughput");

    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::new("all_detectors", size), size, |b, &size| {
            let paths: Vec<_> = (0..size)
                .map(|i| {
                    let path = PathBuf::from(format!("/bin/file_{i}"));
                    let rel_path = PathBuf::from(format!("/bin/file_{i}"));
                    (path, rel_path)
                })
                .collect();

            b.iter(|| {
                let mut total = 0;
                for (path, rel_path) in &paths {
                    let ctx = create_file_context(path, rel_path, 0o755);
                    total += black_box(registry.detect(&ctx).len());
                }
                total
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_permissions_detectors,
    bench_elf_detector,
    bench_credentials_detectors,
    bench_package_manager_detectors,
    bench_risky_detectors,
    bench_detector_throughput
);
criterion_main!(benches);