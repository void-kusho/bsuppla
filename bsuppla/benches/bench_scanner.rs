use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use bsuppla::core::{FileContext, Finding, Severity};
use bsuppla::detectors;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn setup_test_fs(root: &std::path::Path, num_files: usize, num_dirs: usize) {
    fs::create_dir_all(root).unwrap();

    for i in 0..num_dirs {
        let dir = root.join(format!("dir_{i}"));
        fs::create_dir_all(&dir).unwrap();

        for j in 0..(num_files / num_dirs.max(1)) {
            let file = dir.join(format!("file_{j}"));
            fs::write(&file, b"test content").unwrap();
            let mut perms = fs::metadata(&file).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&file, perms).unwrap();
        }
    }
}

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

fn bench_registry_detection(c: &mut Criterion) {
    let registry = detectors::default_registry();
    let mut group = c.benchmark_group("registry_detection");

    for size in [10, 100, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::new("files", size), size, |b, &size| {
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

fn bench_individual_detectors(c: &mut Criterion) {
    let registry = detectors::default_registry();
    let mut group = c.benchmark_group("individual_detectors");

    let test_cases = vec![
        ("suid_binary", PathBuf::from("/bin/sudo"), 0o4755),
        ("world_writable", PathBuf::from("/tmp/script"), 0o777),
        ("normal_binary", PathBuf::from("/bin/ls"), 0o755),
        ("hidden_exec", PathBuf::from("/home/user/.hidden"), 0o755),
        ("elf_stripped", PathBuf::from("/usr/bin/stripped"), 0o755),
        ("private_key", PathBuf::from("/root/.ssh/id_rsa"), 0o644),
        ("credential_file", PathBuf::from("/app/.env"), 0o644),
        ("risky_tool", PathBuf::from("/usr/bin/curl"), 0o755),
        ("crypto_miner", PathBuf::from("/usr/bin/xmrig"), 0o755),
        ("startup_script", PathBuf::from("/etc/init.d/service"), 0o755),
    ];

    for (name, path, mode) in test_cases {
        let rel_path = path.clone();

        group.bench_function(name, |b| {
            b.iter(|| {
                let ctx = create_file_context(&path, &rel_path, mode);
                black_box(registry.detect(&ctx))
            })
        });
    }
    group.finish();
}

fn bench_filesystem_walk(c: &mut Criterion) {
    use bsuppla::scan;
    use tempfile::tempdir;

    let mut group = c.benchmark_group("filesystem_walk");

    for (num_files, num_dirs) in [(100, 10), (1000, 50), (5000, 100)] {
        group.throughput(Throughput::Elements(num_files as u64));
        group.bench_with_input(
            BenchmarkId::new("walk", format!("{num_files}f_{num_dirs}d")),
            &(num_files, num_dirs),
            |b, &(num_files, num_dirs)| {
                let temp = tempdir().unwrap();
                setup_test_fs(temp.path(), num_files, num_dirs);

                b.iter(|| {
                    let _ = scan::scan_filesystem(
                        temp.path().to_str().unwrap(),
                        None,
                        None,
                        None,
                    );
                });
            },
        );
    }
    group.finish();
}

fn bench_finding_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("finding_creation");

    group.bench_function("create_finding", |b| {
        b.iter(|| {
            Finding::new(
                black_box("test_signal"),
                black_box(PathBuf::from("/test/path")),
                black_box("test detail".to_string()),
                black_box(Severity::High),
            )
        });
    });

    group.bench_function("finding_key", |b| {
        let finding = Finding::new(
            "test_signal",
            PathBuf::from("/test/path"),
            "test detail".to_string(),
            Severity::High,
        );
        b.iter(|| black_box(finding.key()));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_registry_detection,
    bench_individual_detectors,
    bench_filesystem_walk,
    bench_finding_creation
);
criterion_main!(benches);