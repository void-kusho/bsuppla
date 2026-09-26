use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use bsuppla::ingest;
use bsuppla::scan;
use bsuppla::scan::allowlist::{load_allowlist, is_allowlisted};
use bsuppla::scan::baseline::{diff_with_baseline, load_baseline, write_baseline};
use bsuppla::core::Finding;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tempfile::tempdir;

fn create_test_image_tar(output_path: &std::path::Path, num_layers: usize, files_per_layer: usize) {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tar::Builder;

    let tar_path = output_path.with_extension(".tar");
    let mut tar = Builder::new(fs::File::create(&tar_path).unwrap());

    let mut manifest = serde_json::json!({
        "Config": "config.json",
        "Layers": [],
        "RepoTags": ["test:latest"]
    });

    let config_json = serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64",
        "os": "linux",
        "rootfs": { "type": "layers", "diff_ids": [] }
    })).unwrap();

    tar.append_data(&mut tar::Header::new_gnu(), "config.json", &*config_json).unwrap();

    for i in 0..num_layers {
        let layer_dir = tempdir().unwrap();
        for j in 0..files_per_layer {
            let file_path = layer_dir.path().join(format!("file_{i}_{j}"));
            fs::write(&file_path, format!("content_{i}_{j}")).unwrap();
            let mut perms = fs::metadata(&file_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&file_path, perms).unwrap();
        }

        let layer_tar_path = layer_dir.path().join("layer.tar");
        let mut layer_tar = Builder::new(fs::File::create(&layer_tar_path).unwrap());
        layer_tar.append_dir_all(".", layer_dir.path()).unwrap();
        drop(layer_tar);

        let layer_data = fs::read(&layer_tar_path).unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&layer_data).unwrap();
        let compressed = gz.finish().unwrap();

        let layer_name = format!("layer_{i}.tar.gz");
        let layer_path = output_path.with_file_name(&layer_name);
        fs::write(&layer_path, &compressed).unwrap();

        manifest["Layers"].as_array_mut().unwrap().push(serde_json::Value::String(layer_name.clone()));
    }

    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    tar.append_data(&mut tar::Header::new_gnu(), "manifest.json", &*manifest_bytes).unwrap();
    drop(tar);
}

fn bench_image_loading(c: &mut Criterion) {
    let mut group = c.benchmark_group("image_loading");

    for (num_layers, files_per_layer) in [(1, 10), (5, 50), (10, 100)] {
        group.throughput(Throughput::Elements((num_layers * files_per_layer) as u64));
        group.bench_with_input(
            BenchmarkId::new("load", format!("{num_layers}l_{files_per_layer}f")),
            &(num_layers, files_per_layer),
            |b, &(num_layers, files_per_layer)| {
                let temp = tempdir().unwrap();
                let tar_path = temp.path().join("image");
                create_test_image_tar(&tar_path, num_layers, files_per_layer);

                let tar_file = format!("{}.tar", tar_path.display());

                b.iter(|| {
                    let manifest_json = black_box(ingest::read_manifest_from_image(&tar_file)).unwrap();
                    let entries = black_box(ingest::parse_manifest(&manifest_json)).unwrap();
                    for entry in entries {
                        let _ = black_box(ingest::locate_layers(&tar_file, &entry.layers));
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_filesystem_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("filesystem_extraction");

    for (num_layers, files_per_layer) in [(1, 100), (5, 500), (10, 1000)] {
        group.throughput(Throughput::Elements((num_layers * files_per_layer) as u64));
        group.bench_with_input(
            BenchmarkId::new("extract", format!("{num_layers}l_{files_per_layer}f")),
            &(num_layers, files_per_layer),
            |b, &(num_layers, files_per_layer)| {
                let temp = tempdir().unwrap();
                let tar_path = temp.path().join("image");
                create_test_image_tar(&tar_path, num_layers, files_per_layer);

                let tar_file = format!("{}.tar", tar_path.display());
                let manifest_json = ingest::read_manifest_from_image(&tar_file).unwrap();
                let entries = ingest::parse_manifest(&manifest_json).unwrap();
                let entry = &entries[0];
                let layers = ingest::locate_layers(&tar_file, &entry.layers).unwrap();
                let output_dir = temp.path().join("output");

                b.iter(|| {
                    black_box(ingest::build_filesystem(&tar_file, &layers, output_dir.to_str().unwrap())).unwrap();
                });
            },
        );
    }
    group.finish();
}

fn bench_full_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_scan");

    for (num_files, num_dirs) in [(100, 10), (1000, 50), (5000, 100)] {
        group.throughput(Throughput::Elements(num_files as u64));
        group.bench_with_input(
            BenchmarkId::new("scan", format!("{num_files}f_{num_dirs}d")),
            &(num_files, num_dirs),
            |b, &(num_files, num_dirs)| {
                let temp = tempdir().unwrap();
                let root = temp.path().join("fs");
                fs::create_dir_all(&root).unwrap();

                for i in 0..num_dirs {
                    let dir = root.join(format!("dir_{i}"));
                    fs::create_dir_all(&dir).unwrap();
                    for j in 0..(num_files / num_dirs.max(1)) {
                        let file = dir.join(format!("file_{j}"));
                        fs::write(&file, b"test").unwrap();
                        let mut perms = fs::metadata(&file).unwrap().permissions();
                        perms.set_mode(0o755);
                        fs::set_permissions(&file, perms).unwrap();
                    }
                }

                let allowlist_path = temp.path().join("allowlist.txt");
                fs::write(&allowlist_path, "").unwrap();

                b.iter(|| {
                    let _ = scan::scan_filesystem(
                        root.to_str().unwrap(),
                        Some(allowlist_path.to_str().unwrap()),
                        None,
                        None,
                    );
                });
            },
        );
    }
    group.finish();
}

fn bench_allowlist_filtering(c: &mut Criterion) {
    use bsuppla::core::Finding;
    use bsuppla::scan::allowlist::{load_allowlist, is_allowlisted};

    let mut group = c.benchmark_group("allowlist_filtering");

    let allowlist = load_allowlist(Some(""));
    let findings: Vec<_> = (0..1000)
        .map(|i| Finding::new(
            "elf_suspicious",
            PathBuf::from(format!("/usr/bin/tool_{i}")),
            "stripped".to_string(),
            bsuppla::core::Severity::Medium,
        ))
        .collect();

    group.bench_function("filter_1000", |b| {
        b.iter(|| {
            let filtered: Vec<_> = findings
                .iter()
                .filter(|f| !is_allowlisted(f, &allowlist))
                .collect();
            black_box(filtered.len())
        });
    });

    let findings_mixed: Vec<_> = (0..1000)
        .map(|i| {
            let kind = if i % 3 == 0 { "elf_suspicious" } else { "other_signal" };
            Finding::new(
                kind,
                PathBuf::from(format!("/bin/file_{i}")),
                "detail".to_string(),
                bsuppla::core::Severity::Medium,
            )
        })
        .collect();

    group.bench_function("filter_mixed_1000", |b| {
        b.iter(|| {
            let filtered: Vec<_> = findings_mixed
                .iter()
                .filter(|f| !is_allowlisted(f, &allowlist))
                .collect();
            black_box(filtered.len())
        });
    });
    group.finish();
}

fn bench_baseline_operations(c: &mut Criterion) {
    use bsuppla::core::Finding;
    use bsuppla::scan::baseline::{diff_with_baseline, load_baseline, write_baseline};
    use std::collections::HashSet;

    let mut group = c.benchmark_group("baseline_operations");

    let findings: Vec<_> = (0..1000)
        .map(|i| Finding::new(
            "test_signal",
            PathBuf::from(format!("/test/file_{i}")),
            "detail".to_string(),
            bsuppla::core::Severity::Medium,
        ))
        .collect();

    let findings_refs: Vec<_> = findings.iter().collect();
    let baseline: HashSet<_> = findings.iter().map(|f| f.key()).collect();
    let baseline_path = tempdir().unwrap().path().join("baseline.txt");
    write_baseline(baseline_path.to_str().unwrap(), &findings_refs).unwrap();

    group.bench_function("load_baseline_1000", |b| {
        b.iter(|| black_box(load_baseline(Some(baseline_path.to_str().unwrap()))));
    });

    group.bench_function("diff_with_baseline_1000", |b| {
        b.iter(|| black_box(diff_with_baseline(&findings_refs, &baseline)));
    });

    group.bench_function("write_baseline_1000", |b| {
        let out = tempdir().unwrap().path().join("out.txt");
        b.iter(|| black_box(write_baseline(out.to_str().unwrap(), &findings_refs)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_image_loading,
    bench_filesystem_extraction,
    bench_full_scan,
    bench_allowlist_filtering,
    bench_baseline_operations
);
criterion_main!(benches);