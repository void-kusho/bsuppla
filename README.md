# bsuppla

**[Documentation](https://void-kusho.github.io/bsuppla/)**

Statically analyze Docker images without executing them. The tool pulls an image, saves it as a tarball, reconstructs the filesystem, and scans it for supply-chain indicators and suspicious artifacts.

**Highlights**
- No container execution. It inspects the image tar and layers offline.
- Reports a simple list of identifications/suspicions.
- Optional allowlist file to suppress known-safe findings.
- Outputs an overall suspicion level: `low`, `medium`, or `high`.

**Quick Start**
```bash
cd bsuppla/bsuppla
cargo run -- alpine:latest alpine.tar
```

See `USAGE.md` for the full guide. See `docs/DEVELOPMENT.md` for how the
code is organized and how to add new detectors.

**Requirements**
- Rust toolchain (stable)
- Docker daemon (only for pulling/saving images)

## Build
```bash
cd bsuppla/bsuppla
cargo build --release
```

Binary path:
```
bsuppla/bsuppla/target/release/bsuppla
```

## Install
```bash
bash scripts/install.sh
```

Or via Make:
```bash
make install
```

## Usage
Basic:
```bash
cargo run -- <image> <image.tar>
```

With allowlist:
```bash
cargo run -- <image> <image.tar> <allowlist.txt>
```

With allowlist and baseline:
```bash
cargo run -- <image> <image.tar> <allowlist.txt> <baseline.txt>
```

With baseline export:
```bash
cargo run -- <image> <image.tar> <allowlist.txt> <baseline.txt> --baseline-out new-baseline.txt
```

Example:
```bash
cargo run -- alpine:latest alpine.tar allowlist.txt baseline.txt
```

## Allowlist File
Optional text file, one path per line. Lines starting with `#` are comments. Paths are treated as root-relative inside the image filesystem.

Allowlist entries can optionally include the finding kind:
```
<kind>: <path-or-pattern>
```
Patterns support `*` and `?`.

If no allowlist is provided, a built‑in default allowlist is used for
`elf_suspicious` findings in standard library and binary locations.

Example `allowlist.txt`:
```txt
# Common Alpine items
/bin/busybox
/sbin/apk
/usr/lib/libcrypto.so.3
/usr/lib/libssl.so.3

# Kind-specific pattern
elf_suspicious: /usr/lib/*
```

## Baseline File
Optional text file used to compare current findings against a known-good scan. Each line should match the scanner output format:
```
<kind>: <path>
```

Example `baseline.txt`:
```txt
elf_suspicious: /bin/busybox
startup_script_present: /var/spool/cron/crontabs/root
```

When a baseline is provided, the scanner lists **new** findings and shows any **missing** baseline entries.

To generate a baseline file from the current scan:
```bash
cargo run -- <image> <image.tar> <allowlist.txt> --baseline-out baseline.txt
```

## Output
The scanner prints:
- A list of findings (if any)
- The overall suspicion level

Example output:
```
[+] Findings:
 - elf_suspicious: sbin/apk (stripped)
 - startup_script_present: var/spool/cron/crontabs/root (init/rc/cron)
[+] Suspicion level: medium
```

Example high-severity output:
```
[+] Findings:
 - crypto_miner_candidate: usr/bin/xmrig (known miner name)
 - private_key_candidate: root/.ssh/id_rsa (key material present)
 - suid_or_sgid_executable: usr/bin/sudo (mode=4755)
 - apk_repository_suspicious: etc/apk/repositories (non-alpine repo: http://example.com/alpine)
[+] Suspicion level: high
```

## Signals Detected
- Suspicious ELF traits (stripped, static, packed sections)
- Executables in writable directories
- World-writable or SUID/SGID executables
- Hidden executables (dotfiles)
- ELF binaries outside common bin/lib paths
- Insecure `/etc/shadow` permissions
- SSH authorized keys
- Private key candidates in `.ssh/`
- Credential files (`.env*`, `.npmrc`, `.pypirc`, `.netrc`, `.aws/*`, `.kube/config`, `.docker/config.json`)
- Risky dual-use tools (`curl`, `wget`, `nc`, `socat`, `ssh`, `tcpdump`, etc.)
- Crypto miner names
- Startup scripts in init/rc/cron locations
- Suspicious APK repositories or unusual APK key names
- Suspicious package manager configs or lockfile sources (npm/pip/gem)

## Environment Variables
These are optional:
- `BSUPPLA_SKIP_DOCKER=1` to skip `docker pull/save` (useful for offline scans of an existing tar)
- `BSUPPLA_SKIP_SCAN=1` to skip scanning after extraction
- `BSUPPLA_OUTPUT_DIR=/path` to control the filesystem extraction directory (default `container_fs`)

## Tests
```bash
cargo test
```

## Notes
- The tool performs static inspection only. It does not execute files from the image.
- The allowlist suppresses findings by exact path match inside the image filesystem.
