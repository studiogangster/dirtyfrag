# DirtyFrag Detector Toolkit

Lightweight, portable tooling to help defenders quickly assess likely Linux exposure conditions related to DirtyFrag module combinations.

This repo contains:
- a safe detection probe implemented in Go (`cmd/probe_pure`)
- single-file self-contained scripts with embedded binaries (no `gcc` needed on target)
- helper scripts to regenerate release artifacts for `linux/amd64`, `linux/arm64`, and universal multi-arch
- optional Nessus custom plugin starter (`nessus/`)

## Important Scope

This toolkit is for **authorized defensive testing** only.

The detector checks for module presence patterns and reports:
- `LIKELY_VULNERABLE`
- `LIKELY_NOT_VULNERABLE`
- `UNKNOWN`
- `NOT_APPLICABLE`

It is a posture check, not a full exploit validation.

## Quick Start (Pre-generated Scripts)

Pre-generated scripts are in `release/`:
- `release/dirtyfrag-probe-linux-amd64.sh`
- `release/dirtyfrag-probe-linux-arm64.sh`
- `release/dirtyfrag-probe-linux-universal.sh`

Run (example):

```bash
bash release/dirtyfrag-probe-linux-amd64.sh
```

Universal script auto-selects amd64 vs arm64:

```bash
bash release/dirtyfrag-probe-linux-universal.sh
```

## Run Without Cloning (Raw GitHub URL)

Use commit-pinned URLs for stable, cache-safe fetches:

```bash
# amd64
curl -fsSL https://raw.githubusercontent.com/studiogangster/dirtyfrag/bf3a199/release/dirtyfrag-probe-linux-amd64.sh -o dirtyfrag-probe.sh
chmod +x dirtyfrag-probe.sh
./dirtyfrag-probe.sh
```

```bash
# arm64
curl -fsSL https://raw.githubusercontent.com/studiogangster/dirtyfrag/bf3a199/release/dirtyfrag-probe-linux-arm64.sh -o dirtyfrag-probe.sh
chmod +x dirtyfrag-probe.sh
./dirtyfrag-probe.sh
```

```bash
# universal (auto-selects amd64/arm64)
curl -fsSL https://raw.githubusercontent.com/studiogangster/dirtyfrag/bf3a199/release/dirtyfrag-probe-linux-universal.sh -o dirtyfrag-probe.sh
chmod +x dirtyfrag-probe.sh
./dirtyfrag-probe.sh
```

If you prefer branch-based URLs, replace `bf3a199` with `master`.

## Logging Results

The scripts print result output to stdout. Persist logs with:

```bash
bash release/dirtyfrag-probe-linux-universal.sh | tee -a /var/log/dirtyfrag-probe.log
```

## Lab-Only: Re-enable Vulnerable Module State For Retesting

Do this only in an isolated lab VM you can rebuild. This intentionally weakens host security posture.

Risk advisory:
- Do not run on production systems.
- Take a VM snapshot first.
- Keep the host isolated from untrusted networks.
- Re-apply mitigation immediately after testing.

```bash
sudo rm -f /etc/modprobe.d/dirtyfrag.conf
sudo depmod -a
sudo modprobe esp4 2>/dev/null || true
sudo modprobe esp6 2>/dev/null || true
sudo modprobe rxrpc 2>/dev/null || true
lsmod | grep -E 'esp4|esp6|rxrpc'
```

## Cleanup

Important: After exploit-style testing, page cache may be contaminated. Clear polluted page cache and ensure system stability by either running:

```bash
echo 3 > /proc/sys/vm/drop_caches
```

or rebooting the system.

## Mitigation

Because responsible disclosure timelines and embargo handling can vary, patch availability may differ by distribution and time. If vendor fixes are not yet available in your environment, use the following temporary mitigation to disable relevant modules and clear page cache:

```bash
sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches; true"
```

Once your distribution backports and ships official fixes, update kernels/packages accordingly.

## Build From Source

Requirements:
- Go 1.22+

Build local checker binary:

```bash
make build
```

Build multi-platform checker binaries:

```bash
make build-all
```

## Generate Single-File Release Scripts

Generate all release scripts (`amd64`, `arm64`, `universal`):

```bash
make build-probe-scripts
```

or directly:

```bash
bash scripts/build-single-file-probes.sh ./release
```

Compatibility wrapper (also generates all):

```bash
bash scripts/build-single-file-probe.sh ./release
```

## Output Semantics

Exit and result meaning:
- Exit `0`: `LIKELY_VULNERABLE`
- Exit `1`: `LIKELY_NOT_VULNERABLE`
- Exit `2`: `UNKNOWN` or runtime issue
- Exit `3`: `NOT_APPLICABLE` (non-Linux)

## Nessus Custom Plugin (Optional)

Starter files are under `nessus/`:
- `nessus/dirtyfrag_local_check.nasl`
- `nessus/package/upload_this.tar.gz`

Use these as a base for internal authenticated local checks.

## Repository Layout

- `cmd/probe_pure/main.go` - pure-Go detector logic
- `scripts/build-single-file-probes.sh` - generates release scripts
- `release/` - pre-generated distributable scripts
- `nessus/` - custom NASL plugin starter package

## License / Policy

Use only on systems you own or are explicitly authorized to test.
