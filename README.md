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

## Logging Results

The scripts print result output to stdout. Persist logs with:

```bash
bash release/dirtyfrag-probe-linux-universal.sh | tee -a /var/log/dirtyfrag-probe.log
```

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
