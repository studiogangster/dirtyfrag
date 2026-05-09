# DirtyFrag Quick Guide

Use only on systems you own or are explicitly authorized to test.

## Exploit Test

```bash
curl -fsSL https://raw.githubusercontent.com/studiogangster/dirtyfrag/master/release/dirtyfrag-probe-linux-universal.sh -o dirtyfrag-probe.sh
chmod +x dirtyfrag-probe.sh
./dirtyfrag-probe.sh

sudo echo 3 > /proc/sys/vm/drop_caches
```

## Patch

```bash
sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches; true"
```

## Verify

```bash
curl -fsSL https://raw.githubusercontent.com/studiogangster/dirtyfrag/master/release/dirtyfrag-probe-linux-amd64.sh -o dirtyfrag-probe.sh
chmod +x dirtyfrag-probe.sh
./dirtyfrag-probe.sh
```
