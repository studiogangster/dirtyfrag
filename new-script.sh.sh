
#!/bin/bash

# =========================================================
# DirtyFrag CVE Test + Patch Validation + Callback Reporter
# Embeds payload C source in this script (no separate payload.c needed)
# Supports: Ubuntu / Debian / CentOS / RHEL / Rocky / Alma
# =========================================================

set -e

# ---------------- CONFIG ----------------
CALLBACK_URL="http://172.29.52.162:8080/callback"

HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
HOSTNAME=$(hostname)
KERNEL=$(uname -r)
OS=$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')

# fallback if hostname -I fails
if [ -z "$HOST_IP" ]; then
    HOST_IP=$(ip route get 1 | awk '{print $7;exit}')
fi

# script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------- EMBEDDED C PAYLOAD ----------------
PAYLOAD_SOURCE_FILE="$(mktemp /tmp/dirtyfrag-payload-XXXXXX.c)"
cleanup() {
    rm -f "$PAYLOAD_SOURCE_FILE"
}
trap cleanup EXIT

cat >"$PAYLOAD_SOURCE_FILE" <<'PAYLOAD_C_EOF'
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

static int exists(const char *path) {
  return access(path, F_OK) == 0;
}

int main(void) {
  struct utsname u;
  if (uname(&u) != 0) {
    fprintf(stderr, "ERROR: uname failed\n");
    return 2;
  }

  printf("sysname=%s\n", u.sysname);
  printf("release=%s\n", u.release);
  printf("machine=%s\n", u.machine);

  if (strcmp(u.sysname, "Linux") != 0) {
    printf("result=NOT_APPLICABLE (not Linux)\n");
    return 3;
  }

  int has_esp4 = exists("/sys/module/esp4");
  int has_esp6 = exists("/sys/module/esp6");
  int has_rxrpc = exists("/sys/module/rxrpc");

  printf("modules_loaded: esp4=%d esp6=%d rxrpc=%d\n", has_esp4, has_esp6, has_rxrpc);

  if ((has_esp4 || has_esp6) && has_rxrpc) {
    printf("result=LIKELY_VULNERABLE (required modules loaded)\n");
    return 0;
  }

  if (!has_rxrpc && !(has_esp4 || has_esp6)) {
    printf("result=LIKELY_NOT_VULNERABLE (modules not loaded)\n");
    return 1;
  }

  printf("result=UNKNOWN (partial module exposure)\n");
  return 2;
}
PAYLOAD_C_EOF

# ---------------- CALLBACK FUNCTION ----------------
send_callback() {
    local STAGE="$1"
    local STATUS="$2"
    local MESSAGE="$3"

    echo $1 $2 $3    

    # curl -s -X POST "$CALLBACK_URL" \
    #     -H "Content-Type: application/json" \
    #     -d "{
    #         \"hostname\":\"$HOSTNAME\",
    #         \"host_ip\":\"$HOST_IP\",
    #         \"kernel\":\"$KERNEL\",
    #                                                                                                                                    \"os\":\"$OS\",
    #         \"stage\":\"$STAGE\",
    #         \"status\":\"$STATUS\",            \"message\":\"$(echo "$MESSAGE" | tr '"' "'")\",
    #         \"timestamp\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"
    #     }" >/dev/null 2>&1 || true
}

# ---------------- START ----------------
send_callback "start" "info" "DirtyFrag validation started"

echo "[*] Host: $HOSTNAME ($HOST_IP)"
echo "[*] Kernel: $KERNEL"
echo "[*] OS: $OS"

# =========================================================
# OPTIONAL DEPENDENCY INSTALL
# =========================================================

install_deps() {
    if command -v apt >/dev/null 2>&1; then
        apt update -y
        apt install -y gcc make curl libbsd-dev
    elif command -v yum >/dev/null 2>&1; then
        yum install -y gcc make curl libbsd-devel
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y gcc make curl libbsd-devel
    fi
}

# send_callback "dependency_install" "running" "Installing dependencies"

# if install_deps; then
#     send_callback "dependency_install" "success" "Dependencies installed"
# else
#     send_callback "dependency_install" "failed" "Dependency installation failed"
# fi

# =========================================================
# PRE-PATCH VULNERABILITY TEST
# =========================================================

cd "$SCRIPT_DIR"

send_callback "pre_patch_test" "running" "Compiling embedded payload source"

if gcc -O0 -Wall -o exp "$PAYLOAD_SOURCE_FILE" -lutil; then
    send_callback "pre_patch_compile" "success" "Exploit compiled"
else
    send_callback "pre_patch_compile" "failed" "Exploit compilation failed"
    exit 1
fi

# give ownership to original sudo caller
chown "$SUDO_USER" ./exp

# make executable
chmod u+x ./exp



if [ ! -x ./exp ]; then
    send_callback "pre_patch_compile" "failed" "Binary not executable"
    exit 1
fi

send_callback "pre_patch_test" "running" "Executing exploit before patch"

PRE_OUTPUT=$(sudo -u "$SUDO_USER" bash -c '
echo "EXEC_USER=$(whoami)"
echo "EXEC_UID=$(id -u)"
./exp
' 2>&1 || true)

echo "$PRE_OUTPUT"

if echo "$PRE_OUTPUT" | grep -qiE "vulnerable|success|root"; then
    send_callback "pre_patch_test" "info" $SUDO_USER "vulnerable" "$PRE_OUTPUT"
else
    send_callback "pre_patch_test" "info" $SUDO_USER  "not_vulnerable" "$PRE_OUTPUT"
fi

# =========================================================
# APPLY PATCH / MITIGATION
# =========================================================

send_callback "patch" "running" "Applying mitigation"

PATCH_CMD='
printf "install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n" > /etc/modprobe.d/dirtyfrag.conf
rmmod esp4 esp6 rxrpc 2>/dev/null || true
echo 3 > /proc/sys/vm/drop_caches
'

if bash -c "$PATCH_CMD"; then
    send_callback "patch" "success" "Mitigation applied successfully"
else
    send_callback "patch" "failed" "Mitigation failed"
    exit 1
fi

# =========================================================
# POST-PATCH VALIDATION
# =========================================================

send_callback "post_patch_test" "running" "Executing exploit after patch"

# POST_OUTPUT=$(timeout 30 bash -c "./exp" 2>&1 || true)
POST_OUTPUT=$(sudo -u "$SUDO_USER" ./exp 2>&1 || true)


echo "$POST_OUTPUT"

send_callback "post_patch_test" $(whoami) $SUDO_USER "vulnerable" "$POST_OUTPUT"



# =========================================================
# FINAL STATUS
# =========================================================

send_callback "complete" "done" "DirtyFrag validation completed"

echo "[+] Completed"
