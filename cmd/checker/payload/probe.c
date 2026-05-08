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
