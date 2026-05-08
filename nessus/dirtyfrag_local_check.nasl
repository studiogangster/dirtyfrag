include("compat.inc");

# NOTE:
# - Set script_id() to a unique custom ID in your environment.
# - This is an authenticated/local check intended for Linux targets.

if (description)
{
  script_id(990001);
  script_version("1.0");
  script_cve_id("CVE-2022-2588");

  script_name("DirtyFrag (CVE-2022-2588) - Local Exposure Check (Custom)");
  script_summary("Checks whether module conditions associated with DirtyFrag exposure are present.");

  script_set_attribute(attribute:"synopsis", value:
    "Detects likely exposure to DirtyFrag by checking Linux kernel and relevant modules via authenticated checks.");

  script_set_attribute(attribute:"description", value:
    "This custom plugin performs a local/authenticated posture check for DirtyFrag-related exposure. " +
    "It reports hosts where rxrpc is loaded together with esp4 or esp6.");

  script_set_attribute(attribute:"solution", value:
    "Apply vendor kernel/security updates and mitigation guidance. " +
    "If temporary mitigation is required, disable/unload impacted modules per your hardening policy.");

  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_set_attribute(attribute:"plugin_publication_date", value:"2026/05/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/18");

  script_category(ACT_GATHER_INFO);
  script_family("Linux Local Security Checks");

  # Requires authenticated checks.
  script_dependencies("ssh_authorization.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

if (!get_kb_item("Host/local_checks_enabled"))
  exit(0);

kernel = chomp(pread(cmd:"uname -r 2>/dev/null"));
if (!kernel)
  exit(0);

sysname = chomp(pread(cmd:"uname -s 2>/dev/null"));
if (sysname != "Linux")
  exit(0);

has_esp4  = chomp(pread(cmd:"test -d /sys/module/esp4  && echo 1 || echo 0"));
has_esp6  = chomp(pread(cmd:"test -d /sys/module/esp6  && echo 1 || echo 0"));
has_rxrpc = chomp(pread(cmd:"test -d /sys/module/rxrpc && echo 1 || echo 0"));

if ((has_rxrpc == "1") && ((has_esp4 == "1") || (has_esp6 == "1")))
{
  report =
    'Kernel: ' + kernel + '\n' +
    'Modules loaded: esp4=' + has_esp4 + ', esp6=' + has_esp6 + ', rxrpc=' + has_rxrpc + '\n\n' +
    'Result: LIKELY_EXPOSED (module condition met).\n' +
    'Note: This is a posture check, not exploit validation.';

  security_warning(port:0, extra:report);
  exit(0);
}

# No finding emitted when module condition is not met.
exit(0);
