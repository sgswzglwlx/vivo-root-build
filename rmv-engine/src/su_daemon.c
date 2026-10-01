#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

/* Пути — через RMV_HOME (резолвер rmv_home() живёт в util.c, но su_daemon
 * собирается и отдельным бинарником без него — дублируем тут компактно):
 * приложение ставит RMV_HOME в свой filesDir/rmv, старые shell-запуски
 * работают с дефолтом /data/local/tmp. */
static char g_sock_path[300];
static char g_pid_path[300];
static char g_home[256];
static int g_paths_init = 0;

static void rmv_paths_init(void) {
  if (g_paths_init) {
    return;
  }
  g_paths_init = 1;
  const char *e = getenv("RMV_HOME");
  size_t n = e ? strlen(e) : 0;
  if (n == 0 || n >= sizeof(g_home) - 32) {
    snprintf(g_home, sizeof(g_home), "/data/local/tmp");
  } else {
    snprintf(g_home, sizeof(g_home), "%s", e);
    size_t h = strlen(g_home);
    while (h > 1 && g_home[h - 1] == '/') {
      g_home[--h] = 0;
    }
  }
  snprintf(g_sock_path, sizeof(g_sock_path), "%s/temp_su.sock", g_home);
  snprintf(g_pid_path, sizeof(g_pid_path), "%s/temp_su.pid", g_home);
}

#define SOCK_PATH (rmv_paths_init(), g_sock_path)
#define PID_PATH (rmv_paths_init(), g_pid_path)

/* Убить демона из прошлой попытки/запуска: он навсегда висит в
 * accept4() на осиротевшем сокете (новый демон уже сделал unlink+bind
 * по тому же пути) и копится — по одному на каждый успешный эксплойт.
 * PID-файл пишем до fork-клиентов, проверяем по /proc/<pid>/cmdline,
 * чтобы не зацепить чужой процесс с реиспользованным PID. */
static void kill_previous_daemon(void) {
  FILE *f = fopen(PID_PATH, "r");
  if (!f) {
    return;
  }
  char cmdline[64];
  long pid = 0;
  int ok = fscanf(f, "%ld", &pid) == 1;
  fclose(f);
  if (!ok || pid <= 1 || pid == getpid()) {
    return;
  }
  snprintf(cmdline, sizeof(cmdline), "/proc/%ld/cmdline", pid);
  char buf[128] = {0};
  int fd = open(cmdline, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return; /* процесса нет — PID устарел */
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0 || strstr(buf, "su --daemon") == NULL) {
    return; /* не наш процесс */
  }
  kill((pid_t)pid, SIGTERM);
  /* даём ему умереть: accept4 в главном потоке не прерывается сигналом
   * по умолчанию без обработчика — ставим его до этого в daemon_main */
  usleep(200000);
  kill((pid_t)pid, SIGKILL);
}

static void set_root_env(void) {
  setenv("PATH",
         "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
         "/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:"
         "/odm/bin:/vendor/bin:/vendor/xbin",
         1);
  setenv("HOME", (rmv_paths_init(), g_home), 1);
  setenv("USER", "root", 1);
  setenv("LOGNAME", "root", 1);
}

static void xwrite(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      _exit(111);
    }
    p += n;
    len -= (size_t)n;
  }
}

static int read_full(int fd, void *buf, size_t len) {
  char *p = (char *)buf;
  while (len) {
    ssize_t n = read(fd, p, len);
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

static int connect_daemon(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("su: socket");
    return -1;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SOCK_PATH);

  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("su: connect daemon");
    close(fd);
    return -1;
  }
  return fd;
}

static int pump_pair(int a, int b) {
  char buf[4096];
  int a_open = 1;
  int b_open = 1;

  while (a_open || b_open) {
    struct pollfd pfd[2];
    int nfd = 0;
    if (a_open) {
      pfd[nfd].fd = a;
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    if (b_open) {
      pfd[nfd].fd = b;
      pfd[nfd].events = POLLIN;
      nfd++;
    }

    int pr = poll(pfd, (nfds_t)nfd, -1);
    if (pr < 0 && errno == EINTR) {
      continue;
    }
    if (pr < 0) {
      return 1;
    }

    int idx = 0;
    if (a_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(a, buf, sizeof(buf));
        if (n > 0) {
          xwrite(b, buf, (size_t)n);
        } else {
          a_open = 0;
          shutdown(b, SHUT_WR);
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        a_open = 0;
        shutdown(b, SHUT_WR);
      }
    }
    if (b_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(b, buf, sizeof(buf));
        if (n > 0) {
          xwrite(a, buf, (size_t)n);
        } else {
          b_open = 0;
          shutdown(a, SHUT_WR);
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        b_open = 0;
        shutdown(a, SHUT_WR);
      }
    }
  }
  return 0;
}

/* When the KernelSU su binary (/system/bin/su) is present and usable, forward
 * to it instead of the standalone socket daemon. This binary is often reached
 * through /apex/com.android.virt/bin/su (which PATH resolves first); the socket
 * daemon it would otherwise talk to runs in the kernel domain whose socket the
 * shell client cannot connect to (EACCES). KernelSU's su provides the real
 * root. Returns 1 if we exec'd it (never returns on success). */
static int try_forward_kernelsu(int argc, char **argv) {
  if (access("/system/bin/su", F_OK) != 0) {
    return 0;
  }
  /* Build argv with argv[0] set to the target path so KernelSU's su behaves
   * normally. Keep flags and args as passed. */
  char *new_argv[64];
  int n = argc;
  if (n > 63) {
    n = 63;
  }
  new_argv[0] = "/system/bin/su";
  for (int i = 1; i < n; i++) {
    new_argv[i] = argv[i];
  }
  new_argv[n] = NULL;
  execv(new_argv[0], new_argv);
  /* exec failed: fall through to the socket daemon. */
  return 0;
}

static int client_main(int argc, char **argv) {
  if (try_forward_kernelsu(argc, argv)) {
    /* not reached on success */
  }

  int fd = connect_daemon();
  if (fd < 0) {
    return 127;
  }

  if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
    char mode = 'C';
    uint32_t len = (uint32_t)strlen(argv[2]);
    xwrite(fd, &mode, 1);
    xwrite(fd, &len, sizeof(len));
    xwrite(fd, argv[2], len);
    shutdown(fd, SHUT_WR);

    char buf[4096];
    for (;;) {
      ssize_t n = read(fd, buf, sizeof(buf));
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n <= 0) {
        break;
      }
      xwrite(STDOUT_FILENO, buf, (size_t)n);
    }
    close(fd);
    return 0;
  }

  char mode = 'I';
  xwrite(fd, &mode, 1);
  int rc = pump_pair(STDIN_FILENO, fd);
  close(fd);
  return rc;
}

static void exec_command_client(int conn, const char *cmd) {
  pid_t pid = fork();
  if (pid == 0) {
    dup2(conn, STDIN_FILENO);
    dup2(conn, STDOUT_FILENO);
    dup2(conn, STDERR_FILENO);
    close(conn);
    set_root_env();
    execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
    _exit(127);
  }

  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
}

static int open_pty_master(char *slave, size_t slave_len) {
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0) {
    return -1;
  }
  if (grantpt(master) != 0 || unlockpt(master) != 0) {
    close(master);
    return -1;
  }
  if (ptsname_r(master, slave, slave_len) != 0) {
    close(master);
    return -1;
  }
  return master;
}

static void exec_interactive_client(int conn) {
  char slave_name[128];
  int master = open_pty_master(slave_name, sizeof(slave_name));
  if (master < 0) {
    const char msg[] = "su daemon: failed to open pty\n";
    xwrite(conn, msg, sizeof(msg) - 1);
    return;
  }

  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
      _exit(126);
    }
    ioctl(slave, TIOCSCTTY, 0);
    dup2(slave, STDIN_FILENO);
    dup2(slave, STDOUT_FILENO);
    dup2(slave, STDERR_FILENO);
    if (slave > STDERR_FILENO) {
      close(slave);
    }
    close(master);
    close(conn);
    set_root_env();
    execl("/system/bin/sh", "sh", "-i", (char *)NULL);
    _exit(127);
  }

  pump_pair(conn, master);
  kill(pid, SIGHUP);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  close(master);
}

static void serve_one(int conn) {
  char mode = 0;
  if (!read_full(conn, &mode, 1)) {
    return;
  }

  if (mode == 'C') {
    uint32_t len = 0;
    if (!read_full(conn, &len, sizeof(len)) || len > 65536) {
      return;
    }
    char *cmd = calloc(1, (size_t)len + 1);
    if (!cmd) {
      return;
    }
    if (!read_full(conn, cmd, len)) {
      free(cmd);
      return;
    }
    exec_command_client(conn, cmd);
    free(cmd);
  } else if (mode == 'I') {
    exec_interactive_client(conn);
  }
}

static void try_chcon_socket(void) {
  pid_t pid = fork();
  if (pid == 0) {
    execl("/system/bin/chcon", "chcon", "u:object_r:shell_data_file:s0",
          SOCK_PATH, (char *)NULL);
    _exit(127);
  }
  if (pid > 0) {
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
  }
}

static int daemon_main(void) {
  signal(SIGPIPE, SIG_IGN);
  /* accept4() прерывается сигналом только с SA_RESTART выключенным */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; /* без SA_REESTART: accept вернёт EINTR */
  sigaction(SIGTERM, &sa, NULL);
  set_root_env();

  kill_previous_daemon();

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("socket");
    return 1;
  }

  unlink(SOCK_PATH);
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SOCK_PATH);

  if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("bind");
    return 1;
  }
  chmod(SOCK_PATH, 0666);
  /* Give the unix socket a context the shell domain may connect to; without
   * this, SELinux rejects the client's connect() with EACCES even though the
   * file mode is 0666. */
  try_chcon_socket();
  if (listen(fd, 16) != 0) {
    perror("listen");
    return 1;
  }

  fprintf(stderr, "su daemon ready pid=%d socket=%s uid=%d euid=%d\n",
          getpid(), SOCK_PATH, getuid(), geteuid());

  /* PID-файл: следующий демон по нему найдёт и завершит нас */
  {
    FILE *pf = fopen(PID_PATH, "w");
    if (pf) {
      fprintf(pf, "%ld\n", (long)getpid());
      fclose(pf);
    }
  }

  for (;;) {
    int conn = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0 && errno == EINTR) {
      continue;
    }
    if (conn < 0) {
      perror("accept");
      sleep(1);
      continue;
    }

    pid_t pid = fork();
    if (pid == 0) {
      close(fd);
      serve_one(conn);
      close(conn);
      _exit(0);
    }
    close(conn);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
  }
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "--daemon") == 0) {
    return daemon_main();
  }
  return client_main(argc, argv);
}
