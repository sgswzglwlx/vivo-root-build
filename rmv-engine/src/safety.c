/*
 * safety.c — защита от kernel panic во время эксплойта.
 *
 * Две главные защиты:
 *
 * 1. «Проверка перед записью» (write guard): перед каждой опасной
 *    записью в ядро через pipe physrw читаем целевое слово и сверяем
 *    с ожидаемым «sanity»-паттерном. Если значение выглядит мусорным
 *    (не похоже на канонический адрес/маленькое число) — запись
 *    пропускается, попытка завершается как неудача, но ядро живо.
 *    Причина большинства паников upstream: запись в неправильный адрес
 *    после неудачного reclaim'а.
 *
 * 2. «Период покоя» (quiesce): перед PI-маршрутом коротко ждём, пока
 *    система успокоится (реальная загрузка CPU по PSI). При высокой
 *    нагрузке schedule-тайминги рвутся и waiter попадает в чужой
 *    фрейм → panic.
 *
 *    ВАЖНО: /proc/loadavg на этом ядре (vivo) непригоден — он считает
 *    ещё и nr_uninterruptible-подобный счётчик vivo RSC (заморозка
 *    binder-фонов), который после загрузки взлетает до 500–1000 и
 *    распадается десятки минут, при реальной загрузке CPU 2–9% (PSI).
 *    Старый quiesce по loadavg<4 ждал зря и сам подгружал CPU.
 */

#include "common.h"
#include <stdio.h>

/* Читаем 1-минутный load average. Возвращает -1 при ошибке.
 * Диагностический лог только: как метрика покоя не используется. */
double safety_loadavg(void) {
  FILE *f = fopen("/proc/loadavg", "r");
  if (!f) {
    return -1;
  }
  double load = -1;
  int n = fscanf(f, "%lf", &load);
  fclose(f);
  return n == 1 ? load : -1;
}

/* Реальная загруженность CPU: дельта idle/total из /proc/stat,
 * усреднённая за окно ~1 с. Доступна всем (в отличие от /proc/pressure/*
 * на этом устройстве — SELinux EACCES для shell-домена).
 * Возвращает busy-fraction 0..1, при ошибке -1. */
double safety_cpu_busy(void) {
  FILE *f = fopen("/proc/stat", "r");
  if (!f) {
    return -1;
  }
  /* "cpu  user nice system idle iowait irq softirq steal guest guest_nice" */
  long long v[10] = {0};
  int n = fscanf(f, "cpu %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
                 &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7],
                 &v[8], &v[9]);
  fclose(f);
  if (n < 5) {
    return -1;
  }
  long long total = 0;
  for (int i = 0; i < n && i < 10; i++) {
    total += v[i];
  }
  long long idle = v[3] + (n > 4 ? v[4] : 0);
  usleep(1000000);
  f = fopen("/proc/stat", "r");
  if (!f) {
    return -1;
  }
  long long w[10] = {0};
  n = fscanf(f, "cpu %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
             &w[0], &w[1], &w[2], &w[3], &w[4], &w[5], &w[6], &w[7],
             &w[8], &w[9]);
  fclose(f);
  if (n < 5) {
    return -1;
  }
  long long total2 = 0;
  for (int i = 0; i < n && i < 10; i++) {
    total2 += w[i];
  }
  long long idle2 = w[3] + (n > 4 ? w[4] : 0);
  long long dt = total2 - total;
  if (dt <= 0) {
    return -1;
  }
  long long di = idle2 - idle;
  if (di < 0) {
    di = 0;
  }
  return (double)(dt - di) / (double)dt;
}

/* Ждём, пока реальная загрузка CPU (дельта /proc/stat) опустится ниже
 * threshold (busy-fraction 0..1; 0.5 = «занято больше половины времени
 * CPU»). Проверяем каждые 200 мс — быстро реагируем на просвет и не
 * грузим CPU сами. Каждая итерация логируется: если ожидание затянулось
 * или /proc/stat недоступен, это видно в live-логе (раньше «тихий
 * провал» на quiesce выглядел как зависание без причины). */
void safety_quiesce(double threshold, int timeout_sec) {
  for (int waited_ms = 0; waited_ms < timeout_sec * 1000;
       waited_ms += 200) {
    double busy = safety_cpu_busy();
    if (busy < 0) {
      pr_info("quiesce: /proc/stat unavailable (errno=%d), wait %dms — "
              "continuing without load check\n", errno, waited_ms);
      return;
    }
    if (busy < threshold) {
      if (waited_ms > 0) {
        pr_info("quiesce: settled after %dms (busy=%.2f)\n",
                waited_ms, busy);
      }
      return;
    }
    if ((waited_ms % 2000) == 0) {
      pr_info("quiesce: busy=%.2f >= %.2f, waited %dms (max %dms)\n",
              busy, threshold, waited_ms, timeout_sec * 1000);
    }
    usleep(200000);
  }
  /* Таймаут вышли без просвета: идём дальше, но честно сообщаем —
   * при высокой загрузке тайминги рвутся и попытка, скорее всего,
   * промахнётся (waiter попадёт в чужой фрейм). */
  pr_warning("quiesce: timeout %dms, busy still high — proceeding anyway, "
             "timings may miss\n", timeout_sec * 1000);
}

/* Sanity-проверка значения по адресу перед записью.
 * Ожидаем либо канонический kernel-адрес (0xffffff8.../0xffffffc...),
 * либо маленькое целое (флаги/счётчики). Всё остальное — мусор от
 * неудачного reclaim'а, писать нельзя. */
int safety_value_sane(uint64_t v) {
  if (v == 0) {
    return 1; /* ноль — нормальное значение для enforcing/флагов */
  }
  if (v >= 0xffffff8000000000ULL && v <= 0xffffffffffffffffULL) {
    return 1; /* канонический kernel указатель */
  }
  if (v < 0x100000ULL) {
    return 1; /* маленькое целое */
  }
  return 0;
}

/* Проверить слово по адресу через существующий physrw fd.
 * Возвращает 1 если значение прошло sanity-проверку. */
int safety_check_target(int fd, uintptr_t addr) {
  if (fd < 0) {
    return 1; /* нет fd — не проверяем, путь старый */
  }
  uint64_t v = 0;
  ssize_t n = kernel_read_data(fd, addr, &v, sizeof(v));
  if (n != (ssize_t)sizeof(v)) {
    return 0; /* нечитается — определённо мусор */
  }
  return safety_value_sane(v);
}
