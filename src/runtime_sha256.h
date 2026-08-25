#ifndef RUNTIME_SHA256_H
#define RUNTIME_SHA256_H

#include <stddef.h>
#include <stdint.h>

struct runtime_sha256 {
  uint32_t state[8];
  uint64_t bit_count;
  unsigned char block[64];
  size_t block_used;
};

void runtime_sha256_init(struct runtime_sha256 *ctx);
void runtime_sha256_update(struct runtime_sha256 *ctx, const void *data,
                           size_t size);
void runtime_sha256_final(struct runtime_sha256 *ctx, unsigned char out[32]);
void runtime_sha256_hex(const void *data, size_t size, char out[65]);

#endif
