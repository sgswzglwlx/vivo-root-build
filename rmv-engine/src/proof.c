/* RMV-PROOF: доказательство реального рута для отчёта валидации пейлоада.
 *
 * Приложение передаёт нонс через env RMV_PROOF_NONCE (hex, до 64 символов)
 * и id пейлоада через env RMV_PROOF_PID (до 64 байт). После подтверждённого
 * uid==0 движок печатает в stdout строку:
 *   RMV-PROOF <hmac_sha256(nonce||'\\n'||uname||'\\n'||payload_id)>
 * HMAC-ключ зашит здесь (не в APK) — функция вызывается только после
 * реального получения рута из root-стадии, вне её недостижима. */
#include "common.h"

#include <sys/utsname.h>

/* 32 байта, известны только нативной части и CI-верификатору (Actions secret
 * RMV_PROOF_KEY). Меняются только вместе с перевыпуском всех пейлоадов. */
static const unsigned char rmv_proof_key[32] = {
  0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
  0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
  0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x6b, 0x8e, 0x21,
  0x9f, 0x19, 0x71, 0xd4, 0x95, 0xa1, 0x37, 0x87
};

/* компактный SHA-256 (public domain style, size-optimized) */
typedef struct { uint32_t s[8]; uint64_t len; uint8_t buf[64]; size_t n; } sha256_ctx;

static uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(sha256_ctx *c, const uint8_t p[64]) {
  static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
  uint32_t w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|
           ((uint32_t)p[i*4+2]<<8)|p[i*4+3];
  }
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ror32(w[i-15],7)^ror32(w[i-15],18)^(w[i-15]>>3);
    uint32_t s1 = ror32(w[i-2],17)^ror32(w[i-2],19)^(w[i-2]>>10);
    w[i] = w[i-16]+s0+w[i-7]+s1;
  }
  uint32_t a=c->s[0],b=c->s[1],d=c->s[2],e=c->s[3];
  uint32_t f=c->s[4],g=c->s[5],h=c->s[6],i2=c->s[7];
  for (int i = 0; i < 64; i++) {
    uint32_t S1 = ror32(e,6)^ror32(e,11)^ror32(e,25);
    uint32_t ch = (e&f)^((~e)&g);
    uint32_t t1 = h+S1+ch+K[i]+w[i];
    uint32_t S0 = ror32(a,2)^ror32(a,13)^ror32(a,22);
    uint32_t mj = (a&b)^(a&d)^(b&d);
    uint32_t t2 = S0+mj;
    h=g; g=f; f=e; e=d+t1; d=i2; i2=b; b=a; a=t1+t2;
  }
  c->s[0]+=a; c->s[1]+=b; c->s[2]+=d; c->s[3]+=e;
  c->s[4]+=f; c->s[5]+=g; c->s[6]+=h; c->s[7]+=i2;
}

static void sha256_init(sha256_ctx *c) {
  static const uint32_t IV[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  for (int i = 0; i < 8; i++) c->s[i] = IV[i];
  c->len = 0; c->n = 0;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t n) {
  const uint8_t *p = data;
  c->len += n;
  while (n) {
    size_t take = 64 - c->n; if (take > n) take = n;
    memcpy(c->buf + c->n, p, take);
    c->n += take; p += take; n -= take;
    if (c->n == 64) { sha256_compress(c, c->buf); c->n = 0; }
  }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
  uint64_t bits = c->len * 8;
  uint8_t pad = 0x80;
  sha256_update(c, &pad, 1);
  pad = 0;
  while (c->n != 56) sha256_update(c, &pad, 1);
  uint8_t tail[8];
  for (int i = 0; i < 8; i++) tail[i] = (uint8_t)(bits >> (56 - i*8));
  c->len -= 8; /* эти 8 байт не считаются длиной */
  sha256_update(c, tail, 8);
  for (int i = 0; i < 8; i++) {
    out[i*4]   = (uint8_t)(c->s[i]>>24);
    out[i*4+1] = (uint8_t)(c->s[i]>>16);
    out[i*4+2] = (uint8_t)(c->s[i]>>8);
    out[i*4+3] = (uint8_t)(c->s[i]);
  }
}

/* hmac_sha256(key, klen, msg, mlen, out32) */
static void rmv_hmac_sha256(const unsigned char *key, size_t klen,
                            const void *msg, size_t mlen,
                            unsigned char out[32]) {
  unsigned char k[64] = {0}, opad[64], ipad[64], inner[32];
  if (klen > 64) {
    sha256_ctx t; sha256_init(&t);
    sha256_update(&t, key, klen); sha256_final(&t, k);
    memcpy(k, k, 32);
  } else {
    memcpy(k, key, klen);
  }
  for (int i = 0; i < 64; i++) { ipad[i] = k[i]^0x36; opad[i] = k[i]^0x5c; }
  sha256_ctx c;
  sha256_init(&c); sha256_update(&c, ipad, 64);
  sha256_update(&c, msg, mlen); sha256_final(&c, inner);
  sha256_init(&c); sha256_update(&c, opad, 64);
  sha256_update(&c, inner, 32); sha256_final(&c, out);
}

/* Вызывается из root-стадии (после подтверждённого uid==0 в
 * collect_root_child). Пишет в stdout одну строку — приложение парсит
 * её из live-лога эксплойта. Без env-параметров молчит (старые пейлоады
 * и ручные запуски отчёт не шлют). */
void rmv_emit_proof(void) {
  const char *nonce = getenv("RMV_PROOF_NONCE");
  const char *pid = getenv("RMV_PROOF_PID");
  if (!nonce || !*nonce || !pid || !*pid) {
    return;
  }
  size_t nlen = strnlen(nonce, 129);
  if (nlen > 128) return;
  struct utsname u;
  if (uname(&u) != 0) return;
  char msg[512];
  int m = snprintf(msg, sizeof(msg), "%s\n%s\n%s", nonce, u.release, pid);
  if (m < 0 || (size_t)m >= sizeof(msg)) return;
  unsigned char mac[32];
  rmv_hmac_sha256(rmv_proof_key, sizeof(rmv_proof_key), msg, (size_t)m, mac);
  char hex[65];
  for (int i = 0; i < 32; i++) snprintf(hex + i*2, 3, "%02x", mac[i]);
  printf("RMV-PROOF %s\n", hex);
  fflush(stdout);
}
