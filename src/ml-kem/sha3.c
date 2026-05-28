/*
 * Copyright (C) 2025 A. Russon
 *
 * Released under the MIT license.
 */

#include <string.h>
#include "sha3.h"

#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

#define NROUNDS 24
#define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))

static uint64_t load64(const uint8_t *a) {
  uint64_t b;
  b = (uint64_t)a[0]
      | (uint64_t)a[1] << 8
      | (uint64_t)a[2] << 16
      | (uint64_t)a[3] << 24
      | (uint64_t)a[4] << 32
      | (uint64_t)a[5] << 40
      | (uint64_t)a[6] << 48
      | (uint64_t)a[7] << 56;
  return b;
}

/* Keccak round constants */
static const uint64_t RC[NROUNDS] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

/**
 * Adapted from the public domain implementation http://bench.cr.yp.to/supercop.html
 * in the file crypto_hash/keccakc512/simple/Keccak-simple.c.
 */
static void keccak_p(uint64_t *state) {
  int round;
  uint64_t a[KECCAK_BLOCK_WORD_LEN];
  uint64_t b[5];
  uint64_t d[5];
  uint64_t e[KECCAK_BLOCK_WORD_LEN];

  memcpy(a, state, KECCAK_BLOCK_BYTE_LEN);

  for (round = 0; round < NROUNDS; round += 2) {
    b[0] = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    b[1] = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    b[2] = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    b[3] = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    b[4] = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

    d[0] = b[4] ^ ROL(b[1], 1);
    d[1] = b[0] ^ ROL(b[2], 1);
    d[2] = b[1] ^ ROL(b[3], 1);
    d[3] = b[2] ^ ROL(b[4], 1);
    d[4] = b[3] ^ ROL(b[0], 1);

    b[0] =     a[0]  ^ d[0];
    b[1] = ROL(a[6]  ^ d[1], 44);
    b[2] = ROL(a[12] ^ d[2], 43);
    b[3] = ROL(a[18] ^ d[3], 21);
    b[4] = ROL(a[24] ^ d[4], 14);
    e[0] = b[0] ^ ((~b[1]) & b[2]) ^ RC[round];
    e[1] = b[1] ^ ((~b[2]) & b[3]);
    e[2] = b[2] ^ ((~b[3]) & b[4]);
    e[3] = b[3] ^ ((~b[4]) & b[0]);
    e[4] = b[4] ^ ((~b[0]) & b[1]);

    b[0] = ROL(a[3]  ^ d[3], 28);
    b[1] = ROL(a[9]  ^ d[4], 20);
    b[2] = ROL(a[10] ^ d[0], 3);
    b[3] = ROL(a[16] ^ d[1], 45);
    b[4] = ROL(a[22] ^ d[2], 61);
    e[5] = b[0] ^ ((~b[1]) & b[2]);
    e[6] = b[1] ^ ((~b[2]) & b[3]);
    e[7] = b[2] ^ ((~b[3]) & b[4]);
    e[8] = b[3] ^ ((~b[4]) & b[0]);
    e[9] = b[4] ^ ((~b[0]) & b[1]);

    b[0] = ROL(a[1]  ^ d[1], 1);
    b[1] = ROL(a[7]  ^ d[2], 6);
    b[2] = ROL(a[13] ^ d[3], 25);
    b[3] = ROL(a[19] ^ d[4], 8);
    b[4] = ROL(a[20] ^ d[0], 18);
    e[10] = b[0] ^ ((~b[1]) & b[2]);
    e[11] = b[1] ^ ((~b[2]) & b[3]);
    e[12] = b[2] ^ ((~b[3]) & b[4]);
    e[13] = b[3] ^ ((~b[4]) & b[0]);
    e[14] = b[4] ^ ((~b[0]) & b[1]);

    b[0] = ROL(a[4]  ^ d[4], 27);
    b[1] = ROL(a[5]  ^ d[0], 36);
    b[2] = ROL(a[11] ^ d[1], 10);
    b[3] = ROL(a[17] ^ d[2], 15);
    b[4] = ROL(a[23] ^ d[3], 56);
    e[15] = b[0] ^ ((~b[1]) & b[2]);
    e[16] = b[1] ^ ((~b[2]) & b[3]);
    e[17] = b[2] ^ ((~b[3]) & b[4]);
    e[18] = b[3] ^ ((~b[4]) & b[0]);
    e[19] = b[4] ^ ((~b[0]) & b[1]);

    b[0] = ROL(a[2]  ^ d[2], 62);
    b[1] = ROL(a[8]  ^ d[3], 55);
    b[2] = ROL(a[14] ^ d[4], 39);
    b[3] = ROL(a[15] ^ d[0], 41);
    b[4] = ROL(a[21] ^ d[1], 2);
    e[20] = b[0] ^ ((~b[1]) & b[2]);
    e[21] = b[1] ^ ((~b[2]) & b[3]);
    e[22] = b[2] ^ ((~b[3]) & b[4]);
    e[23] = b[3] ^ ((~b[4]) & b[0]);
    e[24] = b[4] ^ ((~b[0]) & b[1]);

    b[0] = e[0] ^ e[5] ^ e[10] ^ e[15] ^ e[20];
    b[1] = e[1] ^ e[6] ^ e[11] ^ e[16] ^ e[21];
    b[2] = e[2] ^ e[7] ^ e[12] ^ e[17] ^ e[22];
    b[3] = e[3] ^ e[8] ^ e[13] ^ e[18] ^ e[23];
    b[4] = e[4] ^ e[9] ^ e[14] ^ e[19] ^ e[24];

    d[0] = b[4] ^ ROL(b[1], 1);
    d[1] = b[0] ^ ROL(b[2], 1);
    d[2] = b[1] ^ ROL(b[3], 1);
    d[3] = b[2] ^ ROL(b[4], 1);
    d[4] = b[3] ^ ROL(b[0], 1);

    b[0] =     e[0]  ^ d[0];
    b[1] = ROL(e[6]  ^ d[1], 44);
    b[2] = ROL(e[12] ^ d[2], 43);
    b[3] = ROL(e[18] ^ d[3], 21);
    b[4] = ROL(e[24] ^ d[4], 14);
    a[0] = b[0] ^ ((~b[1]) & b[2]) ^ RC[round + 1];
    a[1] = b[1] ^ ((~b[2]) & b[3]);
    a[2] = b[2] ^ ((~b[3]) & b[4]);
    a[3] = b[3] ^ ((~b[4]) & b[0]);
    a[4] = b[4] ^ ((~b[0]) & b[1]);

    b[0] = ROL(e[3]  ^ d[3], 28);
    b[1] = ROL(e[9]  ^ d[4], 20);
    b[2] = ROL(e[10] ^ d[0], 3);
    b[3] = ROL(e[16] ^ d[1], 45);
    b[4] = ROL(e[22] ^ d[2], 61);
    a[5] = b[0] ^ ((~b[1]) & b[2]);
    a[6] = b[1] ^ ((~b[2]) & b[3]);
    a[7] = b[2] ^ ((~b[3]) & b[4]);
    a[8] = b[3] ^ ((~b[4]) & b[0]);
    a[9] = b[4] ^ ((~b[0]) & b[1]);

    b[0] = ROL(e[1]  ^ d[1], 1);
    b[1] = ROL(e[7]  ^ d[2], 6);
    b[2] = ROL(e[13] ^ d[3], 25);
    b[3] = ROL(e[19] ^ d[4], 8);
    b[4] = ROL(e[20] ^ d[0], 18);
    a[10] = b[0] ^ ((~b[1]) & b[2]);
    a[11] = b[1] ^ ((~b[2]) & b[3]);
    a[12] = b[2] ^ ((~b[3]) & b[4]);
    a[13] = b[3] ^ ((~b[4]) & b[0]);
    a[14] = b[4] ^ ((~b[0]) & b[1]);

    b[0] = ROL(e[4]  ^ d[4], 27);
    b[1] = ROL(e[5]  ^ d[0], 36);
    b[2] = ROL(e[11] ^ d[1], 10);
    b[3] = ROL(e[17] ^ d[2], 15);
    b[4] = ROL(e[23] ^ d[3], 56);
    a[15] = b[0] ^ ((~b[1]) & b[2]);
    a[16] = b[1] ^ ((~b[2]) & b[3]);
    a[17] = b[2] ^ ((~b[3]) & b[4]);
    a[18] = b[3] ^ ((~b[4]) & b[0]);
    a[19] = b[4] ^ ((~b[0]) & b[1]);

    b[0] = ROL(e[2]  ^ d[2], 62);
    b[1] = ROL(e[8]  ^ d[3], 55);
    b[2] = ROL(e[14] ^ d[4], 39);
    b[3] = ROL(e[15] ^ d[0], 41);
    b[4] = ROL(e[21] ^ d[1], 2);
    a[20] = b[0] ^ ((~b[1]) & b[2]);
    a[21] = b[1] ^ ((~b[2]) & b[3]);
    a[22] = b[2] ^ ((~b[3]) & b[4]);
    a[23] = b[3] ^ ((~b[4]) & b[0]);
    a[24] = b[4] ^ ((~b[0]) & b[1]);
  }

  memcpy(state, a, KECCAK_BLOCK_BYTE_LEN);
}

static void keccak_init(keccak_state_t *k_state, const size_t rate) {
  memset((uint8_t *)k_state->state, 0, KECCAK_BLOCK_BYTE_LEN);
  k_state->pos = 0;
  k_state->rate = rate;
}

static void keccak_absorb(keccak_state_t *k_state, const uint8_t *input, const size_t len) {
  size_t n, i, j, nblocks, rem_len;

  n = k_state->rate - k_state->pos;

  if (len < n) {
    // continue to fill the incomplete block
    memcpy(&k_state->buf[k_state->pos], input, len);
    k_state->pos += len;
  }
  else {
    // complete current block
    memcpy(&k_state->buf[k_state->pos], input, n);
    for(i = 0; i < k_state->rate; i += 8) {
      k_state->state[i / 8] ^= load64(&k_state->buf[i]);
    }
    keccak_p(k_state->state);

    // full blocks (xor directly in state)
    nblocks = (len - n) / k_state->rate;
    rem_len = (len - n) % k_state->rate;
    for(i = 0; i < nblocks; i++) {
      for(j = 0; j < k_state->rate; j += 8) {
        k_state->state[j / 8] ^= load64(&input[n + i*k_state->rate + j]);
      }
      keccak_p(k_state->state);
    }

    // last incomplete block (copy in buf)
    k_state->pos = rem_len;
    memcpy(k_state->buf, &input[n + nblocks*k_state->rate], rem_len);
  }
}

static void keccak_finalize(keccak_state_t *k_state, const uint8_t pad) {
  size_t i;
  
  // pad block
  memset(&k_state->buf[k_state->pos], 0, k_state->rate - k_state->pos);
  k_state->buf[k_state->pos] = pad;
  k_state->buf[k_state->rate - 1] |= 0x80;
  for(i = 0; i < k_state->rate; i += 8) {
    k_state->state[i / 8] ^= load64(&k_state->buf[i]);
  }

  k_state->pos = 0;
}

// single call to absorb
static void keccak_absorb_finalize(keccak_state_t *k_state,
                                   const uint8_t *input, const size_t len,
                                   const uint8_t pad) {
  size_t i, j, nblocks, rem_len;
  
  nblocks = len / k_state->rate;
  rem_len = len % k_state->rate;

  // full blocks
  for(i = 0; i < nblocks; i++) {
    for(j = 0; j < k_state->rate; j += 8) {
      k_state->state[j / 8] ^= load64(&input[i*k_state->rate + j]);
    }
    keccak_p(k_state->state);
  }

  // incomplete block
  memcpy(k_state->buf, &input[nblocks*k_state->rate], rem_len);
  memset(&k_state->buf[rem_len], 0, k_state->rate - rem_len);
  k_state->buf[rem_len] = pad;
  k_state->buf[k_state->rate - 1] |= 0x80;
  for(i = 0; i < k_state->rate; i += 8) {
    k_state->state[i / 8] ^= load64(&k_state->buf[i]);
  }
}

// applies a keccak round and copy into buf byte array
static void keccak_squeeze_block(keccak_state_t *k_state) {
  size_t i, j;
  keccak_p(k_state->state);
  for(i = 0; i < KECCAK_BLOCK_WORD_LEN; i++) {
    for(j = 0; j < 8; j++) {
      k_state->buf[i*8 + j] = (uint8_t)(k_state->state[i] >> (j*8));
    }
  }
}

// extract some output
static void keccak_squeeze(keccak_state_t *k_state, uint8_t *output, const size_t len) {
  size_t i, nblocks, remblock_len, rem_len;
  
  rem_len = k_state->rate - k_state->pos;
  if (len >= rem_len) {
    // use all remaining bytes of current state
    memcpy(output, &(k_state->buf[k_state->pos]), rem_len);
    k_state->pos = 0;
  }
  else {
    // use a part of the remaining bytes of current state
    memcpy(output, &(k_state->buf[k_state->pos]), len);
    k_state->pos += len;
    return;
  }

  // full blocks
  nblocks = (len - rem_len) / k_state->rate;
  remblock_len = (len - rem_len) % k_state->rate;
  for(i = 0; i < nblocks; i++) {
    keccak_squeeze_block(k_state);
    memcpy(&output[rem_len + i*k_state->rate], k_state->buf, k_state->rate);
  }

  // last bytes
  keccak_squeeze_block(k_state);
  if (remblock_len > 0) {
    memcpy(&output[rem_len + nblocks*k_state->rate], k_state->buf, remblock_len);
    k_state->pos = remblock_len;
  }
}

/**
 * SHA3-256
 *
 * Single call to compute a single hash with SHA3-256.
 *
 * Arguments:
 *  - output: pointer to output (32 bytes)
 *  - input:  pointer to input
 *  - len:    length of input in bytes
 */
void sha3_256(uint8_t output[SHA3_256_LEN], const uint8_t *input, const size_t len) {
  keccak_state_t k_state;
  keccak_init(&k_state, SHA3_256_RATE);
  keccak_absorb_finalize(&k_state, input, len, 0x06);
  keccak_squeeze_block(&k_state);
  memcpy(output, k_state.buf, SHA3_256_LEN);
}

/**
 * SHA3-256 initialization
 *
 * Initialization of a SHA3-256 context for multiple call to update.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void sha3_256_init(sha3_state_t *state) {
  keccak_init(state, SHA3_256_RATE);
}

/**
 * SHA3-256 update
 *
 * Absorb new bytes into the internal state.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 *  - input: pointer to input
 *  - len:   length of input in bytes
 */
void sha3_256_update(sha3_state_t *state, const uint8_t *input, const size_t len) {
  keccak_absorb(state, input, len);
}

/**
 * SHA3-256 digest
 *
 * Returns the SHA3-256 digest of all aborbed bytes.
 *
 * Arguments:
 *  - state:  pointer to context that contains the internal state
 *  - output: pointer to output (32 bytes)
 */
void sha3_256_digest(sha3_state_t *state, uint8_t output[SHA3_256_LEN]) {
  keccak_finalize(state, 0x06);
  keccak_squeeze_block(state);
  memcpy(output, state->buf, SHA3_256_LEN);
}

/**
 * SHA3-512
 *
 * Single call to compute a single hash with SHA3-512.
 *
 * Arguments:
 *  - output: pointer to output (64 bytes)
 *  - input:  pointer to input
 *  - len:    length of input in bytes
 */
void sha3_512(uint8_t output[SHA3_512_LEN], const uint8_t *input, const size_t len) {
  keccak_state_t k_state;
  keccak_init(&k_state, SHA3_512_RATE);
  keccak_absorb_finalize(&k_state, input, len, 0x06);
  keccak_squeeze_block(&k_state);
  memcpy(output, k_state.buf, SHA3_512_LEN);
}

/**
 * SHA3-512 initialization
 *
 * Initialization of a SHA3-512 context for multiple call to update.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void sha3_512_init(sha3_state_t *state) {
  keccak_init(state, SHA3_512_RATE);
}

/**
 * SHA3-512 update
 *
 * Absorb new bytes into the internal state.
 * Can be called multiple times.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 *  - input: pointer to input
 *  - len:   length of input in bytes
 */
void sha3_512_update(sha3_state_t *state, const uint8_t *input, const size_t len) {
  keccak_absorb(state, input, len);
}

/**
 * SHA3-512 digest
 *
 * Returns the SHA3-512 digest of all aborbed bytes.
 *
 * Arguments:
 *  - state:  pointer to context that contains the internal state
 *  - output: pointer to output (64 bytes)
 */
void sha3_512_digest(sha3_state_t *state, uint8_t output[SHA3_512_LEN]) {
  keccak_finalize(state, 0x06);
  keccak_squeeze_block(state);
  memcpy(output, state->buf, SHA3_512_LEN);
}

/**
 * SHAKE128
 *
 * Single call to compute a SHAKE128 variable output.
 *
 * Arguments:
 *  - output:     pointer to output (caller is responsible for allocation)
 *  - output_len: length of output in bytes
 *  - input:      pointer to input
 *  - input_len:  length of input in bytes
 */
void shake128(uint8_t *output, const size_t output_len,
              const uint8_t *input, const size_t input_len) {
  keccak_state_t k_state;
  keccak_init(&k_state, SHAKE128_RATE);
  keccak_absorb_finalize(&k_state, input, input_len, 0x1f);
  keccak_squeeze_block(&k_state);
  keccak_squeeze(&k_state, output, output_len);
}

/**
 * SHAKE128 initialization
 *
 * Initialization of a SHAKE128 context for multiple call to update/squeeze.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake128_init(shake_state_t *state) {
  keccak_init(state, SHAKE128_RATE);
}

/**
 * SHAKE128 absorb
 *
 * Absorb new bytes into the SHAKE128 internal state.
 * Can be called multiple times.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 *  - input: pointer to input
 *  - len:   length of input in bytes
 */
void shake128_absorb(shake_state_t *state, const uint8_t *input, const size_t len) {
  keccak_absorb(state, input, len);
}

/**
 * SHAKE128 finalize
 *
 * Terminate the aborption phase.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake128_finalize(shake_state_t *state) {
  keccak_finalize(state, 0x1f);
  keccak_squeeze_block(state);
}

/**
 * SHAKE128 squeeze
 *
 * Squeeze some bytes.
 * Can be called multiple times.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake128_squeeze(shake_state_t *state, uint8_t *output, const size_t len) {
  keccak_squeeze(state, output, len);
}

/**
 * SHAKE256
 *
 * Single call to compute a SHAKE256 variable output.
 *
 * Arguments:
 *  - output:     pointer to output (caller is responsible for allocation)
 *  - output_len: length of output in bytes
 *  - input:      pointer to input
 *  - input_len:  length of input in bytes
 */
void shake256(uint8_t *output, const size_t output_len,
              const uint8_t *input, const size_t input_len) {
  keccak_state_t k_state;
  keccak_init(&k_state, SHAKE256_RATE);
  keccak_absorb_finalize(&k_state, input, input_len, 0x1f);
  keccak_squeeze_block(&k_state);
  keccak_squeeze(&k_state, output, output_len);
}

/**
 * SHAKE256 initialization
 *
 * Initialization of a SHAKE256 context for multiple call to update/squeeze.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake256_init(shake_state_t *state) {
  keccak_init(state, SHAKE256_RATE);
}

/**
 * SHAKE256 absorb
 *
 * Absorb new bytes into the SHAKE256 internal state.
 * Can be called multiple times.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 *  - input: pointer to input
 *  - len:   length of input in bytes
 */
void shake256_absorb(shake_state_t *state, const uint8_t *input, const size_t len) {
  keccak_absorb(state, input, len);
}

/**
 * SHAKE256 finalize
 *
 * Terminate the aborption phase.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake256_finalize(shake_state_t *state) {
  keccak_finalize(state, 0x1f);
  keccak_squeeze_block(state);
}

/**
 * SHAKE256 squeeze
 *
 * Squeeze some bytes.
 * Can be called multiple times.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake256_squeeze(shake_state_t *state, uint8_t *output, const size_t len) {
  keccak_squeeze(state, output, len);
}
