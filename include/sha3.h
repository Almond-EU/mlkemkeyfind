/*
 * Copyright (C) 2025 A. Russon
 *
 * Released under the MIT license.
 */

#ifndef SHA3_H_
#define SHA3_H_

#include <stddef.h>
#include <stdint.h>

#define SHA3_256_LEN 32
#define SHA3_512_LEN 64

#define KECCAK_BLOCK_WORD_LEN 25
#define KECCAK_BLOCK_BYTE_LEN 200

typedef struct {
  uint64_t state[KECCAK_BLOCK_WORD_LEN];
  uint8_t buf[KECCAK_BLOCK_BYTE_LEN];
  size_t pos;
  size_t rate;
} keccak_state_t;

typedef keccak_state_t sha3_state_t;
typedef keccak_state_t shake_state_t;

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
void sha3_256(uint8_t output[SHA3_256_LEN], const uint8_t *input, const size_t len);

/**
 * SHA3-256 initialization
 *
 * Initialization of a SHA3-256 context for multiple call to update.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void sha3_256_init(sha3_state_t *state);

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
void sha3_256_update(sha3_state_t *state, const uint8_t *input, const size_t len);

/**
 * SHA3-256 digest
 *
 * Returns the SHA3-256 digest of all aborbed bytes.
 *
 * Arguments:
 *  - state:  pointer to context that contains the internal state
 *  - output: pointer to output (32 bytes)
 */
void sha3_256_digest(sha3_state_t *state, uint8_t output[SHA3_256_LEN]);

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
void sha3_512(uint8_t output[SHA3_512_LEN], const uint8_t *input, const size_t len);

/**
 * SHA3-512 initialization
 *
 * Initialization of a SHA3-512 context for multiple call to update.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void sha3_512_init(sha3_state_t *state);

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
void sha3_512_update(sha3_state_t *state, const uint8_t *input, const size_t len);

/**
 * SHA3-512 digest
 *
 * Returns the SHA3-512 digest of all aborbed bytes.
 *
 * Arguments:
 *  - state:  pointer to context that contains the internal state
 *  - output: pointer to output (64 bytes)
 */
void sha3_512_digest(sha3_state_t *state, uint8_t output[SHA3_512_LEN]);

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
              const uint8_t *input, const size_t input_len);

/**
 * SHAKE128 initialization
 *
 * Initialization of a SHAKE128 context for multiple call to update/squeeze.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake128_init(shake_state_t *state);

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
void shake128_absorb(shake_state_t *state, const uint8_t *input, const size_t len);

/**
 * SHAKE128 finalize
 *
 * Terminate the aborption phase.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake128_finalize(shake_state_t *state);

/**
 * SHAKE128 squeeze
 *
 * Squeeze some bytes.
 * Can be called multiple times.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake128_squeeze(shake_state_t *state, uint8_t *output, const size_t len);

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
              const uint8_t *input, const size_t input_len);

/**
 * SHAKE256 initialization
 *
 * Initialization of a SHAKE256 context for multiple call to update/squeeze.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake256_init(shake_state_t *state);

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
void shake256_absorb(shake_state_t *state, const uint8_t *input, const size_t len);

/**
 * SHAKE256 finalize
 *
 * Terminate the aborption phase.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake256_finalize(shake_state_t *state);

/**
 * SHAKE256 squeeze
 *
 * Squeeze some bytes.
 * Can be called multiple times.
 *
 * Arguments:
 *  - state: pointer to context that contains the internal state
 */
void shake256_squeeze(shake_state_t *state, uint8_t *output, const size_t len);

#endif
