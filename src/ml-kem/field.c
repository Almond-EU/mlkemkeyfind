#include "ml-kem.h"

/**
 * Reduces a 16-bit integer modulo 3329 centered in [-1664, 1664].
 */
int16_t fq_barrett_reduce(const int16_t a) {
  int16_t t;
  const int16_t v = ((1 << 26) + MLKEM_Q / 2) / MLKEM_Q;

  t  = ((int32_t)v * a + (1 << 25)) >> 26;
  t *= MLKEM_Q;
  return a - t;
}

/**
 * Simple reduction modulo 3329 for an integer that is in [-(q-1), q-1].
 *
 * Argument:
 *  - a: integer in [-(q-1), q-1]
 */
int16_t fq_simple_reduce(int16_t a) {
  if (a > 1664) {
    a -= MLKEM_Q;
  }
  else if (a < -1664) {
    a += MLKEM_Q;
  }
  return a;
}

/**
 * Reduce an integer modulo 3329 centered in [-1664, 1664].
 *
 * Argument:
 * - x: integer in [-(q-1)^2, (q-1)^2]
 */
int16_t fq_reduce(const int32_t x) {
    int64_t product = (int64_t)x * 5039;
    int32_t quotient = (int32_t)(product >> 24);
    quotient *= MLKEM_Q;

    return fq_barrett_reduce((int16_t)(x - quotient));
}

/**
 * Multiply two integers and returns a reduced integer in [-1664, 1664].
 *
 * Arguments:
 *  - a: reduced integer in [-(q-1), q-1]
 *  - b: reduced integer in [-(q-1), q-1]
 */
int16_t fq_mul(const int16_t a, const int16_t b) {
  return fq_reduce((int32_t)a * b);
}
