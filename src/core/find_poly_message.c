#include <string.h>
#include "mlkemkeyfind.h"
#include "ml-kem.h"
#include "util.h"

/**
 * Global variable to store the frequency of "bit 0" in a polynomial.
 * A random polynomial message should have a very very high probability
 * to have between 88 and 168 coefficients that correspond to bit 0 (around 128).
 */
#define MAX_FREQ_MESSAGE 168
#define MIN_FREQ_MESSAGE 88
static int FREQ_0 = 0;
static int FREQ_0_SHIFT = 0;

/**
 * Returns the number of consecutive coefficients that are 0 or 1665.
 * 
 * Arguments:
 *  - coef_list: pointer to an array of 256 coefficients
 *  - start:     offset to start the search
 *  - freq:      frequency of value 0
 */
static int check_interval_message(const int16_t coef_list[MLKEM_N], const size_t start, int *freq) {
  size_t i;
  int16_t coef;

  for (i = start; i < MLKEM_N; i++) {
    coef = coef_list[i];
    /* absolute value of the coefficient */
    if (coef < 0) {
      coef = -coef;
    }

    /* not a valid coefficient */
    if ((coef != 1665) && (coef != 0)) {
      *freq = 0;
      break;
    }

    /* valid coefficient: update frequency only if coefficient is 0 */
    if (coef == 0) {
      *freq += 1;  
    }
  }

  /* if i = 256 then all coefficients satisfy the conditions */
  return i;
}

/**
 * Find secret polynomials that could be a message from the encapsulation/decapsulation.
 * Coefficients are either 0 or 1665.
 * 
 * Arguments:
 *  - polymsg_list: array of polynomials found
 *  - buf:          pointer to the buffer to analyze
 *  - len:          length of the buffer
 *  - offset:       starting position in the buffer
 *  - freq:         pointer to the frequency of value 0
 */
static size_t find_secret_message(poly_t *polymsg_list, const uint8_t *buf, const size_t len,
                                  size_t *offset, int *freq) {
  size_t n_found = 0;
  size_t n_valid = 0;
  int16_t *coef_list;
  poly_t pol;

  while (*offset + 512 <= len) {
    coef_list = (int16_t *)(&buf[*offset]);
    n_valid = check_interval_message(coef_list, n_valid, freq);
    /* if < 256 coefficients, update offset, continue */
    if (n_valid < MLKEM_N) {
      *offset += (n_valid + 1)*2;
      n_valid = 0;
      continue;
    }

    /* check frequency */
    if ((*freq > MAX_FREQ_MESSAGE) || (*freq < MIN_FREQ_MESSAGE)) {
      /* remove frequency of first coefficient */
      if (coef_list[0] == 0) {
        *freq -= 1;
      }
      *offset += 2;
      n_valid = 255;
      continue;
    }

    /* good candidate for a polynomial message */
    memcpy((uint8_t *)pol.c, (uint8_t *)coef_list, 512);
    polymsg_list[n_found] = pol;

    /* the correct message polynomial could be surrounded by null bytes */
    n_found += 1;
    *offset += 2;
    n_valid = 255;
  }

  return n_found;
}

/**
 * General function to find messages in polynomial form in memory.
 * 
 * Arguments:
 *  - polymsg_list: array of polynomials found
 *  - buf:          pointer to a buffer to analyze
 *  - len:          length of the buffer
 *  - offset:       starting position in the buffer
 *  - reset:        boolean to reset frequency for value 0
 */
int find_message_poly(poly_t *polymsg_list, const uint8_t *buf, const size_t len, offset_t *offset,
                      int reset) {
  size_t n_polymsg = 0;

  if (reset) {
    FREQ_0 = 0;
    FREQ_0_SHIFT = 0;
  }

  n_polymsg += find_secret_message(polymsg_list, buf, len, &offset->msg, &FREQ_0);
  n_polymsg += find_secret_message(&polymsg_list[n_polymsg], buf, len, &offset->msg_shift,
                                   &FREQ_0_SHIFT);

  return n_polymsg;
}
