#include <string.h>
#include "mlkemkeyfind.h"
#include "ml-kem.h"
#include "util.h"

extern int check_sampled(const poly_t *pol);

/* Useful for byte frequencies of the current buffer analyzed */
#define MAX_FREQ 8
#define MAX_FREQ_NO_NTT 150
static int FREQ[3329] = {0};
static int FREQ_SHIFT[3329] = {0};

/**
 * Check if all frequencies of the current buffer analyzed are under MAX_FREQ.
 *
 * Returns 1 or 0.
 *
 * Argument:
 *  - freq: array of frequencies
 */
static int check_frequency(const int freq[3329]) {
  size_t i;
  int is_ok = 1;
  for (i = 0; i < MLKEM_Q; i++) {
    if (freq[i] > MAX_FREQ) {
      is_ok = 0;
      break;
    }
  }
  return is_ok;
}

/**
 * Check if frequencies are consistent with a sampled polynomial.
 * The distribution is centered around 0, but very unlikely to have too many "0".
 * So a very basic check is made.
 * It could be improved further eventually, but it is sufficient to rule out null buffers.
 * 
 * Returns 1 or 0.
 *
 * Argument:
 *  - freq: array of frequencies
 */
static int check_frequency_no_ntt(const int freq[3329]) {
  int is_ok = 1;
  if (freq[3] > MAX_FREQ_NO_NTT) {
    is_ok = 0;
  }
  return is_ok;
}

static void increment_frequency(int freq[3329], const int16_t coef) {
  freq[coef + 1664] += 1;
}

static void decrement_frequency(int freq[3329], const int16_t coef) {
  freq[coef + 1664] -= 1;
}

static void increment_frequency_positive(int freq[3329], const int16_t coef) {
  freq[coef] += 1;
}

static void decrement_frequency_positive(int freq[3329], const int16_t coef) {
  freq[coef] -= 1;
}

static void increment_frequency_no_ntt(int freq[3329], const int16_t coef) {
  freq[coef + 3] += 1;
}

static void decrement_frequency_no_ntt(int freq[3329], const int16_t coef) {
  freq[coef + 3] -= 1;
}

/**
 * Reset all frequencies in the global buffer `FREQ`.
 */
static void reset_frequency(int freq[3329]) {
  memset(freq, 0, MLKEM_Q*sizeof(int));
}

/**
 * Returns the number of consecutive coefficients that are in [-1664, 1664].
 *
 * Arguments:
 *  - coef_list: pointer to an array of 256 coefficients
 *  - start:     offset to start the search
 *  - freq:      current frequencies
 */
static size_t check_interval_centered(const int16_t coef_list[MLKEM_N], const size_t start,
                                      int freq[3329]) {
  size_t i;
  int16_t coef;

  for (i = start; i < MLKEM_N; i++) {
    coef = coef_list[i];
    if ((coef < -1664) || (coef > 1664)) {
      reset_frequency(freq);
      break;
    }

    /* valid coefficient: update frequency */
    increment_frequency(freq, coef);
  }

  /* if i = 256 then all coefficients are in [-1664, 1664] */
  return i;
}

/** 
 * Returns the number of consecutive coefficients that are in [0, 3328].
 *
 * Arguments:
 *  - coef_list: pointer to an array of 256 coefficients
 *  - start:     offset to start the search
 *  - freq:      current frequencies
 */
static size_t check_interval_positive(const int16_t coef_list[MLKEM_N], const size_t start,
                                      int freq[3329]) {
  size_t i;
  int16_t coef;

  for (i = start; i < MLKEM_N; i++) {
    coef = coef_list[i];
    if ((coef < 0) || (coef > 3328)) {
      reset_frequency(freq);
      break;
    }

    /* valid coefficient: update frequency */
    increment_frequency_positive(freq, coef);
  }

  /* if i = 256 then all coefficients are in [0, 3328] */
  return i;
}

/**
 * Returns the number of consecutive coefficients that are in [-3, 3].
 *
 * Arguments:
 *  - coef_list: pointer to an array of 256 coefficients
 *  - start:     offset to start the search
 *  - freq:      current frequencies
 */
static size_t check_interval_no_ntt(const int16_t coef_list[MLKEM_N], const size_t start,
                                    int freq[3329]) {
  size_t i;
  int16_t coef;

  for (i = start; i < MLKEM_N; i++) {
    coef = coef_list[i];
    if ((coef < -3) || (coef > 3)) {
      reset_frequency(freq);
      break;
    }

    /* valid coefficient: update frequency */
    increment_frequency_no_ntt(freq, coef);
  }

  /* if i = 256 then all coefficients are in [-3, 3] */
  return i;
}

/**
 * Search for secret polynomials in a buffer.
 *
 * Returns the list of polynomials found (function argument)
 * and number of polynomial found (return value).
 *
 * Arguments:
 *  - polybuf_list: array of polynomials
 *  - buf: pointer to an array to analyze
 *  - len: length of the array
 *  - offset: current position in the buffer
 *  - freq: frequency of each value
 */
static size_t find_secret_poly_centered(poly_t *polybuf_list, const uint8_t *buf, const size_t len,
                                        size_t *offset, int freq[3329]) {
  size_t n_found = 0; // number of polynomials found
  size_t n_valid = 0; // number of valid consecutive coefficients
  int16_t *coef_list;
  poly_t pol;

  while (*offset + 512 <= len) {
    coef_list = (int16_t *)(&buf[*offset]);
    n_valid = check_interval_centered(coef_list, n_valid, freq);
    /* if < 256 coefficents, update offset, continue */
    if (n_valid < MLKEM_N) {
      *offset += (n_valid + 1)*2;
      n_valid = 0;
      continue;
    }

    /* check frequency */
    if (!check_frequency(freq)) {
      /* remove first coefficient */
      decrement_frequency(freq, coef_list[0]);
      *offset += 2;
      n_valid = 255;
      continue;
    }

    /* good candidate to test NTT^-1 */
    memcpy((uint8_t *)pol.c, (uint8_t *)coef_list, 512); 
    poly_invntt(&pol);

    if (!check_sampled(&pol)) {
      /* remove first coefficient */
      decrement_frequency(freq, coef_list[0]);
      *offset += 2;
      n_valid = 255;
      continue;
    }

    /*
     * polynomial found (put it back in NTT form)
     * update offset to start looking AFTER the polynomial that was found (no overlap)
     */
    poly_ntt(&pol);
    polybuf_list[n_found] = pol;
    n_found += 1;
    *offset += 512;
    n_valid = 0;
    reset_frequency(freq);
  }

  return n_found;
}

/**
 * Search for secret polynomials in a buffer where coefficients are in their positive
 * representation modulo 3329 (in [0, 3328], such as in OpenSSL 3.5.x).
 * 
 * Returns the list of polynomials found (function argument)
 * and number of polynomial found (return value).
 *
 * Arguments:
 *  - polybuf_list: array of polynomials
 *  - buf:          pointer to an array to analyze
 *  - len:          length of the buffer
 *  - offset:       current position in the buffer
 *  - freq:         frequency of each value
 */
static size_t find_secret_poly_positive(poly_t *polybuf_list, const uint8_t *buf, const size_t len,
                                        size_t *offset, int freq[3329]) {
  size_t n_found = 0; // number of polynomials found
  size_t n_valid = 0; // number of valid consecutive coefficients
  int16_t *coef_list;
  poly_t pol;

  while (*offset + 512 <= len) {
    coef_list = (int16_t *)(&buf[*offset]);
    n_valid = check_interval_positive(coef_list, n_valid, freq);
    /* if < 256 coefficents, update offset, continue */
    if (n_valid < MLKEM_N) {
      *offset += (n_valid + 1)*2;
      n_valid = 0;
      continue;
    }

    /* check frequency */
    if (!check_frequency(freq)) {
      /* remove first coefficient */
      decrement_frequency_positive(freq, coef_list[0]);
      *offset += 2;
      n_valid = 255;
      continue;
    }

    /* good candidate to test NTT^-1 */
    memcpy((uint8_t *)pol.c, (uint8_t *)coef_list, 512);
    poly_reduce(&pol);
    poly_invntt(&pol);

    if (!check_sampled(&pol)) {
      /* remove first coefficient */
      decrement_frequency_positive(freq, coef_list[0]);
      *offset += 2;
      n_valid = 255;
      continue;
    }

    /*
     * polynomial found (put it back in NTT form)
     * update offset to start looking AFTER the polynomial that was found (no overlap)
     */
    poly_ntt(&pol);
    polybuf_list[n_found] = pol;
    n_found += 1;
    *offset += 512;
    n_valid = 0;
    reset_frequency(freq);
  }

  return n_found;
}

/**
 * Search for secret polynomials in a memory map where coefficients are not in NTT representation,
 * meaning that they are in [-3, 3].
 * 
 * Returns the list of polynomials found (function argument)
 * and number of polynomial found (return value).
 *
 * Arguments:
 *  - polybuf_list: array of polynomials
 *  - buf:          pointer to a buffer to analyze
 *  - len:          length of the buffer
 *  - offset:       current position in the buffer
 *  - freq:         frequency of each value
 */
static size_t find_secret_poly_no_ntt(poly_t *polybuf_list, const uint8_t *buf, const size_t len,
                                      size_t *offset, int freq[3329]) {
  size_t n_found = 0; // number of polynomials found
  size_t n_valid = 0; // number of valid consecutive coefficients
  int16_t *coef_list;
  poly_t pol;

  while (*offset + 512 <= len) {
    coef_list = (int16_t *)(&buf[*offset]);
    n_valid = check_interval_no_ntt(coef_list, n_valid, freq);
    /* if < 256 coefficents, update offset, continue */
    if (n_valid < MLKEM_N) {
      *offset += (n_valid + 1)*2;
      n_valid = 0;
      continue;
    }

    /* check frequency */
    if (!check_frequency_no_ntt(freq)) {
      /* remove first coefficient */
      decrement_frequency_no_ntt(freq, coef_list[0]);
      *offset += 2;
      n_valid = 255;
      continue;
    }

    /* good candidate */
    memcpy((uint8_t *)pol.c, (uint8_t *)coef_list, 512);
 
    /*
     * polynomial found (put it in NTT representation)
     * update offset to start looking AFTER the polynomial that was found (no overlap)
     */
    poly_ntt(&pol);
    polybuf_list[n_found] = pol;
    n_found += 1;
    *offset += 512;
    n_valid = 0;
  }

  return n_found;
}

/**
 * Search for secret polynomials.
 * 
 * Arguments:
 *  - poly_list: pointer to a list of polynomials
 *  - mode:      representation of polynomials (centered, positive, small)
 *  - buf:       pointer to a buffer to analyze
 *  - len:       length of the buffer
 *  - offset:    current position in the buffer
 *  - reset:     boolean to reset frequencies
 */
int find_secret_poly(poly_t *poly_list, const int mode, const uint8_t *buf, const size_t len,
                     offset_t *offset, int reset) {
  size_t n_poly = 0;

  if (reset) {
    reset_frequency(FREQ);
    reset_frequency(FREQ_SHIFT);
  }

  if (mode == SEARCH_MODE_CENTERED) {
    n_poly += find_secret_poly_centered(poly_list, buf, len, &offset->secret, FREQ);
    n_poly += find_secret_poly_centered(&poly_list[n_poly], buf, len, &offset->secret_shift,
                                        FREQ_SHIFT);
  }
  else if (mode == SEARCH_MODE_POSITIVE) {
    n_poly += find_secret_poly_positive(poly_list, buf, len, &offset->secret, FREQ);
    n_poly += find_secret_poly_positive(&poly_list[n_poly], buf, len, &offset->secret_shift, 
                                        FREQ_SHIFT);
  }
  else if (mode == SEARCH_MODE_SMALL) {
    n_poly += find_secret_poly_no_ntt(poly_list, buf, len, &offset->secret, FREQ);
    n_poly += find_secret_poly_no_ntt(&poly_list[n_poly], buf, len, &offset->secret_shift, 
                                      FREQ_SHIFT);
  }

  return n_poly;
}
