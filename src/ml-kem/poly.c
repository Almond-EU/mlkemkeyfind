#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "inverses.h"
#include "ml-kem.h"
#include "sha3.h"

/**
 * zeta^bitrev(i) for i in [0, 127] with their representation in [-1664, 1664].
 */
const int16_t ZETAS[128] = {
  1,     -1600,  -749,   -40,  -687,   630, -1432,   848,
  1062,  -1410,   193,   797,  -543,   -69,   569, -1583,
  296,    -882,  1339,  1476,  -283,    56, -1089,  1333,
  1426,  -1235,   535,  -447,  -936,  -450, -1355,   821,
  289,     331,   -76, -1573,  1197, -1025, -1052, -1274,
  650,   -1352,  -816,   632,  -464,    33,  1320, -1414,
  -1010,  1435,   807,   452,  1438,  -461,  1534,  -927,
  -682,   -712,  1481,   648,  -855,  -219,  1227,   910,
  17,     -568,   583,  -680,  1637,   723, -1041,  1100,
  1409,   -667,   -48,   233,   756, -1173,  -314,  -279,
  -1626,  1651,  -540, -1540, -1482,   952,  1461,  -642,
  939,   -1021,  -892,  -941,   733,  -992,   268,   641,
  1584,  -1031, -1292,  -109,   375,  -780, -1239,  1645,
  1063,    319,  -556,   757, -1230,   561,  -863,  -735,
  -525,   1092,   403,  1026,  1143, -1179,  -554,   886,
  -1607,  1212, -1455,  1029, -1219,  -394,   885, -1175
};

/**
 * zeta^(2*bitrev(i) + 1) mod q for i in [0, 127]
 */
const int16_t ZETAS_2[128] = {
     17,   -17,  -568,   568,   583,  -583,  -680,   680,
   1637, -1637,   723,  -723, -1041,  1041,  1100, -1100,
   1409, -1409,  -667,   667,   -48,    48,   233,  -233,
    756,  -756, -1173,  1173,  -314,   314,  -279,   279,
  -1626,  1626,  1651, -1651,  -540,   540, -1540,  1540,
  -1482,  1482,   952,  -952,  1461, -1461,  -642,   642,
    939,  -939, -1021,  1021,  -892,   892,  -941,   941,
    733,  -733,  -992,   992,   268,  -268,   641,  -641,
   1584, -1584, -1031,  1031, -1292,  1292,   -109,  109,
    375,  -375,  -780,   780, -1239,  1239,  1645, -1645,
   1063, -1063,   319,  -319,  -556,   556,   757,  -757,
  -1230,  1230,   561,  -561,  -863,   863,  -735,   735,
   -525,   525,  1092, -1092,   403,  -403,  1026, -1026,
   1143, -1143, -1179,  1179,  -554,   554,   886,  -886,
  -1607,  1607,  1212, -1212, -1455,  1455,  1029, -1029,
  -1219,  1219,  -394,   394,   885,  -885, -1175,  1175
};

/**
 * Computes the NTT representation of a polynomial.
 */
void poly_ntt(poly_t *r) {
  size_t len, start, j, k;
  int16_t t, zeta;

  k = 1;
  for (len = 128; len >= 2; len >>= 1) {
    for (start = 0; start < 256; start = j + len) {
      zeta = ZETAS[k++];
      for (j = start; j < start + len; j++) {
        t = fq_mul(zeta, r->c[j + len]);
        r->c[j + len] = r->c[j] - t;
        r->c[j] = r->c[j] + t;
      }
    }
  }
  for (j = 0; j < MLKEM_N; j++) {
    r->c[j] = fq_barrett_reduce(r->c[j]);
  }
}

/**
 * Computes the inverse of the NTT representation of a polynomial.
 */
void poly_invntt(poly_t *r) {
  size_t start, len, j, k;
  int16_t t, zeta;

  k = 127;
  for (len = 2; len <= 128; len <<= 1) {
    for (start = 0; start < 256; start = j + len) {
      zeta = ZETAS[k--];
      for (j = start; j < start + len; j++) {
        t = r->c[j];
        r->c[j] = fq_simple_reduce(t + r->c[j + len]);
        r->c[j + len] = r->c[j + len] - t;
        r->c[j + len] = fq_mul(zeta, r->c[j + len]);
      }
    }
  }

  for (j = 0; j < MLKEM_N; j++) {
    r->c[j] = fq_mul(r->c[j], -26);
  }
}

void poly_add(poly_t *res, const poly_t *a, const poly_t *b) {
  size_t i;
  for (i = 0; i < MLKEM_N; i++) {
    res->c[i] = fq_simple_reduce(a->c[i] + b->c[i]);
  }
}

void poly_sub(poly_t *res, const poly_t *a, const poly_t *b) {
  size_t i;
  for (i = 0; i < MLKEM_N; i++) {
    res->c[i] = fq_simple_reduce(a->c[i] - b->c[i]);
  }
}

void poly_reduce(poly_t *pol) {
  size_t i;

  for (i = 0; i < MLKEM_N; i++) {
    pol->c[i] = fq_reduce(pol->c[i]);
  }
}

/**
 * Computes (a0 + a1*X)*(b0 + b1*X) mod (X^2 - zeta).
 * Algorithm 12 of FIPS 203
 */
void ntt_mul(int16_t r[2], const int16_t a[2], const int16_t b[2], const int16_t zeta) {
  int16_t t[2];
  t[0]  = fq_mul(a[1], b[1]);
  t[0]  = fq_mul(t[0], zeta);
  t[0] += fq_mul(a[0], b[0]);
  t[1]  = fq_mul(a[0], b[1]);
  t[1] += fq_mul(a[1], b[0]);
  r[0] = fq_simple_reduce(t[0]);
  r[1] = fq_simple_reduce(t[1]);
}

/**
 * Multiplication of polynomials in NTT representation.
 * Algorithm 11 of FIPS 203.
 */
void poly_mul(poly_t *res, const poly_t *a, const poly_t *b) {
  size_t i;
  for (i = 0; i < 128; i++) {
    ntt_mul(&res->c[2 * i], &a->c[2 * i], &b->c[2 * i], ZETAS_2[i]);
  }
}

void poly_tobytes(uint8_t r[MLKEM_POLY_LEN], const poly_t *a) {
  size_t i;
  uint16_t t0, t1;

  for (i = 0; i < MLKEM_N / 2; i++) {
    t0 = a->c[2*i];
    t0 += ((int16_t)t0 >> 15) & MLKEM_Q;
    t1 = a->c[2*i + 1];
    t1 += ((int16_t)t1 >> 15) & MLKEM_Q;
    r[3 * i + 0] = (uint8_t)(t0 >> 0);
    r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
    r[3 * i + 2] = (uint8_t)(t1 >> 4);
  }
}

/**
 * Retrieve coefficients of a polynomial from a byte array.
 *
 * Arguments:
 *  - pol: pointer to an array of MLKEM_N coefficients
 *  - a:   pointer to an array of MLKEM_POLY_LEN bytes
 */
void poly_frombytes(poly_t *pol, const uint8_t a[MLKEM_POLY_LEN]) {
  size_t i;
  for (i = 0; i < MLKEM_N / 2; i++) {
    pol->c[2 * i]     = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
    pol->c[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;

    pol->c[2 * i]     = fq_simple_reduce(pol->c[2 * i]);
    pol->c[2 * i + 1] = fq_simple_reduce(pol->c[2 * i + 1]);
  }
}

/**
 * Decompress and decode the second part of a ciphertext into a polynomial with d_v = 4.
 * Only for ML-KEM-512 and ML-KEM-768.
 * One byte -> two coefficients.
 *
 * Arguments:
 *  - coefs: pointer to the list of coefficients of the polynomial
 *  - a:     buffer that contains the compressed and encoded polynomial
 */
void poly_decompress_d4(poly_t *pol, const uint8_t a[POLY_DV_4_LEN]) {
  size_t i;
  for (i = 0; i < POLY_DV_4_LEN; i++) {
    pol->c[2 * i]     = ((uint32_t)(a[i] & 0xf) * MLKEM_Q + 8) >> 4;
    pol->c[2 * i + 1] = ((uint32_t)(a[i] >> 4)  * MLKEM_Q + 8) >> 4;
  }
}

/**
 * Decompress and decode the second part of a ciphertext into a polynomial with d_v = 5.
 * Only for ML-KEM-1024.
 * 5 bytes -> 8 coefficients.
 *
 * Arguments:
 *  - coefs: pointer to the list of coefficients of the polynomial
 *  - a:     buffer that contains the compressed and encoded polynomial
 */
void poly_decompress_d5(poly_t *pol, const uint8_t a[POLY_DV_5_LEN]) {
  uint8_t t[8];
  size_t i, j;

  for (i = 0; i < MLKEM_N / 8; i++) {
    t[0] = a[0];
    t[1] = (a[0] >> 5) | (a[1] << 3);
    t[2] = (a[1] >> 2);
    t[3] = (a[1] >> 7) | (a[2] << 1);
    t[4] = (a[2] >> 4) | (a[3] << 4);
    t[5] = (a[3] >> 1);
    t[6] = (a[3] >> 6) | (a[4] << 2);
    t[7] = (a[4] >> 3);
    a += 5;

    for (j = 0; j < 8; j++) {
      pol->c[8 * i + j] = fq_simple_reduce(((uint32_t)(t[j] & 0x1f) * MLKEM_Q + 16) >> 5);
    }
  }
}

/**
 * Compress and encode the second part of a ciphertext from a polynomial with d_v = 4.
 * Only or ML-KEM-512 and ML-KEM-768.
 * 2 coefficientS -> 1 byte
 */
void poly_compress_d4(uint8_t a[POLY_DV_4_LEN], const poly_t *pol) {
  size_t i, j;
  int16_t c;
  uint8_t t[2];

  for (i = 0; i < 128; i++) {
    for (j = 0; j < 2; j++) {
      c = pol->c[i*2 + j];
      /* positive representation */
      if (c < 0) {
        c += MLKEM_Q;
      }
      t[j] = ((((uint16_t)c << 4) + 1664) / MLKEM_Q) & 0xf;
    }

    a[0] = t[0] | (t[1] << 4);
    a += 1;
  }
}

/**
 * Compress and encode the second part of a ciphertext from a polynomial with d_v = 5.
 * Only or ML-KEM-1024.
 * 8 coefficients -> 5 bytes
 */
void poly_compress_d5(uint8_t a[POLY_DV_5_LEN], const poly_t *pol) {
  size_t i, j;
  int16_t c;
  uint8_t t[8];

  for (i = 0; i < 32; i++) {
    for (j = 0; j < 8; j++) {
      c = pol->c[i*8 + j];
      /* positive representation */
      if (c < 0) {
        c += MLKEM_Q;
      }
      t[j] = ((((uint32_t)c << 5) + 1664) / MLKEM_Q) & 0x1f;
    }

    a[0] = (t[0] >> 0) | (t[1] << 5);
    a[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
    a[2] = (t[3] >> 1) | (t[4] << 4);
    a[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
    a[4] = (t[6] >> 2) | (t[7] << 3);
    a += 5;
  }
}

void poly_tomsg(uint8_t msg[32], const poly_t *a) {
  size_t i, j;
  uint32_t t;

  for (i = 0; i < 32; i++) {
    msg[i] = 0;
    for (j = 0; j < 8; j++) {
      t = a->c[i*8 + j];
      if ((int16_t)t < 0) {
        t += MLKEM_Q;
      }
      t = (((t << 1) + MLKEM_Q/2) / MLKEM_Q) & 1;
      msg[i] |= (t << j);
    }
  }
}

void poly_frommsg(poly_t *a, const uint8_t msg[32]) {
  size_t i, j;
  uint8_t bit;

  for (i = 0; i < 32; i++) {
    for (j = 0; j < 8; j++) {
      bit = (msg[i] >> j) & 1;
      if (bit == 0) {
        a->c[i*8 + j] = 0;
      }
      else {
        a->c[i*8 + j] = 1665;
      }
    }
  }
}

/* Functions for polynomial inversion */

static size_t find_pivot_index(const int16_t *mat, const size_t col) {
  size_t i;
  size_t index = -1;
  for(i = col; i < MLKEM_N; i++) {
    if (mat[i*(2*MLKEM_N) + col] != 0) {
      index = i;
      break;
    }
  }
  return index;
}

static void matrix_mul_line(int16_t *row, const uint16_t value, const size_t start) {
  size_t i;
  for(i = start; i < (2*MLKEM_N); i++) {
    row[i] = fq_mul(row[i], value);
  }
}

static void matrix_swap_lines(int16_t *row1, int16_t *row2) {
  int i;
  for(i = 0; i < (2*MLKEM_N); i++) {
    row1[i] ^= row2[i];
    row2[i] ^= row1[i];
    row1[i] ^= row2[i];
  }
}

static int16_t inverse_mod_q(const int16_t a) {
  if (a < 0) {
    return INVERSES_MOD_Q[a + MLKEM_Q];
  }
  else {
    return INVERSES_MOD_Q[a];
  }
}

static void matrix_muladd_line(int16_t *row1, const int16_t *row2, int start) {
  int16_t coef, t;
  size_t i;
  coef = row1[start];
  for(i = start; i < (2*MLKEM_N); i++) {
    t = fq_mul(coef, row2[i]);
    row1[i] = fq_simple_reduce(row1[i] - t);
  }
}

static int matrix_inverse(int16_t *mat_inv, const int16_t *mat) {
  int16_t *m;
  int16_t pivot_inverse;
  size_t i, j, k;
  int invertible = 1;
  
  m = (int16_t *)malloc((MLKEM_N*MLKEM_N*2)*sizeof(int16_t));

  /* initialization */
  memset((uint8_t *)m, 0, MLKEM_N*MLKEM_N*2*2);
  for(i = 0; i < MLKEM_N; i++) {
    for(j = 0; j < MLKEM_N; j++) {
      m[i*(2*MLKEM_N) + j] = mat[i*MLKEM_N + j];
    }
    m[i*(2*MLKEM_N) + (i + MLKEM_N)] = 1;
  }

  for(j = 0; j < MLKEM_N; j++) {
    /* find pivot */
    i = find_pivot_index(m, j);

    /* not invertible, stop here */
    if (i == -1) {
      invertible = 0;
      break;
    }
    pivot_inverse = inverse_mod_q(m[i*(2*MLKEM_N) + j]);

    /* invert line */
    matrix_mul_line(&m[i*(2*MLKEM_N)], pivot_inverse, j);

    /* zero in column */
    for(k = 0; k < i; k++) {
      matrix_muladd_line(&m[k*(2*MLKEM_N)], &m[i*(2*MLKEM_N)], j);
    }
    for(k = i + 1; k < MLKEM_N; k++) {
      matrix_muladd_line(&m[k*(2*MLKEM_N)], &m[i*(2*MLKEM_N)], j);
    }

    /* swap lines */
    if (i != j) {
      matrix_swap_lines(&m[i*(2*MLKEM_N)], &m[j*(2*MLKEM_N)]);
    }
  }

  /* copy the inverted matrix */
  if (invertible) {
    for(i = 0; i < MLKEM_N; i++) {
      for(j = 0; j < MLKEM_N; j++) {
        mat_inv[i*MLKEM_N + j] = m[i*(2*MLKEM_N) + (j + MLKEM_N)];
      }
    }
  }

  free(m);
  return invertible;
}

/**
 * Calculate the inverse of a polynomial (in its NTT representation).
 * It does the following:
 *  - Applies the NTT inverse
 *  - Converts the polynomial in its matrix representation
 *  - Gauss's pivot to inverse the matrix
 *  - Convert back to a polynomial representation
 *  - Applies NTT
 *
 * Arguments:
 *  - poly_inv: pointer to the output polynomial in NTT representation
 *  - poly:     pointer to the input polynomial in NTT representation
 */
int poly_inverse(poly_t *poly_inv, const poly_t *poly) {
  size_t i, j;
  int16_t mat[MLKEM_N * MLKEM_N], mat_inv[MLKEM_N * MLKEM_N];
  int invertible;

  *poly_inv = *poly;
  poly_invntt(poly_inv);

  /* matrix representation of the polynomial */
  for (i = 0; i < MLKEM_N; i++) {
    for (j = i; j < MLKEM_N; j++) {
      mat[j * MLKEM_N + i] = poly_inv->c[j - i];
    }
    for (j = 0; j < i; j++) {
      mat[j * MLKEM_N + i] = -poly_inv->c[MLKEM_N + j - i];
    }
  }

  /* inverse matrix */
  invertible = matrix_inverse(mat_inv, mat);
  if (!invertible) {
    goto end;
  }

  /* coefficients from the first column */
  for (i = 0; i < MLKEM_N; i++) {
    poly_inv->c[i] = mat_inv[i * MLKEM_N];
  }

  // application NTT
  poly_ntt(poly_inv);

end:
  return invertible;
}

static void cbd2(poly_t *r, const uint8_t buf[128]) {
  size_t i, j;
  uint32_t t,d;
  int16_t a, b;

  for (i = 0; i < 32; i++) {
    t =  (uint32_t)buf[4*i]
      | ((uint32_t)buf[4*i + 1] << 8)
      | ((uint32_t)buf[4*i + 2] << 16)
      | ((uint32_t)buf[4*i + 3] << 24);
    d = t & 0x55555555;
    d += (t >> 1) & 0x55555555;

    for (j = 0; j < 8; j++) {
      a = (d >> (4 * j))     & 0x3;
      b = (d >> (4 * j + 2)) & 0x3;
      r->c[8*i + j] = a - b;
    }
  }
}

static void cbd3(poly_t *r, const uint8_t buf[192]) {
  size_t i, j;
  uint32_t t,d;
  int16_t a, b;

  for (i = 0; i < 64; i++) {
    t =  (uint32_t)buf[3 * i]
      | ((uint32_t)buf[3*i + 1] << 8)
      | ((uint32_t)buf[3*i + 2] << 16);
    d  = t & 0x00249249;
    d += (t >> 1) & 0x00249249;
    d += (t >> 2) & 0x00249249;

    for (j = 0; j < 4; j++) {
      a = (d >> (6 * j + 0)) & 0x7;
      b = (d >> (6 * j + 3)) & 0x7;
      r->c[4 * i + j] = a - b;
    }
  }
}

void poly_sample(poly_t *r, const uint8_t input[32], const uint8_t n, const size_t eta) {
  uint8_t buf[MLKEM512_ETA1_LEN];
  shake_state_t xof;

  shake256_init(&xof);
  shake256_absorb(&xof, input, 32);
  shake256_absorb(&xof, &n, 1);
  shake256_finalize(&xof);
  if (eta == MLKEM512_ETA1) {
    shake256_squeeze(&xof, buf, MLKEM512_ETA1_LEN);
    cbd3(r, buf);
  }
  else {
    shake256_squeeze(&xof, buf, MLKEM768_ETA1_LEN);
    cbd2(r, buf);
  }
}
