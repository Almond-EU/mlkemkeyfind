#include <stdlib.h>
#include <string.h>
#include "ml-kem.h"
#include "sha3.h"

/**
 * Generate matrix A
 *
 * Arguments:
 *  - mat:     pointer to all polynomials of the matrix (row by row, colomn by column)
 *  - seed:    pointer to the seed buffer array
 *  - param_k: ML-KEM parameter k (2, 3 or 4), used to know the size of the matrix
 */
void gen_public_matrix(poly_t *mat, const uint8_t seed[32], const size_t param_k) {
  size_t i, j, l;
  poly_t *pol;
  uint8_t extseed[34];
  uint8_t c[3];
  int16_t d1, d2;
  shake_state_t xof;

  memcpy(extseed, seed, 32);

  for (i = 0; i < param_k; i++) {
    for (j = 0; j < param_k; j++) {
      pol = &mat[i * param_k + j];
      extseed[32] = j;
      extseed[33] = i;
      shake128_init(&xof);
      shake128_absorb(&xof, extseed, 34);
      shake128_finalize(&xof);

      l = 0;
      while (l < MLKEM_N) {
        shake128_squeeze(&xof, c, 3);
        d1 = (int16_t)c[0] | ((int16_t)(c[1] & 0xf) << 8);
        d2 = (int16_t)(c[1] >> 4) | ((int16_t)c[2] << 4);
        if (d1 < MLKEM_Q) {
          if (d1 > 1664) {
            d1 -= MLKEM_Q;
          }
          pol->c[l] = d1;
          l += 1;
        }
        if (d2 < MLKEM_Q && j < MLKEM_N) {
          if (d2 > 1664) {
            d2 -= MLKEM_Q;
          }
          pol->c[l] = d2;
          l += 1;
        }
      }
    }
  }
}

/**
 * Computes M*y where M is a matrix and y a vector.
 * Their coefficients are polynomials.
 *
 * Arguments:
 *  - res: pointer to a list of param_k polynomials (result of A*s)
 *  - mat: pointer to a list of param_k*param_k polynomials (matrix A)
 *  - vec: pointer to a list of param_k polynomials (vector s)
 */
void mat_vec_mul(poly_t *res, const poly_t *mat, const poly_t *vec, const size_t param_k) {
  size_t i, j;
  poly_t t;

  for (i = 0; i < param_k; i++) {
    memset((uint8_t *)&res[i], 0, sizeof(poly_t));
    for (j = 0; j < param_k; j++) {
      poly_mul(&t, &mat[i*param_k + j], &vec[j]);
      poly_add(&res[i], &res[i], &t);
    }
  }
}

/* Functions for public matrix inversion */

static size_t find_pivot_and_index(poly_t *pivot_inv, const poly_t *mat, const size_t param_k, const size_t col) {
  size_t i;
  size_t index = -1;
  for (i = col; i < param_k; i++) {
    if (poly_inverse(pivot_inv, &mat[i*(2*param_k) + col]) != 0) {
      index = i;
      break;
    }
  }
  return index;
}

static void matrix_mul_line(poly_t *row, const size_t param_k, const poly_t *value, const size_t start) {
  size_t i;
  for (i = start; i < (2*param_k); i++) {
    poly_mul(&row[i], &row[i], value);
  }
}

static void matrix_muladd_line(poly_t *row1, const poly_t *row2, const size_t param_k, const size_t start) {
  size_t i;
  poly_t pol, t;

  pol = row1[start];
  for (i = start; i < (2*param_k); i++) {
    poly_mul(&t, &pol, &row2[i]);
    poly_sub(&row1[i], &row1[i], &t);
  }
}

static void matrix_swap_lines(poly_t *row1, poly_t *row2, const size_t param_k) {
  size_t i, n;
  uint8_t *ptr1, *ptr2;

  n = 2* param_k * sizeof(poly_t);
  ptr1 = (uint8_t *)row1;
  ptr2 = (uint8_t *)row2;

  for (i = 0; i < n; i++) {
    ptr1[i] ^= ptr2[i];
    ptr2[i] ^= ptr1[i];
    ptr1[i] ^= ptr2[i];
  }
}

/**
 * Compute the inverse of a public matrix using NTT representation.
 *
 * Arguments:
 *  - mat_inv: pointer to a list of param_k*param_k polynomials (inverse matrix)
 *  - mat:     pointer to a list of param_k*param_k polynomials (input matrix)
 *  - param_k: ML-KEM parameter k (2, 3 or 4), used to know the size of the matrix
 */
int mat_inverse(poly_t *mat_inv, const poly_t *mat, const size_t param_k) {
  poly_t *m;
  poly_t pivot_inv;
  size_t i, j, l;
  int invertible = 1;

  /* m = [ M | I ] */
  m = (poly_t *)malloc(param_k*param_k*2*sizeof(poly_t));

  /* initialization */
  memset((uint8_t *)m, 0, param_k*param_k*2*sizeof(poly_t));
  for (i = 0; i < param_k; i++) {
    /* first half is the input matrix */
    for (j = 0; j < param_k; j++) {
      m[i * (2*param_k) + j] = mat[i * (param_k) + j];
    }
    /* second half is the identity matrix */
    /* NTT(1) = (1 + 0*X, ..., 1 + 0*X)*/
    for (l = 0; l < MLKEM_N; l += 2) {
      m[i * (2*param_k) + param_k + i].c[l] = 1;
    }
  }

  for (j = 0; j < param_k; j++) {
    /* find pivot index and its invert */
    i = find_pivot_and_index(&pivot_inv, m, param_k, j);
    
    /* not invertible, stop here */
    if (i == -1) {
      invertible = 0;
      break;
    }

    /* invert line */
    matrix_mul_line(&m[i * (2*param_k)], param_k, &pivot_inv, j);

    /* zero in column */
    for (l = 0; l < i; l++) {
      matrix_muladd_line(&m[l*(2*param_k)], &m[i*(2*param_k)], param_k, j);
    }
    for (l = i + 1; l < param_k; l++) {
      matrix_muladd_line(&m[l*(2*param_k)], &m[i*(2*param_k)], param_k, j);
    }

    // swap lines
    if (i != j) {
      matrix_swap_lines(&m[i*(2*param_k)], &m[j*(2*param_k)], param_k);
    }
  }

  /* copy inverted matrix in mat_inv */
  if (invertible) {
    for (i = 0; i < param_k; i++) {
      for (j = 0; j < param_k; j++) {
        mat_inv[i*param_k + j] = m[i*(2*param_k) + j + param_k];
      }
    }
  }

  free(m);
  return invertible;
}
