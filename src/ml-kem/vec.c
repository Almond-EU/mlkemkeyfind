#include "ml-kem.h"

/**
 * Computes the subtraction of two vectors: t = a - b.
 *
 * Arguments:
 *  - res: pointer to a list of param_k polynomials (vector t)
 *  - a:   pointer to a list of param_k polynomials (vector a)
 *  - b:   pointer to a list of param_k polynomials (vector b)
 */
void vec_sub(poly_t *res, const poly_t *a, const poly_t *b, const size_t param_k) {
  size_t i;
  for (i = 0; i < param_k; i++) {
    poly_sub(&res[i], &a[i], &b[i]);
  }
}

/**
 * Dot product of two vectors (using NTT represetentation).
 * 
 * Arguments:
 *  - res:     pointer to a polynomial (result of dot product <a, b>)
 *  - a:       pointer to a vector of param_k polynomials
 *  - b:       pointer to a vector of param_k polynomials
 *  - param_k: ML-KEM parameter k (2, 3 or 4), used to know the length of vectors
 */
void vec_mul(poly_t *res, const poly_t *a, const poly_t *b, const size_t param_k) {
  poly_t t;
  size_t i;

  poly_mul(res, &a[0], &b[0]);
  for (i = 1; i < param_k; i++) {
    poly_mul(&t, &a[i], &b[i]);
    poly_add(res, res, &t);
  }
}

/**
 * Encode vector into a secret buffer.
 * Input is expected to be in NTT represenatation
 *
 * Arguments:
 *  - buf:     pointer to the output buffer
 *  - vec:     pointer to a list of param_k polynomials
 *  - param_k: ML-KEM parameter k (2, 3 or 4), used to know the size of the matrix
 */
void vec_tobytes(uint8_t *buf, const poly_t *vec, const size_t param_k) {
  size_t i;
  for (i = 0; i < param_k; i++) {
    poly_tobytes(&buf[i * MLKEM_POLY_LEN], &vec[i]);
  }
}

/**
 * Retrieve a vector of polynomials from a byte array.
 * The caller is responsible for the allocation of output array.
 *
 * Arguments:
 *  - vec: pointer to a list of param_k polynomials
 *  - a:   pointer to an array of MLKEM_POLY_LEN*param_k bytes
 */
void vec_frombytes(poly_t *vec, const uint8_t *a, const size_t param_k) {
  size_t i;
  for (i = 0; i < param_k; i++) {
    poly_frombytes(&vec[i], &a[i * MLKEM_POLY_LEN]);
  }
}
