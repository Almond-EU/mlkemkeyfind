#include <string.h>
#include "ml-kem.h"
#include "sha3.h"

/**
 * Returns 1 if all coefficients are in [-3, 3].
 */
int check_sampled(const poly_t *pol) {
  size_t i;
  int is_sampled = 1;

  for (i = 0; i < MLKEM_N; i++) {
    if (pol->c[i] < -3 || pol->c[i] > 3) {
      is_sampled = 0;
      break;
    }
  }
  return is_sampled;
}

/**
 * Check if the selection of secret polynomials correspond to the secret vector s.
 * It must satisfy t = A*s + e.
 *
 * Arguments:
 *  - vec_s:     output pointer to the secret vector if found
 *  - poly_list: list of sample polynomials (coefficients in [-3, 3] or [-2, 2], but in NTT form)
 *  - selection: pointer to a list of indexes to choose from poly_list
 *                to construct a vector (must have length param_k)
 *  - vec_t:     pointer to the public vector
 *  - mat_a:     pointer to the public matrix
 *  - param_k:   ML-KEM parameter k (2, 3 or 4), used to know the size of the matrix
 */
int is_secret_vector(poly_t *vec_s, const poly_t *poly_list, const size_t *selection,
                     const poly_t *vec_t, const poly_t *mat_a, const size_t param_k) {
  size_t i;
  poly_t vec_e[MLKEM1024_K];
  int found;

  /* copy in vec_s the selection of secret polynomials */
  for (i = 0; i < param_k; i++) {
    vec_s[i] = poly_list[selection[i]];
  }

  /* A*s */
  mat_vec_mul(vec_e, mat_a, vec_s, param_k);

  /* t - A*s */
  vec_sub(vec_e, vec_t, vec_e, param_k);

  /* check if e is a vector of secret polynomials */
  found = 1;
  for (i = 0; i < param_k; i++) {
    poly_invntt(&vec_e[i]);
    found = check_sampled(&vec_e[i]);
    if (found == 0) {
      break;
    }
  }

  return found;
}

/**
 * Returns:
 *  - 0 if not a secret vector
 *  - 1 if it is the secret vector
 *
 * If found, the secret vector is returned in vec_s.
 *
 * Arguments:
 *  - vec_s:     output pointer to the secret vector if found
 *  - poly_list: list of sample polynomials (coefficients in [-3, 3] or [-2, 2] but in NTT form)
 *  - selection: pointer to a list of indexes to choose from poly_list
 *                to construct a vector (must have length param_k)
 *  - vec_t:     pointer to the public vector
 *  - mat_a_inv: pointer to the inverse of public matrix
 *  - param_k:   ML-KEM parameter k (2, 3 or 4), used to know the size of the matrix
 */
int is_error_vector(poly_t *vec_s, const poly_t *poly_list, const size_t *selection,
                    const poly_t *vec_t, const poly_t *mat_a_inv, const size_t param_k) {
  size_t i;
  /* to prevent gcc warning since vec_e is passed as const in vec_sub function */
  poly_t vec_e[MLKEM1024_K] = { {{0}}, {{0}}, {{0}}, {{0}} };
  poly_t vec_tmp[MLKEM1024_K];
  int found;

  /* copy in vec_e the selection of secret polynomials */
  for (i = 0; i < param_k; i++) {
    vec_e[i] = poly_list[selection[i]];
  }

  /* t - e */
  vec_sub(vec_tmp, vec_t, vec_e, param_k);

  /* A^-1*(t - e) */
  mat_vec_mul(vec_s, mat_a_inv, vec_tmp, param_k);

  /* check if vec_s is sampled */
  found = 1;
  for (i = 0; i < param_k; i++) {
    poly_invntt(&vec_s[i]);
    found = check_sampled(&vec_s[i]);
    if (found == 0) {
      break;
    }
  }

  /* if found, we revert vec_s to its NTT representation */
  if (found == 1) {
    for (i = 0; i < param_k; i++) {
      poly_ntt(&vec_s[i]);
    }
  }

  return found;
}

/**
 * Reconstruction of the KEM secret key from the secret vector and public key.
 *
 * Arguments:
 *  - sk:      pointer to the KEM secret key
 *  - vec_s:   pointer to the secret vector s
 *  - pk:      pointer to the KEM public key
 *  - param_k: ML-KEM parameter k (2, 3 or 4)
 */
void recover_secret_key(uint8_t *sk, const poly_t *vec_s, const uint8_t *pk, const size_t param_k) {
  size_t pk_len;
  uint8_t *pub_ptr, *pkh_ptr, *z_ptr;

  if (param_k == MLKEM512_K) {
    pk_len = MLKEM512_PK_LEN;
  }
  else if (param_k == MLKEM768_K) {
    pk_len = MLKEM768_PK_LEN;
  }
  else {
    pk_len = MLKEM1024_PK_LEN;
  }

  pub_ptr = &sk[MLKEM_POLY_LEN * param_k];
  pkh_ptr = &pub_ptr[pk_len];
  z_ptr = &pkh_ptr[SHA3_256_LEN];

  /* pack secret vector */
  vec_tobytes(sk, vec_s, param_k);

  /* copy public key buffer */
  memcpy(pub_ptr, pk, pk_len);

  /* hash public key */
  sha3_256(pkh_ptr, pk, pk_len);

  /* fill z with random values or 0 */
  memset(z_ptr, 0, 32);
}
