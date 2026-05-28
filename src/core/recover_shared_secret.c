#include <string.h>
#include "mlkemkeyfind.h"
#include "sha3.h"

/**
 * This function calculates:
 *   (K, r) <- SHA3-512(m || pkh)
 * where pkh is the hash of a public key using SHA3-256.
 */
static void derive_ss_and_encaps_seed(uint8_t ss_r[64], const uint8_t msg[32],
                                      const uint8_t pkh[32]) {
  sha3_state_t state;
  sha3_512_init(&state);
  sha3_512_update(&state, msg, 32);
  sha3_512_update(&state, pkh, 32);
  sha3_512_digest(&state, ss_r);
}

/**
 * Derivation of vector of polynomials y for an encapsulation.
 */
void derive_ntt_y(poly_t *y, const uint8_t seed[32], const size_t param_k) {
  size_t i;
  size_t eta = MLKEM768_ETA1;

  if (param_k == MLKEM512_K) {
    eta = MLKEM512_ETA1;
  }

  for (i = 0; i < param_k; i++) {
    poly_sample(&y[i], seed, (uint8_t)i, eta);
    poly_ntt(&y[i]);
  }
}

/**
 * Returns if the polynomials in inputs form an encapsulation vector
 *
 * Arguments:
 *  - ss:        shared secret if found
 *  - poly_list: list of polynomials
 *  - selection: position of a selection of polynomials in previous list
 *  - vec_t:     public vector
 *  - pol_v:     polynomial from the second component of a ciphertext
 *  - pkh:       hash of public key
 *  - param_k:   ML-KEM parameter k (2, 3 or 4), used to know the size of the matrix
 */
int is_encaps_vector(uint8_t ss[32], const poly_t *poly_list, const size_t *selection,
                     const poly_t *vec_t, const poly_t *pol_v, const uint8_t pkh[32],
                     const size_t param_k) {
  /* to prevent gcc warning since vec_y is passed as const in vec_mul function */
  poly_t vec_y[MLKEM1024_K] = { {{0}}, {{0}}, {{0}}, {{0}} };
  poly_t vec_y_test[MLKEM1024_K];
  poly_t mu;
  size_t i;
  uint8_t msg[32];
  uint8_t ss_r[SHA3_512_LEN];
  int found = 0;

  /* copy in vec_y the selection of secret polynomials */
  for (i = 0; i < param_k; i++) {
    vec_y[i] = poly_list[selection[i]];
  }

  /* dot product <t, y> */
  vec_mul(&mu, vec_y, vec_t, param_k);

  /* remove NTT representation */
  poly_invntt(&mu);

  /* v - <t, y> = e_2 + mu */
  poly_sub(&mu, pol_v, &mu);

  /* compression of mu to retrieve message m */
  poly_tomsg(msg, &mu);

  /* derive shared secret and encapsulation seed */
  derive_ss_and_encaps_seed(ss_r, msg, pkh);

  /* derive encapsulation vector to verify consistency */
  derive_ntt_y(vec_y_test, &ss_r[32], param_k);

  /* comparison */
  found = 1;
  for (i = 0; i < param_k; i++) {
    if (memcmp(vec_y[i].c, vec_y_test[i].c, MLKEM_N) != 0) {
      found = 0;
      break;
    }
  }

  /* if found copy shared secret to output buffer */
  if (found) {
    memcpy(ss, ss_r, 32);
  }

  return found;
}

/**
 * Derive the shared secret from a message in polynomial form and a public key.
 * If a ciphertext is provided, a partial encapsulation is executed to confirm.
 * 
 * Returns:
 *  - 0: not found (verified)
 *  - 1: found     (verified)
 *  - 2: not verified
 * 
 * Arguments:
 *  - ss:      pointer to a buffer to store the computed shared secret
 *  - pol_msg: pointer to a message in polynomial form
 *  - vec_t:   pointer to a public vector of an encapsulation key
 *  - pkh:     public key hash
 *  - ct:      pointer to a buffer containing a ciphertext (can be NULL)
 *  - param_k: ML-KEM parameter k (2, 3 or 4), used to know the size of the matrix
 */
int recover_shared_secret(uint8_t ss[32], const poly_t *pol_msg, const poly_t *vec_t,
                          const uint8_t pkh[32], const uint8_t *ct, const size_t param_k) {
  uint8_t ss_r[64]; // shared secret and encapsulation seed
  uint8_t msg[32];
  uint8_t c2[POLY_DV_5_LEN]; // largest between POLY_DV_4_LEN and POLY_DV_5_LEN
  poly_t vec_y[MLKEM1024_K];
  poly_t e2, v, mu;
  int found = SHARED_SECRET_POTENTIAL;
  
  /* (potential) polynomial message to a buffer array */
  poly_tomsg(msg, pol_msg);
  
  /* derivation of shared secret and encapsulation seed */
  derive_ss_and_encaps_seed(ss_r, msg, pkh);

  /* if a ciphertext is provided, the shared secret found is verified */
  if (ct != NULL) {
    /* derivation of vector y and polynomial e_2*/
    derive_ntt_y(vec_y, &ss_r[32], param_k);
    poly_sample(&e2, &ss_r[32], (uint8_t)(2*param_k), MLKEM_ETA2);

    /* conversion of a message into its polynomial representation */
    poly_frommsg(&mu, msg);

    /* compute v = <t, y> + e_2 + mu */
    vec_mul(&v, vec_t, vec_y, param_k);
    poly_invntt(&v);
    poly_add(&v, &v, &e2);
    poly_add(&v, &v, &mu);

    /* compress v into a ciphertext c_2 */
    if (param_k == MLKEM512_K || param_k == MLKEM768_K) {
      poly_compress_d4(c2, &v);
    }
    else {
      poly_compress_d5(c2, &v);
    }

    found = SHARED_SECRET_NOT_FOUND;
    /* comparison with provided ciphertext */
    if (param_k == MLKEM512_K) {
      if (memcmp(&ct[MLKEM512_CT_U_LEN], c2, POLY_DV_4_LEN) == 0) {
        found = SHARED_SECRET_FOUND;
      }
    }
    else if (param_k == MLKEM768_K) {
      if (memcmp(&ct[MLKEM768_CT_U_LEN], c2, POLY_DV_4_LEN) == 0) {
        found = SHARED_SECRET_FOUND;
      }
    }
    else {
      if (memcmp(&ct[MLKEM1024_CT_U_LEN], c2, POLY_DV_5_LEN) == 0) {
        found = SHARED_SECRET_FOUND;
      }
    }
  }

  /* copy to output if secret or potential secret found */
  if (found != SHARED_SECRET_NOT_FOUND) {
    memcpy(ss, ss_r, 32);
  }

  return found;
}
