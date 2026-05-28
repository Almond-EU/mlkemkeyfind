#include "ml-kem.h"
#include "sha3.h"

/**
 * Load ML-KEM public key from a buffer array.
 *
 * Polynomials and arrays must have been correctly allocated by the caller
 * with a size that is consistent with the parameter k provided as input:
 *  - t:     k polynomials poly_t
 *  - mat_a: k * k polynomials poly_t
 *  - buf:   k * MLKEM_POLY_LEN bytes
 *
 * Arguments:
 *  - t:       pointer to the list of polynomials of the public vector t, where t = A*s + e
 *  - mat_a:   pointer to the list of polynomials of the public matrix A
 *  - pkh:     hash of public key
 *  - buf:     pointer to the byte array that contains the packed public key (according to FIPS-203)
 *  - param_k: ML-KEM parameter k (2, 3 or 4), used to know the size of the matrix
 */
void load_public_key(poly_t *t, poly_t *mat_a, uint8_t pkh[SHA3_256_LEN], const uint8_t *buf,
                     const size_t param_k) {
  /* public key hash */
  if (param_k == MLKEM512_K) {
    sha3_256(pkh, buf, MLKEM512_PK_LEN);
  }
  else if (param_k == MLKEM768_K) {
    sha3_256(pkh, buf, MLKEM768_PK_LEN);
  }
  else {
    sha3_256(pkh, buf, MLKEM1024_PK_LEN);
  }

  /* unpack t from buf */
  vec_frombytes(t, buf, param_k);

  /* generate matrix A */
  gen_public_matrix(mat_a, &buf[param_k*MLKEM_POLY_LEN], param_k);
}

/**
 * Load the polynomial v from the compressed ciphertext (u, v).
 *  - ML-KEM-512 and ML-KEM-768, compression uses d_v = 4
 *  - ML-KEM-1024, compression uses d_v = 5
 * 
 * Arguments:
 *  - v:       pointer to the uncompressed polynomial v of the ciphertext
 *  - buf:     pointer to the buffer array containing the compressed ciphertext
 *  - param_k: ML-KEM parameter k (2, 3 or 4), used to know the compression level
 */
void load_ciphertext_v(poly_t *v, const uint8_t *buf, const size_t param_k) {
  if (param_k == MLKEM512_K) {
    poly_decompress_d4(v, &buf[MLKEM512_CT_U_LEN]);
  }
  else if (param_k == MLKEM768_K) {
    poly_decompress_d4(v, &buf[MLKEM768_CT_U_LEN]);
  }
  else {
    poly_decompress_d5(v, &buf[MLKEM1024_CT_U_LEN]);
  }
}
