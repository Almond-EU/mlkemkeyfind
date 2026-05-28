#ifndef ML_KEM_H_
#define ML_KEM_H_

#include <stddef.h>
#include <stdint.h>

#define MLKEM_N 256
#define MLKEM_Q 3329
#define MLKEM_POLY_LEN 384

/* ML-KEM-512 */
#define MLKEM512_K            2
#define MLKEM512_PK_LEN       800
#define MLKEM512_SK_LEN       1632
#define MLKEM512_CT_LEN       768
#define MLKEM512_POLYVEC_LEN  MLKEM_POLY_LEN * MLKEM768_K
#define MLKEM512_ETA1         3
#define MLKEM512_ETA1_LEN     64 * MLKEM512_ETA1
#define MLKEM512_DV           4
#define MLKEM512_CT_U_LEN     640

/* ML-KEM-768 */
#define MLKEM768_K            3
#define MLKEM768_PK_LEN       1184
#define MLKEM768_SK_LEN       2400
#define MLKEM768_CT_LEN       1088
#define MLKEM768_POLYVEC_LEN  MLKEM_POLY_LEN * MLKEM768_K
#define MLKEM768_ETA1         2
#define MLKEM768_ETA1_LEN     64 * MLKEM768_ETA1
#define MLKEM768_DV           4
#define MLKEM768_CT_U_LEN     960

/* ML-KEM-1024 */
#define MLKEM1024_K            4
#define MLKEM1024_PK_LEN       1568
#define MLKEM1024_SK_LEN       3168
#define MLKEM1024_CT_LEN       1568
#define MLKEM1024_POLYVEC_LEN  MLKEM_POLY_LEN * MLKEM1024_K
#define MLKEM1024_ETA1         2
#define MLKEM1024_ETA1_LEN     64 * MLKEM1024_ETA1
#define MLKEM1024_DV           5
#define MLKEM1024_CT_U_LEN     1408

/* Common to all parameters sets */
#define MLKEM_ETA2 2

/* Poly compression lengths */
#define POLY_DV_4_LEN  128 // 4 bits for each coefficient
#define POLY_DV_5_LEN  160 // 5 bits for each coefficient

typedef struct {
  int16_t c[MLKEM_N];
} poly_t;

/* field */
int16_t fq_barrett_reduce(const int16_t a);
int16_t fq_simple_reduce(int16_t a);
int16_t fq_reduce(const int32_t x);
int16_t fq_mul(const int16_t a, const int16_t b);

/* polynomial */
void poly_ntt(poly_t *r);
void poly_invntt(poly_t *r);
void poly_add(poly_t *res, const poly_t *a, const poly_t *b);
void poly_sub(poly_t *res, const poly_t *a, const poly_t *b);
void poly_mul(poly_t *res, const poly_t *a, const poly_t *b);
void poly_reduce(poly_t *pol);
void poly_tobytes(uint8_t r[MLKEM_POLY_LEN], const poly_t *a);
void poly_frombytes(poly_t *pol, const uint8_t a[MLKEM_POLY_LEN]);
void poly_decompress_d4(poly_t *pol, const uint8_t a[POLY_DV_4_LEN]);
void poly_decompress_d5(poly_t *pol, const uint8_t a[POLY_DV_5_LEN]);
void poly_compress_d4(uint8_t a[POLY_DV_4_LEN], const poly_t *pol);
void poly_compress_d5(uint8_t a[POLY_DV_5_LEN], const poly_t *pol);

int  poly_inverse(poly_t *poly_inv, const poly_t *poly);
void poly_tomsg(uint8_t msg[32], const poly_t *a);
void poly_sample(poly_t *r, const uint8_t input[32], const uint8_t n, const size_t eta);
void poly_frommsg(poly_t *a, const uint8_t msg[32]);

/* vector */
void vec_sub(poly_t *res, const poly_t *a, const poly_t *b, const size_t param_k);
void vec_mul(poly_t *res, const poly_t *a, const poly_t *b, const size_t param_k);
void vec_tobytes(uint8_t *buf, const poly_t *vec, const size_t param_k);
void vec_frombytes(poly_t *vec, const uint8_t *a, const size_t param_k);

/* matrix */
void gen_public_matrix(poly_t *mat, const uint8_t seed[32], const size_t param_k);
void mat_vec_mul(poly_t *res, const poly_t *mat, const poly_t *vec, const size_t param_k);
int  mat_inverse(poly_t *mat_inv, const poly_t *mat, const size_t param_k);

/* other */
void load_public_key(poly_t *t, poly_t *mat_a, uint8_t pkh[32], const uint8_t *buf,
                     const size_t param_k);
void load_ciphertext_v(poly_t *v, const uint8_t *buf, const size_t param_k);

#endif
