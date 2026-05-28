#ifndef MLKEMKEYFIND_H_
#define MLKEMKEYFIND_H_

#include <stdio.h>
#include "ml-kem.h"

#define MLKEMKEYFIND_VERSION "1.0.0"

#define SHARED_SECRET_NOT_FOUND 0
#define SHARED_SECRET_FOUND     1
#define SHARED_SECRET_POTENTIAL 2

#define SEARCH_MODE_CENTERED  0
#define SEARCH_MODE_POSITIVE  1
#define SEARCH_MODE_SMALL     2
#define SEARCH_MODE_UNREDUCED 3

/* Buffer size for searching polynomials */
#define BUFFER_SIZE 512*1024

/* Number of maximum polynomial to be found (for static allocation) */
#define MAX_POLY 1280

typedef struct {
  size_t secret;
  size_t secret_shift;
  size_t msg;
  size_t msg_shift;
} offset_t;


int main_analysis(int argc, char *argv[]);
int main_search(int argc, char *argv[]);

void dump_search(poly_t *poly_list, size_t *n_poly, poly_t *polymsg_list, size_t *n_polymsg,
                 int search_mode, int search_message, FILE *fp);
void process_search(poly_t *poly_list, size_t *n_poly, poly_t *polymsg_list, size_t *n_polymsg,
                    int search_mode, int search_message, const uint32_t pid);

int find_secret_poly(poly_t *poly_list, const int mode, const uint8_t *buf, const size_t len,
                     offset_t *offset, int reset);
int find_message_poly(poly_t *polymsg_list, const uint8_t *buf, const size_t len, offset_t *offset,
                      int reset);

int is_secret_vector(poly_t *vec_s, const poly_t *vec_list, const size_t *selection,
                     const poly_t *t, const poly_t *mat_a, const size_t param_k);
int is_error_vector(poly_t *vec_s, const poly_t *vec_list, const size_t *selection,
                    const poly_t *vec_t, const poly_t *mat_a_inv, const size_t param_k);
int is_encaps_vector(uint8_t ss[32], const poly_t *poly_list, const size_t *selection,
                     const poly_t *vec_t, const poly_t *pol_v, const uint8_t pkh[32],
                     const size_t param_k);
void recover_secret_key(uint8_t *sk, const poly_t *vec_s, const uint8_t *pk,
                        const size_t param_k);
int recover_shared_secret(uint8_t ss[32], const poly_t *pol_msg, const poly_t *vec_t,
                          const uint8_t pkh[32], const uint8_t *ct, const size_t param_k);
#endif
