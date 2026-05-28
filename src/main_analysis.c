#include <stdlib.h>
#include "mlkemkeyfind.h"
#include "util.h"

static void print_usage() {
  printf("Usage: mlkemkeyfind analyze [ARGS]\n"
         "Arguments:\n"
         "  -i <input>          File name containing polynomials\n"
         "  -k <public key>     File name of a public key\n"
         "  -o <output>         File name to store the reconstructed secret key\n"
         "  -c <ciphertext>     File name containing a ciphertext (optional)\n");
}

static int load_polynomials(poly_t *poly_list, size_t *n_poly, poly_t *polymsg_list,
                            size_t *n_polymsg, const char *fname) {
  FILE *fp = NULL;
  size_t i;
  int ret = EXIT_FAILURE;

  fp = fopen(fname, "rb");
  if (fp == NULL) {
    print_error("Cannot open file %s", fname);
    goto err;
  }

  /* read number of secret polynomials */
  if (fread(n_poly, 8, 1, fp) != 1) {
    print_error("Cannot read number of secret polynomials");
    goto err;
  }
  if (*n_poly >= MAX_POLY) {
    print_error("Number of secret polynomials too big: %ld", *n_poly);
    goto err;
  }

  /* read number of message polynomials */
  if (fread(n_polymsg, 8, 1, fp) != 1) {
    print_error("Cannot read number of message polynomials");
    goto err;
  }
  if (*n_polymsg >= MAX_POLY) {
    print_error("Number of message polynomials too big: %ld", *n_polymsg);
    goto err;
  }

  /* read secret polynomials */
  for (i = 0; i < *n_poly; i++) {
    if (fread(poly_list[i].c, 512, 1, fp) != 1) {
      print_error("Cannot read secret polynomials");
      goto err;
    }
  }
  
  /* read message polynomials */
  for (i = 0; i < *n_polymsg; i++) {
    if (fread(polymsg_list[i].c, 512, 1, fp) != 1) {
      print_error("Cannot read message polynomials");
      goto err;
    }
  }

  ret = EXIT_SUCCESS;

err:
  if (fp != NULL) {
    fclose(fp);
  }
  return ret;
}

int main_analysis(int argc, char *argv[]) {
  FILE *fp = NULL;
  int opt;
  int ret = EXIT_FAILURE;
  char options[] = "i:k:o:c:";
  char *input_fname = NULL;
  char *pk_fname = NULL;
  char *output_fname = NULL;
  char *ct_fname = NULL;
  uint8_t *buf_pk = NULL;
  uint8_t ss[32];
  uint8_t pkh[32];
  uint8_t sk[MLKEM1024_SK_LEN]; // largest secret key
  char ss_hex[65];  uint8_t *buf_ct = NULL;
  size_t n_poly, n_polymsg, buf_pk_len, buf_ct_len, param_k, i, j, sk_len;
  size_t selection[MLKEM1024_K];
  int sk_found = 0;
  int ss_found;
  poly_t poly_list[MAX_POLY];
  poly_t polymsg_list[MAX_POLY];
  poly_t *mat_a = NULL;
  poly_t *mat_a_inv = NULL;
  poly_t pol_v;
  poly_t vec_t[MLKEM1024_K]; // largest public vector
  poly_t vec_s[MLKEM1024_K]; // largest secret vector

  /* parsing command line arguments */
  while ((opt = getopt(argc, argv, options)) != -1) {
    switch (opt) {
    case 'i':
      if (input_fname != NULL) {
        print_error("Multiple input file names");
        goto end;
      }
      input_fname = optarg;
      break;

    case 'k':
      if (pk_fname != NULL) {
        print_error("Multiple public key file names");
        goto end;
      }
      pk_fname = optarg;
      break;
    
    case 'o':
      if (output_fname != NULL) {
        print_error("Multiple output file names");
        goto end;
      }
      output_fname = optarg;
      break;

    case 'c':
      if (ct_fname != NULL) {
        print_error("Multiple ciphertext file names");
        goto end;
      }
      ct_fname = optarg;
      break;

    case '?':
      print_error("Read the manual.");
      goto end;
    }
  }

  /* mandatory arguments */
  if (input_fname == NULL || pk_fname == NULL || output_fname == NULL) {
    print_error("Missing input path, public key path or output path.");
    goto end;
  }
  
  /* read polynomials */
  if (load_polynomials(poly_list, &n_poly, polymsg_list, &n_polymsg, input_fname) != 0) {
    goto end;
  }

  /* read public key */
  if (read_file(pk_fname, &buf_pk, &buf_pk_len) != 0) {
    print_error("Cannot read file %s", pk_fname);
    goto end;
  }

  /* open output file here to check for write access */
  fp = fopen(output_fname, "w");
  if (fp == NULL) {
    print_error("Cannot open file %s for write access", output_fname);
    goto end;
  }

  /* find ML-KEM security level from the file length */
  if (buf_pk_len == MLKEM512_PK_LEN) {
    param_k = MLKEM512_K;
    sk_len = MLKEM512_SK_LEN;
  }
  else if (buf_pk_len == MLKEM768_PK_LEN) {
    param_k = MLKEM768_K;
    sk_len = MLKEM768_SK_LEN;
  }
  else if (buf_pk_len == MLKEM1024_PK_LEN) {
    param_k = MLKEM1024_K;
    sk_len = MLKEM1024_SK_LEN;
  }
  else {
    print_error("Public key length not consistent with any ML-KEM parameter set");
    goto end;
  }

  /* load public key vector and matrix */
  mat_a     = (poly_t *)malloc(param_k * param_k * sizeof(poly_t));
  mat_a_inv = (poly_t *)malloc(param_k * param_k * sizeof(poly_t));
  if (mat_a == NULL || mat_a_inv == NULL) {
    print_error("Cannot allocate memory for public matrix A");
    goto end;
  }
  load_public_key(vec_t, mat_a, pkh, buf_pk, param_k);

  /* load second part of ciphertext if present in argument */
  if (ct_fname != NULL) {
    if (read_file(ct_fname, &buf_ct, &buf_ct_len) != 0) {
      print_error("Cannot read file %s.", ct_fname);
      goto end;
    }

    load_ciphertext_v(&pol_v, buf_ct, param_k);
  }

  /* exploitation of secret polynomials found */
  if (n_poly < param_k) {
    print_info("Not enough secret polynomials.\n    "
               "Found: %ld\n    Needed: %ld", n_poly, param_k);
  }
  else {
    /* Look if the secret polynomials correspond to the secret vector s */
    for (i = 0; i + param_k <= n_poly; i++) {
      /* select consecutive polynomials */
      for (j = 0; j < param_k; j++) {
        selection[j] = i + j;
      }

      if (is_secret_vector(vec_s, poly_list, selection, vec_t, mat_a, param_k)) {
        print_success("Secret vector 's' found in memory!");
        sk_found = 1;
        break;
      }
    }

    /* Look if the secret polynomials correspond to the error vector */
    if (!sk_found) {
      /* calculate A^-1 */
      if (!mat_inverse(mat_a_inv, mat_a, param_k)) {
        print_warning("Matrix A is not invertible.");
      }
      else {
        for (i = 0; i + param_k <= n_poly; i++) {
          /* select param_k consecutive polynomials */
          for (j = 0; j < param_k; j++) {
            selection[j] = i + j;
          }

          if (is_error_vector(vec_s, poly_list, selection, vec_t, mat_a_inv, param_k)) {
            print_success("Secret vector 'e' found in memory!");
            sk_found = 1;
            break;
          }
        }
      }
    }

    /* Look if the secret polynomials correspond to the encapsulation vector */
    if (ct_fname != NULL) {
      for (i = 0; i + param_k <= n_poly; i++) {
        /* select consecutive polynomials */
        for (j = 0; j < param_k; j++) {
          selection[j] = i + j;
        }

        if (is_encaps_vector(ss, poly_list, selection, vec_t, &pol_v, pkh, param_k)) {
          buffer_to_hex(ss_hex, ss, 32);
          print_success("Shared secret found from encapsulation vector: %s", ss_hex);
          break;
        }
      }
    }
  }

  /* Look if the potential message polynomials lead to a shared secret */
  for (i = 0; i < n_polymsg; i++) {
    ss_found = recover_shared_secret(ss, &polymsg_list[i], vec_t, pkh, buf_ct, param_k);
    if (ss_found == SHARED_SECRET_NOT_FOUND) {
      print_warning("Shared secret not found");
    }
    else {
      buffer_to_hex(ss_hex, ss, 32);  
      if (ss_found == SHARED_SECRET_FOUND) {
        print_success("Shared secret found: %s", ss_hex);
      }
      else {
        print_warning("Potential shared secret found: %s", ss_hex);
      }
    }
  }

  /* write secret key recovered to an output file */
  if (sk_found) {
    recover_secret_key(sk, vec_s, buf_pk, param_k);
    /* write secret key to file */
    if (fwrite(sk, sk_len, 1, fp) != 1) {
      print_error("Cannot write to output file");
      goto end;
    }
    print_success("Secret key reconstructed!");
  }
  else {
    print_warning("No secret key found");
  }

  ret = EXIT_SUCCESS;

end:
  if (ret == EXIT_FAILURE) {
    print_usage();
  }
  if (buf_pk != NULL) {
    free(buf_pk);
  }
  if (buf_ct != NULL) {
    free(buf_ct);
  }
  if (mat_a != NULL) {
    free(mat_a);
  }
  if (mat_a_inv != NULL) {
    free(mat_a_inv);
  }
  if (fp != NULL) {
    fclose(fp);
  }

  return ret;
}
