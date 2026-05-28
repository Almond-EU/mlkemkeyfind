#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mlkemkeyfind.h"
#include "util.h"

static void print_usage() {
  printf("Usage: mlkemkeyfind search [ARGS]\n"
         "Arguments:\n"
         "  -i <memory dump>    File name of memory dump\n"
         "  -p <pid>            PID of process\n"
         "  -o <output>         File name to store secret polynomials found\n"
         "  -r <search mode>    \"centered\" or \"positive\"\n"
         "  -m                  Search for message polynomials (default to none)\n");
}

int main_search(int argc, char *argv[]) {
  int opt;
  int ret = EXIT_FAILURE;
  char options[] = "i:p:o:r:m";
  char *dump_fname = NULL;
  char *output_fname = NULL;
  int search_mode = SEARCH_MODE_CENTERED;
  int search_message = 0;
  uint32_t pid = 0;
  FILE *fp_out = NULL;
  FILE *fp_dump = NULL;
  poly_t poly_list[MAX_POLY];
  poly_t polymsg_list[MAX_POLY];
  size_t n_poly_dump = 0;
  size_t n_polymsg_dump = 0;
  size_t n_poly_proc = 0;
  size_t n_polymsg_proc = 0;
  size_t i;

  /* parsing command line arguments */
  while ((opt = getopt(argc, argv, options)) != -1) {
    switch (opt) {
    case 'i':
      if (dump_fname != NULL) {
        print_error("Multiple dump file names.");
        goto end;
      }
      dump_fname = optarg;
      break;

    case 'p':
      if (pid != 0) {
        print_error("Multiple PID.");
        goto end;
      }
      pid = atoi(optarg);
      break;
    
    case 'o':
      if (output_fname != NULL) {
        print_error("Multiple output file names.");
        goto end;
      }
      output_fname = optarg;
      break;

    case 'r':
      if (strcmp(optarg, "positive") == 0) {
        search_mode = SEARCH_MODE_POSITIVE;
      }
      else if (strcmp(optarg, "small") == 0) {
        search_mode = SEARCH_MODE_SMALL;
      }
      else if (strcmp(optarg, "unreduced") == 0) {
        search_mode = SEARCH_MODE_UNREDUCED;
      }
      else if (strcmp(optarg, "centered") == 0) {
        search_mode = SEARCH_MODE_CENTERED;
      }
      else {
        print_error("This search mode does not exist.");
        goto end;
      }
      break;

    case 'm':
      search_message = 1;
      break;

    case '?':
      print_error("Read the manual.");
      goto end;
    }
  }

  /* mandatory arguments */
  if (pid == 0 && dump_fname == NULL) {
    print_error("Missing PID or memory dump file name.");
    goto end;
  }
  if (output_fname == NULL) {
    print_error("Missing output file name.");
    goto end;
  }

  /* open output file in advance to check write access */
  fp_out = fopen(output_fname, "wb");
  if (fp_out == NULL) {
    print_error("Cannot open file %s for write access.", output_fname);
    goto end;
  }

  if (search_mode == SEARCH_MODE_CENTERED) {
    print_info("Searching secret polynomials in NTT form with coefficients in [-1664, 1664]");
    if (search_message) {
      print_info("Searching message polynomials with coefficients in [-1664, 1664]");
    }
  }
  else if (search_mode == SEARCH_MODE_POSITIVE) {
    print_info("Searching secret polynomials (NTT) with coefficients in [0, 3328]");
    if (search_message) {
      print_info("Searching message polynomials with coefficients in [0, 3328]");
    }
  }
  else if (search_mode == SEARCH_MODE_SMALL) {
    print_info("Searching for secret polynomials with coefficients in [-3, 3]");
  }

  /* search in memory dump */
  if (dump_fname != NULL) {
    fp_dump = fopen(dump_fname, "rb");
    if (fp_dump == NULL) {
      print_error("Cannot open file %s for read access.", dump_fname);
      goto end;
    }

    print_info("Searching for secrets in memory dump...");
    dump_search(poly_list, &n_poly_dump, polymsg_list, &n_polymsg_dump, search_mode,
                search_message, fp_dump);
    print_info("Secret polynomials found: %ld", n_poly_dump);
    if (search_message) {
      print_info("Message polynomials found: %ld", n_polymsg_dump);
    }
  }

  /* search in process memory */
  if (pid != 0) {
    print_info("Searching for secrets in memory of process %d...", pid);
    process_search(&poly_list[n_poly_dump], &n_poly_proc, &polymsg_list[n_polymsg_dump],
                   &n_polymsg_proc, search_mode, search_message, pid);
    print_info("Secret polynomials found: %ld", n_poly_proc);
    if (search_message) {
      print_info("Message polynomials found: %ld", n_polymsg_proc);
    }
  }

  /* 
   * write all polynomials to file with a simple format:
   * - 8 bytes in LSB: number of secret polynomials
   * - 8 bytes in LSB: number of message polynomials
   * - 512 bytes * (number of secret polynomials) 
   * - 512 bytes * (number of message polynomials)
   * */
  n_poly_dump += n_poly_proc;
  if (fwrite(&n_poly_dump, 8, 1, fp_out) == 0) {
    print_error("Cannot write to file %s.", output_fname);
    goto end;
  }
  n_polymsg_dump += n_polymsg_proc;
  if (fwrite(&n_polymsg_dump, 8, 1, fp_out) == 0) {
    print_error("Cannot write to file %s.", output_fname);
    goto end;
  }
  for (i = 0; i < n_poly_dump; i++) {
    if (fwrite(poly_list[i].c, 512, 1, fp_out) == 0) {
      print_error("Cannot write to file %s.", output_fname);
      goto end;
    }
  }
  for (i = 0; i < n_polymsg_dump; i++) {
    if (fwrite(polymsg_list[i].c, 512, 1, fp_out) == 0) {
      print_error("Cannot write to file %s.", output_fname);
      goto end;
    }
  }

  print_info("Search finished.");
  ret = EXIT_SUCCESS;

end:
  if (ret == EXIT_FAILURE) {
    print_usage();
  }
  if (fp_dump != NULL) {
    fclose(fp_dump);
  }
  if (fp_out != NULL) {
    fclose(fp_out);
  }

  return ret;
}
