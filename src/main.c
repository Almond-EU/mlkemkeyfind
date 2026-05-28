#include <stdlib.h>
#include <string.h>
#include "mlkemkeyfind.h"
#include "util.h"

static void print_usage() {
  printf("mlkemkeyfind (version %s)\n", MLKEMKEYFIND_VERSION);
  printf("Usage: mlkemkeyfind [COMMAND] [ARGS]\n"
         "Commands:\n"
         "  search     Search for secret polynomials in memory\n"
         "  analyze    Reconstruct ML-KEM key or shared secret from secret polynomials\n");
}

int main(int argc, char *argv[]) {
  int ret = EXIT_FAILURE;
  if (argc < 2) {
    print_error("Subcommand is missing");
    print_usage();
    goto end;
  }

  if (strcmp(argv[1], "search") == 0) {
    ret = main_search(argc - 1, argv + 1);
  }
  else if (strcmp(argv[1], "analyze") == 0) {
    ret = main_analysis(argc - 1, argv + 1);
  }
  else {
    print_error("This subcommand does not exist");
    print_usage();
  }

end:
  return ret;
}
