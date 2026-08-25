#include "common.h"

int main(int argc, char **argv) {
  const char *mode = "full";
  if (argc > 2) {
    fprintf(stderr, "usage: %s [--check|--full]\n", argv[0]);
    return 64;
  }
  if (argc == 2) {
    if (!strcmp(argv[1], "--check")) mode = "check";
    else if (!strcmp(argv[1], "--full")) mode = "full";
    else {
      fprintf(stderr, "usage: %s [--check|--full]\n", argv[0]);
      return 64;
    }
  }
  printf("CLI mode=%s default_full=%d\n", mode, argc == 1);
  return run_exploit(argc, argv);
}
