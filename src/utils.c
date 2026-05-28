/**
 * Copyright (c) 2025, A. Russon
 * License: GPL v3
 *
 * --------------------------------------------------------------------------
 * Some part of the code originates from https://github.com/makomk/aeskeyfind
 * under the following license:
 *   Software License Agreement (BSD License)
 *   Copyright (c) 2008, Nadia Heninger and Ariel Feldman
 *             (c) 2008, Cameron Rich
 *             (c) 2017, Aidan Thornton
 *   All rights reserved.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

void print_success(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  fprintf(stdout, "[-] ");
  vfprintf(stdout, fmt, args);
  fprintf(stdout, "\n");
  va_end(args);
}

void print_info(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  fprintf(stdout, "[*] ");
  vfprintf(stdout, fmt, args);
  fprintf(stdout, "\n");
  va_end(args);
}

void print_warning(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  fprintf(stderr, "[!] ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}

void print_error(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  fprintf(stderr, "[x] ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}

/**
 * Memory maps a file and return a pointer on success.
 * Returns a pointer to the memory map and sets length of the file in variable `len`.
 * Does not return on error.
 *
 * This function originates from: https://github.com/makomk/aeskeyfind
 *
 * Arguments:
 *  - map:       pointer to a memory map
 *  - file_name: pointer to the file name
 *  - len:       pointer to the length of the file
 */
int map_file(uint8_t **map, size_t *len, const char *file_name) {
  struct stat st;
  int ret = -1;
  int fd = open(file_name, O_RDONLY);

  if (fd < 0) {
    print_error("Cannot open file \"%s\".", file_name);
    goto end;
  }

  if (fstat(fd, &st) != 0) {
    print_error("fstat failed on file \"%s\".", file_name);
    goto end;
  }

  *map = (uint8_t *)mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (*map == MAP_FAILED) {
    print_error("mmap failed on file \"%s\".", file_name);
    goto end;
  }

  *len = st.st_size;
  ret = 0;

end:
  return ret;
}

/**
 * Read a whole file into a buffer.
 * The caller is responsible to free the buffer (unless the return value is not 0).
 */
int read_file(const char *file_name, uint8_t **buf, size_t *len) {
  FILE *fp = NULL;
  uint8_t *data = NULL;
  size_t current = 0;
  size_t read;
  int ret = -1;
  
  fp = fopen(file_name, "rb");
  if (fp == NULL) {
    print_error("Cannot open file \"%s\".", file_name);
    goto err;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    print_error("Cannot read file (fseek) \"%s\".", file_name);
    goto err;
  }
  *len = ftell(fp);
  if (*len < 0) {
    print_error("Cannot read file (ftell) \"%s\".", file_name);
    goto err;
  }
  rewind(fp);

  data = (uint8_t *)malloc((*len)*sizeof(uint8_t));
  if (data == NULL) {
    print_error("Cannot allocate memory.");
    goto err;
  }

  while ((read = fread(&data[current], 1, 256, fp))) {
    current += read;
  }

  if (ferror(fp)) {
    print_error("Error reading file \"%s\".", file_name);
    goto err;
  }

  if (current != *len) {
    print_error("Error reading file \"%s\" (expected %ld bytes, read %ld bytes).",
                file_name, *len, current);
    goto err;
  }
  
  *buf = data;
  ret = 0;
  
err:
  if (ret != 0) {
    free(data);
  }
  if (fp != NULL) {
    fclose(fp);
  }

  return ret;
}

/**
 * Converts a buffer into an hexadecimal string.
 * The length of the output string MUST be twice the length of the buffer,
 * plus one null byte.
 */
void buffer_to_hex(char *s, const uint8_t *buf, const size_t len) {
  size_t i;
  uint8_t n1, n2;
  char c1, c2;
  for (i = 0; i < len; i++) {
    n1 = buf[i] >> 4;
    n2 = buf[i] & 0xf;
    if (n1 < 10) {
      c1 = '0' + n1;
    }
    else {
      c1 = 'a' + n1 - 10;
    }
    if (n2 < 10) {
      c2 = '0' + n2;
    }
    else {
      c2 = 'a' + n2 - 10;
    }
    s[2 * i]     = (char)c1;
    s[2 * i + 1] = (char)c2;
  }
  s[2 * len] = '\0';
}
