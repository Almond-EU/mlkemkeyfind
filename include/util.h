#ifndef UTILS_H_
#define UTILS_H_

#include <stddef.h>
#include <stdint.h>

/* util */
int map_file(uint8_t **map, size_t *len, const char *file_name);
int read_file(const char *file_name, uint8_t **buf, size_t *len);
void print_success(const char *fmt, ...);
void print_info(const char *fmt, ...);
void print_warning(const char *fmt, ...);
void print_error(const char *fmt, ...);
void buffer_to_hex(char *s, const uint8_t *buf, const size_t len);

int getopt(int argc, char * const argv[], const char *optstring);
extern int optind;
extern char *optarg;

#endif
