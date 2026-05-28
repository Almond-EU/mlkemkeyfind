#include <stdio.h>
#include <string.h>

#include "mlkemkeyfind.h"

void dump_search(poly_t* poly_list, size_t* n_poly, poly_t* polymsg_list, size_t* n_polymsg,
                 int search_mode, int search_message, FILE* fp) {
  uint8_t buffer[BUFFER_SIZE];
  offset_t offset;
  size_t avail, read, min_offset;

  /* initialization */
  *n_poly = 0;
  *n_polymsg = 0;
  offset.msg = 0;
  offset.msg_shift = 1;
  offset.secret = 0;
  offset.secret_shift = 1;

  avail = 0;

  while (1) {
    read = BUFFER_SIZE - avail;
    read = fread(buffer + avail, 1, read, fp);
    avail += read;

    if (read == 0 || avail < 512) {
      /* no more memory to read or not enough for analysis */
      break;
    }

    /* search for secret polynomials */
    *n_poly += find_secret_poly(poly_list, search_mode, buffer, avail, &offset, 0);
    if (search_message) {
      *n_polymsg += find_message_poly(polymsg_list, buffer, avail, &offset, 0);
    }

    /*
     * After the search, each offset points to the next byte, so the minimal
     * offset determines how many bytes are kept before filling the buffer
     * with new bytes.
     */
    min_offset = offset.secret;
    if (offset.secret_shift < min_offset) {
      min_offset = offset.secret_shift;
    }
    if (search_message) {
      if (offset.msg < min_offset) {
        min_offset = offset.msg;
      }
      if (offset.msg_shift < min_offset) {
        min_offset = offset.msg_shift;
      }
    }

    /* move the last bytes to the begining of buffer for the sliding window */
    memmove(buffer, buffer + min_offset, avail - min_offset);
    avail -= min_offset;

    /* update offsets according to the move */
    offset.secret       -= min_offset;
    offset.secret_shift -= min_offset;
    if (search_message) {
      offset.msg       -= min_offset;
      offset.msg_shift -= min_offset;
    }
  }
}
