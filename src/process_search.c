#include <stdio.h>
#include <string.h>
#include "os_linux.h"
#include "mlkemkeyfind.h"
#include "util.h"

void process_search(poly_t *poly_list, size_t *n_poly, poly_t *polymsg_list, size_t *n_polymsg,
                    int search_mode, int search_message, const uint32_t pid) {
  uint8_t buffer[BUFFER_SIZE];
  uint32_t avail = 0;
  uint64_t next_addr;    // address of the next region to analyze
  uint64_t next_size;    // length of the next region to analyze
  uint64_t cur_addr = 0; // address of the current memory region that is analyzed
  uint64_t cur_size = 0; // length of current memory region to analyze
  uint32_t read;
  offset_t offset;
  size_t min_offset;
  bool consecutive = false;

  *n_poly = 0;
  *n_polymsg = 0;

  if (!os_process_begin(pid)) {
    print_error("Failed to open process");
    return;
  }

  /* initialize offsets */
  offset.msg = 0;
  offset.msg_shift = 1;
  offset.secret = 0;
  offset.secret_shift = 1;

  while (1) {
    /* this happens only for first occurrence or when a region has been fully read */
    if (cur_size == 0) {
      next_addr = os_process_next(&next_size);
      if (next_addr == 0) {
        /* no more region to read in this process */
        break;
      }

      /* in case of consecutive regions, we keep previous bytes available in buffer */      
      consecutive = cur_addr == next_addr;
      if (!consecutive) {
        avail = 0;
        offset.msg = 0;
        offset.msg_shift = 1;
        offset.secret = 0;
        offset.secret_shift = 1;
      }

      cur_addr = next_addr;
      cur_size = next_size;
    }

    /* number of bytes to read from the region to fill the buffer */
    read = BUFFER_SIZE - avail;
    if (read > cur_size) {
      read = (uint32_t)cur_size;
    }

    /* read new bytes from the current region of memory */
    read = os_process_read(cur_addr, buffer + avail, read);

    if (read == 0) {
      /* no more memory to read in this region */
      avail = 0;
      cur_size = 0;
      continue;
    }
    cur_addr += read;
    cur_size -= read;
    avail += read;

    /* at least 512 bytes are needed */
    if (avail < 512) {
      continue;
    }

    /* search for secret polynomials */
    *n_poly += find_secret_poly(&poly_list[*n_poly], search_mode, buffer, avail, &offset,
                                !consecutive);
    if (search_message) {
      *n_polymsg += find_message_poly(&polymsg_list[*n_polymsg], buffer, avail, &offset,
                                      !consecutive);
    }

    /*
     * After the search, each offset points to the next byte, so the minimal offset
     * determines how many bytes are kept before filling the buffer with new bytes.
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

  os_process_end();
}
