/* SPDX-License-Identifier: MIT */

#ifndef UTILS_H_
#define UTILS_H_

#include <ngtcp2/ngtcp2.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int resolve_and_connect (const char *host, const char *port,
                         struct sockaddr *local_addr, size_t *local_addrlen,
                         struct sockaddr *remote_addr, size_t *remote_addrlen);

int resolve_and_bind (const char *host, const char *port,
                      struct sockaddr *local_addr, size_t *local_addrlen);

uint64_t timestamp (void);
void log_printf (void *user_data, const char *fmt, ...);
int get_random_cid (ngtcp2_cid *cid);

ssize_t recv_packet (int fd, uint8_t *data, size_t data_size,
                     struct sockaddr *remote_addr, size_t *remote_addrlen);
ssize_t send_packet (int fd, const uint8_t *data, size_t data_size,
                     struct sockaddr *remote_addr, size_t remote_addrlen);

/* For __attribute__((cleanup)) */
static inline void
closep (int *p)
{
  int fd = *p;
  if (fd >= 0)
    close (fd);
}

static inline int
steal_fd (int *p)
{
  int fd = *p;
  *p = -1;
  return fd;
}

#endif  /* UTILS_H_ */
