/* SPDX-License-Identifier: MIT */

#include "config.h"

#include "utils.h"

#include <errno.h>
#include <netdb.h>
#include <glib.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int
resolve_and_connect (const char *host, const char *port,
                     struct sockaddr *local_addr, size_t *local_addrlen,
                     struct sockaddr *remote_addr, size_t *remote_addrlen)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int ret, fd;

  memset (&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  ret = getaddrinfo (host, port, &hints, &result);
  if (ret != 0)
    return -1;

  for (rp = result; rp != NULL; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK,
                   rp->ai_protocol);
      if (fd == -1)
        continue;

      if (connect (fd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
          *remote_addrlen = rp->ai_addrlen;
          memcpy(remote_addr, rp->ai_addr, rp->ai_addrlen);

          socklen_t len = (socklen_t)*local_addrlen;
          if (getsockname (fd, local_addr, &len) == -1)
            return -1;
          *local_addrlen = len;
          break;
        }

      close (fd);
    }

  freeaddrinfo (result);

  if (rp == NULL)
    return -1;

  return fd;
}

int
resolve_and_bind (const char *host, const char *port,
                  struct sockaddr *local_addr, size_t *local_addrlen)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int ret, fd;

  memset (&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags  =  AI_PASSIVE;

  ret = getaddrinfo (host, port, &hints, &result);
  if (ret != 0)
    return -1;

  for (rp = result; rp != NULL; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd == -1)
        continue;

      if (bind (fd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
          *local_addrlen = rp->ai_addrlen;
          memcpy(local_addr, rp->ai_addr, rp->ai_addrlen);
          break;
        }

      close (fd);
    }

  freeaddrinfo(result);

  if (rp == NULL)
    return -1;

  return fd;
}

uint64_t
timestamp (void)
{
  struct timespec tp;

  if (clock_gettime (CLOCK_MONOTONIC, &tp) < 0)
    return 0;

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

void
log_printf (void *user_data, const char *fmt, ...)
{
  va_list ap;
  (void)user_data;

  va_start (ap, fmt);
  g_logv ("ngtcp2", G_LOG_LEVEL_DEBUG, fmt, ap);
  va_end (ap);
}

ssize_t
recv_packet (int fd, uint8_t *data, size_t data_size,
             struct sockaddr *remote_addr, size_t *remote_addrlen)
{
  struct iovec iov;
  iov.iov_base = data;
  iov.iov_len = data_size;

  struct msghdr msg;
  memset (&msg, 0, sizeof(msg));

  msg.msg_name = remote_addr;
  msg.msg_namelen = *remote_addrlen;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ssize_t ret;

  do
    ret = recvmsg (fd, &msg, MSG_DONTWAIT);
  while (ret < 0 && errno == EINTR);

  *remote_addrlen = msg.msg_namelen;

  return ret;
}

ssize_t
send_packet (int fd, const uint8_t *data, size_t data_size,
             struct sockaddr *remote_addr, size_t remote_addrlen)
{
  struct iovec iov;
  iov.iov_base = (void *)data;
  iov.iov_len = data_size;

  struct msghdr msg;
  memset (&msg, 0, sizeof(msg));
  msg.msg_name = remote_addr;
  msg.msg_namelen = remote_addrlen;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ssize_t ret;

  do
    ret = sendmsg (fd, &msg, MSG_DONTWAIT);
  while (ret < 0 && errno == EINTR);

  return ret;
}

int rand_bytes(uint8_t *data, size_t len);

int
get_random_cid (ngtcp2_cid *cid)
{
    uint8_t buf[NGTCP2_MAX_CIDLEN];

    if (rand_bytes(buf, sizeof(buf)) < 0) {
        return -1;
    }
    ngtcp2_cid_init(cid, buf, sizeof(buf));
    return 0;
}
