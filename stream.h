/* SPDX-License-Identifier: MIT */

#ifndef STREAM_H_
#define STREAM_H_

#include <glib.h>
#include <stddef.h>
#include <stdint.h>

typedef struct _Stream Stream;

Stream *stream_new (int64_t id);
void stream_free (Stream *stream);

int64_t stream_get_id (Stream *stream);
int stream_push_data (Stream *stream, const uint8_t *data, size_t data_size);
const uint8_t *stream_peek_data (Stream *stream, size_t *data_size);
void stream_mark_acked (Stream *stream, size_t offset);
void stream_mark_sent (Stream *stream, size_t offset);

/* For __attribute__((cleanup)) */
static inline void
stream_freep (Stream **p)
{
  Stream *stream = *p;
  if (stream)
    stream_free (stream);
}

#endif  /* STREAM_H_ */
