/* SPDX-License-Identifier: MIT */

#include "config.h"

#include "stream.h"

struct _Stream
{
  int64_t id;
  GQueue *buffer;
  /* invariant: sent_offset >= acked_offset */
  size_t sent_offset;
  size_t acked_offset;
};

Stream *
stream_new (int64_t id)
{
  Stream *stream = g_new (Stream, 1);
  g_return_val_if_fail (stream, NULL);
  stream->id = id;
  stream->buffer = g_queue_new ();
  stream->acked_offset = 0;
  stream->sent_offset = 0;
  return stream;
}

void
stream_free (Stream *stream)
{
  if (!stream)
    return;

  g_queue_free_full (stream->buffer, (GDestroyNotify)g_bytes_unref);
  g_free (stream);
}

int64_t
stream_get_id (Stream *stream)
{
  return stream->id;
}

int
stream_push_data (Stream *stream, const uint8_t *data, size_t data_size)
{
  GBytes *bytes = g_bytes_new (data, data_size);
  g_return_val_if_fail (bytes, -1);
  g_queue_push_tail (stream->buffer, bytes);
  return 0;
}

const uint8_t *
stream_peek_data (Stream *stream, size_t *data_size)
{
  size_t start_offset = stream->sent_offset - stream->acked_offset;
  size_t offset = 0;

  for (GList *l = g_queue_peek_head_link (stream->buffer); l; l = l->next)
    {
      GBytes *bytes = (GBytes *)l->data;
      gsize bytes_size;
      const uint8_t *bytes_data = g_bytes_get_data (bytes, &bytes_size);

      if (start_offset - offset < bytes_size)
        {
          *data_size = bytes_size - (start_offset - offset);
          return bytes_data + (start_offset - offset);
        }

      offset += bytes_size;
    }

  *data_size = 0;
  return NULL;
}

void
stream_mark_sent (Stream *stream, size_t offset)
{
  stream->sent_offset += offset;
}

void
stream_mark_acked (Stream *stream, size_t offset)
{
  while (!g_queue_is_empty (stream->buffer))
    {
      GBytes *head = g_queue_peek_head (stream->buffer);
      if (stream->acked_offset + g_bytes_get_size (head) > offset)
        break;

      stream->acked_offset += g_bytes_get_size (head);
      head = g_queue_pop_head (stream->buffer);
      g_bytes_unref (head);
    }
}
