# Echo server and client using the QUIC protocol

This is a demo program used in a DevConf.US 2021 talk [Understanding
QUIC by examples].

## Compiling

1. Install Meson, GLib, and GnuTLS 3.7.2

```console
dnf install meson glib2-devel gnutls-devel
```

2. `meson _build`

3. `meson compile -C _build`

## Running

### Server

```console
_build/serv localhost 5556 credentials/server-key.pem credentials/server.pem
```

### Client

```console
_build/cli localhost 5556 credentials/ca.pem
```

### Logging

To enable logging for the application itself, set the
`G_MESSAGES_DEBUG` envvar to `echo`.  To enable ngtcp2 logging
facility, set the same variable to `ngtcp2`.

## TODO

- ECN marking
- UDP GSO

## License

The MIT License.

[Understanding QUIC by examples]: https://devconfus2021.sched.com/event/lkfO/understanding-quic-by-examples
