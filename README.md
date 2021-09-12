# Echo server and client using the QUIC protocol

This is a demo program used in a DevConf.US 2021 talk [Understanding
QUIC by examples].

## Compiling

1. Install Meson, GLib, GnuTLS 3.7.2, and the dependencies

```console
$ dnf install cmake gcc glib2-devel gnutls-devel g++ meson ninja-build
```

2. `meson _build`

3. `meson compile -C _build`

## Running

### Server

```console
$ _build/serv localhost 5556 credentials/server-key.pem credentials/server.pem
```

### Client

```console
$ _build/cli localhost 5556 credentials/ca.pem
```

### Logging

To enable logging for the application itself, set the
`G_MESSAGES_DEBUG` envvar to `echo`.  To enable ngtcp2 logging
facility, set the same variable to `ngtcp2`.

### Capturing traffic

1. Run either `cli` or `serv` with the `SSLKEYLOGFILE` envvar set:

```console
$ SSLKEYLOGFILE=$PWD/keylog.txt _build/cli localhost 5556 credentials/ca.pem
```

2. Use wireshark or tshark to capture the traffic:

```console
$ tshark -o "tls.keylog_file: $PWD/keylog.txt" \
         -i lo -Px -O quic -Y "udp.port == 5556"
```

## TODO

- ECN marking
- UDP GSO

## License

The MIT License

[Understanding QUIC by examples]: https://devconfus2021.sched.com/event/lkfO/understanding-quic-by-examples
