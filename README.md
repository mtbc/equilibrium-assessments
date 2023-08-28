Prepared by Mark Carroll for Eiger to follow v3 of the coding exercise:
https://github.com/eqlabs/recruitment-exercises/blob/master/node-handshake.md

The attached Rust code peers with public XRP Ledger nodes. Because the current
version of the Overlay handshake requires TLS state from OpenSSL to calculate
the session signature, there is an OpenSSL dependency.

For building the p2p-handshake executable, use current stable rustc, also the
OpenSSL development headers. Those headers may be available on your Linux
system from the libssl-dev or openssl-devel package.

p2p-handshake requires a PEM-encoded Secp256k1 key for use as its own node's.
Use of openssl to generate a suitable key is shown below. Once this key has
been read and used in handshakes, after a few seconds the executable prints
something like,

```
peer zaphod.alloy.ee:51235 sent message types: [56, 56, 2, 61, 30]
peer r.ripple.com:51235 sent message types: [56, 2, 61, 30, 33]
```

Those two public peers are set as default command-line argument values for
convenience.

These listed types refer to the MessageType enum values listed at the start of
https://github.com/XRPLF/rippled/blob/master/src/ripple/proto/ripple.proto
to show that the handshake must have been accepted by the remote peer because
protocol messages are now flowing. The messages are not decoded further, to
avoid an additional, unnecessary dependency on the protocol buffer compiler.

Occasionally, one of the public peers returns a HTTP 503 Service Unavailable
error. If so, waiting briefly, then retrying, tends to see it available again.

For example,

```shell
$ sudo apt install libssl-dev
$ openssl ecparam -name secp256k1 -genkey -noout -out key-sec1.pem
$ cargo build
$ target/debug/p2p-handshake
peer zaphod.alloy.ee:51235 sent message types: [56, 56, 2, 61, 41]
peer r.ripple.com:51235 sent message types: [56, 2, 61, 33, 33]
$ 
```
